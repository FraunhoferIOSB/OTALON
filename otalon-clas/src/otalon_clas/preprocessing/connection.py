"""Connection (UCI) preprocessor with port collapsing and dynamic bucketing.

Applies UCI expansion, port-collapse rules, sparse-port aggregation, and
dynamic time-bucketing to connection-level network metrics fetched from
InfluxDB.
"""

from __future__ import annotations

from typing import Any

import polars as pl
from otalon_common.connection import (
    DynamicBucketConfig,
    PortCollapseConfig,
    PortCollapseRule,
    apply_port_rules,
    determine_port_collapse_rules,
)
from otalon_common.uci import expand_uci
from loguru import logger

from otalon_clas.preprocessing.base import BasePreprocessor
from otalon_clas.preprocessing.port_rules_repository import PortCollapseRulesRepository

DEFAULT_CONNECTION_FEATURES: list[str] = [
    "packet_count",
    "total_volume",
    "mean_packet_size",
    "min_packet_size",
    "max_packet_size",
    "std_packet_size",
    "mean_interarrival_time",
    "min_interarrival_time",
    "max_interarrival_time",
    "std_interarrival_time",
]
"""Default feature columns for connection-level metrics."""

FEATURE_AGG_RULES: dict[str, str] = {
    "packet_count": "sum",
    "total_volume": "sum",
    "min_packet_size": "min",
    "max_packet_size": "max",
    "std_packet_size": "mean",
    "min_interarrival_time": "min",
    "max_interarrival_time": "max",
    "std_interarrival_time": "mean",
}
"""Simple aggregation rules for dynamic bucketing. Weighted-mean features are
handled separately via ``WEIGHTED_MEAN_FEATURES``."""

WEIGHTED_MEAN_FEATURES: tuple[str, ...] = (
    "mean_packet_size",
    "mean_interarrival_time",
)
"""Features aggregated as total_volume.sum()/packet_count.sum() (mean_packet_size)
or weighted by packet_count (mean_interarrival_time)."""


class ConnectionPreprocessor(BasePreprocessor):
    """Preprocessor for connection-level UCI data.

    Supports optional port collapsing (rule-based or sparse-port fallback)
    and dynamic time-bucket aggregation. Port collapsing analyzes port
    variance per base-key group and wildcards high-variance ports to reduce
    the number of unique time series.

    Args:
        tag_key: Tag column name, typically ``"uci"``.
        features: Ordered list of feature column names.
        params: Preprocessing parameters controlling port collapsing and
            dynamic bucketing behavior.
    """

    def __init__(
        self,
        tag_key: str = "uci",
        features: list[str] | None = None,
        params: dict[str, Any] | None = None,
        module_name: str = "conn",
        rules_repository: PortCollapseRulesRepository | None = None,
    ) -> None:
        """Initialize the connection preprocessor.

        Args:
            tag_key: Tag column name for connection identification.
            features: Feature column names. Defaults to
                ``DEFAULT_CONNECTION_FEATURES``.
            params: Optional dict with keys ``port_collapsing_enabled``,
                ``port_collapsing_strategy``, ``dynamic_bucket_enabled``,
                and ``include_protocols_feature`` (default ``True``).
            module_name: Module name used as scope when persisting or
                loading port-collapse rules.
            rules_repository: Optional rules repository for DB-backed
                persistence and loading. When ``None`` rules are recomputed
                in-process on every call.
        """
        self._tag_key = tag_key
        # Numeric metric features used by the bounds detector and the
        # frequency monitor. The categorical ``protocols`` column is
        # NOT part of this list — bounds on a categorical field are
        # meaningless.
        self._features = features if features is not None else list(DEFAULT_CONNECTION_FEATURES)
        resolved_params = params if params is not None else {}
        self._port_collapsing_enabled: bool = resolved_params.get("port_collapsing_enabled", True)
        self._port_collapsing_strategy: str = resolved_params.get("port_collapsing_strategy", "heuristic_frequency")
        self._dynamic_bucket_enabled: bool = resolved_params.get("dynamic_bucket_enabled", True)
        self._include_protocols_feature: bool = resolved_params.get("include_protocols_feature", True)
        self._module_name = module_name
        self._rules_repository = rules_repository
        self._rules_cache: list[PortCollapseRule] | None = None
        # Categorical encoding for the ``protocols`` string column. The
        # map is grown on demand so that previously unseen protocol
        # stacks during inference receive a fresh integer code.
        self._protocol_to_code: dict[str, int] = {"": 0}
        self._protocol_to_code_locked: bool = False

    def preprocess_for_training(self, df: pl.DataFrame) -> pl.DataFrame:
        """Preprocess connection data for training.

        Expands UCI columns, applies port-collapse rules when enabled,
        aggregates sparse ports, and fills null values with zero.

        Args:
            df: Raw DataFrame with ``uci`` and feature columns.

        Returns:
            Preprocessed DataFrame with normalized UCIs and clean features.
        """
        return self._apply_preprocessing(df, mode="training")

    def preprocess_for_prediction(self, df: pl.DataFrame) -> pl.DataFrame:
        """Preprocess connection data for prediction.

        Applies the same pipeline as training to ensure consistency between
        trained models and live/offline prediction data.

        Args:
            df: Raw DataFrame with ``uci`` and feature columns.

        Returns:
            Preprocessed DataFrame with normalized UCIs and clean features.
        """
        return self._apply_preprocessing(df, mode="prediction")

    def preprocess_for_ml_training(self, df: pl.DataFrame) -> pl.DataFrame:
        """Preprocess raw connection data for ML classifier training.

        Applies exactly the same transform as
        :meth:`preprocess_for_prediction`: UCI expansion, port collapsing
        with time bucketing, null filling and protocol encoding.

        This previously kept the raw 1-second records and skipped port
        collapsing and bucketing entirely, to give sparse classes ~60x
        more samples. That reasoning holds for sample count but breaks
        the feature contract: ``packet_count`` and ``total_volume`` are
        summed over a bucket, so for a series whose rule carries
        ``bucket_seconds=300`` the served value is up to 300x the trained
        one, and ``mean_packet_size`` / ``mean_interarrival_time`` become
        packet-count-weighted bucket means rather than per-second values.
        The classifier was therefore fitted on one distribution and
        scored on another, far outside the fitted ``StandardScaler``
        range — exactly where a bounded-depth forest emits confident,
        arbitrary labels (audit CLAS-01).

        Rules are resolved in prediction mode so training does not
        recompute and persist them as a side effect; the bounds path
        (:meth:`preprocess_for_training`) remains the single writer of
        port-collapse rules.

        Args:
            df: Raw DataFrame with ``uci`` and feature columns.

        Returns:
            Bucket-aggregated DataFrame with expanded UCI fields, an
            integer ``protocols`` code and zero-filled features —
            identical in shape and scale to the live prediction input.
        """
        return self._apply_preprocessing(df, mode="prediction")

    def get_tag_column(self) -> str:
        """Return the tag column name.

        Returns:
            The configured tag key (default ``"uci"``).
        """
        return self._tag_key

    def get_feature_columns(self) -> list[str]:
        """Return the ordered feature column list used by the ML classifier.

        Includes the categorical ``protocols`` column (if enabled) at
        the end so that the classifier can use it as an additional
        feature without affecting the upstream bounds detector.

        Returns:
            List of feature column name strings.
        """
        cols = list(self._features)
        if self._include_protocols_feature and "protocols" not in cols:
            cols.append("protocols")
        return cols

    def _apply_preprocessing(self, df: pl.DataFrame, mode: str) -> pl.DataFrame:
        """Shared preprocessing pipeline for both training and prediction.

        Args:
            df: Raw input DataFrame.
            mode: Pipeline mode label for logging (``"training"`` or ``"prediction"``).

        Returns:
            Preprocessed DataFrame.
        """
        if df.is_empty():
            logger.debug("ConnectionPreprocessor: empty input for {}, returning as-is", mode)
            return df

        logger.debug(
            "ConnectionPreprocessor: {} mode, {} rows, port_collapsing={}",
            mode,
            len(df),
            self._port_collapsing_enabled,
        )

        df = self._expand_and_collapse(df, mode)
        df = self._fill_nulls(df)
        df = self._encode_protocols(df, mode)
        return df

    def _expand_and_collapse(self, df: pl.DataFrame, mode: str) -> pl.DataFrame:
        """Expand UCI and apply port-collapse rules.

        In ``training`` mode rules are computed from the input data and
        persisted via the rules repository (when configured).
        In ``prediction`` mode rules are loaded from the repository and
        applied; if no rules are available the data flows through
        unchanged.

        Args:
            df: DataFrame with a ``uci`` column.
            mode: Either ``"training"`` or ``"prediction"``.

        Returns:
            DataFrame with collapsed ports and aggregated features.
        """
        df_expanded = expand_uci(df)

        if not self._port_collapsing_enabled:
            logger.debug("ConnectionPreprocessor: port collapsing disabled, skipping")
            return df

        rules = self._resolve_rules(df_expanded, mode)
        logger.debug(
            "ConnectionPreprocessor[{}]: using {} port-collapse rules",
            mode,
            len(rules),
        )

        if not rules:
            return df

        # New series that are not covered by an existing port-collapse
        # rule (e.g. devices that joined after training) should not be
        # squeezed into a 60s bucket — that loses temporal resolution
        # and aligns the data with neither training distribution. We
        # use a 1s fallback so that live classification mirrors the
        # 1s-record training input.
        df_collapsed = apply_port_rules(df_expanded, rules, default_bucket_seconds=1)
        if "_bucket_epoch" in df_collapsed.columns and "time" not in df_collapsed.columns:
            df_collapsed = df_collapsed.with_columns(
                pl.from_epoch(pl.col("_bucket_epoch"), time_unit="s").alias("time")
            )
        # Re-extract the protocol stack from the collapsed UCI so the
        # downstream classifier can use it as a categorical feature.
        if "uci" in df_collapsed.columns and "protocols" not in df_collapsed.columns:
            df_collapsed = df_collapsed.with_columns(
                pl.col("uci").cast(pl.Utf8).str.split("/").list.get(8).alias("protocols")
            )
        return df_collapsed

    def _resolve_rules(
        self,
        df_expanded: pl.DataFrame,
        mode: str,
    ) -> list[PortCollapseRule]:
        """Compute or load port-collapse rules for the current mode.

        Args:
            df_expanded: DataFrame with expanded UCI columns.
            mode: Either ``"training"`` or ``"prediction"``.

        Returns:
            List of PortCollapseRule instances (empty when none are
            available in prediction mode without a repository).
        """
        if mode == "training":
            port_config = PortCollapseConfig(strategy=self._port_collapsing_strategy)
            bucket_config = DynamicBucketConfig() if self._dynamic_bucket_enabled else None
            rules = determine_port_collapse_rules(
                df_expanded,
                port_config=port_config,
                bucket_config=bucket_config,
            )
            if self._rules_repository is not None:
                self._rules_repository.save(self._module_name, rules)
            self._rules_cache = rules
            return rules

        if self._rules_cache is not None:
            return self._rules_cache

        if self._rules_repository is None:
            logger.warning(
                "ConnectionPreprocessor[{}]: no rules repository configured, " "falling back to in-process computation",
                self._module_name,
            )
            port_config = PortCollapseConfig(strategy=self._port_collapsing_strategy)
            bucket_config = DynamicBucketConfig() if self._dynamic_bucket_enabled else None
            self._rules_cache = determine_port_collapse_rules(
                df_expanded,
                port_config=port_config,
                bucket_config=bucket_config,
            )
            return self._rules_cache

        self._rules_cache = self._rules_repository.load(self._module_name)
        return self._rules_cache

    def reload_rules_cache(self) -> None:
        """Force the next rule resolution to reload from the repository.

        Use this hook when bounds are retrained or rules are externally
        updated and the live loop should pick up the new state without
        a process restart.
        """
        self._rules_cache = None

    def _encode_protocols(self, df: pl.DataFrame, mode: str) -> pl.DataFrame:
        """Replace the ``protocols`` string column with an integer code.

        During training the map grows whenever a new protocol stack is
        seen. During prediction the map is normally locked and unknown
        stacks fall back to ``0`` so that the live decoder is robust to
        rare protocol combinations.

        Args:
            df: DataFrame potentially carrying a ``protocols`` column.
            mode: ``"training"`` or ``"prediction"``.

        Returns:
            DataFrame with ``protocols`` cast to ``Int64``.
        """
        if not self._include_protocols_feature or "protocols" not in df.columns:
            return df
        protocol_values = df["protocols"].cast(pl.Utf8).fill_null("").to_list()
        codes: list[int] = []
        for proto in protocol_values:
            if proto in self._protocol_to_code:
                codes.append(self._protocol_to_code[proto])
                continue
            if self._protocol_to_code_locked:
                codes.append(0)
                continue
            new_code = max(self._protocol_to_code.values(), default=-1) + 1
            self._protocol_to_code[proto] = new_code
            codes.append(new_code)
        return df.with_columns(pl.Series("protocols", codes, dtype=pl.Int64))

    @property
    def protocol_map(self) -> dict[str, int]:
        """Return a copy of the protocol-to-code mapping."""
        return dict(self._protocol_to_code)

    def load_protocol_map(self, mapping: dict[str, int], lock: bool = True) -> None:
        """Restore a previously-trained protocol map for inference.

        Args:
            mapping: ``protocol-string -> code`` dict to load.
            lock: When True (default) further unknown protocols receive
                code ``0`` instead of being added to the map. Use
                ``False`` for incremental learning scenarios.
        """
        self._protocol_to_code = dict(mapping)
        self._protocol_to_code_locked = lock

    def _fill_nulls(self, df: pl.DataFrame) -> pl.DataFrame:
        """Replace null values with zero in all feature columns.

        Args:
            df: DataFrame potentially containing nulls in feature columns.

        Returns:
            DataFrame with nulls filled to zero.
        """
        fill_exprs = [pl.col(col).fill_null(0).alias(col) for col in self._features if col in df.columns]
        if fill_exprs:
            df = df.with_columns(fill_exprs)
        return df
