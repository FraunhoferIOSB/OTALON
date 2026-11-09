"""Bounds-based anomaly detection for time-series feature data.

Provides quantile-based boundary training (BoundsTrainer), persistent
storage in PostgreSQL (BoundsRepository), and real-time boundary
violation checking (BoundsManager) with TTL-based caching.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, cast

import polars as pl
from loguru import logger
from otalon_common.types import AnomalyType
from otalon_common.uci import matches_port_collapse_sibling

from otalon_clas.common.postgres_connector import Bound, PostgresConnector
from otalon_clas.common.settings import BoundaryTrainingConfig, PerFeatureOverride
from otalon_clas.detection.series_blacklist import SeriesBlacklist

NUMERIC_DTYPES: frozenset[type] = frozenset(
    {
        pl.Int8,
        pl.Int16,
        pl.Int32,
        pl.Int64,
        pl.UInt8,
        pl.UInt16,
        pl.UInt32,
        pl.UInt64,
        pl.Float32,
        pl.Float64,
    }
)

DEFAULT_PER_FEATURE_OVERRIDES: dict[str, PerFeatureOverride] = {
    "mean_interarrival_time": PerFeatureOverride(bounds_variation=1.0, upper_bound_min=5.0),
    "max_interarrival_time": PerFeatureOverride(bounds_variation=2.0, upper_bound_min=5.0),
    "min_interarrival_time": PerFeatureOverride(bounds_variation=2.0, upper_bound_min=5.0),
}


@dataclass(frozen=True, slots=True)
class BoundsResult:
    """Result of a single bounds check for one time-series row."""

    is_anomaly: bool
    anomaly_type: str
    confidence: float
    violated_features: list[str]
    severity: float


@dataclass
class _CachedBounds:
    """Internal cache entry holding bounds data and load timestamp."""

    bounds: dict[str, dict[str, tuple[float, float]]]
    loaded_at: float = field(default_factory=time.monotonic)


class BoundsTrainer:
    """Computes quantile-based upper and lower bounds per series and feature.

    Training uses configurable quantile levels and variation margins to
    produce boundary envelopes from historical data.
    """

    def __init__(self, blacklist: str | list[str] = "") -> None:
        """Initialize the trainer with optional series exclusions.

        Args:
            blacklist: Patterns for series to exclude from training
                (plain tags or compound UCIs; see
                :class:`SeriesBlacklist`).
        """
        self._boot_blacklist = blacklist
        self._blacklist = SeriesBlacklist(blacklist)

    @property
    def blacklist(self) -> SeriesBlacklist:
        """Return the blacklist instance currently active for training."""
        return self._blacklist

    def update_blacklist(self, blacklist: SeriesBlacklist | None) -> None:
        """Swap in the runtime blacklist instance (copy-on-write, CLAS-071).

        The runtime retrain JobRunner refreshes this once per job start;
        ``None`` restores the per-module ``config.json`` boot default.

        Args:
            blacklist: Immutable instance resolved from the runtime
                source, or ``None`` when no runtime row exists.
        """
        self._blacklist = blacklist if blacklist is not None else SeriesBlacklist(self._boot_blacklist)

    def train(
        self,
        df: pl.DataFrame,
        tag_key: str,
        features: list[str],
        config: BoundaryTrainingConfig | None = None,
        previous_bounds: dict[str, dict[str, tuple[float, float]]] | None = None,
    ) -> dict[str, dict[str, tuple[float, float]]]:
        """Train bounds from a Polars DataFrame.

        Series whose samples span less than
        ``config.min_series_coverage_hours`` of wall-clock time inside the
        training window are skipped instead of trained (CLAS-028). Such a
        series yields a quantile envelope far tighter than its real
        variability, so every normal fluctuation becomes a
        ``BoundViolation``. A skipped series carries its ``previous_bounds``
        entry forward when one exists and is otherwise left out entirely.

        Args:
            df: Training data with a tag column and numeric feature columns.
            tag_key: Column name identifying each series.
            features: List of feature column names to compute bounds for.
            config: Boundary training configuration. Uses defaults when None.
            previous_bounds: Currently published bounds, used to carry a
                coverage-skipped series forward unchanged.

        Returns:
            Nested dict mapping series_id -> feature_name -> (lower, upper).
        """
        config = config or BoundaryTrainingConfig()
        df = self._filter_blacklisted(df, tag_key)
        merged_overrides = self._merge_overrides(config)
        available_features = self._resolve_features(df, features)

        if not available_features:
            logger.warning("No valid numeric features found for bounds training")
            return {}

        return self._compute_all_series(
            df,
            tag_key,
            available_features,
            config,
            merged_overrides,
            previous_bounds or {},
        )

    def _series_coverage_hours(self, group_df: pl.DataFrame, time_column: str) -> float | None:
        """Return the wall-clock span of a series group in hours.

        Args:
            group_df: Data for one series.
            time_column: Name of the timestamp column.

        Returns:
            Span in hours, or ``None`` when the group carries no usable
            timestamps and the coverage guard cannot be evaluated.
        """
        if time_column not in group_df.columns:
            return None
        column = group_df[time_column].drop_nulls()
        if column.is_empty():
            return None
        first = column.min()
        last = column.max()
        if first is None or last is None:
            return None
        if isinstance(first, datetime) and isinstance(last, datetime):
            return (last - first).total_seconds() / 3600.0
        if isinstance(first, (int, float)) and isinstance(last, (int, float)):
            return (float(last) - float(first)) / 3600.0
        return None

    def _passes_coverage(
        self,
        group_df: pl.DataFrame,
        series_id: str,
        config: BoundaryTrainingConfig,
    ) -> bool:
        """Return whether a series spans enough wall-clock time to train."""
        if config.min_series_coverage_hours <= 0.0:
            return True
        coverage = self._series_coverage_hours(group_df, config.time_column)
        if coverage is None:
            return True
        if coverage >= config.min_series_coverage_hours:
            return True
        logger.warning(
            "Series '{}': training window covers only {:.2f}h "
            "(< {:.2f}h minimum) - skipping bounds publish (CLAS-028)",
            series_id,
            coverage,
            config.min_series_coverage_hours,
        )
        return False

    def _filter_blacklisted(self, df: pl.DataFrame, tag_key: str) -> pl.DataFrame:
        """Remove blacklisted series before calculating quantile envelopes."""
        if self._blacklist.is_empty or tag_key not in df.columns:
            return df
        return df.filter(
            ~pl.col(tag_key)
            .cast(pl.String)
            .map_elements(lambda value: self._blacklist.matches(str(value)), return_dtype=pl.Boolean)
        )

    def _is_blacklisted(self, series_id: str) -> bool:
        """Return whether a series identifier matches configured exclusions."""
        return self._blacklist.matches(series_id)

    def _merge_overrides(
        self,
        config: BoundaryTrainingConfig,
    ) -> dict[str, PerFeatureOverride]:
        """Merge default per-feature overrides with user-supplied overrides.

        Args:
            config: Boundary training configuration with optional overrides.

        Returns:
            Combined override mapping with user values taking precedence.
        """
        merged = dict(DEFAULT_PER_FEATURE_OVERRIDES)
        merged.update(config.per_feature_overrides)
        return merged

    def _resolve_features(self, df: pl.DataFrame, features: list[str]) -> list[str]:
        """Filter requested features to those present and numeric in the DataFrame.

        Args:
            df: Source DataFrame to validate columns against.
            features: Requested feature column names.

        Returns:
            Subset of features that exist and have numeric dtypes.
        """
        schema = df.schema
        return [f for f in features if f in schema and schema[f] in NUMERIC_DTYPES]

    def _compute_all_series(
        self,
        df: pl.DataFrame,
        tag_key: str,
        features: list[str],
        config: BoundaryTrainingConfig,
        overrides: dict[str, PerFeatureOverride],
        previous_bounds: dict[str, dict[str, tuple[float, float]]],
    ) -> dict[str, dict[str, tuple[float, float]]]:
        """Compute bounds for every series in the DataFrame.

        Args:
            df: Training data.
            tag_key: Series identifier column.
            features: Validated feature columns.
            config: Global boundary parameters.
            overrides: Per-feature parameter overrides.
            previous_bounds: Published bounds carried forward for series
                that fail the coverage guard.

        Returns:
            Nested dict of bounds per series and feature.
        """
        result: dict[str, dict[str, tuple[float, float]]] = {}
        skipped = 0
        carried = 0
        for (raw_series_id,), group_df in df.group_by(tag_key):
            series_id = str(raw_series_id)
            if not self._passes_coverage(group_df, series_id, config):
                skipped += 1
                retained = previous_bounds.get(series_id)
                if retained:
                    result[series_id] = retained
                    carried += 1
                continue
            series_bounds = self._compute_series_bounds(group_df, series_id, features, config, overrides)
            if series_bounds:
                result[series_id] = series_bounds
        logger.info(
            "Trained bounds for {} series across {} features "
            "({} skipped for insufficient coverage, {} kept previous bounds)",
            len(result),
            len(features),
            skipped,
            carried,
        )
        return result

    def _compute_series_bounds(
        self,
        group_df: pl.DataFrame,
        series_id: str,
        features: list[str],
        config: BoundaryTrainingConfig,
        overrides: dict[str, PerFeatureOverride],
    ) -> dict[str, tuple[float, float]]:
        """Compute feature bounds for a single series group.

        Args:
            group_df: Data for one series.
            series_id: Identifier of the series (for logging).
            features: Feature columns to process.
            config: Global boundary parameters.
            overrides: Per-feature parameter overrides.

        Returns:
            Dict mapping feature_name -> (lower_bound, upper_bound).
        """
        bounds: dict[str, tuple[float, float]] = {}
        for feature in features:
            if feature not in group_df.columns:
                continue
            lower, upper = self._compute_feature_bounds(group_df, feature, config, overrides)
            bounds[feature] = (lower, upper)
        return bounds

    def _compute_feature_bounds(
        self,
        group_df: pl.DataFrame,
        feature: str,
        config: BoundaryTrainingConfig,
        overrides: dict[str, PerFeatureOverride],
    ) -> tuple[float, float]:
        """Compute lower and upper bound for a single feature column.

        Uses quantile-based envelope with variation margin:
            lower = quantile(q) * (1.0 - bounds_variation)
            upper = quantile(1 - q) * (1.0 + bounds_variation)
            upper = max(upper, upper_bound_min)

        Args:
            group_df: Data for one series.
            feature: Feature column name.
            config: Global boundary parameters.
            overrides: Per-feature parameter overrides.

        Returns:
            Tuple of (lower_bound, upper_bound).
        """
        q = config.quantile
        bounds_variation = config.bounds_variation
        upper_bound_min = config.upper_bound_min

        override = overrides.get(feature)
        if override is not None:
            if override.bounds_variation is not None:
                bounds_variation = override.bounds_variation
            if override.upper_bound_min is not None:
                upper_bound_min = override.upper_bound_min

        col = group_df[feature].drop_nulls().cast(pl.Float64)
        lower_q = float(col.quantile(q, interpolation="linear") or 0.0)
        upper_q = float(col.quantile(1.0 - q, interpolation="linear") or 0.0)

        lower_bound = lower_q * (1.0 - bounds_variation)
        upper_bound = upper_q * (1.0 + bounds_variation)
        upper_bound = max(upper_bound, upper_bound_min)

        return lower_bound, upper_bound


class BoundsRepository:
    """Persists bounds to and loads bounds from the PostgreSQL ``bounds`` table.

    Args:
        connector: PostgreSQL connector providing session management.
    """

    def __init__(self, connector: PostgresConnector) -> None:
        """Initialize the bounds repository."""
        self._connector = connector

    def load(self, module: str) -> dict[str, dict[str, tuple[float, float]]]:
        """Load all bounds for the given module from PostgreSQL.

        Args:
            module: Detection module name (e.g. ``"conn"``).

        Returns:
            Nested dict mapping series_id -> feature -> (lower, upper).
        """
        result: dict[str, dict[str, tuple[float, float]]] = {}
        with self._connector.session() as session:
            rows = session.query(Bound).filter(Bound.module == module).all()
            for row in rows:
                lower = cast(dict[str, Any], row.lower_bounds or {})
                upper = cast(dict[str, Any], row.upper_bounds or {})
                feature_bounds: dict[str, tuple[float, float]] = {}
                for feature, lb in lower.items():
                    if feature not in upper:
                        continue
                    try:
                        feature_bounds[feature] = (float(lb), float(upper[feature]))
                    except (TypeError, ValueError):
                        continue
                if feature_bounds:
                    result[str(row.series_id)] = feature_bounds
        logger.info(
            "BoundsRepository[{}]: loaded {} series from PostgreSQL",
            module,
            len(result),
        )
        return result

    def save(
        self,
        module: str,
        bounds: dict[str, dict[str, tuple[float, float]]],
        first_ts: datetime | None = None,
        last_ts: datetime | None = None,
        replace: bool = False,
    ) -> int:
        """Persist bounds for a module to PostgreSQL via upsert.

        Args:
            module: Detection module name.
            bounds: Nested dict mapping series_id -> feature -> (lower, upper).
            first_ts: Optional first timestamp of the training window.
            last_ts: Optional last timestamp of the training window.
            replace: When ``True``, delete every existing row for the module
                and insert the given bounds inside a single transaction, so a
                retrain replaces the module's bounds atomically and no stale
                series from a prior training survive. When ``False`` (default)
                the legacy per-series upsert semantics are preserved.

        Returns:
            Number of bound rows upserted.

        Raises:
            ValueError: When ``replace=True`` and ``bounds`` is empty. An empty
                retrain result would otherwise either silently keep every stale
                series (delete skipped) or silently wipe all bounds (delete
                run), leaving the module either not-replaced or detection-blind.
                Both are unsafe, so an empty replace is refused loudly. The
                raise happens before the transaction opens, so no DB rows are
                touched. For ``replace=False`` an empty ``bounds`` is a
                harmless no-op that returns 0.
        """
        if not bounds:
            if replace:
                raise ValueError(
                    f"BoundsRepository[{module}]: refusing replace=True with "
                    "empty bounds; an empty retrain window would keep stale "
                    "series or wipe all bounds. Check the training window/data."
                )
            return 0

        now = datetime.now(tz=timezone.utc)
        count = 0
        with self._connector.session() as session:
            if replace:
                deleted = session.query(Bound).filter(Bound.module == module).delete()
                logger.info(
                    "BoundsRepository[{}]: replace=True deleted {} stale rows",
                    module,
                    deleted,
                )
            for series_id, feature_bounds in bounds.items():
                lower = {f: lb for f, (lb, _ub) in feature_bounds.items()}
                upper = {f: ub for f, (_lb, ub) in feature_bounds.items()}
                record = Bound(
                    module=module,
                    series_id=series_id,
                    lower_bounds=lower,
                    upper_bounds=upper,
                    trained_at=now,
                    first_ts=first_ts,
                    last_ts=last_ts,
                )
                session.merge(record)
                count += 1
        logger.info(
            "BoundsRepository[{}]: persisted {} series to PostgreSQL",
            module,
            count,
        )
        return count

    def delete_module(self, module: str) -> int:
        """Delete all bound rows for a module.

        Args:
            module: Detection module name.

        Returns:
            Number of rows deleted.
        """
        with self._connector.session() as session:
            deleted = session.query(Bound).filter(Bound.module == module).delete()
        logger.info(
            "BoundsRepository[{}]: deleted {} rows from PostgreSQL",
            module,
            deleted,
        )
        return int(deleted)

    def snapshot_module(self, module: str) -> list[dict[str, object]]:
        """Capture exact persisted rows for one module, including metadata."""
        with self._connector.session() as session:
            rows = session.query(Bound).filter(Bound.module == module).all()
            return [
                {
                    "module": row.module,
                    "series_id": row.series_id,
                    "lower_bounds": dict(row.lower_bounds or {}),
                    "upper_bounds": dict(row.upper_bounds or {}),
                    "trained_at": row.trained_at,
                    "first_ts": row.first_ts,
                    "last_ts": row.last_ts,
                }
                for row in rows
            ]

    def restore_module(self, module: str, rows: list[dict[str, object]]) -> None:
        """Restore exact previously captured rows for one module."""
        with self._connector.session() as session:
            session.query(Bound).filter(Bound.module == module).delete()
            for row in rows:
                session.add(Bound(**row))


class BoundsManager:
    """Manages loaded bounds and performs real-time violation checks.

    Bounds are loaded from PostgreSQL via :class:`BoundsRepository` and
    cached in memory with a configurable TTL. The check method annotates
    incoming DataFrames with anomaly columns and refreshes the cache from
    the database when it has expired.
    """

    def __init__(
        self,
        module_name: str,
        cache_ttl_seconds: int = 60,
        repository: BoundsRepository | None = None,
        blacklist: str | list[str] = "",
    ) -> None:
        """Initialize the bounds manager.

        Args:
            module_name: Name of the pipeline module this manager belongs to.
            cache_ttl_seconds: Time-to-live in seconds for cached bounds data.
            repository: Optional bounds repository for DB-backed loading.
            blacklist: Patterns for series to exclude from checking
                (plain tags or compound UCIs; see :class:`SeriesBlacklist`).
        """
        self._module_name = module_name
        self._cache_ttl_seconds = cache_ttl_seconds
        self._cache: _CachedBounds | None = None
        self._repository = repository
        self._boot_blacklist = blacklist
        self._blacklist = SeriesBlacklist(blacklist)

    @property
    def blacklist(self) -> SeriesBlacklist:
        """Return the blacklist instance currently active for checking."""
        return self._blacklist

    def update_blacklist(self, blacklist: SeriesBlacklist | None) -> None:
        """Swap in the per-tick blacklist instance (copy-on-write, CLAS-071).

        ``None`` restores the per-module ``config.json`` boot default, so
        deleting the runtime-config row returns the manager to its boot
        behavior on the next tick.

        Args:
            blacklist: Immutable instance resolved once for this tick, or
                ``None`` when no runtime row exists.
        """
        self._blacklist = blacklist if blacklist is not None else SeriesBlacklist(self._boot_blacklist)

    @property
    def module_name(self) -> str:
        """Return the module name this manager is associated with."""
        return self._module_name

    @property
    def is_cache_valid(self) -> bool:
        """Return True if cached bounds exist and have not expired."""
        if self._cache is None:
            return False
        elapsed = time.monotonic() - self._cache.loaded_at
        return elapsed < self._cache_ttl_seconds

    def load_bounds(self, bounds_dict: dict[str, dict[str, tuple[float, float]]]) -> None:
        """Load bounds into memory, refreshing the cache timestamp.

        Args:
            bounds_dict: Nested dict mapping series_id -> feature -> (lower, upper).
        """
        self._cache = _CachedBounds(bounds=bounds_dict)
        logger.debug(
            "[{}] Loaded bounds for {} series into cache",
            self._module_name,
            len(bounds_dict),
        )

    def invalidate(self) -> None:
        """Force the next :meth:`check` to reload bounds from the repository."""
        self._cache = None
        logger.debug("[{}] Bounds cache invalidated", self._module_name)

    def check(
        self,
        df: pl.DataFrame,
        tag_key: str,
        features: list[str],
    ) -> pl.DataFrame:
        """Check a DataFrame for boundary violations per series.

        Annotates the input DataFrame with columns: is_anomaly, anomaly_type,
        confidence, and violated_features.

        Args:
            df: Input data with tag and feature columns.
            tag_key: Column name identifying each series.
            features: Feature columns to check against bounds.

        Returns:
            DataFrame with appended anomaly annotation columns.
        """
        if df.is_empty():
            return self._append_empty_columns(df)

        bounds = self._get_bounds()
        schema = df.schema
        valid_features = [f for f in features if f in schema and schema[f] in NUMERIC_DTYPES]

        result_frames: list[pl.DataFrame] = []
        for (series_id,), group_df in df.group_by(tag_key):
            if self._is_blacklisted(str(series_id)):
                result_frames.append(self._annotate_no_violations(group_df))
                continue
            annotated = self._check_series(group_df, str(series_id), valid_features, bounds)
            result_frames.append(annotated)

        if not result_frames:
            return self._append_empty_columns(df)
        return pl.concat(result_frames)

    def _is_blacklisted(self, series_id: str) -> bool:
        """Return whether a series identifier matches configured exclusions."""
        return self._blacklist.matches(series_id)

    def _get_bounds(self) -> dict[str, dict[str, tuple[float, float]]]:
        """Return cached bounds, refreshing from PostgreSQL when needed.

        Returns:
            Bounds mapping or empty dict if no repository is configured
            and no bounds were loaded manually.
        """
        if self.is_cache_valid and self._cache is not None:
            return self._cache.bounds

        if self._repository is None:
            if self._cache is None:
                logger.warning("[{}] No bounds loaded in cache", self._module_name)
                return {}
            return self._cache.bounds

        try:
            fresh = self._repository.load(self._module_name)
            self.load_bounds(fresh)
            return fresh
        except Exception:
            logger.exception(
                "[{}] Failed to load bounds from PostgreSQL",
                self._module_name,
            )
            return self._cache.bounds if self._cache is not None else {}

    def _check_series(
        self,
        group_df: pl.DataFrame,
        series_id: str,
        features: list[str],
        bounds: dict[str, dict[str, tuple[float, float]]],
    ) -> pl.DataFrame:
        """Check a single series group for bounds violations.

        Bounds are resolved via :meth:`_resolve_bounds`, which tolerates
        wildcard or rotated ports (CLAS-057): an exact key match is the fast
        path, and only on miss does the incoming (possibly wildcard) series
        resolve to a trained concrete sibling of the same connection.

        Args:
            group_df: Data for one series.
            series_id: Identifier of the series.
            features: Feature columns to evaluate.
            bounds: Full bounds dict (all series).

        Returns:
            Annotated DataFrame with anomaly columns.
        """
        series_bounds = self._resolve_bounds(series_id, bounds)
        if series_bounds is None:
            return self._annotate_no_bounds(group_df, features)

        return self._annotate_violations(group_df, series_bounds, features)

    def _resolve_bounds(
        self,
        series_id: str,
        bounds: dict[str, dict[str, tuple[float, float]]],
    ) -> dict[str, tuple[float, float]] | None:
        """Resolve the bounds entry for a series, tolerating wildcard ports.

        An exact ``series_id`` key is the fast path. On miss the incoming
        series -- which may carry wildcard (``*``) ports -- is matched against
        the trained concrete keys using port-collapse sibling semantics
        (:func:`otalon_common.uci.matches_port_collapse_sibling`): the same
        connection identity with possibly rotated or wildcarded ports resolves
        to the trained concrete bounds instead of falling through to
        ``NoBounds`` (CLAS-057).

        When several concrete siblings match, their envelopes are merged
        into the widest one per feature (``min`` of lowers, ``max`` of
        uppers) by :meth:`_merge_bounds`. This is the conservative choice that
        minimises false-positive ``BoundViolation`` flags on normal traffic
        and is order-independent, hence deterministic regardless of the
        bounds-dict iteration order.

        Args:
            series_id: Incoming series identifier (possibly wildcard-ported).
            bounds: Full bounds dict keyed by trained series identifiers.

        Returns:
            Feature -> (lower, upper) bounds for the resolved series, or
            ``None`` when no exact or sibling key matches (the caller then
            declares ``NoBounds``).
        """
        if series_id in bounds:
            return bounds[series_id]

        siblings = [key for key in bounds if matches_port_collapse_sibling(series_id, key)]
        if not siblings:
            return None
        if len(siblings) == 1:
            return bounds[siblings[0]]
        return self._merge_bounds([bounds[key] for key in siblings])

    @staticmethod
    def _merge_bounds(
        sibling_bounds: list[dict[str, tuple[float, float]]],
    ) -> dict[str, tuple[float, float]]:
        """Merge several concrete bound sets into the widest envelope.

        For each feature shared across siblings, the lower bound becomes the
        minimum of the lowers and the upper bound becomes the maximum of the
        uppers. A feature present in only one sibling is carried through
        unchanged. Because ``min``/``max`` are commutative, the result does
        not depend on the iteration order of the bounds dict, so the merge is
        deterministic.

        Args:
            sibling_bounds: Bound sets of the matching concrete siblings.

        Returns:
            Merged feature -> (lower, upper) envelope.
        """
        merged: dict[str, tuple[float, float]] = {}
        for series_bounds in sibling_bounds:
            for feature, (lower, upper) in series_bounds.items():
                if feature not in merged:
                    merged[feature] = (lower, upper)
                    continue
                prev_lower, prev_upper = merged[feature]
                merged[feature] = (min(prev_lower, lower), max(prev_upper, upper))
        return merged

    def _annotate_no_bounds(self, group_df: pl.DataFrame, features: list[str]) -> pl.DataFrame:
        """Mark all rows as NoBounds anomalies when no bounds exist.

        Args:
            group_df: Data for a series with no trained bounds.
            features: Feature columns checked for this series.

        Returns:
            DataFrame annotated with NoBounds anomaly columns.
        """
        return group_df.with_columns(
            pl.lit(True).alias("is_anomaly"),
            pl.lit(AnomalyType.NO_BOUNDS).alias("anomaly_type"),
            pl.lit(1.0).alias("confidence"),
            pl.lit("[]").alias("violated_features"),
            pl.lit(0.0).alias("severity"),
        )

    def _annotate_violations(
        self,
        group_df: pl.DataFrame,
        series_bounds: dict[str, tuple[float, float]],
        features: list[str],
    ) -> pl.DataFrame:
        """Check feature columns against bounds and annotate violations.

        Args:
            group_df: Data for one series.
            series_bounds: Feature -> (lower, upper) bounds for this series.
            features: Feature columns to check.

        Returns:
            DataFrame with is_anomaly, anomaly_type, confidence, violated_features columns.
        """
        checkable = [f for f in features if f in series_bounds and f in group_df.columns]
        if not checkable:
            return self._annotate_no_violations(group_df)

        violation_exprs = self._build_violation_exprs(checkable, series_bounds)
        is_anomaly_expr = pl.any_horizontal(*violation_exprs).alias("is_anomaly")

        violated_features_expr = self._build_violated_features_expr(checkable, series_bounds)

        return group_df.with_columns(
            is_anomaly_expr,
            pl.when(pl.any_horizontal(*violation_exprs))
            .then(pl.lit(AnomalyType.BOUND_VIOLATION))
            .otherwise(pl.lit(""))
            .alias("anomaly_type"),
            pl.when(pl.any_horizontal(*violation_exprs)).then(pl.lit(1.0)).otherwise(pl.lit(0.0)).alias("confidence"),
            violated_features_expr.alias("violated_features"),
            self._build_severity_expr(checkable, series_bounds).alias("severity"),
        )

    def _annotate_no_violations(self, group_df: pl.DataFrame) -> pl.DataFrame:
        """Annotate a group where no features can be checked (no overlap).

        Args:
            group_df: Data for one series.

        Returns:
            DataFrame with all-clean anomaly columns.
        """
        return group_df.with_columns(
            pl.lit(False).alias("is_anomaly"),
            pl.lit("").alias("anomaly_type"),
            pl.lit(0.0).alias("confidence"),
            pl.lit("[]").alias("violated_features"),
            pl.lit(0.0).alias("severity"),
        )

    def _build_violation_exprs(
        self,
        features: list[str],
        series_bounds: dict[str, tuple[float, float]],
    ) -> list[pl.Expr]:
        """Build per-feature boolean violation expressions.

        Args:
            features: Feature column names with available bounds.
            series_bounds: Bounds mapping for the current series.

        Returns:
            List of Polars expressions evaluating to True when violated.
        """
        exprs: list[pl.Expr] = []
        for f in features:
            lower, upper = series_bounds[f]
            expr = (pl.col(f) < pl.lit(lower)) | (pl.col(f) > pl.lit(upper))
            exprs.append(expr)
        return exprs

    def _build_violated_features_expr(
        self,
        features: list[str],
        series_bounds: dict[str, tuple[float, float]],
    ) -> pl.Expr:
        """Build an expression producing a string list of violated feature names.

        Args:
            features: Feature column names with available bounds.
            series_bounds: Bounds mapping for the current series.

        Returns:
            Polars expression producing a string representation of violated features.
        """
        parts: list[pl.Expr] = []
        for f in features:
            lower, upper = series_bounds[f]
            violation = (pl.col(f) < pl.lit(lower)) | (pl.col(f) > pl.lit(upper))
            part = pl.when(violation).then(pl.lit(f + ",")).otherwise(pl.lit(""))
            parts.append(part)
        concat_expr = pl.concat_str(parts)
        return concat_expr

    def _build_severity_expr(
        self,
        features: list[str],
        series_bounds: dict[str, tuple[float, float]],
    ) -> pl.Expr:
        """Build a severity expression as the max relative deviation across features.

        Args:
            features: Feature column names with available bounds.
            series_bounds: Bounds mapping for the current series.

        Returns:
            Polars expression computing max relative severity across features.
        """
        deviation_exprs: list[pl.Expr] = []
        for f in features:
            lower, upper = series_bounds[f]
            span = max(upper - lower, 1e-9)
            dev = (
                pl.when(pl.col(f) > pl.lit(upper))
                .then((pl.col(f) - pl.lit(upper)) / pl.lit(span))
                .when(pl.col(f) < pl.lit(lower))
                .then((pl.lit(lower) - pl.col(f)) / pl.lit(span))
                .otherwise(pl.lit(0.0))
            )
            deviation_exprs.append(dev)
        # NOTE (CLAS-028, 2026-08-25): polars 1.44.0 no longer broadcasts a
        # `pl.max_horizontal(*when/then exprs)` result correctly when the
        # exprs are built from column-referencing when/then chains (raises
        # `InvalidOperationError: Series severity, length 1 doesn't match the
        # DataFrame height`). `pl.concat_list(...).list.max()` produces the
        # identical per-row max but does not hit the broadcast bug. Verified
        # against polars==1.44.0 with a minimal 2-row/2-feature repro.
        return pl.concat_list(deviation_exprs).list.max()

    def _append_empty_columns(self, df: pl.DataFrame) -> pl.DataFrame:
        """Append anomaly annotation columns to an empty DataFrame.

        Args:
            df: Empty DataFrame to extend with anomaly columns.

        Returns:
            DataFrame with added empty typed columns.
        """
        return df.with_columns(
            pl.lit(False).alias("is_anomaly"),
            pl.lit("").alias("anomaly_type"),
            pl.lit(0.0).alias("confidence"),
            pl.lit("").alias("violated_features"),
            pl.lit(0.0).alias("severity"),
        )
