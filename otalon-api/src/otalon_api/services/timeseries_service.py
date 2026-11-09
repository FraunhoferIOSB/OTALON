"""Time-series data service.

Provides methods for querying, transforming, and downsampling time-series
data from InfluxDB for the API layer.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional, cast

import numpy as np
import pandas as pd
from loguru import logger

from otalon_api.domain.time import time_policy
from otalon_api.domain.topology.uci import base_key_without_ports, normalize_uci, parse_uci
from otalon_api.repositories.influx_repo import InfluxRepository
from otalon_api.repositories.postgres_repo import PostgresRepository
from otalon_api.services.aggregation_service import NetcapAggregationService
from otalon_api.settings import Settings


class TimeseriesService:
    """Service for time-series data retrieval and transformation."""

    def __init__(
        self, influx_repo: InfluxRepository, settings: Settings, postgres_repo: PostgresRepository | None = None
    ) -> None:
        """Initialize the timeseries service.

        Args:
            influx_repo: InfluxDB repository for data access.
            settings: Application settings.
        """
        self._repo = influx_repo
        self._settings = settings
        self._postgres_repo = postgres_repo

    def profiled_series_ids(self, series_ids: list[str]) -> set[str]:
        """Return UCIs with bounds or a learned rhythm profile."""
        if self._postgres_repo is None:
            return set(series_ids)
        candidates = set(series_ids)
        for uci in series_ids:
            parts = parse_uci(uci)
            prefix = f"{parts.src_mac}/{parts.dst_mac}/{parts.vlan}/{parts.ip_proto}/{parts.src_ip}/{parts.dst_ip}"
            candidates.update(
                {
                    f"{prefix}/{parts.src_port}/*/{parts.protocols}",
                    f"{prefix}/*/{parts.dst_port}/{parts.protocols}",
                    f"{prefix}/*/*/{parts.protocols}",
                }
            )
        profiled_base_keys = {
            base_key_without_ports(uci)
            for uci in self._postgres_repo.query_profiled_series_ids(list(candidates))
        }
        return {uci for uci in series_ids if base_key_without_ports(uci) in profiled_base_keys}

    def get_between(
        self,
        uci: str,
        start: datetime,
        stop: datetime,
        features: list[str],
        aggregate: str | None = None,
        sample_max_points: int | None = None,
        preserve_extrema: bool = True,
    ) -> tuple[pd.DataFrame, int | None]:
        """Query timeseries data and apply the downsampling pipeline.

        Pipeline steps:
        1. Convert start/stop via time_policy.ui_to_influx_query_range()
        2. Call influx_repo.query_timeseries()
        3. Apply time_policy.normalize_time_for_ui()
        4. Apply _round_time_columns()
        5. Apply _decimate_dataframe() if still over sample_max_points
        6. Return (df, bucket_seconds from df.attrs)

        Args:
            uci: Unique communication identifier to query.
            start: Range start in local time.
            stop: Range end in local time.
            features: List of feature column names to retrieve.
            aggregate: Aggregation function name (e.g. ``"mean"``).
                ``None`` disables server-side aggregation.
            sample_max_points: Maximum number of data points returned.
                Controls both the DATE_BIN bucket size and client-side
                decimation.
            preserve_extrema: When ``True`` and aggregation is active,
                request additional MIN/MAX columns per field.

        Returns:
            A tuple of (DataFrame, bucket_seconds).  *bucket_seconds* is
            ``None`` when no aggregation was applied.
        """
        uci = normalize_uci(uci)
        effective_max = sample_max_points or self._settings.default_sample_max_points
        start_str, stop_str = time_policy.ui_to_influx_query_range(start, stop)

        logger.debug(
            "get_between uci={} start={} stop={} agg={} max_pts={}",
            uci,
            start_str,
            stop_str,
            aggregate,
            effective_max,
        )

        df = self._repo.query_timeseries(
            measurement=self._settings.netcap_measurement,
            id_tag=self._settings.netcap_id_tag,
            fields=list(features),
            start=start_str,
            stop=stop_str,
            tags={self._settings.netcap_id_tag: uci},
            aggregate=aggregate,
            sample_max_points=effective_max if aggregate else None,
            preserve_extrema=preserve_extrema,
        )

        bucket_seconds: int | None = df.attrs.get("bucket_seconds")

        df = cast(pd.DataFrame, time_policy.normalize_time_for_ui(df, time_cols=["time"]))
        df = self._round_time_columns(df)
        df = self._decimate_dataframe(df, effective_max)

        logger.debug("get_between result: {} rows, bucket={}s", len(df), bucket_seconds)
        return df, bucket_seconds

    def list_ids(
        self,
        start: datetime,
        stop: datetime,
        nonzero: bool = False,
        fields: list[str] | None = None,
        group_wildcards: bool = False,
        aggregation_service: NetcapAggregationService | None = None,
    ) -> list[str] | list[dict[str, Any]]:
        """List UCI identifiers available in a time range.

        Args:
            start: Range start in local time.
            stop: Range end in local time.
            nonzero: When ``True``, only return IDs with non-zero summed
                fields.
            fields: Field names for the nonzero filter check.
            group_wildcards: When ``True``, group UCIs by base key and
                return wildcard patterns instead of individual UCIs.
            aggregation_service: Required when *group_wildcards* is
                ``True``.  Provides the grouping logic.

        Returns:
            A sorted list of distinct UCI strings when
            *group_wildcards* is ``False``.  Otherwise a list of dicts
            with grouping metadata and ``rule_trained``.
        """
        start_str, stop_str = time_policy.ui_to_influx_query_range(start, stop)

        ids = self._repo.list_ids_between(
            measurement=self._settings.netcap_measurement,
            id_tag=self._settings.netcap_id_tag,
            start=start_str,
            stop=stop_str,
            nonzero=nonzero,
            fields=fields,
        )
        ids = [normalize_uci(uid) for uid in ids]

        if not group_wildcards or aggregation_service is None:
            return ids

        profiled_ids = self.profiled_series_ids(ids)

        groups = aggregation_service.build_wildcard_groups(ids)

        wildcard_ucis = [uci for uci in groups if "*" in uci.split("/")[6:8]]
        collapsed_counts: dict[str, int] = {}
        if wildcard_ucis:
            collapsed_counts = self._repo.query_collapsed_port_counts(
                measurement=self._settings.netcap_measurement,
                id_tag=self._settings.netcap_id_tag,
                ids=wildcard_ucis,
                start=start_str,
                stop=stop_str,
            )

        return [
            {
                "uci": wildcard_uci,
                "is_wildcard": "*" in wildcard_uci.split("/")[6:8],
                "member_count": len(members),
                "collapsed_port_count": collapsed_counts.get(wildcard_uci),
                "rule_trained": rule_trained,
                "profiled": any(member in profiled_ids for member in members),
            }
            for wildcard_uci, (members, rule_trained) in sorted(groups.items())
        ]

    def find_active_siblings(
        self,
        uci: str,
        start: datetime,
        stop: datetime,
        fields: list[str] | None = None,
    ) -> list[dict[str, str]]:
        """Find base-key siblings of *uci* that have non-zero data in the window.

        Reuses the ``/ids``-style nonzero query without a port constraint, then
        keeps only UCIs that share the same 7 base-key fields with *uci* but
        differ in at least one port. Used by the UI empty-metrics branch to
        detect a rotating-port connection and name its currently-active port.

        Args:
            uci: The selected UCI that returned zero metrics.
            start: Range start in local time.
            stop: Range end in local time.
            fields: Field names for the non-zero check (defaults to the
                configured netcap default fields when available).

        Returns:
            A list of dicts with ``uci``, ``src_port`` and ``dst_port`` for each
            active sibling, sorted by UCI for determinism.
        """
        uci = normalize_uci(uci)
        target_base = base_key_without_ports(uci)
        target_parsed = parse_uci(uci)

        start_str, stop_str = time_policy.ui_to_influx_query_range(start, stop)
        ids = self._repo.list_ids_between(
            measurement=self._settings.netcap_measurement,
            id_tag=self._settings.netcap_id_tag,
            start=start_str,
            stop=stop_str,
            nonzero=True,
            fields=fields,
        )

        siblings: list[dict[str, str]] = []
        for raw in ids:
            candidate = normalize_uci(raw)
            if candidate == uci:
                continue
            if base_key_without_ports(candidate) != target_base:
                continue
            parsed = parse_uci(candidate)
            if parsed.src_port == target_parsed.src_port and parsed.dst_port == target_parsed.dst_port:
                continue
            siblings.append({"uci": candidate, "src_port": parsed.src_port, "dst_port": parsed.dst_port})

        siblings.sort(key=lambda item: item["uci"])
        logger.debug("find_active_siblings uci={} -> {} sibling(s)", uci, len(siblings))
        return siblings

    def get_plot_data(
        self,
        uci: str,
        start: datetime,
        stop: datetime,
        features: list[str],
        sample_max_points: int = 500,
        preserve_extrema: bool = True,
    ) -> tuple[pd.DataFrame, int | None]:
        """Convenience wrapper: get_between with aggregate='mean'.

        Args:
            uci: Unique communication identifier to query.
            start: Range start in local time.
            stop: Range end in local time.
            features: List of feature column names to retrieve.
            sample_max_points: Maximum number of data points returned.
            preserve_extrema: When ``True``, request MIN/MAX columns.

        Returns:
            A tuple of (DataFrame, bucket_seconds).
        """
        return self.get_between(
            uci=uci,
            start=start,
            stop=stop,
            features=features,
            aggregate="mean",
            sample_max_points=sample_max_points,
            preserve_extrema=preserve_extrema,
        )

    @staticmethod
    def _round_time_columns(df: pd.DataFrame) -> pd.DataFrame:
        """Round all datetime columns to second precision.

        Args:
            df: Input DataFrame.

        Returns:
            DataFrame with datetime columns rounded to whole seconds.
        """
        if not isinstance(df, pd.DataFrame) or df.empty:
            return df

        result = df.copy()
        for col in result.columns:
            if pd.api.types.is_datetime64_any_dtype(result[col]):
                result[col] = result[col].dt.round("s")
        if isinstance(result.index, pd.DatetimeIndex):
            result.index = result.index.round("s")
        return result

    @staticmethod
    def _decimate_dataframe(df: pd.DataFrame, target_points: Optional[int]) -> pd.DataFrame:
        """Downsample by selecting evenly-spaced indices via np.linspace.

        Args:
            df: Input DataFrame.
            target_points: Desired maximum number of rows.  ``None`` or
                non-positive values disable decimation.

        Returns:
            The (possibly downsampled) DataFrame.
        """
        if not isinstance(df, pd.DataFrame) or df.empty:
            return df

        try:
            points = int(target_points) if target_points is not None else None
        except (TypeError, ValueError):
            points = None

        if points is None or points <= 0:
            return df
        if len(df) <= points:
            return df

        indices = np.linspace(0, len(df) - 1, points).astype(int)
        return df.iloc[indices].reset_index(drop=True)
