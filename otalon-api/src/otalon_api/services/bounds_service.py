"""Bounds service for retrieving and merging bounds with timeseries data.

Combines InfluxDB timeseries data with PostgreSQL boundary thresholds to
produce the merged GD-05 response format used by the anomaly bounds
endpoint.
"""

from __future__ import annotations

import math
from datetime import datetime
from typing import Any, cast

import numpy as np
import pandas as pd
from loguru import logger

from otalon_api.domain.anomaly.processing import prepare_timeseries_with_bounds
from otalon_api.domain.netcap.models import proto_series_hash
from otalon_api.domain.netcap.proto_resolver import ProtoHashResolver
from otalon_api.domain.time import time_policy
from otalon_api.domain.topology.uci import base_key_without_ports, is_wildcard_uci, normalize_uci
from otalon_api.repositories.influx_repo import InfluxRepository
from otalon_api.repositories.postgres_repo import PostgresRepository
from otalon_api.services.aggregation_service import NetcapAggregationService
from otalon_api.settings import Settings
from otalon_api.utils import run_in_thread

_CONNECTION_AGGREGATES: dict[str, str] = {
    "packet_count": "mean",
    "total_volume": "sum",
    "min_packet_size": "min",
    "max_packet_size": "max",
    "std_packet_size": "mean",
    "min_interarrival_time": "min",
    "max_interarrival_time": "max",
    "std_interarrival_time": "mean",
    "mean_packet_size": "mean",
    "mean_interarrival_time": "mean",
}

_NATIVE_BUCKET_SECONDS = 1
_EXTENSIVE_METRICS: frozenset[str] = frozenset(
    {metric for metric, aggregate in _CONNECTION_AGGREGATES.items() if aggregate == "sum"}
    | {"out_total_volume", "in_total_volume", "proto_total_volume"}
)

_SUMMARY_AGGREGATES: dict[str, str] = {
    "packet_count": "sum",
    "total_volume": "sum",
    "min_packet_size": "min",
    "max_packet_size": "max",
}


def _downsample_with_extrema(df: pd.DataFrame, metric: str, max_points: int) -> pd.DataFrame:
    """Downsample a timeseries DataFrame preserving min/max extrema.

    Mimics the InfluxDB DATE_BIN aggregation: groups rows into
    equal-sized time buckets and computes mean, min, and max per bucket.

    Args:
        df: DataFrame with ``time`` and *metric* columns.
        metric: The feature column name.
        max_points: Target maximum number of output rows.

    Returns:
        DataFrame with columns ``time``, *metric*, ``<metric>_min``,
        ``<metric>_max``.  If the input has fewer rows than *max_points*,
        returns the input unchanged (no min/max columns added since there
        is no aggregation spread).
    """
    if df.empty or len(df) <= max_points:
        return df

    col_min = f"{metric}_min"
    col_max = f"{metric}_max"

    time_col = pd.to_datetime(df["time"])
    time_range_s = (time_col.max() - time_col.min()).total_seconds()
    bucket_s = max(1, math.ceil(time_range_s / max_points))

    bucket_origin = time_col.min()
    buckets = ((time_col - bucket_origin).dt.total_seconds() // bucket_s).astype(int)

    grouped = df.assign(_bucket=buckets).groupby("_bucket", sort=True)
    agg_dict: dict[str, Any] = {"time": ("time", "first")}
    if metric in df.columns:
        agg_dict[metric] = (metric, "mean")
        agg_dict[col_min] = (metric, "min")
        agg_dict[col_max] = (metric, "max")

    result: pd.DataFrame = grouped.agg(**agg_dict).reset_index(drop=True)

    for col in [metric, col_min, col_max]:
        if col in result.columns:
            result[col] = pd.to_numeric(result[col], errors="coerce").replace(np.nan, None)

    return result


class BoundsService:
    """Service for boundary threshold data retrieval and timeseries merging."""

    def __init__(
        self,
        influx_repo: InfluxRepository,
        postgres_repo: PostgresRepository,
        settings: Settings,
        aggregation_service: NetcapAggregationService | None = None,
        proto_resolver: ProtoHashResolver | None = None,
    ) -> None:
        """Initialize the bounds service.

        Args:
            influx_repo: InfluxDB repository for timeseries data access.
            postgres_repo: PostgreSQL repository for bounds data access.
            settings: Application settings.
            aggregation_service: Optional aggregation service for wildcard
                UCI resolution.
            proto_resolver: Optional resolver for proto hash → protocol.
        """
        self._influx_repo = influx_repo
        self._postgres_repo = postgres_repo
        self._settings = settings
        self._aggregation_service = aggregation_service
        self._proto_resolver = proto_resolver

    @run_in_thread
    def get_bounds(self, module: str, series_id: str | None = None) -> dict[str, Any]:
        """Retrieve raw bounds from PostgreSQL.

        Args:
            module: Detection module name (e.g. ``"netcap"``).
            series_id: Optional UCI / series identifier to filter by.

        Returns:
            Response dict with ``data``, ``row_count``, and ``parameters``.
        """
        logger.debug("get_bounds module={} series_id={}", module, series_id)
        rows = self._postgres_repo.query_bounds(module=module, series_id=series_id)
        return {
            "data": rows,
            "row_count": len(rows),
            "parameters": {"module": module, "series_id": series_id},
        }

    def _resolve_source(self, module: str) -> tuple[str, str]:
        """Map a detection module to its InfluxDB measurement and id tag.

        MAC and Proto sources store data under their own measurements with
        dedicated tag keys; everything else falls back to the conn defaults
        from settings.  Without this mapping the bounds merge would query
        the conn measurement for a MAC/proto series_id and return no rows.

        Args:
            module: Detection module name (``"mac_traffic"``,
                ``"proto_traffic"`` or a conn module).

        Returns:
            A ``(measurement, id_tag)`` tuple for the InfluxDB query.
        """
        source_map = {
            "mac_traffic": ("mac_traffic", "mac_address"),
            "proto_traffic": ("proto_traffic", "protocol"),
        }
        return source_map.get(
            module,
            (self._settings.netcap_measurement, self._settings.netcap_id_tag),
        )

    def _proto_pg_bounds_key(self, requested_series: str, resolved_plaintext: str) -> str:
        """Decide the PostgreSQL bounds key for a proto_traffic series_id.

        The proto detection pipeline persists bounds under the *stringified
        hash* of the protocol stack (see :func:`proto_series_hash`), never the
        plaintext.  The caller may send either identifier:

        * a canonical numeric hash (the UI's chart identity) — used verbatim as
          the PG key; it must never be hashed again;
        * a plaintext protocol stack (legacy callers), which is colon-delimited
          for real stacks (e.g. ``"Ethernet:IPv4:UDP:DNS"``) — hashed here so the
          PG lookup matches the persisted hashed row.

        The discriminator is explicit and resolver-derived, not a bare
        ``.isdigit()`` heuristic: an id is treated as an already-persisted hash
        iff it is a *known* hash in the resolver vocabulary, or it is purely
        numeric (the only shape :func:`proto_series_hash` ever emits).  An
        unknown numeric persisted hash therefore stays canonical for PG (and
        fails honestly / empty against Influx, whose ``protocol`` tag is
        plaintext), while a plaintext stack is hashed.  Normalization cannot
        alter this decision because slash normalization is confined to conn
        sources.

        Args:
            requested_series: The caller's original, unmodified series_id.
            resolved_plaintext: The resolver's plaintext for *requested_series*,
                or *requested_series* itself when the resolver did not map it.

        Returns:
            The series_id to use as the PostgreSQL bounds key.
        """
        resolver_known = resolved_plaintext != requested_series
        if resolver_known or requested_series.isdigit():
            return requested_series
        return proto_series_hash(requested_series)

    @run_in_thread
    def get_timeseries_with_bounds(
        self,
        uci: str,
        metric: str,
        start: datetime,
        stop: datetime,
        module: str = "netcap",
        sample_max_points: int | None = None,
        normalize: bool = True,
    ) -> dict[str, Any]:
        """Load timeseries from InfluxDB, merge with bounds from PostgreSQL.

        Pipeline:
        1. Convert start/stop via time_policy for InfluxDB query
        2. Query timeseries from InfluxDB (single metric, with aggregation)
        3. Normalize timestamps for UI
        4. Query bounds from PostgreSQL
        5. Merge via :func:`prepare_timeseries_with_bounds`
        6. Return GD-05 format response

        Args:
            uci: Unique communication identifier.
            metric: Feature name (e.g. ``"mean_packet_size"``).
            start: Range start in local time.
            stop: Range end in local time.
            module: Detection module name for bounds lookup.
            sample_max_points: Maximum number of timeseries data points.
            normalize: When ``True`` (default), slash-delimited UCI
                normalisation is applied — but only for conn/netcap sources.
                It is NEVER applied to ``mac_traffic`` or ``proto_traffic``
                series_ids regardless of this flag, because those identifiers
                (a MAC address, a plaintext protocol stack, or a numeric proto
                hash) are not slash-delimited UCIs and normalisation would
                corrupt them (e.g. a bare numeric hash → ``"<hash>////////"``).

        Returns:
            Response dict with ``data``, ``row_count``, and ``parameters``.
        """
        effective_max = sample_max_points or self._settings.default_sample_max_points

        measurement, id_tag = self._resolve_source(module)
        is_conn_source = id_tag == self._settings.netcap_id_tag

        # Normalise slash-delimited UCIs for conn/netcap sources only. MAC and
        # proto series_ids are resolved by module before this point, so their
        # identity survives the default normalize=True production path.
        if normalize and is_conn_source:
            uci = normalize_uci(uci)

        requested_series = uci
        display_protocol = uci
        if module == "proto_traffic" and self._proto_resolver is not None:
            display_protocol = self._proto_resolver.resolve(uci)
            if display_protocol != uci:
                uci = display_protocol

        start_str, stop_str = time_policy.ui_to_influx_query_range(start, stop)
        aggregate, detector_bucket = self._detector_aggregation(module, uci, metric, start, stop)
        if aggregate == "sum" and metric in _EXTENSIVE_METRICS:
            # Extensive sum metrics (e.g. total_volume) were pinned to a 1s
            # native bucket so live values match the per-second detector
            # contract. Over windows larger than the point budget that
            # floods the frontend (API-067: ~134k rows for a 39h window).
            # Switch to mean aggregation with an InfluxDB-computed bucket;
            # preserve_extrema (set on the query below) keeps the bucket
            # max so in-window anomaly spikes still flag violations. Sum
            # over a wide bucket would be ~Nx per-second volume and trip a
            # constant false violation against per-second bounds, hence
            # mean (avg per-second) rather than sum.
            window_seconds = (stop - start).total_seconds()
            if window_seconds > effective_max:
                aggregate = "mean"
                detector_bucket = None
            else:
                detector_bucket = _NATIVE_BUCKET_SECONDS
        logger.debug("bounds aggregation={} bucket={}", aggregate, detector_bucket)
        logger.debug(
            "get_timeseries_with_bounds uci={} metric={} module={} "
            "measurement={} id_tag={} start={} stop={} max_pts={}",
            uci,
            metric,
            module,
            measurement,
            id_tag,
            start_str,
            stop_str,
            effective_max,
        )

        if is_conn_source and is_wildcard_uci(uci) and self._aggregation_service is not None:
            df = self._aggregation_service.resolve_and_aggregate(
                wildcard_uci=uci,
                start=start,
                stop=stop,
                features=[metric],
            )
            df = _downsample_with_extrema(df, metric=metric, max_points=effective_max)
        else:
            df = self._influx_repo.query_timeseries(
                measurement=measurement,
                id_tag=id_tag,
                fields=[metric],
                start=start_str,
                stop=stop_str,
                tags={id_tag: uci},
                aggregate=aggregate,
                sample_max_points=effective_max,
                preserve_extrema=True,
                bucket_seconds=detector_bucket,
            )

            df = cast(pd.DataFrame, time_policy.normalize_time_for_ui(df, time_cols=["time"]))

        anomaly_rows = self._query_detector_anomalies(module, uci, start, stop)
        df = _overlay_persisted_violation_values(df, anomaly_rows, metric)

        bounds_series_id = uci
        if module in {"conn", "netcap"} and is_wildcard_uci(uci):
            profiled = self._postgres_repo.query_all_profiled_series_ids("conn")
            siblings = sorted(
                candidate for candidate in profiled if base_key_without_ports(candidate) == base_key_without_ports(uci)
            )
            if siblings:
                bounds_series_id = siblings[0]
        if module == "proto_traffic":
            bounds_series_id = self._proto_pg_bounds_key(requested_series, display_protocol)
        bounds = self._postgres_repo.query_bounds(module=module, series_id=bounds_series_id)

        merged = prepare_timeseries_with_bounds(timeseries_df=df, bounds=bounds, metric=metric)

        logger.debug("get_timeseries_with_bounds result: {} rows", len(merged))

        result: dict[str, Any] = {
            "data": merged,
            "row_count": len(merged),
            "parameters": {
                # Echo the caller's canonical identifier, not the internally
                # resolved plaintext. For proto_traffic the UI sends the
                # canonical numeric hash; Influx is queried by the resolved
                # plaintext (``uci``) while PG bounds keep the hash, but the
                # diagnostic must report the canonical requested id so the
                # caller's identity stays canonical end-to-end (CAPTURE 31).
                "uci": requested_series,
                "feature": metric,
                "start": start_str,
                "stop": stop_str,
                "sample_max_points": effective_max,
            },
        }
        if len(merged) > 1:
            times = sorted(pd.Timestamp(row["time"]) for row in merged if row.get("time") is not None)
            if len(times) > 1:
                deltas = [(right - left).total_seconds() for left, right in zip(times, times[1:]) if right > left]
                if deltas:
                    result["parameters"]["bucket_seconds"] = min(deltas)
        if module == "proto_traffic" and self._proto_resolver is not None:
            result["protocol"] = display_protocol
        return result

    def _query_detector_anomalies(
        self, module: str, series_id: str, start: datetime, stop: datetime
    ) -> list[dict[str, Any]]:
        """Load persisted detector rows used to place violation markers."""
        modules = [module]
        if module == "netcap":
            modules.append("conn")
        for anomaly_module in modules:
            rows = self._postgres_repo.query_anomalies(
                module=anomaly_module,
                series_id=series_id,
                time_range=(start.isoformat(), stop.isoformat()),
            )
            if rows:
                return rows
        return []

    def _detector_aggregation(
        self,
        module: str,
        series_id: str,
        metric: str,
        start: datetime,
        stop: datetime,
    ) -> tuple[str, int | None]:
        """Resolve detector aggregation for a matching stored violation."""
        aggregate = _aggregate_for_metric(module, metric)
        if module not in {"conn", "netcap"}:
            return aggregate, _native_bucket_for_metric(metric, aggregate)
        rows = self._query_detector_anomalies(module, series_id, start, stop)
        for row in rows:
            if row.get("anomaly_type") != "BoundViolation":
                continue
            if metric not in (row.get("violated_features") or []):
                continue
            raw_bucket = row.get("bucket_seconds")
            bucket = int(raw_bucket) if raw_bucket is not None and int(raw_bucket) > 0 else None
            return aggregate, bucket or _native_bucket_for_metric(metric, aggregate)
        return aggregate, _native_bucket_for_metric(metric, aggregate)


def _aggregate_for_metric(module: str, metric: str) -> str:
    """Return live aggregation contract for source metric."""
    if module in {"conn", "netcap"}:
        return _CONNECTION_AGGREGATES.get(metric, "mean")
    if metric in _EXTENSIVE_METRICS:
        return "sum"
    return "mean"


def _native_bucket_for_metric(metric: str, aggregate: str) -> int | None:
    """Pin extensive metrics to raw-cadence training granularity."""
    if aggregate == "sum" and metric in _EXTENSIVE_METRICS:
        return _NATIVE_BUCKET_SECONDS
    return None


def _overlay_persisted_violation_values(
    df: pd.DataFrame, anomaly_rows: list[dict[str, Any]], metric: str
) -> pd.DataFrame:
    """Overlay stored detector values so markers use detector semantics.

    Bounds charts still display live Influx data, but violation flags must use
    the value that triggered the persisted detector anomaly. This avoids
    treating a detector ``sum`` bucket as a fresh live ``mean`` query.
    """
    if df.empty or metric not in df.columns:
        return df
    values_by_time: list[tuple[pd.Timestamp, float, int]] = []
    for row in anomaly_rows:
        if row.get("anomaly_type") != "BoundViolation":
            continue
        if metric not in (row.get("violated_features") or []):
            continue
        raw_value: Any = row.get("value")
        if raw_value is None:
            summary = row.get("feature_summary") or {}
            feature_stats = summary.get(metric) if isinstance(summary, dict) else None
            if isinstance(feature_stats, dict):
                summary_key = _SUMMARY_AGGREGATES.get(metric, "max")
                raw_value = feature_stats.get(summary_key)
                if raw_value is None:
                    raw_value = feature_stats.get("max")
        try:
            value = float(raw_value)
            if not math.isfinite(value):
                continue
            raw_timestamp = row.get("start_ts")
            if raw_timestamp is None:
                continue
            timestamp = pd.Timestamp(raw_timestamp)
            if timestamp.tz is not None:
                timestamp = timestamp.tz_localize(None)
            normalized = time_policy.normalize_time_for_ui(pd.DataFrame({"time": [timestamp]}), time_cols=["time"])
            timestamp = pd.Timestamp(normalized["time"].iloc[0])
            raw_bucket = row.get("bucket_seconds")
            bucket = int(raw_bucket) if raw_bucket is not None else 0
            values_by_time.append((timestamp, value, max(bucket, 1)))
        except (TypeError, ValueError):
            continue
    if not values_by_time:
        return df
    result = df.copy()
    timestamps = pd.to_datetime(result["time"]).map(
        lambda item: item.tz_localize(None) if item.tzinfo is not None else item
    )
    for anomaly_time, value, bucket in values_by_time:
        distances = timestamps.map(lambda item: abs((item - anomaly_time).total_seconds()))
        nearest_index = distances.idxmin()
        if distances.loc[nearest_index] <= bucket:
            result.at[nearest_index, metric] = value
    return result
