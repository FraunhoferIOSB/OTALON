"""Time-series data router.

Provides REST endpoints for querying netcap time-series data,
UCI identifier listings, wildcard aggregations, and plot-ready
downsampled data.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any

import numpy as np
import pandas as pd
from fastapi import APIRouter, Depends, HTTPException, Query
from loguru import logger

from otalon_api.api.schemas.timeseries import (
    DataExtentResponse,
    FeaturesResponse,
    IdsResponse,
    IdsResponseItem,
    SiblingItem,
    SiblingsResponse,
    TimeseriesResponse,
)
from otalon_api.dependencies import get_aggregation_service, get_influx_repo, get_timeseries_service
from otalon_api.domain.netcap.models import ALL_FEATURES
from otalon_api.domain.topology.uci import is_wildcard_uci
from otalon_api.repositories.influx_repo import InfluxRepository
from otalon_api.services.aggregation_service import NetcapAggregationService
from otalon_api.services.timeseries_service import TimeseriesService

router = APIRouter(prefix="/api/v1/timeseries", tags=["timeseries"])

ALLOWED_AGGREGATES: frozenset[str] = frozenset({"mean", "sum", "min", "max", "count"})

_ALL_FEATURES_SET: frozenset[str] = frozenset(ALL_FEATURES)

# QUA-12 — cardinality/length caps on per-request list and identifier
# parameters. Every extra member expands the aggregation work, and an
# unbounded UCI string is carried into the Influx query. The caps sit far
# above real usage: the feature catalog holds 10 names, a live UCI is
# ~113 chars, and the UI never sends more than a handful of members.
MAX_FEATURES = 32
MAX_MEMBERS = 64
MAX_UCI_LENGTH = 512
MAX_SAMPLE_POINTS = 100_000


@router.get("/data-extent", response_model=DataExtentResponse)
async def data_extent(
    influx_repo: InfluxRepository = Depends(get_influx_repo),
) -> DataExtentResponse:
    """Return the boundedly discovered extent of network metrics data."""
    extent = await asyncio.to_thread(influx_repo.query_data_extent, measurement="network_metrics")
    if extent is None:
        return DataExtentResponse(has_data=False)
    first_ts, last_ts = extent
    return DataExtentResponse(
        has_data=True,
        first_ts=first_ts.tz_convert("UTC").isoformat(),
        last_ts=last_ts.tz_convert("UTC").isoformat(),
    )


def _validate_features(features: list[str]) -> None:
    """Raise HTTPException 400 if any feature name is not in ALL_FEATURES.

    Args:
        features: List of feature names to validate.

    Raises:
        HTTPException: If one or more feature names are invalid.
    """
    invalid = [f for f in features if f not in _ALL_FEATURES_SET]
    if invalid:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid feature(s): {', '.join(invalid)}",
        )


def _validate_aggregate(aggregate: str | None) -> None:
    """Raise HTTPException 400 if the aggregate function name is not allowed.

    Args:
        aggregate: Aggregate function name or ``None``.

    Raises:
        HTTPException: If the aggregate name is not in ALLOWED_AGGREGATES.
    """
    if aggregate is not None and aggregate not in ALLOWED_AGGREGATES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid aggregate '{aggregate}'. Allowed: {', '.join(sorted(ALLOWED_AGGREGATES))}",
        )


def _sanitize_value(value: Any) -> Any:
    """Replace NaN / NaT / Infinity with ``None`` for JSON serialization.

    Args:
        value: A scalar value from a DataFrame cell.

    Returns:
        The original value or ``None`` if it is not JSON-serializable.
    """
    if value is None:
        return None
    if isinstance(value, float) and (np.isnan(value) or np.isinf(value)):
        return None
    if isinstance(value, pd.Timestamp):
        if pd.isna(value):
            return None
        return value.isoformat()
    if isinstance(value, datetime):
        return value.isoformat()
    if pd.isna(value):
        return None
    return value


def _df_to_records(df: pd.DataFrame) -> list[dict[str, Any]]:
    """Convert a DataFrame to a list of JSON-safe dictionaries.

    The ``time`` column is formatted as an ISO 8601 string.  NaN, NaT,
    and Infinity values are replaced with ``None``.

    Args:
        df: Source DataFrame.

    Returns:
        A list of row dictionaries suitable for JSON responses.
    """
    if df.empty:
        return []

    result = df.copy()
    if "time" in result.columns:
        result["time"] = pd.to_datetime(result["time"], errors="coerce").dt.strftime("%Y-%m-%dT%H:%M:%S")

    records = result.to_dict(orient="records")
    return [{str(k): _sanitize_value(v) for k, v in row.items()} for row in records]


@router.get("/ids")
async def list_ids(
    start: datetime,
    stop: datetime,
    nonzero: bool = False,
    fields: list[str] | None = Query(default=None, max_length=MAX_FEATURES),
    group_wildcards: bool = False,
    service: TimeseriesService = Depends(get_timeseries_service),
    agg_service: NetcapAggregationService = Depends(get_aggregation_service),
) -> IdsResponse:
    """List UCI identifiers available in a time range.

    When *group_wildcards* is ``True``, UCIs that differ only in port
    numbers are merged into wildcard groups.
    """
    if start >= stop:
        raise HTTPException(status_code=400, detail="start must be before stop")
    if fields:
        _validate_features(fields)

    try:
        raw = await asyncio.to_thread(
            service.list_ids,
            start=start,
            stop=stop,
            nonzero=nonzero,
            fields=fields,
            group_wildcards=group_wildcards,
            aggregation_service=agg_service if group_wildcards else None,
        )
    except Exception as exc:
        logger.error("list_ids failed: {}", exc)
        raise HTTPException(status_code=500, detail="Failed to list identifiers") from exc

    if group_wildcards:
        raw_dicts: list[dict[str, Any]] = raw  # type: ignore[assignment]
        data = [
            IdsResponseItem(
                uci=str(item["uci"]),
                is_wildcard=bool(item["is_wildcard"]),
                member_count=int(item["member_count"]),
                collapsed_port_count=(
                    int(item["collapsed_port_count"]) if item.get("collapsed_port_count") is not None else None
                ),
                rule_trained=bool(item.get("rule_trained", True)),
                profiled=bool(item.get("profiled", True)),
            )
            for item in raw_dicts
        ]
    else:
        raw_strs: list[str] = raw  # type: ignore[assignment]
        profiled_ids = await asyncio.to_thread(service.profiled_series_ids, raw_strs)
        data = [IdsResponseItem(uci=uci_val, profiled=uci_val in profiled_ids) for uci_val in raw_strs]

    return IdsResponse(
        start=start.isoformat(),
        stop=stop.isoformat(),
        nonzero=nonzero,
        count=len(data),
        data=data,
    )


@router.get("/siblings")
async def list_active_siblings(
    uci: str = Query(max_length=MAX_UCI_LENGTH),
    start: datetime = Query(),
    stop: datetime = Query(),
    fields: list[str] | None = Query(default=None, max_length=MAX_FEATURES),
    service: TimeseriesService = Depends(get_timeseries_service),
) -> SiblingsResponse:
    """List base-key siblings of *uci* that have non-zero data in the window.

    Returns UCIs sharing the same 7 base-key fields but differing in port,
    restricted to the window with non-zero data. The connections page uses
    this in its empty-metrics branch to surface a rotating-port hint.
    """
    if start >= stop:
        raise HTTPException(status_code=400, detail="start must be before stop")
    if fields:
        _validate_features(fields)

    try:
        siblings = await asyncio.to_thread(
            service.find_active_siblings,
            uci=uci,
            start=start,
            stop=stop,
            fields=fields,
        )
    except Exception as exc:
        logger.error("list_active_siblings failed for uci={}: {}", uci, exc)
        raise HTTPException(status_code=500, detail="Failed to look up siblings") from exc

    items = [SiblingItem(uci=str(s["uci"]), src_port=str(s["src_port"]), dst_port=str(s["dst_port"])) for s in siblings]
    return SiblingsResponse(
        uci=uci,
        start=start.isoformat(),
        stop=stop.isoformat(),
        has_active_sibling=len(items) > 0,
        count=len(items),
        siblings=items,
    )


@router.get("/data")
async def query_data(
    uci: str = Query(max_length=MAX_UCI_LENGTH),
    start: datetime = Query(),
    stop: datetime = Query(),
    features: list[str] = Query(max_length=MAX_FEATURES),
    aggregate: str | None = Query(default=None, max_length=32),
    sample_max_points: int | None = Query(default=None, ge=1, le=MAX_SAMPLE_POINTS),
    preserve_extrema: bool = True,
    service: TimeseriesService = Depends(get_timeseries_service),
    agg_service: NetcapAggregationService = Depends(get_aggregation_service),
) -> TimeseriesResponse:
    """Query timeseries data for a single UCI.

    When *uci* contains wildcard port fields (``"*"``), the members
    are resolved server-side and the aggregated result is returned.
    """
    if start >= stop:
        raise HTTPException(status_code=400, detail="start must be before stop")
    if not features:
        raise HTTPException(status_code=400, detail="At least one feature is required")
    _validate_features(features)
    _validate_aggregate(aggregate)

    try:
        if is_wildcard_uci(uci):
            df = await asyncio.to_thread(
                agg_service.resolve_and_aggregate,
                wildcard_uci=uci,
                start=start,
                stop=stop,
                features=list(features),
            )
            bucket_seconds = None
        else:
            df, bucket_seconds = await asyncio.to_thread(
                service.get_between,
                uci=uci,
                start=start,
                stop=stop,
                features=list(features),
                aggregate=aggregate,
                sample_max_points=sample_max_points,
                preserve_extrema=preserve_extrema,
            )
    except Exception as exc:
        logger.error("query_data failed for uci={}: {}", uci, exc)
        raise HTTPException(status_code=500, detail="Failed to query timeseries data") from exc

    return TimeseriesResponse(
        uci=uci,
        start=start.isoformat(),
        stop=stop.isoformat(),
        features=list(features),
        bucket_seconds=bucket_seconds,
        row_count=len(df),
        data=_df_to_records(df),
    )


@router.get("/wildcard", deprecated=True)
async def query_wildcard(
    wildcard_uci: str = Query(max_length=MAX_UCI_LENGTH),
    members: list[str] = Query(max_length=MAX_MEMBERS),
    start: datetime = Query(),
    stop: datetime = Query(),
    features: list[str] = Query(max_length=MAX_FEATURES),
    service: NetcapAggregationService = Depends(get_aggregation_service),
) -> TimeseriesResponse:
    """Query aggregated wildcard timeseries.

    .. deprecated::
        Use ``GET /data`` or ``GET /plot`` with a wildcard UCI instead.
        Wildcard UCIs are now detected and resolved automatically.

    Args:
        wildcard_uci: Wildcard UCI string (``"*"`` in port positions).
        members: List of concrete member UCIs.
        start: Range start timestamp.
        stop: Range stop timestamp.
        features: Feature columns to aggregate.
        service: Injected aggregation service.

    Returns:
        A TimeseriesResponse with the aggregated data.
    """
    if start >= stop:
        raise HTTPException(status_code=400, detail="start must be before stop")
    if not members:
        raise HTTPException(status_code=400, detail="At least one member UCI is required")
    if not features:
        raise HTTPException(status_code=400, detail="At least one feature is required")
    _validate_features(features)

    try:
        df = await asyncio.to_thread(
            service.aggregate_wildcard_timeseries,
            wildcard_uci=wildcard_uci,
            members=list(members),
            start=start,
            stop=stop,
            features=list(features),
        )
    except Exception as exc:
        logger.error("query_wildcard failed for uci={}: {}", wildcard_uci, exc)
        raise HTTPException(status_code=500, detail="Failed to query wildcard timeseries") from exc

    return TimeseriesResponse(
        uci=wildcard_uci,
        start=start.isoformat(),
        stop=stop.isoformat(),
        features=list(features),
        bucket_seconds=None,
        row_count=len(df),
        data=_df_to_records(df),
    )


@router.get("/plot")
async def query_plot(
    uci: str = Query(max_length=MAX_UCI_LENGTH),
    start: datetime = Query(),
    stop: datetime = Query(),
    features: list[str] = Query(max_length=MAX_FEATURES),
    sample_max_points: int = Query(default=500, ge=1, le=MAX_SAMPLE_POINTS),
    preserve_extrema: bool = True,
    service: TimeseriesService = Depends(get_timeseries_service),
    agg_service: NetcapAggregationService = Depends(get_aggregation_service),
) -> TimeseriesResponse:
    """Query plot-ready downsampled timeseries.

    When *uci* contains wildcard port fields (``"*"``), the members
    are resolved server-side and the aggregated result is returned.
    """
    if start >= stop:
        raise HTTPException(status_code=400, detail="start must be before stop")
    if not features:
        raise HTTPException(status_code=400, detail="At least one feature is required")
    _validate_features(features)

    try:
        if is_wildcard_uci(uci):
            df = await asyncio.to_thread(
                agg_service.resolve_and_aggregate,
                wildcard_uci=uci,
                start=start,
                stop=stop,
                features=list(features),
            )
            bucket_seconds = None
        else:
            df, bucket_seconds = await asyncio.to_thread(
                service.get_plot_data,
                uci=uci,
                start=start,
                stop=stop,
                features=list(features),
                sample_max_points=sample_max_points,
                preserve_extrema=preserve_extrema,
            )
    except Exception as exc:
        logger.error("query_plot failed for uci={}: {}", uci, exc)
        raise HTTPException(status_code=500, detail="Failed to query plot data") from exc

    return TimeseriesResponse(
        uci=uci,
        start=start.isoformat(),
        stop=stop.isoformat(),
        features=list(features),
        bucket_seconds=bucket_seconds,
        row_count=len(df),
        data=_df_to_records(df),
    )


@router.get("/features")
async def list_features() -> FeaturesResponse:
    """List all available timeseries features.

    Returns:
        A FeaturesResponse with the complete feature list.
    """
    return FeaturesResponse(features=list(ALL_FEATURES))
