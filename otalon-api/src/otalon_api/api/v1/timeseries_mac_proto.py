"""Parallel MAC and Proto time-series subrouters.

Mounted additively alongside the existing UCI conn endpoints under
``/api/v1/timeseries/mac/...`` and ``/api/v1/timeseries/proto/...``.
No conn route is modified or shadowed.
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
    FeaturesResponse,
    SourceIdsResponse,
    SourceIdsResponseItem,
    SourceTimeseriesResponse,
)
from otalon_api.dependencies import get_mac_timeseries_service, get_proto_hash_resolver, get_proto_timeseries_service
from otalon_api.domain.netcap.models import MAC_FEATURES, PROTO_FEATURES
from otalon_api.domain.netcap.proto_resolver import ProtoHashResolver
from otalon_api.services.source_timeseries_service import SourceTimeseriesService

mac_router = APIRouter(prefix="/api/v1/timeseries/mac", tags=["timeseries-mac"])
proto_router = APIRouter(prefix="/api/v1/timeseries/proto", tags=["timeseries-proto"])

ALLOWED_AGGREGATES: frozenset[str] = frozenset({"mean", "sum", "min", "max", "count"})

_MAC_FEATURES_SET: frozenset[str] = frozenset(MAC_FEATURES)
_PROTO_FEATURES_SET: frozenset[str] = frozenset(PROTO_FEATURES)

# QUA-12 — cardinality/length caps on per-request list and identifier
# parameters. The MAC catalog holds 13 names and the Proto catalog 10, a
# MAC id is 17 chars and a protocol id (hash or stack name) stays well
# under 128, so these caps never reject a real request.
MAX_FEATURES = 32
MAX_SERIES_ID_LENGTH = 256
MAX_SAMPLE_POINTS = 100_000


def _validate_mac_features(features: list[str]) -> None:
    """Raise HTTPException 400 if any feature is not in the MAC catalog."""
    invalid = [f for f in features if f not in _MAC_FEATURES_SET]
    if invalid:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid feature(s): {', '.join(invalid)}",
        )


def _validate_proto_features(features: list[str]) -> None:
    """Raise HTTPException 400 if any feature is not in the Proto catalog."""
    invalid = [f for f in features if f not in _PROTO_FEATURES_SET]
    if invalid:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid feature(s): {', '.join(invalid)}",
        )


def _validate_aggregate(aggregate: str | None) -> None:
    """Raise HTTPException 400 if the aggregate function is not allowed."""
    if aggregate is not None and aggregate not in ALLOWED_AGGREGATES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid aggregate '{aggregate}'. Allowed: {', '.join(sorted(ALLOWED_AGGREGATES))}",
        )


def _sanitize_value(value: Any) -> Any:
    """Replace NaN / NaT / Infinity with ``None`` for JSON serialization."""
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
    """Convert a DataFrame to a list of JSON-safe dictionaries."""
    if df.empty:
        return []

    result = df.copy()
    if "time" in result.columns:
        result["time"] = pd.to_datetime(result["time"], errors="coerce").dt.strftime("%Y-%m-%dT%H:%M:%S")

    records = result.to_dict(orient="records")
    return [{str(k): _sanitize_value(v) for k, v in row.items()} for row in records]


# ---------------------------------------------------------------------------
# MAC endpoints
# ---------------------------------------------------------------------------


@mac_router.get("/ids")
async def list_mac_ids(
    start: datetime,
    stop: datetime,
    nonzero: bool = False,
    fields: list[str] | None = Query(default=None, max_length=MAX_FEATURES),
    service: SourceTimeseriesService = Depends(get_mac_timeseries_service),
) -> SourceIdsResponse:
    """List MAC addresses available in a time range."""
    if start >= stop:
        raise HTTPException(status_code=400, detail="start must be before stop")

    try:
        raw = await asyncio.to_thread(
            service.list_ids,
            start=start,
            stop=stop,
            nonzero=nonzero,
            fields=fields,
        )
    except Exception as exc:
        logger.error("list_mac_ids failed: {}", exc)
        raise HTTPException(status_code=500, detail="Failed to list MAC identifiers") from exc

    data = [SourceIdsResponseItem(id=id_val) for id_val in raw]
    return SourceIdsResponse(
        start=start.isoformat(),
        stop=stop.isoformat(),
        nonzero=nonzero,
        count=len(data),
        data=data,
    )


@mac_router.get("/data")
async def query_mac_data(
    mac: str = Query(max_length=MAX_SERIES_ID_LENGTH),
    start: datetime = Query(),
    stop: datetime = Query(),
    features: list[str] = Query(max_length=MAX_FEATURES),
    aggregate: str | None = Query(default=None, max_length=32),
    sample_max_points: int | None = Query(default=None, ge=1, le=MAX_SAMPLE_POINTS),
    preserve_extrema: bool = True,
    service: SourceTimeseriesService = Depends(get_mac_timeseries_service),
) -> SourceTimeseriesResponse:
    """Query timeseries data for a single MAC address."""
    if start >= stop:
        raise HTTPException(status_code=400, detail="start must be before stop")
    if not features:
        raise HTTPException(status_code=400, detail="At least one feature is required")
    _validate_mac_features(features)
    _validate_aggregate(aggregate)

    try:
        df, bucket_seconds = await asyncio.to_thread(
            service.get_between,
            series_id=mac,
            start=start,
            stop=stop,
            features=list(features),
            aggregate=aggregate,
            sample_max_points=sample_max_points,
            preserve_extrema=preserve_extrema,
        )
    except Exception as exc:
        logger.error("query_mac_data failed for mac={}: {}", mac, exc)
        raise HTTPException(status_code=500, detail="Failed to query MAC timeseries data") from exc

    return SourceTimeseriesResponse(
        series_id=mac,
        start=start.isoformat(),
        stop=stop.isoformat(),
        features=list(features),
        bucket_seconds=bucket_seconds,
        row_count=len(df),
        data=_df_to_records(df),
    )


@mac_router.get("/plot")
async def query_mac_plot(
    mac: str = Query(max_length=MAX_SERIES_ID_LENGTH),
    start: datetime = Query(),
    stop: datetime = Query(),
    features: list[str] = Query(max_length=MAX_FEATURES),
    sample_max_points: int = Query(default=500, ge=1, le=MAX_SAMPLE_POINTS),
    preserve_extrema: bool = True,
    service: SourceTimeseriesService = Depends(get_mac_timeseries_service),
) -> SourceTimeseriesResponse:
    """Query plot-ready downsampled timeseries for a MAC address."""
    if start >= stop:
        raise HTTPException(status_code=400, detail="start must be before stop")
    if not features:
        raise HTTPException(status_code=400, detail="At least one feature is required")
    _validate_mac_features(features)

    try:
        df, bucket_seconds = await asyncio.to_thread(
            service.get_plot_data,
            series_id=mac,
            start=start,
            stop=stop,
            features=list(features),
            sample_max_points=sample_max_points,
            preserve_extrema=preserve_extrema,
        )
    except Exception as exc:
        logger.error("query_mac_plot failed for mac={}: {}", mac, exc)
        raise HTTPException(status_code=500, detail="Failed to query MAC plot data") from exc

    return SourceTimeseriesResponse(
        series_id=mac,
        start=start.isoformat(),
        stop=stop.isoformat(),
        features=list(features),
        bucket_seconds=bucket_seconds,
        row_count=len(df),
        data=_df_to_records(df),
    )


@mac_router.get("/features")
async def list_mac_features() -> FeaturesResponse:
    """List all available MAC timeseries features."""
    return FeaturesResponse(features=list(MAC_FEATURES))


# ---------------------------------------------------------------------------
# Proto endpoints
# ---------------------------------------------------------------------------


@proto_router.get("/ids")
async def list_proto_ids(
    start: datetime,
    stop: datetime,
    nonzero: bool = False,
    fields: list[str] | None = Query(default=None, max_length=MAX_FEATURES),
    service: SourceTimeseriesService = Depends(get_proto_timeseries_service),
    proto_resolver: ProtoHashResolver = Depends(get_proto_hash_resolver),
) -> SourceIdsResponse:
    """List protocol stacks available in a time range."""
    if start >= stop:
        raise HTTPException(status_code=400, detail="start must be before stop")

    def _list_and_resolve() -> list[tuple[str, str]]:
        """Fetch the ids and resolve them in ONE worker-thread hop.

        ``resolve()`` performs a synchronous InfluxDB query on a cache
        miss, so calling it from the comprehension ran blocking IO on the
        event loop — once per unknown id (audit QUA-08). ``resolve_many``
        refreshes at most once for the whole batch, and doing it here
        keeps the resolution inside the same hop as the data query.
        """
        ids = service.list_ids(start=start, stop=stop, nonzero=nonzero, fields=fields)
        return list(zip(ids, proto_resolver.resolve_many(list(ids))))

    try:
        resolved = await asyncio.to_thread(_list_and_resolve)
    except Exception as exc:
        logger.error("list_proto_ids failed: {}", exc)
        raise HTTPException(status_code=500, detail="Failed to list protocol identifiers") from exc

    data = [SourceIdsResponseItem(id=id_val, protocol=protocol) for id_val, protocol in resolved]
    return SourceIdsResponse(
        start=start.isoformat(),
        stop=stop.isoformat(),
        nonzero=nonzero,
        count=len(data),
        data=data,
    )


@proto_router.get("/data")
async def query_proto_data(
    protocol: str = Query(max_length=MAX_SERIES_ID_LENGTH),
    start: datetime = Query(),
    stop: datetime = Query(),
    features: list[str] = Query(max_length=MAX_FEATURES),
    aggregate: str | None = Query(default=None, max_length=32),
    sample_max_points: int | None = Query(default=None, ge=1, le=MAX_SAMPLE_POINTS),
    preserve_extrema: bool = True,
    service: SourceTimeseriesService = Depends(get_proto_timeseries_service),
    proto_resolver: ProtoHashResolver = Depends(get_proto_hash_resolver),
) -> SourceTimeseriesResponse:
    """Query timeseries data for a single protocol stack."""
    if start >= stop:
        raise HTTPException(status_code=400, detail="start must be before stop")
    if not features:
        raise HTTPException(status_code=400, detail="At least one feature is required")
    _validate_proto_features(features)
    _validate_aggregate(aggregate)

    def _query_and_resolve() -> tuple[Any, int | None, str]:
        """Query the data and resolve the protocol in one worker-thread hop.

        ``resolve()`` hits InfluxDB synchronously on a cache miss, so it
        must not run on the event loop (audit QUA-08).
        """
        frame, bucket = service.get_between(
            series_id=protocol,
            start=start,
            stop=stop,
            features=list(features),
            aggregate=aggregate,
            sample_max_points=sample_max_points,
            preserve_extrema=preserve_extrema,
        )
        return frame, bucket, proto_resolver.resolve(protocol)

    try:
        df, bucket_seconds, resolved_protocol = await asyncio.to_thread(_query_and_resolve)
    except Exception as exc:
        logger.error("query_proto_data failed for protocol={}: {}", protocol, exc)
        raise HTTPException(status_code=500, detail="Failed to query protocol timeseries data") from exc

    return SourceTimeseriesResponse(
        series_id=resolved_protocol,
        protocol=resolved_protocol,
        start=start.isoformat(),
        stop=stop.isoformat(),
        features=list(features),
        bucket_seconds=bucket_seconds,
        row_count=len(df),
        data=_df_to_records(df),
    )


@proto_router.get("/plot")
async def query_proto_plot(
    protocol: str = Query(max_length=MAX_SERIES_ID_LENGTH),
    start: datetime = Query(),
    stop: datetime = Query(),
    features: list[str] = Query(max_length=MAX_FEATURES),
    sample_max_points: int = Query(default=500, ge=1, le=MAX_SAMPLE_POINTS),
    preserve_extrema: bool = True,
    service: SourceTimeseriesService = Depends(get_proto_timeseries_service),
    proto_resolver: ProtoHashResolver = Depends(get_proto_hash_resolver),
) -> SourceTimeseriesResponse:
    """Query plot-ready downsampled timeseries for a protocol stack."""
    if start >= stop:
        raise HTTPException(status_code=400, detail="start must be before stop")
    if not features:
        raise HTTPException(status_code=400, detail="At least one feature is required")
    _validate_proto_features(features)

    def _query_and_resolve() -> tuple[Any, int | None, str]:
        """Query plot data and resolve the protocol in one worker-thread hop.

        ``resolve()`` hits InfluxDB synchronously on a cache miss, so it
        must not run on the event loop (audit QUA-08).
        """
        frame, bucket = service.get_plot_data(
            series_id=protocol,
            start=start,
            stop=stop,
            features=list(features),
            sample_max_points=sample_max_points,
            preserve_extrema=preserve_extrema,
        )
        return frame, bucket, proto_resolver.resolve(protocol)

    try:
        df, bucket_seconds, resolved_protocol = await asyncio.to_thread(_query_and_resolve)
    except Exception as exc:
        logger.error("query_proto_plot failed for protocol={}: {}", protocol, exc)
        raise HTTPException(status_code=500, detail="Failed to query protocol plot data") from exc

    return SourceTimeseriesResponse(
        series_id=resolved_protocol,
        protocol=resolved_protocol,
        start=start.isoformat(),
        stop=stop.isoformat(),
        features=list(features),
        bucket_seconds=bucket_seconds,
        row_count=len(df),
        data=_df_to_records(df),
    )


@proto_router.get("/features")
async def list_proto_features() -> FeaturesResponse:
    """List all available protocol timeseries features."""
    return FeaturesResponse(features=list(PROTO_FEATURES))
