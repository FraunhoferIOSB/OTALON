"""Parallel MAC and Proto anomalies/bounds subrouters.

Mounted additively alongside the existing UCI conn endpoints under
``/api/v1/anomalies/mac/...`` and ``/api/v1/anomalies/proto/...``.
No conn route is modified or shadowed.
"""

from __future__ import annotations

from datetime import datetime

import psycopg2
from fastapi import APIRouter, Depends, HTTPException
from loguru import logger

from otalon_api.api.schemas.anomalies import (
    AlarmIntervalsResponse,
    AnomalyGroupsResponse,
    BoundsResponse,
    TimeseriesWithBoundsResponse,
)
from otalon_api.api.schemas.common import TimeRangeParams
from otalon_api.dependencies import get_anomaly_service, get_bounds_service
from otalon_api.domain.netcap.models import MAC_FEATURES, PROTO_FEATURES, proto_series_hash
from otalon_api.services.anomaly_service import AnomalyService
from otalon_api.services.bounds_service import BoundsService

mac_router = APIRouter(prefix="/api/v1/anomalies/mac", tags=["anomalies-mac"])
proto_router = APIRouter(prefix="/api/v1/anomalies/proto", tags=["anomalies-proto"])

_MAC_FEATURES_SET: frozenset[str] = frozenset(MAC_FEATURES)
_PROTO_FEATURES_SET: frozenset[str] = frozenset(PROTO_FEATURES)


# ---------------------------------------------------------------------------
# MAC endpoints
# ---------------------------------------------------------------------------


@mac_router.get("/series", response_model=BoundsResponse)
async def get_mac_anomaly_series(
    series_id: str,
    start: datetime | None = None,
    stop: datetime | None = None,
    service: AnomalyService = Depends(get_anomaly_service),
) -> BoundsResponse:
    """Query anomaly intervals for a MAC series."""
    try:
        result = await service.get_anomaly_series(
            module="mac_traffic",
            series_id=series_id,
            start=start,
            stop=stop,
        )
    except ValueError as exc:
        logger.warning("get_mac_anomaly_series not found: {}", exc)
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.error("get_mac_anomaly_series failed: {}", exc)
        raise HTTPException(status_code=500, detail="Failed to query MAC anomaly series") from exc

    return BoundsResponse(**result)


@mac_router.get("/bounds", response_model=TimeseriesWithBoundsResponse)
async def get_mac_timeseries_with_bounds(
    series_id: str,
    metric: str,
    start: datetime,
    stop: datetime,
    sample_max_points: int | None = None,
    service: BoundsService = Depends(get_bounds_service),
) -> TimeseriesWithBoundsResponse:
    """Query timeseries merged with boundary thresholds for a MAC and metric."""
    if start >= stop:
        raise HTTPException(status_code=400, detail="start must be before stop")
    if metric not in _MAC_FEATURES_SET:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid metric '{metric}'",
        )

    try:
        result = await service.get_timeseries_with_bounds(
            uci=series_id,
            metric=metric,
            start=start,
            stop=stop,
            module="mac_traffic",
            sample_max_points=sample_max_points,
            normalize=False,
        )
    except ValueError as exc:
        logger.warning("get_mac_timeseries_with_bounds not found: {}", exc)
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.error("get_mac_timeseries_with_bounds failed for series_id={}: {}", series_id, exc)
        raise HTTPException(status_code=500, detail="Failed to query MAC timeseries with bounds") from exc

    return TimeseriesWithBoundsResponse(**result)


@mac_router.get("/groups", response_model=AnomalyGroupsResponse)
async def get_mac_anomaly_groups(
    time_range: TimeRangeParams = Depends(),
    limit: int = 100,
    service: AnomalyService = Depends(get_anomaly_service),
) -> AnomalyGroupsResponse:
    """Query MAC alarm groups with optional time-range filter."""
    try:
        result = await service.get_anomaly_groups(
            module="mac_traffic",
            start=time_range.start,
            stop=time_range.stop,
            limit=limit,
        )
    except Exception as exc:
        logger.error("get_mac_anomaly_groups failed: {}", exc)
        raise HTTPException(status_code=500, detail="Failed to query MAC anomaly groups") from exc

    return AnomalyGroupsResponse(**result)


@mac_router.get("/intervals", response_model=AlarmIntervalsResponse)
async def get_mac_anomaly_intervals(
    series_id: str,
    start: datetime | None = None,
    stop: datetime | None = None,
    limit: int = 200,
    service: AnomalyService = Depends(get_anomaly_service),
) -> AlarmIntervalsResponse:
    """Get alarm intervals that overlap with a specific MAC."""
    if start is not None and stop is not None and start >= stop:
        raise HTTPException(status_code=400, detail="start must be before stop")

    try:
        result = await service.get_anomaly_intervals(
            uci=series_id,
            module=None,
            start=start,
            stop=stop,
            limit=limit,
        )
    except ValueError as exc:
        logger.warning("get_mac_anomaly_intervals not found: {}", exc)
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except psycopg2.OperationalError as exc:
        logger.error(
            "Database timeout for MAC anomaly intervals series_id={}: {}",
            series_id,
            exc,
        )
        raise HTTPException(status_code=504, detail="Database query timed out") from exc
    except Exception as exc:
        logger.error("get_mac_anomaly_intervals failed for series_id={}: {}", series_id, exc)
        raise HTTPException(status_code=500, detail="Failed to query MAC anomaly intervals") from exc

    return AlarmIntervalsResponse(**result)


# ---------------------------------------------------------------------------
# Proto endpoints
# ---------------------------------------------------------------------------


@proto_router.get("/series", response_model=BoundsResponse)
async def get_proto_anomaly_series(
    series_id: str,
    start: datetime | None = None,
    stop: datetime | None = None,
    service: AnomalyService = Depends(get_anomaly_service),
) -> BoundsResponse:
    """Query anomaly intervals for a protocol series.

    Note:
        Legacy proto anomalies written before the A.3 hash fix may
        contain non-reversible hashed series_ids.  The endpoint
        returns whatever series_id matches without attempting hash
        reversal.
    """
    try:
        result = await service.get_anomaly_series(
            module="proto_traffic",
            series_id=series_id,
            start=start,
            stop=stop,
        )
    except ValueError as exc:
        logger.warning("get_proto_anomaly_series not found: {}", exc)
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.error("get_proto_anomaly_series failed: {}", exc)
        raise HTTPException(status_code=500, detail="Failed to query protocol anomaly series") from exc

    return BoundsResponse(**result)


@proto_router.get("/bounds", response_model=TimeseriesWithBoundsResponse)
async def get_proto_timeseries_with_bounds(
    series_id: str,
    metric: str,
    start: datetime,
    stop: datetime,
    sample_max_points: int | None = None,
    service: BoundsService = Depends(get_bounds_service),
) -> TimeseriesWithBoundsResponse:
    """Query timeseries merged with boundary thresholds for a protocol and metric.

    Note:
        Legacy proto anomalies written before the A.3 hash fix may
        contain non-reversible hashed series_ids.  The endpoint
        queries by the raw series_id without hash reversal.
    """
    if start >= stop:
        raise HTTPException(status_code=400, detail="start must be before stop")
    if metric not in _PROTO_FEATURES_SET:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid metric '{metric}'",
        )

    try:
        result = await service.get_timeseries_with_bounds(
            uci=series_id,
            metric=metric,
            start=start,
            stop=stop,
            module="proto_traffic",
            sample_max_points=sample_max_points,
            normalize=False,
        )
    except ValueError as exc:
        logger.warning("get_proto_timeseries_with_bounds not found: {}", exc)
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.error(
            "get_proto_timeseries_with_bounds failed for series_id={}: {}",
            series_id,
            exc,
        )
        raise HTTPException(status_code=500, detail="Failed to query protocol timeseries with bounds") from exc

    return TimeseriesWithBoundsResponse(**result)


@proto_router.get("/groups", response_model=AnomalyGroupsResponse)
async def get_proto_anomaly_groups(
    time_range: TimeRangeParams = Depends(),
    limit: int = 100,
    service: AnomalyService = Depends(get_anomaly_service),
) -> AnomalyGroupsResponse:
    """Query protocol alarm groups with optional time-range filter."""
    try:
        result = await service.get_anomaly_groups(
            module="proto_traffic",
            start=time_range.start,
            stop=time_range.stop,
            limit=limit,
        )
    except Exception as exc:
        logger.error("get_proto_anomaly_groups failed: {}", exc)
        raise HTTPException(status_code=500, detail="Failed to query protocol anomaly groups") from exc

    return AnomalyGroupsResponse(**result)


@proto_router.get("/intervals", response_model=AlarmIntervalsResponse)
async def get_proto_anomaly_intervals(
    series_id: str,
    start: datetime | None = None,
    stop: datetime | None = None,
    limit: int = 200,
    service: AnomalyService = Depends(get_anomaly_service),
) -> AlarmIntervalsResponse:
    """Get alarm intervals that overlap with a specific protocol.

    The UI sends the plaintext protocol stack (e.g. ``"Ethernet:ARP"``)
    as ``series_id``, but proto alarm groups persist their
    ``series_ids`` as the stable hash of that stack.  The plaintext
    ``series_id`` is therefore translated via :func:`proto_series_hash`
    before matching against the persisted hashed ``series_ids``.
    """
    if start is not None and stop is not None and start >= stop:
        raise HTTPException(status_code=400, detail="start must be before stop")

    try:
        result = await service.get_anomaly_intervals(
            uci=series_id,
            module=None,
            start=start,
            stop=stop,
            limit=limit,
            match_uci=proto_series_hash(series_id),
        )
    except ValueError as exc:
        logger.warning("get_proto_anomaly_intervals not found: {}", exc)
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except psycopg2.OperationalError as exc:
        logger.error(
            "Database timeout for proto anomaly intervals series_id={}: {}",
            series_id,
            exc,
        )
        raise HTTPException(status_code=504, detail="Database query timed out") from exc
    except Exception as exc:
        logger.error("get_proto_anomaly_intervals failed for series_id={}: {}", series_id, exc)
        raise HTTPException(status_code=500, detail="Failed to query protocol anomaly intervals") from exc

    return AlarmIntervalsResponse(**result)
