"""Anomalies router.

Provides REST endpoints for querying anomaly data, alarm groups,
alarm intervals, bounds with timeseries, and alarm group management.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

import psycopg2
from fastapi import APIRouter, Depends, HTTPException, Query
from loguru import logger
from pydantic import BaseModel

from otalon_api.api.schemas.anomalies import (
    AlarmIntervalsResponse,
    AnomalyGroupsResponse,
    BoundsResponse,
    GroupEntitiesResponse,
    TimeseriesWithBoundsResponse,
)
from otalon_api.api.schemas.common import TimeRangeParams
from otalon_api.dependencies import get_anomaly_details_service, get_anomaly_service, get_bounds_service
from otalon_api.domain.netcap.models import ALL_FEATURES, MAC_FEATURES, PROTO_FEATURES
from otalon_api.services.anomaly_details_service import AnomalyDetailsService
from otalon_api.services.anomaly_service import AnomalyService
from otalon_api.services.bounds_service import BoundsService

router = APIRouter(prefix="/api/v1/anomalies", tags=["anomalies"])

# Explicit per-module feature contracts. The generic bounds endpoint validates
# the requested metric against the *selected module's* family, not a global
# union, so a cross-family pair (e.g. module=conn + metric=proto_total_packets)
# is rejected before the service is reached. ``"conn"`` and the legacy/default
# wire value ``"netcap"`` both map to the connection feature list, preserving
# the historical default-module contract.
_MODULE_FEATURES: dict[str, frozenset[str]] = {
    "conn": frozenset(ALL_FEATURES),
    "netcap": frozenset(ALL_FEATURES),
    "mac_traffic": frozenset(MAC_FEATURES),
    "proto_traffic": frozenset(PROTO_FEATURES),
}

# QUA-12 — bounds on the identifier and scan-size parameters. ``uci`` is
# carried into the Influx query and matched against every group's
# ``series_ids``; ``limit`` sizes the group scan. The caps sit far above
# real values (longest live series id: 113 chars, 200 is the default
# scan size).
MAX_SERIES_ID_LENGTH = 512
MAX_MODULE_LENGTH = 64
MAX_METRIC_LENGTH = 64
MAX_INTERVAL_SCAN = 2000
MAX_SAMPLE_POINTS = 100_000


class UpdateGroupRequest(BaseModel):
    """Request body for updating the confirmed status of an alarm group."""

    confirmed: bool


class UpdateGroupPrimaryTypeRequest(BaseModel):
    """Request body for adopting a subagent classification as primary_type."""

    primary_type: str


@router.get("/series", response_model=BoundsResponse)
async def get_anomaly_series(
    uci: str | None = Query(default=None, max_length=MAX_SERIES_ID_LENGTH),
    module: str = Query(default="netcap", max_length=MAX_MODULE_LENGTH),
    start: datetime | None = None,
    stop: datetime | None = None,
    service: AnomalyService = Depends(get_anomaly_service),
) -> BoundsResponse:
    """Query anomaly intervals for a module and optional UCI filter.

    Args:
        uci: Optional unique communication identifier (used as series_id).
        module: Detection module name.
        start: Optional range start timestamp.
        stop: Optional range stop timestamp.
        service: Injected anomaly service.

    Returns:
        A BoundsResponse with matching anomaly series data.
    """
    try:
        result = await service.get_anomaly_series(
            module=module,
            series_id=uci,
            start=start,
            stop=stop,
        )
    except ValueError as exc:
        logger.warning("get_anomaly_series not found: {}", exc)
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.error("get_anomaly_series failed: {}", exc)
        raise HTTPException(status_code=500, detail="Failed to query anomaly series") from exc

    return BoundsResponse(**result)


@router.get("/bounds", response_model=TimeseriesWithBoundsResponse)
async def get_timeseries_with_bounds(
    uci: str = Query(max_length=MAX_SERIES_ID_LENGTH),
    metric: str = Query(max_length=MAX_METRIC_LENGTH),
    start: datetime = Query(),
    stop: datetime = Query(),
    module: str = Query(default="netcap", max_length=MAX_MODULE_LENGTH),
    sample_max_points: int | None = Query(default=None, ge=1, le=MAX_SAMPLE_POINTS),
    service: BoundsService = Depends(get_bounds_service),
) -> TimeseriesWithBoundsResponse:
    """Query timeseries merged with boundary thresholds for a UCI and metric.

    Args:
        uci: Unique communication identifier.
        metric: Feature name (e.g. ``"mean_packet_size"``).
        start: Range start timestamp.
        stop: Range stop timestamp.
        module: Detection module name for bounds lookup.
        sample_max_points: Maximum number of timeseries data points.
        service: Injected bounds service.

    Returns:
        A TimeseriesWithBoundsResponse with merged timeseries and bounds.
    """
    if start >= stop:
        raise HTTPException(status_code=400, detail="start must be before stop")
    allowed_metrics = _MODULE_FEATURES.get(module)
    if allowed_metrics is None:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown module '{module}'",
        )
    if metric not in allowed_metrics:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid metric '{metric}' for module '{module}'",
        )

    try:
        result = await service.get_timeseries_with_bounds(
            uci=uci,
            metric=metric,
            start=start,
            stop=stop,
            module=module,
            sample_max_points=sample_max_points,
        )
    except ValueError as exc:
        logger.warning("get_timeseries_with_bounds not found: {}", exc)
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.error("get_timeseries_with_bounds failed for uci={}: {}", uci, exc)
        raise HTTPException(status_code=500, detail="Failed to query timeseries with bounds") from exc

    return TimeseriesWithBoundsResponse(**result)


@router.get("/groups", response_model=AnomalyGroupsResponse)
async def get_anomaly_groups(
    time_range: TimeRangeParams = Depends(),
    module: str | None = Query(default=None, max_length=MAX_MODULE_LENGTH),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    service: AnomalyService = Depends(get_anomaly_service),
) -> AnomalyGroupsResponse:
    """Query alarm groups with optional module and time-range filters.

    Args:
        time_range: Optional ``start``/``stop`` query parameters
            (:class:`otalon_api.api.schemas.common.TimeRangeParams`).
        module: Optional detection module filter.
        limit: Maximum number of groups to return (1-500, default 50).
        offset: Number of groups to skip for pagination (default 0).
        service: Injected anomaly service.

    Returns:
        An AnomalyGroupsResponse with the matching alarm groups.
        ``row_count`` is the total matching count (not the page count).
    """
    try:
        result = await service.get_anomaly_groups(
            module=module,
            start=time_range.start,
            stop=time_range.stop,
            limit=limit,
            offset=offset,
        )
    except Exception as exc:
        logger.error("get_anomaly_groups failed: {}", exc)
        raise HTTPException(status_code=500, detail="Failed to query anomaly groups") from exc

    return AnomalyGroupsResponse(**result)


@router.get("/intervals", response_model=AlarmIntervalsResponse)
async def get_anomaly_intervals(
    uci: str = Query(max_length=MAX_SERIES_ID_LENGTH),
    module: str | None = Query(default=None, max_length=MAX_MODULE_LENGTH),
    start: datetime | None = None,
    stop: datetime | None = None,
    limit: int = Query(default=200, ge=1, le=MAX_INTERVAL_SCAN),
    service: AnomalyService = Depends(get_anomaly_service),
) -> AlarmIntervalsResponse:
    """Get alarm intervals that overlap with a specific UCI.

    Args:
        uci: Unique communication identifier to match.
        module: Optional detection module filter.
        start: Optional range start timestamp.
        stop: Optional range stop timestamp.
        limit: Maximum number of groups to scan.
        service: Injected anomaly service.

    Returns:
        An AlarmIntervalsResponse with matching alarm intervals.

    Note:
        Uses an explicit 400-check for ``start >= stop`` to preserve
        the historical wire contract (callers expect HTTP 400). The
        shared :class:`otalon_api.api.schemas.common.TimeRangeParams` would
        produce HTTP 422 — semantically equivalent but different on
        the wire — so it is not used here.
    """
    if start is not None and stop is not None and start >= stop:
        raise HTTPException(status_code=400, detail="start must be before stop")

    try:
        result = await service.get_anomaly_intervals(
            uci=uci,
            module=module,
            start=start,
            stop=stop,
            limit=limit,
        )
    except ValueError as exc:
        logger.warning("get_anomaly_intervals not found: {}", exc)
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except psycopg2.OperationalError as exc:
        logger.error("Database timeout for anomaly intervals uci={}: {}", uci, exc)
        raise HTTPException(status_code=504, detail="Database query timed out") from exc
    except Exception as exc:
        logger.error("get_anomaly_intervals failed for uci={}: {}", uci, exc)
        raise HTTPException(status_code=500, detail="Failed to query anomaly intervals") from exc

    return AlarmIntervalsResponse(**result)


@router.get("/groups/{group_id}/entities", response_model=GroupEntitiesResponse)
async def get_group_entities(
    group_id: str,
    service: AnomalyDetailsService = Depends(get_anomaly_details_service),
) -> GroupEntitiesResponse:
    """Retrieve parsed UCI entities for an alarm group.

    Args:
        group_id: The alarm group UUID.
        service: Injected anomaly details service.

    Returns:
        A GroupEntitiesResponse with parsed UCI entity data.
    """
    try:
        result = await service.get_group_entities(group_id)
    except ValueError as exc:
        logger.warning("get_group_entities not found: {}", exc)
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.error("get_group_entities failed for group_id={}: {}", group_id, exc)
        raise HTTPException(status_code=500, detail="Failed to query group entities") from exc

    return GroupEntitiesResponse(**result)


@router.patch("/groups/{group_id}")
async def update_group_confirmed(
    group_id: str,
    body: UpdateGroupRequest,
    service: AnomalyService = Depends(get_anomaly_service),
) -> dict[str, Any]:
    """Update the confirmed status of an alarm group.

    Args:
        group_id: The alarm group UUID.
        body: Request body containing the new confirmed status.
        service: Injected anomaly service.

    Returns:
        A dict with the update result and parameters.
    """
    try:
        result = await service.update_group_confirmed(
            group_id=group_id,
            confirmed=body.confirmed,
        )
    except ValueError as exc:
        logger.warning("update_group_confirmed not found: {}", exc)
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.error("update_group_confirmed failed for group_id={}: {}", group_id, exc)
        raise HTTPException(status_code=500, detail="Failed to update alarm group") from exc

    return result


@router.patch("/groups/{group_id}/primary-type")
async def update_group_primary_type(
    group_id: str,
    body: UpdateGroupPrimaryTypeRequest,
    service: AnomalyService = Depends(get_anomaly_service),
) -> dict[str, Any]:
    """Adopt a free-form attack-method label as the alarm's ``primary_type``.

    Operator action triggered from the alarm detail panel after a subagent
    classification: replaces the supervised-ML label with the LLM's Step-1
    ``technical_method``. Anomaly statistics are preserved; only the
    headline label and ``multi_type`` flag are updated.

    Args:
        group_id: The alarm group ID.
        body: Request body containing the new ``primary_type`` string.

    Returns:
        Updated alarm row plus the parameters that were applied.
    """
    try:
        result = await service.update_group_primary_type(
            group_id=group_id,
            primary_type=body.primary_type,
        )
    except ValueError as exc:
        logger.warning("update_group_primary_type rejected: {}", exc)
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.error("update_group_primary_type failed for group_id={}: {}", group_id, exc)
        raise HTTPException(
            status_code=500,
            detail="Failed to update alarm group primary_type",
        ) from exc

    return result
