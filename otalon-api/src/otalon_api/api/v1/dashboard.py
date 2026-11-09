"""Dashboard router.

Provides REST endpoints for dashboard KPIs and summary data, plus the
per-account layout and global tour-completion state endpoints.
"""

from __future__ import annotations

import asyncio
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from loguru import logger

from otalon_api.api.schemas.dashboard import (
    DashboardKpisResponse,
    DashboardLayoutPayload,
    ThroughputResponse,
    TopAssetsResponse,
    TopProtocolsResponse,
    TourStatePayload,
    VulnerabilitySummaryResponse,
)
from otalon_api.dependencies import get_dashboard_kpi_service, get_dashboard_user_state_repo
from otalon_api.middleware.session_auth import require_session
from otalon_api.repositories.dashboard_user_state_repo import DashboardUserStateRepository
from otalon_api.repositories.identity_repo import UserEntry
from otalon_api.services.dashboard_kpi_service import DashboardKpiService

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])


@router.get("/kpis", response_model=DashboardKpisResponse)
async def get_kpis(
    start: datetime | None = None,
    stop: datetime | None = None,
    service: DashboardKpiService = Depends(get_dashboard_kpi_service),
) -> DashboardKpisResponse:
    """Compute and return dashboard KPIs for the given time window.

    Args:
        start: Optional range start timestamp.
        stop: Optional range stop timestamp.
        service: Injected dashboard KPI service.

    Returns:
        A DashboardKpisResponse with signal color and aggregated counts.
    """
    try:
        result = await service.get_kpis(start=start, stop=stop)
    except Exception as exc:
        logger.error("get_kpis failed: {}", exc)
        raise HTTPException(status_code=500, detail="Failed to compute dashboard KPIs") from exc

    return DashboardKpisResponse(**result)


@router.get("/top-assets", response_model=TopAssetsResponse)
async def get_top_assets(
    start: datetime | None = None,
    stop: datetime | None = None,
    limit: int = Query(default=5, ge=1, le=50),
    service: DashboardKpiService = Depends(get_dashboard_kpi_service),
) -> TopAssetsResponse:
    """Return the top MAC addresses by traffic volume.

    Each entry includes aggregated packet/byte counts, an anomaly
    flag derived from active ``mac_traffic`` alarm groups, and a
    sparkline of total bytes over the time window.

    Args:
        start: Optional range start timestamp.
        stop: Optional range stop timestamp.
        limit: Number of top assets to return (1–50, default 5).
        service: Injected dashboard KPI service.

    Returns:
        A TopAssetsResponse with ranked MAC addresses and sparklines.
    """
    try:
        result = await service.get_top_assets(start=start, stop=stop, limit=limit)
    except Exception as exc:
        logger.error("get_top_assets failed: {}", exc)
        raise HTTPException(status_code=500, detail="Failed to compute top assets") from exc

    return TopAssetsResponse(**result)


@router.get("/top-protocols", response_model=TopProtocolsResponse)
async def get_top_protocols(
    start: datetime | None = None,
    stop: datetime | None = None,
    limit: int = Query(default=5, ge=1, le=50),
    service: DashboardKpiService = Depends(get_dashboard_kpi_service),
) -> TopProtocolsResponse:
    """Return the top protocol stacks by traffic volume.

    Each entry includes aggregated packet/byte counts, an anomaly
    flag derived from active ``proto_traffic`` alarm groups, and a
    sparkline of total bytes over the time window.

    Args:
        start: Optional range start timestamp.
        stop: Optional range stop timestamp.
        limit: Number of top protocols to return (1–50, default 5).
        service: Injected dashboard KPI service.

    Returns:
        A TopProtocolsResponse with ranked protocols and sparklines.
    """
    try:
        result = await service.get_top_protocols(start=start, stop=stop, limit=limit)
    except Exception as exc:
        logger.error("get_top_protocols failed: {}", exc)
        raise HTTPException(status_code=500, detail="Failed to compute top protocols") from exc

    return TopProtocolsResponse(**result)


@router.get("/vulnerabilities-summary", response_model=VulnerabilitySummaryResponse)
async def get_vulnerability_summary(
    service: DashboardKpiService = Depends(get_dashboard_kpi_service),
) -> VulnerabilitySummaryResponse:
    """Return aggregated vulnerability data for the dashboard widget.

    Queries PostgreSQL ``vulnerability_observations`` for affected
    device counts, total CVEs, severity breakdown, and top CVEs.

    Args:
        service: Injected dashboard KPI service.

    Returns:
        A VulnerabilitySummaryResponse with summary counts.
    """
    try:
        result = await service.get_vulnerability_summary()
    except Exception as exc:
        logger.error("get_vulnerability_summary failed: {}", exc)
        raise HTTPException(status_code=500, detail="Failed to query vulnerability summary") from exc

    return VulnerabilitySummaryResponse(**result)


@router.get("/throughput", response_model=ThroughputResponse)
async def get_throughput(
    start: datetime | None = None,
    stop: datetime | None = None,
    buckets: int = Query(default=60, ge=10, le=300),
    service: DashboardKpiService = Depends(get_dashboard_kpi_service),
) -> ThroughputResponse:
    """Return aggregated network throughput data for the sparkline widget.

    Sums ``total_volume`` and ``packet_count`` from ``network_metrics``
    across all UCIs, bucketed into *buckets* time intervals.  If
    *start*/*stop* are omitted the last hour is used.

    Args:
        start: Optional range start timestamp.
        stop: Optional range stop timestamp.
        buckets: Number of time buckets (10–300, default 60).
        service: Injected dashboard KPI service.

    Returns:
        A ThroughputResponse with time-bucketed throughput data.
    """
    try:
        result = await service.get_throughput(start=start, stop=stop, buckets=buckets)
    except Exception as exc:
        logger.error("get_throughput failed: {}", exc)
        raise HTTPException(status_code=500, detail="Failed to query network throughput") from exc

    return ThroughputResponse(**result)


@router.get("/layout", response_model=DashboardLayoutPayload)
async def get_dashboard_layout(
    user: UserEntry = Depends(require_session),
    repo: DashboardUserStateRepository = Depends(get_dashboard_user_state_repo),
) -> DashboardLayoutPayload:
    """Return the caller's own persisted dashboard layout.

    If the account has no saved layout yet, the endpoint returns 404 so
    the frontend can fall back to localStorage or the default layout.

    Args:
        user: Session-bound caller identity (never a body-supplied id).
        repo: Injected per-account dashboard-state repository.

    Returns:
        The caller's stored dashboard layout payload.

    Raises:
        HTTPException: 404 when the caller has no stored layout.
    """
    try:
        payload = await asyncio.to_thread(repo.get_layout, user.id)
    except Exception as exc:
        logger.error("get_dashboard_layout failed: {}", exc)
        raise HTTPException(status_code=500, detail="Failed to load dashboard layout") from exc
    if payload is None:
        raise HTTPException(status_code=404, detail="No dashboard layout saved")
    return DashboardLayoutPayload(**payload)


@router.put("/layout", response_model=DashboardLayoutPayload)
async def put_dashboard_layout(
    payload: DashboardLayoutPayload,
    user: UserEntry = Depends(require_session),
    repo: DashboardUserStateRepository = Depends(get_dashboard_user_state_repo),
) -> DashboardLayoutPayload:
    """Upsert the caller's own dashboard layout.

    Args:
        payload: Layout geometry and hidden-widget list (caps enforced).
        user: Session-bound caller identity (never a body-supplied id).
        repo: Injected per-account dashboard-state repository.

    Returns:
        The stored payload.
    """
    try:
        await asyncio.to_thread(repo.set_layout, user.id, payload.model_dump())
    except Exception as exc:
        logger.error("put_dashboard_layout failed: {}", exc)
        raise HTTPException(status_code=500, detail="Failed to save dashboard layout") from exc
    return payload


@router.get("/tour", response_model=TourStatePayload)
async def get_dashboard_tour(
    user: UserEntry = Depends(require_session),
    repo: DashboardUserStateRepository = Depends(get_dashboard_user_state_repo),
) -> TourStatePayload:
    """Return the caller's global tour-completion flag.

    Unlike the layout endpoint there is no 404 for a missing row:
    ``completed: false`` IS the default state of an account that never
    finished (or skipped) the onboarding tour.

    Args:
        user: Session-bound caller identity.
        repo: Injected per-account dashboard-state repository.

    Returns:
        The account-wide tour completion flag.
    """
    try:
        completed = await asyncio.to_thread(repo.get_tour_completed, user.id)
    except Exception as exc:
        logger.error("get_dashboard_tour failed: {}", exc)
        raise HTTPException(status_code=500, detail="Failed to load tour state") from exc
    return TourStatePayload(completed=completed)


@router.put("/tour", response_model=TourStatePayload)
async def put_dashboard_tour(
    payload: TourStatePayload,
    user: UserEntry = Depends(require_session),
    repo: DashboardUserStateRepository = Depends(get_dashboard_user_state_repo),
) -> TourStatePayload:
    """Upsert the caller's global tour-completion flag.

    Args:
        payload: Global completion flag (one flag for the whole account).
        user: Session-bound caller identity.
        repo: Injected per-account dashboard-state repository.

    Returns:
        The stored tour completion flag.
    """
    try:
        await asyncio.to_thread(repo.set_tour_completed, user.id, payload.completed)
    except Exception as exc:
        logger.error("put_dashboard_tour failed: {}", exc)
        raise HTTPException(status_code=500, detail="Failed to save tour state") from exc
    return TourStatePayload(completed=payload.completed)
