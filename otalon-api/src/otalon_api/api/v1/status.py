"""Health and status router.

Provides liveness and readiness probes for container orchestration
and load-balancer health checks, as well as a comprehensive health
check endpoint for all dependent services.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from loguru import logger

from otalon_api.api.schemas.common import ComponentStatus, ReadinessResponse
from otalon_api.dependencies import (
    get_cache_manager,
    get_health_incident_service,
    get_health_service,
    get_influx_repo,
    get_postgres_repo,
)
from otalon_api.repositories.cache import CacheManager
from otalon_api.repositories.influx_repo import InfluxRepository
from otalon_api.repositories.postgres_repo import PostgresRepository
from otalon_api.services.health_incident_service import HealthIncidentService
from otalon_api.services.health_service import HealthService

router = APIRouter(tags=["status"])

READYZ_PROBE_TIMEOUT_S: float = 2.0


def _has_valid_credential(request: Request) -> bool:
    """Return whether the request carries a verified operator key or product session.

    ``ApiKeyAuthMiddleware`` and ``SessionAuthMiddleware`` both attach their
    own state key on success (``api_key_entry`` / ``user_entry`` respectively)
    — either one proves the caller is authenticated for a detail-gated probe.
    """
    return (
        getattr(request.state, "api_key_entry", None) is not None
        or getattr(request.state, "user_entry", None) is not None
    )


@router.get("/health")
async def health() -> dict[str, str]:
    """Unversioned liveness probe, consistent across the suite (HC34).

    Every other OTALON service (otalon-scan, otalon-ai, pcap_recorder,
    pcap_import, otalon-mcp) answers ``GET /health`` with
    ``{"status": "ok"}``; otalon-api was the one service without it, so a
    container healthcheck or uptime probe needed a different path here
    than everywhere else.

    This is deliberately the *cheap* probe: no dependency checks, no
    authentication. The dependency-aware variant stays at
    ``GET /api/v1/status/health``, which additionally reports per-service
    status and cache statistics.

    Returns:
        A JSON object with ``{"status": "ok"}``.
    """
    return {"status": "ok"}


@router.get("/livez")
async def liveness() -> dict[str, str]:
    """Liveness probe — confirms the process is running.

    Kept alongside :func:`health` because Kubernetes-style probes and
    existing call sites use it; ``/health`` is the suite-wide convention.

    Returns:
        A JSON object with ``{"status": "alive"}``.
    """
    return {"status": "alive"}


async def _probe_postgres(repo: PostgresRepository, timeout_s: float) -> ComponentStatus:
    """Probe PostgreSQL reachability with a short timeout.

    Runs the synchronous ``PostgresRepository.health_check`` in a
    worker thread so the FastAPI event loop is not blocked.

    Args:
        repo: Injected PostgreSQL repository.
        timeout_s: Maximum wait time before declaring the probe failed.

    Returns:
        A :class:`ComponentStatus` with ``name='postgres'``.
    """
    t0 = time.perf_counter()
    try:
        ok = await asyncio.wait_for(asyncio.to_thread(repo.health_check), timeout=timeout_s)
    except asyncio.TimeoutError:
        ms = round((time.perf_counter() - t0) * 1000)
        logger.warning("readyz: postgres probe timed out after {} ms", ms)
        return ComponentStatus(name="postgres", ready=False, detail=f"timeout after {ms} ms")
    except Exception as exc:
        ms = round((time.perf_counter() - t0) * 1000)
        logger.warning("readyz: postgres probe failed: {} ({} ms)", exc, ms)
        return ComponentStatus(name="postgres", ready=False, detail=f"{exc} ({ms} ms)")

    ms = round((time.perf_counter() - t0) * 1000)
    if ok:
        return ComponentStatus(name="postgres", ready=True, detail=f"ok in {ms} ms")
    return ComponentStatus(name="postgres", ready=False, detail=f"health_check returned False ({ms} ms)")


async def _probe_influx(repo: InfluxRepository, timeout_s: float) -> ComponentStatus:
    """Probe InfluxDB reachability with a short timeout.

    The underlying repository exposes an async ``health_check`` but the
    InfluxDB client call itself is synchronous, so we wrap the awaitable
    in :func:`asyncio.wait_for` to enforce a hard timeout.

    Args:
        repo: Injected InfluxDB repository.
        timeout_s: Maximum wait time before declaring the probe failed.

    Returns:
        A :class:`ComponentStatus` with ``name='influxdb'``.
    """
    t0 = time.perf_counter()
    try:
        ok = await asyncio.wait_for(repo.health_check(), timeout=timeout_s)
    except asyncio.TimeoutError:
        ms = round((time.perf_counter() - t0) * 1000)
        logger.warning("readyz: influxdb probe timed out after {} ms", ms)
        return ComponentStatus(name="influxdb", ready=False, detail=f"timeout after {ms} ms")
    except Exception as exc:
        ms = round((time.perf_counter() - t0) * 1000)
        logger.warning("readyz: influxdb probe failed: {} ({} ms)", exc, ms)
        return ComponentStatus(name="influxdb", ready=False, detail=f"{exc} ({ms} ms)")

    ms = round((time.perf_counter() - t0) * 1000)
    if ok:
        return ComponentStatus(name="influxdb", ready=True, detail=f"ok in {ms} ms")
    return ComponentStatus(name="influxdb", ready=False, detail=f"health_check returned False ({ms} ms)")


@router.get("/readyz")
async def readiness(
    request: Request,
    response: Response,
    postgres_repo: PostgresRepository = Depends(get_postgres_repo),
    influx_repo: InfluxRepository = Depends(get_influx_repo),
) -> dict[str, Any]:
    """Readiness probe — confirms the service can handle requests.

    Probes PostgreSQL and InfluxDB connectivity in parallel with a
    short per-component timeout. Returns HTTP 200 with the per-component
    detail when both dependencies are reachable, HTTP 503 with the
    same envelope when at least one is not.

    Args:
        response: Mutable response object; status code is overridden
            to 503 on failure.
        postgres_repo: Injected PostgreSQL repository.
        influx_repo: Injected InfluxDB repository.

    Returns:
        A :class:`ReadinessResponse` with per-component diagnostics.
    """
    if request.query_params.get("detail") != "true":
        return {"status": "ok"}
    if not _has_valid_credential(request):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    pg, influx = await asyncio.gather(
        _probe_postgres(postgres_repo, READYZ_PROBE_TIMEOUT_S),
        _probe_influx(influx_repo, READYZ_PROBE_TIMEOUT_S),
    )
    components = [pg, influx]
    all_ready = all(c.ready for c in components)
    if not all_ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return ReadinessResponse(status="ready" if all_ready else "not_ready", components=components).model_dump()


@router.get("/api/v1/status/health")
async def health_check(
    request: Request,
    health_service: HealthService = Depends(get_health_service),
    cache_manager: CacheManager = Depends(get_cache_manager),
    incident_service: HealthIncidentService = Depends(get_health_incident_service),
) -> dict[str, Any]:
    """Run health checks against all dependent services.

    The response is augmented with the current cache statistics
    (hits, misses, hit-ratio, size, maxsize, ttl) for every cache
    namespace managed by :class:`CacheManager`. Operators can use this
    to verify that the B-09 read-path caches are receiving traffic
    and producing the expected hit ratio.

    Returns:
        A HealthResponse with individual service statuses, an overall
        system health indicator, and per-cache statistics.
    """
    if request.query_params.get("detail") != "true":
        return {"status": "ok"}
    if not _has_valid_credential(request):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    result = await health_service.check_all()
    result["caches"] = cache_manager.stats_snapshot()
    summaries = await incident_service.summaries_async()
    result.update(summaries)
    incident_service.latch_overall_status(result, summaries)
    return result
