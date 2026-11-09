"""Vulnerability / CVE-lookup router (SCAN-033 extraction).

Owns the CVE-lookup job surface (start / list / detail / SSE / stop) and
the vulnerability triage patch.

Logging note (SCAN-034): stdlib ``logging`` call sites moved verbatim.
"""

from __future__ import annotations

import json
import os
from typing import Any, AsyncIterator, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from loguru import logger
from sse_starlette.sse import EventSourceResponse

from ...core.auth import verify_api_key
from ...cve_lookup import NvdSource
from ...repositories.models import CveLookupStatus, ScanStatus
from ...repositories.postgres_repo import ScannerPostgresRepo
from ...repositories.vulnerability_observation_repo import VulnerabilityObservationRepo
from ..dependencies import get_api_state, get_optional_repo, require_repo
from ..schemas.vulnerabilities import (
    CveLookupItem,
    CveLookupsListResponse,
    StopLookupResponse,
    VulnerabilityItem,
    VulnerabilityLookupRequest,
    VulnerabilityLookupResponse,
    VulnerabilityPatchRequest,
)
from ..serializers import cve_lookup_row_to_item, vuln_row_to_item
from ..state import ApiState

__all__ = ["router"]

router = APIRouter()


@router.post(
    "/vulnerabilities/lookup",
    response_model=VulnerabilityLookupResponse,
    status_code=202,
    dependencies=[Depends(verify_api_key("operator"))],
)
async def lookup_vulnerabilities(
    req: VulnerabilityLookupRequest,
    repo: Optional[ScannerPostgresRepo] = Depends(get_optional_repo),
    state: ApiState = Depends(get_api_state),
) -> JSONResponse:
    """Trigger a CVE lookup as a tracked async job — 202 Accepted (WA.4).

    The 502-fix core (design.md § D3): this endpoint no longer waits for
    the (potentially minutes-long) NVD sweep. It

    1. resolves the D4-eligible asset set (optionally scoped to
       ``device_ids``);
    2. creates a synthetic ``scans`` row (FK target for the hits) and a
       ``cve_lookups`` job-header (``running``) — the ``cve_lookups.id``
       is the ``job_id`` correlation key;
    3. registers a tracked asyncio task (Fork 2b,
       :class:`LookupJobRegistry`) that runs the unchanged ``run_lookup``,
       upserts the hits and finalizes the job;
    4. returns ``202 Accepted`` with ``{job_id, status, eligible_assets}``
       **immediately**.

    Because no synchronous wait happens here, the upstream proxy can never
    again trip its ``timeout=5.0`` ReadTimeout into an HTTP 502 — a long
    lookup just keeps running in the background (CONCEPT §10.1).
    """
    repository = require_repo(repo)

    eligible_assets = await repository.lookup_eligible_assets()
    if req.device_ids:
        id_set = set(req.device_ids)
        eligible_assets = [a for a in eligible_assets if a.device_id in id_set]
    elif not req.all:
        eligible_assets = []

    scope = "device" if req.device_ids else "all"
    device_id = (
        req.device_ids[0] if req.device_ids and len(req.device_ids) == 1 else None
    )
    api_key_used = bool(os.environ.get("NVD_API_KEY"))

    # Synthetic scan row owns the FK for ``vulnerability_observations``.
    scan_id = await repository.start_scan(
        module_name="cve_lookup",
        parameters={"trigger": "api", "device_ids": req.device_ids, "all": req.all},
    )
    # Job-header — its id is the job_id surfaced to the caller (D1).
    job_id = await repository.start_lookup(
        scope=scope,
        source="nvd",
        api_key_used=api_key_used,
        device_id=device_id,
    )

    async def _persist(_job_id: str, result: Any) -> int:
        vuln_repo = VulnerabilityObservationRepo(repository)
        return await vuln_repo.persist_lookup_result(scan_id=scan_id, result=result)

    async def _finalize_scan(status_value: str, error_text: Optional[str]) -> None:
        # The synthetic scan mirrors the job's terminal state for parity
        # with the existing scan-job lifecycle. Invoked by the job body on
        # EVERY terminal branch (completed / failed / aborted) so an
        # operator-cancelled lookup no longer strands the scan row
        # ``RUNNING``/``finished_at NULL`` (E2E-B1).
        await repository.finish_scan(
            scan_id, ScanStatus(status_value), error_message=error_text
        )

    state.lookup_registry.start(
        job_id=job_id,
        assets=eligible_assets,
        source=NvdSource(api_key=os.environ.get("NVD_API_KEY")),
        repo=repository,
        persist=_persist,
        finalize_scan=_finalize_scan,
        api_key_used=api_key_used,
    )

    logger.info(
        "cve_lookup: api trigger accepted job_id={} scan_id={} scope={} eligible={}",
        job_id,
        scan_id,
        scope,
        len(eligible_assets),
    )

    body = VulnerabilityLookupResponse(
        job_id=str(job_id),
        status=CveLookupStatus.RUNNING.value,
        eligible_assets=len(eligible_assets),
    )
    return JSONResponse(status_code=202, content=body.model_dump(mode="json"))


@router.get(
    "/vulnerabilities/lookups",
    response_model=CveLookupsListResponse,
    dependencies=[Depends(verify_api_key("viewer"))],
)
async def list_cve_lookups(
    limit: int = 100,
    offset: int = 0,
    repo: Optional[ScannerPostgresRepo] = Depends(get_optional_repo),
) -> CveLookupsListResponse:
    """List recent CVE-lookup job-headers, newest first (WB.1).

    Mirrors ``GET /scans``: the Recent-Lookups panel reads this to show
    every triggered lookup with its status / parameters / summary. The
    repository already orders ``started_at DESC, id DESC`` so the newest
    job wins on a start-time tie.

    Query parameters:
        limit: Page size (default 100, clamped to 1..1000).
        offset: Pagination offset (default 0).
    """
    rows = await require_repo(repo).list_lookups(
        limit=min(max(1, limit), 1000), offset=max(0, offset)
    )
    return CveLookupsListResponse(lookups=[cve_lookup_row_to_item(r) for r in rows])


@router.get(
    "/vulnerabilities/lookups/{job_id}",
    response_model=CveLookupItem,
    dependencies=[Depends(verify_api_key("viewer"))],
)
async def get_cve_lookup(
    job_id: str,
    repo: Optional[ScannerPostgresRepo] = Depends(get_optional_repo),
) -> CveLookupItem:
    """Return one CVE-lookup job-header by id incl. summary/error (WB.1).

    Returns the flat :class:`CveLookupItem` for the detail pane. Raises a
    fachliche 404 when no row matches the id, and a 400 when ``job_id``
    is not a parseable UUID (distinct from a route-miss).
    """
    try:
        row = await require_repo(repo).get_lookup(job_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"invalid job_id: {exc}") from exc
    if row is None:
        raise HTTPException(status_code=404, detail=f"cve lookup {job_id!r} not found")
    return cve_lookup_row_to_item(row)


@router.get(
    "/vulnerabilities/lookups/{job_id}/events",
    dependencies=[Depends(verify_api_key("viewer"))],
)
async def cve_lookup_events(
    job_id: str,
    repo: Optional[ScannerPostgresRepo] = Depends(get_optional_repo),
    state: ApiState = Depends(get_api_state),
) -> EventSourceResponse:
    """Stream live CVE-lookup ``progress`` + terminal events via SSE (WB.2).

    Mirrors :func:`scan_events`: subscribes to the per-job progress bus on
    the :class:`~otalon_scan.cve_lookup.job.LookupJobRegistry` and emits one
    ``text/event-stream`` chunk per yielded event. Event kinds:

    - ``progress`` — one per looked-up asset (V2 per-asset live progress);
    - ``done`` / ``failed`` — the single **terminal** event carrying
      ``{job_id, status, cves_found, critical}`` (or ``error`` on
      failure) emitted before the stream closes.

    A job that already finished before the client connects still receives
    the terminal event by replay (design.md § D5) so the global
    notification layer (UI-051) never misses a completion. Raises a
    fachliche 404 when the id matches no job-header.
    """
    try:
        row = await require_repo(repo).get_lookup(job_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"invalid job_id: {exc}") from exc
    if row is None:
        raise HTTPException(status_code=404, detail=f"cve lookup {job_id!r} not found")

    async def _event_stream() -> AsyncIterator[Dict[str, Any]]:
        async for evt in state.lookup_registry.stream_events(job_id):
            yield {
                "event": str(evt.get("event") or "message"),
                "data": json.dumps(evt.get("data") or {}),
            }

    return EventSourceResponse(_event_stream())


@router.post(
    "/vulnerabilities/lookups/{job_id}/stop",
    response_model=StopLookupResponse,
    dependencies=[Depends(verify_api_key("operator"))],
)
async def stop_cve_lookup(
    job_id: str,
    repo: Optional[ScannerPostgresRepo] = Depends(get_optional_repo),
    state: ApiState = Depends(get_api_state),
) -> StopLookupResponse:
    """Request cooperative cancellation of an in-flight CVE lookup (R-02).

    Mirrors :func:`stop_scan`: flags the running lookup task for
    cancellation via the :class:`~otalon_scan.cve_lookup.job.LookupJobRegistry`.
    The lookup core polls the flag between assets, so an in-flight sweep
    stops issuing further NVD queries at the next iteration boundary and
    the job finalizes itself as ``aborted`` with a terminal ``aborted``
    SSE event. The terminal status is written by the job body (not here)
    so this endpoint never races the finalization path.

    Returns ``stopped=True`` when a live task was flagged. A
    fachliche 404 is raised when the id matches no job-header, and a 400
    when ``job_id`` is not a parseable UUID (distinct from a route-miss).
    """
    try:
        row = await require_repo(repo).get_lookup(job_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"invalid job_id: {exc}") from exc
    if row is None:
        raise HTTPException(status_code=404, detail=f"cve lookup {job_id!r} not found")

    stopped = state.lookup_registry.request_cancel(job_id)
    if stopped:
        # Await the abort path's shielded finalization (cve_lookups +
        # synthetic scans row → aborted) so the terminal state is durably
        # persisted and the DB connection is released before we return —
        # the previous fire-and-forget cancel left the scan row stuck
        # RUNNING and could strand a connection (E2E-B1 event-loop block).
        finalized = await state.lookup_registry.await_cancelled(job_id)
        logger.info(
            "cve_lookup: stop awaited job_id={} finalized={}", job_id, finalized
        )
    logger.info("cve_lookup: stop requested job_id={} stopped={}", job_id, stopped)
    return StopLookupResponse(job_id=str(job_id), stopped=bool(stopped))


@router.patch(
    "/vulnerabilities/{vuln_id}",
    response_model=VulnerabilityItem,
    dependencies=[Depends(verify_api_key("operator"))],
)
async def patch_vulnerability(
    vuln_id: str,
    body: VulnerabilityPatchRequest,
    repo: Optional[ScannerPostgresRepo] = Depends(get_optional_repo),
) -> VulnerabilityItem:
    """Update mutable triage fields of a vulnerability observation (B-E1).

    Accepts the ``status`` / ``severity`` / ``summary`` / ``status_changed_by``
    subset (all optional). Returns the updated row on success. Raises a
    fachliche 404 when no ``vulnerability_observations`` row matches
    ``vuln_id`` (distinct from a FastAPI route-miss). ``vuln_id`` is the
    integer PK; a non-integer id resolves to a fachliche 404 (the row
    cannot exist) rather than a route-miss/422.
    """
    repository = require_repo(repo)
    try:
        vuln_pk = int(vuln_id)
    except (TypeError, ValueError):
        raise HTTPException(
            status_code=404, detail=f"vulnerability {vuln_id!r} not found"
        ) from None
    updated = await repository.update_vulnerability(
        vuln_pk,
        status=body.status,
        severity=body.severity,
        summary=body.summary,
        status_changed_by=body.status_changed_by,
    )
    if updated is None:
        raise HTTPException(
            status_code=404, detail=f"vulnerability {vuln_id} not found"
        )
    logger.bind(vuln_id=vuln_id).info("vulnerability patched")
    return vuln_row_to_item(updated)
