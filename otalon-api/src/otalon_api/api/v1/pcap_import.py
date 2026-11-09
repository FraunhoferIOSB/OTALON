"""PCAP import router (UI-078, Wave B).

Two surfaces with different audiences:

* ``/api/v1/operations/pcap-import`` — operator-facing upload and status.
  It sits under the ``/api/v1/operations`` prefix and is therefore already
  covered by :class:`~otalon_api.middleware.auth.ApiKeyAuthMiddleware`; the
  per-route dependencies (operator for the write, viewer for the read) are
  applied in addition so the endpoints stay authenticated when the router
  is exercised without the middleware.
* ``/internal/jobs/{display_id}`` — the worker's report channel. It is
  **not** under a middleware-protected prefix, so it authenticates itself
  against ``PCAP_IMPORT_WORKER_TOKEN``. It can drive a job to a terminal
  state, so it fails closed: without a configured token nothing is
  accepted, and a bad token leaves the job record untouched.
"""

from __future__ import annotations

import asyncio
import hmac
import json
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from loguru import logger

from otalon_api.api.schemas.pcap_import import (
    PcapImportAccepted,
    PcapImportConflict,
    PcapImportList,
    PcapImportReport,
    PcapImportReportAck,
    PcapImportResult,
    PcapImportStatus,
)
from otalon_api.dependencies import (
    get_pcap_import_service,
    get_pcap_upload_service,
    get_settings,
    require_api_key,
)
from otalon_api.domain.operations import JobState, OperationsJob
from otalon_api.domain.pcap_import import CaptureTimeRange, read_capture_time_range
from otalon_api.middleware.auth import require_operator_api_key
from otalon_api.services.pcap_import_service import PcapImportService
from otalon_api.services.pcap_upload_service import (
    MalformedUpload,
    PcapUploadService,
    StoredUpload,
    UnsupportedCapture,
    UploadTooLarge,
)
from otalon_api.settings import Settings

router = APIRouter(prefix="/api/v1/operations", tags=["operations-pcap-import"])
internal_router = APIRouter(prefix="/internal", tags=["operations-pcap-import-internal"])


async def _store_upload(request: Request, uploads: PcapUploadService) -> StoredUpload:
    """Stream the request body into the import directory.

    Raises:
        HTTPException: ``422`` for a non-capture, ``413`` when the size
            budget is exceeded, ``400`` for an unusable envelope.
    """
    try:
        return await uploads.store(request.headers.get("content-type", ""), request.stream())
    except UnsupportedCapture as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except UploadTooLarge as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    except MalformedUpload as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


async def _guard_overlap(
    service: PcapImportService,
    upload: StoredUpload,
    time_range: CaptureTimeRange | None,
    force: bool,
) -> None:
    """Refuse an import that would overwrite existing measurements.

    Raises:
        HTTPException: ``409`` naming the conflicting range.
    """
    if force or time_range is None:
        return
    conflict = await service.find_overlap(time_range)
    if conflict is None:
        return
    await asyncio.to_thread(upload.path.unlink, True)
    body = PcapImportConflict(
        message=("Measurements already exist for this capture's time range. " "Importing it would overwrite them."),
        conflict_start=conflict.time_start,
        conflict_end=conflict.time_end,
        measurement=conflict.measurement,
    )
    raise HTTPException(status_code=409, detail=body.model_dump(mode="json"))


@router.post(
    "/pcap-import",
    response_model=PcapImportAccepted,
    status_code=201,
    dependencies=[Depends(require_operator_api_key)],
)
async def import_pcap(
    request: Request,
    uploads: PcapUploadService = Depends(get_pcap_upload_service),
    service: PcapImportService = Depends(get_pcap_import_service),
) -> PcapImportAccepted:
    """Accept a capture upload, validate it, and enqueue an import job.

    The file is identified by its leading bytes, bounded in size while it
    streams, stored under a server-generated name, probed for its packet
    time window and checked against existing measurements before a job is
    created. Delivery to the worker is attempted immediately; a busy or
    unreachable worker leaves the job ``queued`` for the dispatch loop.
    """
    upload = await _store_upload(request, uploads)
    time_range = await asyncio.to_thread(read_capture_time_range, upload.path)
    await _guard_overlap(service, upload, time_range, upload.force)
    job = await service.create_job(upload, time_range, force=upload.force)
    delivered = await service.deliver(job)
    return PcapImportAccepted(
        display_id=job.display_id,
        job_id=job.id,
        state="running" if delivered else "queued",
        filename=upload.filename,
        original_filename=upload.original_filename,
        size_bytes=upload.size_bytes,
        sha256=upload.sha256,
        time_start=time_range.time_start if time_range else None,
        time_end=time_range.time_end if time_range else None,
        forced=upload.force,
        delivered=delivered,
    )


def _status_of(job: OperationsJob) -> PcapImportStatus:
    """Project an import job onto its public status envelope."""
    params: dict[str, Any] = job.params or {}
    return PcapImportStatus(
        display_id=job.display_id,
        job_id=job.id,
        state=job.state,
        phase_current=job.phase_current,
        phase_total=job.phase_total,
        phase_label=job.phase_label,
        latest_event=job.latest_event,
        original_filename=params.get("original_filename"),
        size_bytes=params.get("size_bytes"),
        time_start=params.get("time_start"),
        time_end=params.get("time_end"),
        forced=bool(params.get("force")),
        started_at=job.started_at,
        ended_at=job.ended_at,
        error=job.error,
        result=_result_of(job),
    )


def _result_of(job: OperationsJob) -> PcapImportResult | None:
    """Parse the worker's completion payload out of ``job.result``."""
    if job.state != "completed" or not job.result:
        return None
    try:
        payload = json.loads(job.result)
    except (TypeError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    try:
        return PcapImportResult.model_validate(payload)
    except ValueError:
        return None


@router.get(
    "/pcap-import",
    response_model=PcapImportList,
    dependencies=[Depends(require_api_key)],
)
async def list_pcap_imports(
    limit: int = Query(default=20, ge=1, le=200),
    state: JobState | None = Query(default=None),
    service: PcapImportService = Depends(get_pcap_import_service),
) -> PcapImportList:
    """Return recent import jobs, newest first.

    Read-only companion to the detail endpoint. The generic job list
    cannot serve this surface: its list item carries no ``params``, so
    neither the ``kind`` filter nor the filename, size and capture window
    an operator needs are reachable there.
    """
    jobs = sorted(await service.list_jobs(state=state), key=_started_at_key, reverse=True)
    items = [_status_of(job) for job in jobs[:limit]]
    return PcapImportList(items=items, total=len(items))


def _started_at_key(job: OperationsJob) -> datetime:
    """Return a comparable UTC start time so ordering never raises.

    Rows read straight from PostgreSQL are uniformly aware, but a naive
    value would make the sort explode on the first mixed comparison
    instead of merely ordering oddly.
    """
    started = job.started_at
    return started if started.tzinfo is not None else started.replace(tzinfo=timezone.utc)


@router.get(
    "/pcap-import/{display_id}",
    response_model=PcapImportStatus,
    dependencies=[Depends(require_api_key)],
)
async def get_pcap_import(
    display_id: str,
    service: PcapImportService = Depends(get_pcap_import_service),
) -> PcapImportStatus:
    """Return state, progress and — once finished — window and point count."""
    job = await service.get_job(display_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Import job not found")
    return _status_of(job)


@router.post(
    "/pcap-import/{display_id}/cancel",
    response_model=PcapImportStatus,
    dependencies=[Depends(require_operator_api_key)],
)
async def cancel_pcap_import(
    display_id: str,
    service: PcapImportService = Depends(get_pcap_import_service),
) -> PcapImportStatus:
    """Cancel a queued or running import, stopping the worker if needed."""
    job = await service.cancel_job(display_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Import job not found")
    return _status_of(job)


def _authorize_worker(request: Request, settings: Settings) -> None:
    """Authenticate the report channel against the worker token.

    Fails closed: an unset token means the channel accepts nothing, since
    a report can drive a job to a terminal state.

    Raises:
        HTTPException: ``503`` when no token is configured, ``401`` when
            the presented credential does not match.
    """
    expected = settings.pcap_import_worker_token.strip()
    if not expected:
        logger.error("pcap-import report channel called but PCAP_IMPORT_WORKER_TOKEN is unset — refusing")
        raise HTTPException(status_code=503, detail="Import report channel is not configured")
    header = request.headers.get("authorization", "")
    scheme, _, presented = header.partition(" ")
    if scheme.lower() != "bearer" or not _constant_time_equals(presented.strip(), expected):
        raise HTTPException(status_code=401, detail="Invalid or missing worker token")


def _constant_time_equals(left: str, right: str) -> bool:
    """Compare two secrets without leaking their relation through timing."""
    return hmac.compare_digest(left, right)


@internal_router.patch("/jobs/{display_id}", response_model=PcapImportReportAck)
async def report_pcap_import(
    display_id: str,
    report: PcapImportReport,
    request: Request,
    settings: Settings = Depends(get_settings),
    service: PcapImportService = Depends(get_pcap_import_service),
) -> PcapImportReportAck:
    """Apply a worker progress/outcome report to the owning job record.

    Fields the worker omits mean "no change"; they never null a column.
    """
    _authorize_worker(request, settings)
    job = await service.apply_report(display_id, report)
    if job is None:
        raise HTTPException(status_code=404, detail="Import job not found")
    return PcapImportReportAck(display_id=job.display_id, state=job.state, applied=True)
