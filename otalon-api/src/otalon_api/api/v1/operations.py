"""Operations router.

Provides pipeline freshness, attention aggregation, durable job/audit
endpoints and Server-Sent Events for the Jobs & History page. All routes
under ``/api/v1/operations`` are protected by the API-key middleware.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import Any, AsyncIterator
from urllib.parse import unquote

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from otalon_common.auth import UserRole
from starlette.responses import StreamingResponse

from otalon_api.api.schemas.operations import (
    ArtifactManifestResponse,
    AttentionFinding,
    AttentionFindingLink,
    AttentionResponse,
    AuditListItem,
    AuditListResponse,
    BackupRequest,
    BoundReviewResponse,
    BoundsCorrectionApplyRequest,
    BoundsCorrectionPreviewRequest,
    BoundsCorrectionRequest,
    BoundSuggestionRequest,
    BoundSuggestionResponse,
    CaptureStatus,
    DetectionReadinessResponse,
    HealthIncidentListResponse,
    HealthIncidentSummary,
    InfluxResetPreviewRequest,
    JobActionResponse,
    JobDetail,
    JobListItem,
    JobsListResponse,
    PassiveDiscoveryStatus,
    PipelineDetection,
    PipelineInflux,
    PipelineResponse,
    PipelineSource,
    ResetPreviewRequest,
    ResetRequest,
    RestoreRequest,
    ServiceActionRequest,
    StorageResponse,
    SupportBundleRequest,
)
from otalon_api.dependencies import (
    get_capture_status_service,
    get_compose_runner,
    get_detection_readiness_service,
    get_docker_service,
    get_health_incident_service,
    get_influx_repo,
    get_operations_backup_service,
    get_operations_jobs_service,
    get_operations_maintenance_service,
    get_operations_pipeline_service,
    get_operations_reset_service,
    get_passive_discovery_service,
    get_postgres_repo,
)
from otalon_api.domain.operations import AuditCategory, OperationsAuditAppend
from otalon_api.middleware.auth import require_operator_api_key
from otalon_api.middleware.session_auth import require_minimum_role
from otalon_api.repositories.identity_repo import UserEntry
from otalon_api.repositories.influx_repo import InfluxRepository
from otalon_api.repositories.postgres_repo import BoundsCorrectionConflict, PostgresRepository
from otalon_api.services.capture_status_service import CaptureStatusService
from otalon_api.services.compose_runner import (
    ALLOWED_ACTIONS,
    ALLOWED_SERVICES as COMPOSE_SERVICES,
    ComposeRunner,
)
from otalon_api.services.detection_readiness_service import DetectionReadinessService
from otalon_api.services.docker_service import ALLOWED_SERVICES, DockerService
from otalon_api.services.health_incident_service import HealthIncidentService
from otalon_api.services.operations_backup_service import (
    InfluxBackupNotAvailable,
    OperationsBackupService,
    RestoreNotAvailable,
)
from otalon_api.services.operations_jobs_service import OperationsJobsService
from otalon_api.services.operations_maintenance_service import OperationsMaintenanceService
from otalon_api.services.operations_pipeline_service import OperationsPipelineService
from otalon_api.services.operations_reset_service import OperationsResetService
from otalon_api.services.passive_discovery_service import PassiveDiscoveryService

router = APIRouter(prefix="/api/v1/operations", tags=["operations"])

# QUA-12 — bounds for free-text filters. ``q`` reaches a double-wildcard
# ``ILIKE`` over two columns (``operations_audit_repo.query``) and the
# in-memory bound-review needle, so an unbounded pattern is a per-request
# CPU amplifier. The caps are far above every real value on the live
# database (longest audit target: 130 chars, longest series id: 113).
MAX_SEARCH_LENGTH = 200
MAX_FILTER_LENGTH = 120


async def _append_restore_audit(
    jobs_service: OperationsJobsService,
    actor: str,
    body: RestoreRequest,
    *,
    executed: bool,
    status: str,
) -> None:
    """Record safe evidence for an authorized restore request."""
    await jobs_service.append_audit(
        OperationsAuditAppend(
            category="job",
            actor=actor,
            action="restore",
            target=body.artifact_id or ":latest",
            reason="Operations restore request",
            detail=json.dumps({"dry_run": body.dry_run, "executed": executed, "status": status}),
        )
    )


@router.get("/health-incidents", response_model=HealthIncidentListResponse)
async def health_incidents(
    status_filter: str | None = Query(default=None, alias="status"),
    service_filter: str | None = Query(default=None, alias="service", max_length=120),
    limit: int = Query(default=50, ge=1, le=50),
    service: HealthIncidentService = Depends(get_health_incident_service),
    _operator: Any = Depends(require_operator_api_key),
) -> dict[str, Any]:
    """Return bounded backend-owned health incident history."""
    if status_filter not in (None, "active", "recovered"):
        raise HTTPException(status_code=422, detail="status must be active or recovered")
    items = await service.list_async(status_filter, service_filter, limit)
    return {"items": items, "retention": {"max_incidents": 50, "max_days": 7}}


@router.get("/health-incidents/{incident_id}", response_model=HealthIncidentSummary)
async def health_incident_detail(
    incident_id: str,
    service: HealthIncidentService = Depends(get_health_incident_service),
    _operator: Any = Depends(require_operator_api_key),
) -> dict[str, Any]:
    """Return structured evidence for one stable health incident ID."""
    from uuid import UUID

    try:
        detail = await service.detail_async(UUID(incident_id))
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Health incident not found") from exc
    if detail is None:
        raise HTTPException(status_code=404, detail="Health incident not found")
    return detail


@router.post("/health-incidents/{incident_id}/acknowledge", response_model=HealthIncidentSummary)
async def acknowledge_health_incident(
    incident_id: str,
    service: HealthIncidentService = Depends(get_health_incident_service),
    operator: Any = Depends(require_operator_api_key),
) -> dict[str, Any]:
    """Acknowledge one incident while retaining active health latching."""
    from uuid import UUID

    try:
        actor = getattr(operator, "name", "operator")
        detail = await service.acknowledge_async(UUID(incident_id), actor=actor)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Health incident not found") from exc
    if detail is None:
        raise HTTPException(status_code=404, detail="Health incident not found")
    return detail


@router.get("/storage", response_model=StorageResponse)
async def storage(
    service: OperationsMaintenanceService = Depends(get_operations_maintenance_service),
) -> StorageResponse:
    """Return reconciled local storage accounting."""
    # ``storage()`` stats mounts and walks the Influx/PG/PCAP trees.
    return StorageResponse.model_validate(await asyncio.to_thread(service.storage))


@router.get("/version")
async def version(
    service: OperationsMaintenanceService = Depends(get_operations_maintenance_service),
) -> dict[str, Any]:
    """Return locally-known component versions without call-home."""
    return await asyncio.to_thread(service.version)


@router.post("/update/check")
async def update_check(
    service: OperationsMaintenanceService = Depends(get_operations_maintenance_service),
    backup_service: OperationsBackupService = Depends(get_operations_backup_service),
    _operator: Any = Depends(require_operator_api_key),
) -> dict[str, Any]:
    """Return manual update gates without contacting a registry."""
    storage = await asyncio.to_thread(service.storage)
    backup = await asyncio.to_thread(backup_service.latest)
    return {
        "manual_only": True,
        "checked": True,
        "registry_contacted": False,
        "gate": {
            "compatibility": {
                "status": "unknown",
                "detail": "No registry or release compatibility evidence available",
            },
            "migrations": {
                "status": "unknown",
                "detail": "Migration status is not exposed locally",
            },
            "storage": {
                "status": "pass" if storage["host"].get("free_gb", 0) > 1 else "warn",
                "detail": "Local disk free space",
            },
            "backup_age": {
                "status": ("pass" if backup and backup.get("verified") and not backup.get("stale") else "warn"),
                "detail": "Latest local backup verification",
            },
            "rollback": {
                "status": "unknown",
                "detail": "Rollback package readiness is unavailable",
            },
        },
    }


@router.post("/health-check")
async def health_check(
    service: OperationsMaintenanceService = Depends(get_operations_maintenance_service),
    postgres: PostgresRepository = Depends(get_postgres_repo),
    influx: InfluxRepository = Depends(get_influx_repo),
    _operator: Any = Depends(require_operator_api_key),
) -> dict[str, Any]:
    """Run read-only dependency checks."""
    return await service.health_check(postgres, influx)


@router.get("/support-bundle/preview")
async def support_bundle_preview(
    service: OperationsMaintenanceService = Depends(get_operations_maintenance_service),
) -> dict[str, Any]:
    """Return support-bundle privacy boundaries."""
    return await asyncio.to_thread(service.support_preview)


@router.post("/support-bundle")
async def support_bundle(
    body: SupportBundleRequest,
    service: OperationsMaintenanceService = Depends(get_operations_maintenance_service),
    _operator: Any = Depends(require_operator_api_key),
) -> dict[str, Any]:
    """Create a local, redacted support bundle."""
    return await asyncio.to_thread(service.create_support_bundle, Path(body.output_dir))


@router.get("/backups")
async def backups(
    service: OperationsBackupService = Depends(get_operations_backup_service),
) -> dict[str, Any]:
    """Return selectable persisted backup verification metadata."""
    # ``catalog()`` re-verifies every archive with SHA-256.
    manifest, items, scopes = await asyncio.gather(
        asyncio.to_thread(service.latest),
        asyncio.to_thread(service.catalog),
        asyncio.to_thread(service.scope_catalog),
    )
    return {
        "items": items,
        "scopes": scopes,
        "last_backup": manifest,
        "verified": bool(manifest and manifest.get("verified")),
        "stale": bool(manifest and manifest.get("stale")),
    }


@router.post("/backup")
async def backup(
    body: BackupRequest,
    service: OperationsBackupService = Depends(get_operations_backup_service),
    jobs_service: OperationsJobsService = Depends(get_operations_jobs_service),
    _operator: Any = Depends(require_operator_api_key),
) -> dict[str, Any]:
    """Create a backup job and persist its manifest."""
    job = await jobs_service.record_job(
        "backup",
        "Create backup",
        "operator",
        {"scope": body.scope},
        "operator",
        can_cancel=False,
    )
    started = await jobs_service.start_job(job.id)
    if started is not None:
        job = started
    try:
        manifest = await asyncio.to_thread(service.create_manifest, body.scope)
        finished = await jobs_service.complete_job(job.id, result=manifest["archive"])
        if finished is not None:
            job = finished
        await jobs_service.append_audit(
            OperationsAuditAppend(
                category="job",
                actor="operator",
                action="backup",
                target=job.display_id,
                reason="Backup completed",
            )
        )
    except (InfluxBackupNotAvailable, OSError, ValueError, RuntimeError) as exc:
        await jobs_service.fail_job(job.id, error=str(exc))
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"job": _job_to_detail(job), "manifest": manifest}


@router.post("/restore")
async def restore(
    body: RestoreRequest,
    service: OperationsBackupService = Depends(get_operations_backup_service),
    jobs_service: OperationsJobsService = Depends(get_operations_jobs_service),
    admin: UserEntry = Depends(require_minimum_role("admin")),
    _operator: Any = Depends(require_operator_api_key),
) -> dict[str, Any]:
    """Run a restore precheck; execute only behind fail-closed non-dry-run gates.

    The live unattended run always sends ``dry_run=True`` (the default), so this
    returns the compatibility precheck without touching data. A non-dry-run
    request must pass typed-confirmation, verified/non-stale backup and executor
    gates; production wires no executor, so a real restore fails closed with 503.
    """
    job = await jobs_service.record_job(
        "maintenance",
        "Restore backup",
        "operator",
        {"scope": body.scope, "artifact_id": body.artifact_id, "dry_run": body.dry_run},
        admin.username,
        can_cancel=False,
    )
    started = await jobs_service.start_job(job.id)
    if started is not None:
        job = started
    try:
        selected = await asyncio.to_thread(service.select, body.artifact_id)
        if body.artifact_id and selected is None:
            raise HTTPException(status_code=404, detail="Backup artifact not found")
        effective_dry_run = body.dry_run if admin.role is UserRole.ADMIN else True
        result = await asyncio.to_thread(
            service.restore,
            body.scope,
            body.confirmation,
            effective_dry_run,
            body.artifact_id,
        )
    except ValueError as exc:
        await jobs_service.fail_job(job.id, error=str(exc))
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RestoreNotAvailable as exc:
        await jobs_service.fail_job(job.id, error=str(exc))
        await _append_restore_audit(jobs_service, admin.username, body, executed=False, status="unavailable")
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    finished = await jobs_service.complete_job(job.id, result=json.dumps(result, default=str))
    if finished is not None:
        job = finished
    await _append_restore_audit(
        jobs_service,
        admin.username,
        body,
        executed=bool(result.get("executed")),
        status="accepted",
    )
    return {"job": _job_to_detail(job), **result}


@router.post("/reset")
async def reset(
    body: ResetRequest,
    reset_service: OperationsResetService = Depends(get_operations_reset_service),
    backup_service: OperationsBackupService = Depends(get_operations_backup_service),
    jobs_service: OperationsJobsService = Depends(get_operations_jobs_service),
    admin: UserEntry = Depends(require_minimum_role("admin")),
    _operator: Any = Depends(require_operator_api_key),
) -> dict[str, Any]:
    """Gate a domain reset; execute only the mapped narrow operation when armed.

    Fail-closed order: typed-confirmation phrase, then (factory only) a fresh
    verified-backup precondition, then — only for an explicit ``dry_run=false``
    request — the mapped narrow PostgreSQL delete. The live unattended run sends
    ``dry_run=True`` (default), so it exercises validation/audit without deleting
    any data. The audit row is written for every accepted (armed or dry-run)
    request; a rejected phrase never audits.
    """
    job = await jobs_service.record_job(
        "maintenance",
        "Reset data",
        "operator",
        {"scope": body.scope, "dry_run": body.dry_run},
        admin.username,
        can_cancel=False,
    )
    started = await jobs_service.start_job(job.id)
    if started is not None:
        job = started
    phrase = reset_service.required_phrase(body.scope)
    if body.confirmation != phrase:
        await jobs_service.fail_job(job.id, error=f"Typed confirmation must be '{phrase}'")
        raise HTTPException(status_code=422, detail=f"Typed confirmation must be '{phrase}'")
    if body.scope == "factory":
        latest = await asyncio.to_thread(backup_service.latest)
        full_scope = {"config", "postgresql", "models", "baselines", "pcap_archive"}
        if (
            not latest
            or not latest.get("verified")
            or latest.get("stale")
            or not full_scope <= set(latest.get("scope", []))
        ):
            await jobs_service.fail_job(job.id, error="Factory reset requires a recent verified FULL backup")
            raise HTTPException(
                status_code=409,
                detail="Factory reset requires a recent verified FULL backup",
            )
    try:
        effective_dry_run = body.dry_run if admin.role is UserRole.ADMIN else True
        result = await asyncio.to_thread(reset_service.execute, body.scope, body.confirmation, effective_dry_run)
    except ValueError as exc:
        await jobs_service.fail_job(job.id, error=str(exc))
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    finished = await jobs_service.complete_job(
        job.id,
        result=json.dumps(
            {
                "scope": body.scope,
                "tables": result["tables"],
                "dry_run": effective_dry_run,
            },
            default=str,
        ),
    )
    if finished is not None:
        job = finished
    await jobs_service.append_audit(
        OperationsAuditAppend(
            category="reset",
            actor=admin.username,
            action="reset",
            target=body.scope,
            reason=body.reason,
            detail=json.dumps({"dry_run": effective_dry_run, "tables": result["tables"]}),
        )
    )
    return {"job": _job_to_detail(job), **result}


@router.post("/reset/postgresql/preview")
async def postgresql_reset_preview(
    body: ResetPreviewRequest,
    reset_service: OperationsResetService = Depends(get_operations_reset_service),
    backup_service: OperationsBackupService = Depends(get_operations_backup_service),
) -> dict[str, Any]:
    """Return PostgreSQL reset impact without executing a mutation."""
    backup = await asyncio.to_thread(backup_service.latest)
    if body.scope == "factory":
        full_scope = {"config", "postgresql", "models", "baselines", "pcap_archive"}
        if (
            not backup
            or not backup.get("verified")
            or backup.get("stale")
            or not full_scope <= set(backup.get("scope", []))
        ):
            raise HTTPException(
                status_code=409,
                detail="Factory reset requires a recent verified FULL backup",
            )
    return reset_service.preview(body.scope, backup)


@router.post("/reset/influx/preview")
async def influx_reset_preview(body: InfluxResetPreviewRequest) -> dict[str, Any]:
    """Return InfluxDB reset contract without exposing an execution path."""
    return {
        "target": "influxdb",
        "scope": body.scope,
        "measurements": ["network_metrics", "mac_traffic", "proto_traffic"],
        "destructive": True,
        "execution_supported": False,
        "requires_fresh_full_backup": body.scope == "factory",
        "executed": False,
    }


@router.get("/services")
async def services(
    docker: DockerService = Depends(get_docker_service),
) -> dict[str, Any]:
    """List service lifecycle state."""
    return {"services": await asyncio.to_thread(docker.list_containers)}


@router.get("/services/{name}/logs")
async def service_logs(name: str, docker: DockerService = Depends(get_docker_service)) -> dict[str, Any]:
    """Return bounded logs for an allowlisted service."""
    if name not in ALLOWED_SERVICES:
        raise HTTPException(status_code=404, detail="Service not available")
    return {
        "name": name,
        "logs": await asyncio.to_thread(docker.get_container_logs, name, 100),
    }


@router.post("/services/action")
async def service_action(
    body: ServiceActionRequest,
    compose: ComposeRunner = Depends(get_compose_runner),
    jobs_service: OperationsJobsService = Depends(get_operations_jobs_service),
    admin: UserEntry = Depends(require_minimum_role("admin")),
    _operator: Any = Depends(require_operator_api_key),
) -> dict[str, Any]:
    """Wrap non-core service lifecycle in a non-cancellable audited job."""
    if body.action not in ALLOWED_ACTIONS:
        raise HTTPException(status_code=422, detail="Service action is not allowed")
    core_aliases = {"postgres", "postgresql", "influx", "influxdb", "influxdb3"}
    if body.service in core_aliases:
        raise HTTPException(status_code=409, detail="Core database lifecycle is disabled")
    if body.service not in COMPOSE_SERVICES:
        raise HTTPException(status_code=404, detail="Service not available")
    required_phrase = f"CONFIRM {body.action.upper()} {body.service}"
    if body.confirmation != required_phrase:
        raise HTTPException(status_code=422, detail=f"Typed confirmation must be '{required_phrase}'")
    job = await jobs_service.record_job(
        "service",
        f"{body.action.title()} service {body.service}",
        "operator",
        {"action": body.action, "service": body.service},
        admin.username,
        can_cancel=False,
    )
    await jobs_service.append_audit(
        OperationsAuditAppend(
            category="service",
            actor=admin.username,
            action=body.action,
            target=body.service,
            reason="Operations service lifecycle",
        )
    )
    try:
        result = await asyncio.to_thread(compose.run_action, body.action, body.service)
        finished = await jobs_service.maybe_finish_service_job(job.id, int(result.get("exit_code", 1)))
        if finished is not None:
            job = finished
    except Exception as exc:
        await jobs_service.fail_job(job.id, error=str(exc))
        raise HTTPException(status_code=502, detail="Service action failed") from exc
    return {"job": _job_to_detail(job), "result": result}


@router.get("/detection/readiness", response_model=DetectionReadinessResponse)
async def detection_readiness(
    service: DetectionReadinessService = Depends(get_detection_readiness_service),
    jobs_service: OperationsJobsService = Depends(get_operations_jobs_service),
) -> DetectionReadinessResponse:
    """Return readiness derived from bounds, frequency, anomalies and jobs."""
    jobs = await jobs_service.list_jobs(state="running", type_="training")
    running_modules = {str(module) for job in jobs for module in job.params.get("modules", [])}
    # ``readiness`` issues several synchronous PostgreSQL queries per module.
    modules = await asyncio.to_thread(service.readiness, running_modules)
    return DetectionReadinessResponse.model_validate(
        {
            "modules": modules,
            "live_poll_interval_seconds": service.live_poll_interval_seconds(),
        }
    )


@router.get("/detection/artifacts", response_model=ArtifactManifestResponse)
async def detection_artifacts(
    service: DetectionReadinessService = Depends(get_detection_readiness_service),
) -> ArtifactManifestResponse:
    """Return metadata-only classifier artifacts; model binaries are never loaded."""
    items = await asyncio.to_thread(service.artifacts)
    return ArtifactManifestResponse.model_validate({"items": items})


@router.get("/bounds", response_model=BoundReviewResponse)
async def review_bounds(
    module: str | None = Query(default=None, max_length=MAX_FILTER_LENGTH),
    state: str | None = Query(default=None, max_length=MAX_FILTER_LENGTH),
    from_: datetime | None = Query(default=None, alias="from"),
    to: datetime | None = Query(default=None),
    since: datetime | None = Query(default=None),
    q: str | None = Query(default=None, max_length=MAX_SEARCH_LENGTH),
    service: DetectionReadinessService = Depends(get_detection_readiness_service),
) -> BoundReviewResponse:
    """Return read-only bound-review rows for the strict ``[from, to)`` window.

    ``from``/``to`` are the canonical UTC boundaries. The legacy ``since``
    parameter is retained for backward compatibility and is treated as
    ``from`` when the newer parameter is absent. Events at exactly ``to`` are
    excluded (half-open interval).
    """
    window_start = from_ if from_ is not None else since
    if to is not None and window_start is None:
        raise HTTPException(status_code=400, detail="to requires from or since")
    if window_start is not None and to is not None and window_start >= to:
        raise HTTPException(status_code=400, detail="from must be before to")
    items = await asyncio.to_thread(service.bounds, module, state, window_start, q, until=to)
    return BoundReviewResponse.model_validate({"items": items, "total": len(items)})


@router.post("/bounds/suggestion", response_model=BoundSuggestionResponse)
async def suggest_bounds(
    body: BoundSuggestionRequest,
    service: DetectionReadinessService = Depends(get_detection_readiness_service),
) -> BoundSuggestionResponse:
    """Return a read-only proposal grounded in real values in ``[from, to)``."""
    result = await asyncio.to_thread(
        service.suggest_bounds,
        body.module,
        body.series_id,
        body.action,
        body.from_,
        body.to,
    )
    return BoundSuggestionResponse.model_validate(result)


async def _correct_bounds(
    series: str,
    action: str,
    body: BoundsCorrectionRequest,
    postgres: PostgresRepository,
    jobs_service: OperationsJobsService,
) -> dict[str, Any]:
    """Apply correction, then append exactly one operations audit row.

    Series identifiers contain ``/`` (MAC/protocol UCIs). The request body
    ``series_id`` is authoritative when present (robust across clients); the
    ``{series}`` path segment is a double-encoded fallback we ``unquote`` once.
    """
    resolved = body.series_id if body.series_id else unquote(series)
    result = await asyncio.to_thread(
        postgres.correct_bounds,
        body.module,
        resolved,
        action,
        body.lower_bounds,
        body.upper_bounds,
        body.reason,
        "operator",
    )
    await jobs_service.append_audit(
        OperationsAuditAppend(
            category="bounds",
            actor="operator",
            action=action,
            target=f"{body.module}:{resolved}",
            reason=body.reason,
            detail=json.dumps(result["prior"], default=str),
        )
    )
    return result


@router.post("/bounds/{series}/expand")
async def expand_bounds(
    series: str,
    body: BoundsCorrectionRequest,
    postgres: PostgresRepository = Depends(get_postgres_repo),
    jobs_service: OperationsJobsService = Depends(get_operations_jobs_service),
    _operator: Any = Depends(require_operator_api_key),
) -> dict[str, Any]:
    """Widen existing bounds and audit the prior envelope."""
    try:
        return await _correct_bounds(series, "expand", body, postgres, jobs_service)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/bounds/{series}/correction/preview")
async def preview_bounds_correction(
    series: str,
    body: BoundsCorrectionPreviewRequest,
    postgres: PostgresRepository = Depends(get_postgres_repo),
) -> dict[str, Any]:
    """Preview a correction without mutating bounds, history, audit, or jobs."""
    resolved = body.series_id or unquote(series)
    after = body.after
    try:
        return await asyncio.to_thread(
            postgres.preview_bounds_correction,
            body.module,
            resolved,
            body.action,
            dict(after.get("lower_bounds") or {}),
            dict(after.get("upper_bounds") or {}),
            body.before,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/bounds/{series}/correction/apply")
async def apply_bounds_correction(
    series: str,
    body: BoundsCorrectionApplyRequest,
    postgres: PostgresRepository = Depends(get_postgres_repo),
    jobs_service: OperationsJobsService = Depends(get_operations_jobs_service),
    _operator: Any = Depends(require_operator_api_key),
) -> dict[str, Any]:
    """Validate, compare stale state, and apply one audited correction action."""
    resolved = body.series_id or unquote(series)
    after = body.after
    try:
        await asyncio.to_thread(
            postgres.preview_bounds_correction,
            body.module,
            resolved,
            body.action,
            dict(after.get("lower_bounds") or {}),
            dict(after.get("upper_bounds") or {}),
            body.before,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    job = await jobs_service.record_job(
        "maintenance",
        "Apply bounds correction",
        "operator",
        {"module": body.module, "series_id": resolved, "action": body.action},
        "operator",
        can_cancel=False,
    )
    started = await jobs_service.start_job(job.id)
    if started is not None:
        job = started
    try:
        result = await asyncio.to_thread(
            postgres.correct_bounds,
            body.module,
            resolved,
            body.action,
            dict(after.get("lower_bounds") or {}),
            dict(after.get("upper_bounds") or {}),
            body.reason,
            "operator",
            body.before,
        )
        finished = await jobs_service.complete_job(job.id, result=result["history_id"])
        if finished is not None:
            job = finished
    except BoundsCorrectionConflict as exc:
        await jobs_service.fail_job(job.id, error=str(exc))
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except (ValueError, RuntimeError) as exc:
        await jobs_service.fail_job(job.id, error=str(exc))
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    await jobs_service.append_audit(
        OperationsAuditAppend(
            category="bounds",
            actor="operator",
            action="correction",
            target=f"{body.module}:{resolved}",
            reason=body.reason,
            detail=json.dumps({"job_id": job.id, "prior": result["prior"]}, default=str),
        )
    )
    return {"job": _job_to_detail(job), "correction": result}


@router.post("/bounds/{series}/replace")
async def replace_bounds(
    series: str,
    body: BoundsCorrectionRequest,
    postgres: PostgresRepository = Depends(get_postgres_repo),
    jobs_service: OperationsJobsService = Depends(get_operations_jobs_service),
    _operator: Any = Depends(require_operator_api_key),
) -> dict[str, Any]:
    """Replace full bounds envelope as an advanced audited operation."""
    try:
        return await _correct_bounds(series, "replace", body, postgres, jobs_service)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/bounds/{series}/create")
async def create_bounds(
    series: str,
    body: BoundsCorrectionRequest,
    postgres: PostgresRepository = Depends(get_postgres_repo),
    jobs_service: OperationsJobsService = Depends(get_operations_jobs_service),
    _operator: Any = Depends(require_operator_api_key),
) -> dict[str, Any]:
    """Create bounds for a series without an existing envelope."""
    try:
        return await _correct_bounds(series, "create", body, postgres, jobs_service)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/pipeline", response_model=PipelineResponse)
async def pipeline(
    pipeline_service: OperationsPipelineService = Depends(get_operations_pipeline_service),
) -> PipelineResponse:
    """Return the current pipeline freshness snapshot.

    Args:
        pipeline_service: Service that computes source freshness.

    Returns:
        A :class:`PipelineResponse` with source, Influx, detection and
        backlog information.
    """
    snapshot = await pipeline_service.get_pipeline()
    return PipelineResponse(
        sources=[
            PipelineSource(
                name=s.name,
                last_record=s.last_record,
                age_seconds=s.age_seconds,
                state=s.state,
                records_per_hour=s.records_per_hour,
                expected_interval_seconds=s.expected_interval_seconds,
            )
            for s in snapshot.sources
        ],
        influx=PipelineInflux(
            last_write=snapshot.influx.last_write,
            age_seconds=snapshot.influx.age_seconds,
        ),
        detection=PipelineDetection(
            last_cycle=snapshot.detection.last_cycle,
            age_seconds=snapshot.detection.age_seconds,
            duration_seconds=snapshot.detection.duration_seconds,
            series_evaluated=snapshot.detection.series_evaluated,
        ),
        backlog=snapshot.backlog,
    )


@router.get("/capture-status", response_model=CaptureStatus)
async def capture_status(
    capture_service: CaptureStatusService = Depends(get_capture_status_service),
) -> CaptureStatus:
    """Return read-only capture status.

    This endpoint only reads recorder/network state. It never starts,
    stops or reconfigures capture.

    Args:
        capture_service: Service that gathers capture state.

    Returns:
        A :class:`CaptureStatus` snapshot with whatever fields can be
        sourced truthfully; unknown fields are ``None``.
    """
    status = await capture_service.get_status()
    return CaptureStatus(
        interface=status.interface,
        link_up=status.link_up,
        recording=status.recording,
        drops_24h_pct=status.drops_24h_pct,
        overflows=status.overflows,
    )


@router.get("/passive-discovery", response_model=PassiveDiscoveryStatus)
async def passive_discovery(
    service: PassiveDiscoveryService = Depends(get_passive_discovery_service),
) -> PassiveDiscoveryStatus:
    """Return read-only Passive Discovery producer status.

    Every field is derived from persisted ``network_interfaces`` rows
    tagged ``source='passive'``. This endpoint never enables, disables
    or reconfigures the seeder, and never inspects its process or
    container health. ``runtime_control_enabled`` is always ``False``
    because the runtime control plane is boot/env-managed and remains
    deferred under UI-015.

    Args:
        service: Injected passive-discovery status service.

    Returns:
        A :class:`PassiveDiscoveryStatus` snapshot.
    """
    status = await service.get_status()
    return PassiveDiscoveryStatus(
        observed_asset_count=status.observed_asset_count,
        observed_interface_count=status.observed_interface_count,
        latest_seen_at=status.latest_seen_at,
        first_seen_at=status.first_seen_at,
        age_seconds=status.age_seconds,
        freshness=status.freshness,
        runtime_control_enabled=status.runtime_control_enabled,
    )


@router.get("/attention", response_model=AttentionResponse)
async def attention(
    pipeline_service: OperationsPipelineService = Depends(get_operations_pipeline_service),
) -> AttentionResponse:
    """Return ranked operational attention findings.

    Wave A aggregates only freshness findings from the pipeline. Later
    waves extend the aggregator with detection readiness, storage and
    backup facts without changing the response shape.

    Args:
        pipeline_service: Service that computes available findings.

    Returns:
        A :class:`AttentionResponse` with zero or more findings.
    """
    raw_findings = await pipeline_service.get_attention()
    findings = [
        AttentionFinding(
            priority=f["priority"],
            kind=f["kind"],
            title=f["title"],
            link=AttentionFindingLink(
                label=f["link"]["label"],
                route=f["link"]["route"],
            ),
        )
        for f in raw_findings
    ]
    return AttentionResponse(findings=findings)


# ---------------------------------------------------------------------------
# Jobs
# ---------------------------------------------------------------------------


def _job_to_detail(job: Any) -> JobDetail:
    return JobDetail.model_validate(job.model_dump(mode="json"))


def _job_to_list_item(job: Any) -> JobListItem:
    return JobListItem.model_validate(job.model_dump(mode="json"))


@router.get("/jobs", response_model=JobsListResponse)
async def list_jobs(
    state: str | None = Query(default=None, max_length=MAX_FILTER_LENGTH),
    type: str | None = Query(default=None, max_length=MAX_FILTER_LENGTH),
    actor: str | None = Query(default=None, max_length=MAX_FILTER_LENGTH),
    since: datetime | None = Query(default=None),
    jobs_service: OperationsJobsService = Depends(get_operations_jobs_service),
) -> JobsListResponse:
    """Return operations jobs with optional filters."""
    jobs = await jobs_service.list_jobs(state=state, type_=type, actor=actor, since=since)
    return JobsListResponse(items=[_job_to_list_item(j) for j in jobs], total=len(jobs))


@router.get("/jobs/{job_id}", response_model=JobDetail)
async def get_job(
    job_id: int,
    jobs_service: OperationsJobsService = Depends(get_operations_jobs_service),
) -> JobDetail:
    """Return full detail for a single operations job."""
    job = await jobs_service.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return _job_to_detail(job)


@router.post("/jobs/{job_id}/cancel", response_model=JobActionResponse)
async def cancel_job(
    job_id: int,
    jobs_service: OperationsJobsService = Depends(get_operations_jobs_service),
    _operator: Any = Depends(require_operator_api_key),
) -> JobActionResponse:
    """Cooperatively cancel an operations job.

    Cancelling is a two-phase operation when the underlying work cannot
    stop immediately: the job enters ``cancelling`` and only reaches the
    terminal ``cancelled`` state once the stop actually lands. Whether a
    job stops immediately is derived from its type by the service.
    """
    updated = await jobs_service.cancel_job(job_id, actor="operator")
    if updated is None:
        current = await jobs_service.get_job(job_id)
        if current is None:
            raise HTTPException(status_code=404, detail="Job not found")
        return JobActionResponse(
            success=True,
            job=_job_to_detail(current),
            message="Job not cancellable or already terminal",
        )
    return JobActionResponse(success=True, job=_job_to_detail(updated))


@router.post("/jobs/{job_id}/retry", response_model=JobActionResponse)
async def retry_job(
    job_id: int,
    jobs_service: OperationsJobsService = Depends(get_operations_jobs_service),
    _operator: Any = Depends(require_operator_api_key),
) -> JobActionResponse:
    """Create a new running job from a retryable terminal job."""
    source = await jobs_service.get_job(job_id)
    if source is None:
        raise HTTPException(status_code=404, detail="Job not found")
    if not source.can_retry or source.state not in ("failed", "cancelled"):
        raise HTTPException(status_code=409, detail="Job is not retryable")

    new_job = await jobs_service.retry_job(job_id, actor="operator")
    if new_job is None:
        if source.retried_as_id:
            existing = await jobs_service.get_job(source.retried_as_id)
            if existing:
                return JobActionResponse(
                    success=True,
                    job=_job_to_detail(existing),
                    message="Retry already existed",
                )
        raise HTTPException(status_code=409, detail="Retry not available")
    return JobActionResponse(success=True, job=_job_to_detail(new_job))


@router.get("/jobs/{job_id}/events")
async def job_events(
    job_id: int,
    request: Request,
    jobs_service: OperationsJobsService = Depends(get_operations_jobs_service),
) -> StreamingResponse:
    """Server-Sent Events for a single operations job.

    Polls the durable job row and emits a ``status`` frame on every state
    change, plus an initial snapshot. Errors are delivered as in-stream
    ``event: error`` frames while the HTTP status stays 200 per SSE
    convention (mirrors ``scans.py:329-336``). The loop terminates on a
    terminal state or when the client disconnects.
    """

    async def _stream() -> AsyncIterator[bytes]:
        try:
            job = await jobs_service.get_job(job_id)
            if job is None:
                yield b'event: error\ndata: {"detail": "Job not found"}\n\n'
                return

            last_state = job.state
            # Emit an initial snapshot so the client has something immediately.
            yield f"event: status\ndata: {job.model_dump_json()}\n\n".encode("utf-8")

            while True:
                if await request.is_disconnected():
                    return
                await asyncio.sleep(0.5)
                job = await jobs_service.get_job(job_id)
                if job is None:
                    yield b'event: error\ndata: {"detail": "Job disappeared"}\n\n'
                    return
                if job.state != last_state:
                    last_state = job.state
                    yield f"event: status\ndata: {job.model_dump_json()}\n\n".encode("utf-8")
                if job.state in ("completed", "failed", "cancelled", "rejected"):
                    return
        except asyncio.CancelledError:
            return
        except Exception as exc:
            payload = json.dumps({"reason": "stream_error", "detail": f"{type(exc).__name__}: {exc}"})
            yield f"event: error\ndata: {payload}\n\n".encode("utf-8")

    return StreamingResponse(
        _stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ---------------------------------------------------------------------------
# Change Audit
# ---------------------------------------------------------------------------


def _audit_to_list_item(entry: Any) -> AuditListItem:
    return AuditListItem.model_validate(entry.model_dump(mode="json"))


@router.get("/audit", response_model=AuditListResponse)
async def list_audit(
    category: AuditCategory | None = Query(default=None),
    actor: str | None = Query(default=None, max_length=MAX_FILTER_LENGTH),
    since: datetime | None = Query(default=None),
    q: str | None = Query(default=None, max_length=MAX_SEARCH_LENGTH),
    jobs_service: OperationsJobsService = Depends(get_operations_jobs_service),
) -> AuditListResponse:
    """Return Change Audit entries ordered most-recent first."""
    entries = await jobs_service.query_audit(category=category, actor=actor, since=since, q=q)
    return AuditListResponse(items=[_audit_to_list_item(e) for e in entries], total=len(entries))
