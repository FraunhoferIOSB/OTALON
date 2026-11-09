"""Scan-lifecycle router (SCAN-033 extraction).

Owns the scan surface: start / stop / list / running / finished / results,
the per-module override-schema introspection endpoint, the merged
``GET|DELETE /scans/{scan_id}`` route and the bulk scan reaper.

Route order inside this module is load-bearing: every literal
``/scans/<segment>`` path MUST be declared before the catch-all
``/scans/{scan_id}``, otherwise Starlette matches ``running`` /
``finished`` / ``start`` as a scan id. ``/scans/interfaces`` lives in
:mod:`otalon_scan.api.routers.interfaces`, which the composition root includes
ahead of this router for the same reason.

State objects are *injected* as ``Optional`` and narrowed with the
``require_*`` guards in the handler body rather than by a raising
``Depends``, so params and body still validate first. See
:mod:`otalon_scan.api.dependencies`.

Logging note (SCAN-034): stdlib ``logging`` call sites moved verbatim.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any, Dict, List, Optional, Union
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from loguru import logger

from ...core.auth import verify_api_key
from ...core.module_config import MODULE_SCHEMA_REGISTRY, resolve_module_slug
from ...core.module_manager import ModuleManager
from ...repositories.models import ScanStatus
from ...repositories.postgres_repo import ScannerPostgresRepo
from ..dependencies import (
    get_api_state,
    get_optional_manager,
    get_optional_repo,
    require_manager,
    require_repo,
    require_runtime,
)
from ..schemas.modules import ModuleSchemaKeyItem, ModuleSchemaResponse
from ..schemas.scans import (
    BulkDeleteScansRequest,
    BulkDeleteScansResponse,
    FinishedScansResponse,
    RunningScansResponse,
    ScansListResponse,
    StartScanRequest,
    StartScanResponse,
    StopScanResponse,
)
from ..serializers import scan_row_to_item, serialize_module_results
from ..state import ApiState

__all__ = ["router"]

router = APIRouter()


@router.post(
    "/scans/start",
    response_model=StartScanResponse,
    dependencies=[Depends(verify_api_key("operator"))],
)
async def start_scan(
    req: StartScanRequest,
    manager: Optional[ModuleManager] = Depends(get_optional_manager),
    repo: Optional[ScannerPostgresRepo] = Depends(get_optional_repo),
    state: ApiState = Depends(get_api_state),
) -> StartScanResponse:
    """Start a scan for the given module_name and optional overrides.

    Validation failures surface as HTTP 422 (FastAPI's natural Pydantic
    request-body response):

    - Unknown ``module_name`` (no per-module override schema registered).
    - ``overrides`` contains unknown keys (per-module schemas are
      ``extra="forbid"``).
    - Any override field fails its dedicated validator
      (:mod:`otalon_scan.core.validators`): unknown interface, malformed CIDR /
      IP, malformed port range, out-of-range port, illegal timing
      template, etc.

    Failures discovered *after* validation (e.g. ``start_module``
    returning ``None`` for an internal reason, or the persistence layer
    being unavailable) still surface as HTTP 400 / 500 as before.
    """
    runtime = require_runtime(manager, repo)

    # SC-01: ``start_module`` prunes finished runs (blocking finalize path);
    # keep it off the event loop.
    run_id = await asyncio.to_thread(
        runtime.manager.start_module, req.module_name, req.overrides or None
    )
    if not run_id:
        raise HTTPException(status_code=400, detail="Failed to start module")

    scan_id = str(
        await runtime.repo.start_scan(
            module_name=req.module_name,
            source_ip=None,
            source_mac=None,
            parameters=req.overrides or {},
        )
    )
    state.run_to_scan_map[run_id] = scan_id
    try:
        # SC-01: ``register_scan_id`` re-drives deferred finalisation
        # (blocking persistence path); keep it off the event loop.
        await asyncio.to_thread(runtime.manager.register_scan_id, run_id, scan_id)
    except KeyError:
        # The orchestrator may have already moved the run to finished
        # between ``start_module`` and this call. Non-fatal for the
        # client request — they still get the run_id and scan_id back.
        logger.bind(run_id=run_id, scan_id=scan_id).debug(
            "register_scan_id: run_id already retired by ModuleManager",
        )
    except Exception:
        logger.bind(run_id=run_id, scan_id=scan_id).exception("register_scan_id failed")

    return StartScanResponse(
        run_id=run_id,
        scan_id=scan_id,
        module_name=req.module_name,
        status=ScanStatus.RUNNING.value,
    )


@router.post(
    "/scans/{run_id}/stop",
    response_model=StopScanResponse,
    dependencies=[Depends(verify_api_key("operator"))],
)
async def stop_scan(
    run_id: str,
    manager: Optional[ModuleManager] = Depends(get_optional_manager),
    repo: Optional[ScannerPostgresRepo] = Depends(get_optional_repo),
) -> StopScanResponse:
    """Stop a running module by UUID.

    The terminal :class:`ScanStatus` (``ABORTED`` if the buffer was empty
    at cancellation, ``CANCELLED_PARTIAL`` if findings were flushed — D4
    resolved 2026-05-17) is set by :meth:`ModuleManager._finalize_run`
    via the finish-sink registered in the lifespan startup. We do NOT
    write the status here so we don't race with the orchestrator's
    finalisation path.
    """
    runtime = require_runtime(manager, repo)

    # SC-01: ``stop_module`` blocks in psutil terminate/wait; keep it off
    # the event loop.
    stopped = await asyncio.to_thread(runtime.manager.stop_module, run_id)

    return StopScanResponse(run_id=run_id, stopped=bool(stopped))


@router.get(
    "/scans",
    response_model=ScansListResponse,
    dependencies=[Depends(verify_api_key("viewer"))],
)
async def list_scans(
    status: Optional[str] = None,
    module: Optional[str] = None,
    since: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    repo: Optional[ScannerPostgresRepo] = Depends(get_optional_repo),
) -> ScansListResponse:
    """List recent scans from the persistence layer.

    Mirrors the UI's ``GET /api/v1/scans`` contract (Wave-C scan proxy).
    Filters are AND-combined; unknown ``status`` values yield an empty
    list (rather than 422) so the UI's Recent-Scans panel degrades to
    "no rows" instead of an error banner.

    Query parameters:
        status: Optional :class:`ScanStatus` value (e.g. ``running``,
            ``completed``, ``failed``, ``aborted``, ``cancelled_partial``).
        module: Optional module-name filter (leaf slug, e.g. ``arp_scan``).
        since: Optional ISO-8601 lower bound on ``started_at``.
            Malformed values are ignored (treated as "no filter").
        limit: Page size (default 100, max 1000).
        offset: Pagination offset (default 0).
    """
    repository = require_repo(repo)
    since_dt: Optional[datetime] = None
    if since:
        try:
            since_dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
        except ValueError:
            since_dt = None
    rows = await repository.list_scans(
        status=status,
        module=module,
        since=since_dt,
        limit=min(max(1, limit), 1000),
        offset=max(0, offset),
    )
    return ScansListResponse(scans=[scan_row_to_item(r) for r in rows])


@router.get(
    "/scans/running",
    response_model=RunningScansResponse,
    dependencies=[Depends(verify_api_key("viewer"))],
)
async def list_running_scans(
    manager: Optional[ModuleManager] = Depends(get_optional_manager),
) -> RunningScansResponse:
    """Return mapping of run UUID to module for currently running scans."""
    module_manager = require_manager(manager)
    # SC-01: blocking cleanup/finalize path — offload from the event loop.
    running = await asyncio.to_thread(module_manager.get_all_running_modules_status)
    return RunningScansResponse(running=running)


@router.get(
    "/scans/{run_id}/results",
    dependencies=[Depends(verify_api_key("viewer"))],
)
async def get_scan_results(
    run_id: str,
    manager: Optional[ModuleManager] = Depends(get_optional_manager),
) -> Dict[str, Any]:
    """Return module results captured on completion (if available)."""
    module_manager = require_manager(manager)
    # SC-01: blocking cleanup/finalize path — offload from the event loop.
    raw = await asyncio.to_thread(module_manager.get_module_results, run_id)
    return {"results": serialize_module_results(raw)}


@router.get(
    "/scans/finished",
    response_model=FinishedScansResponse,
    dependencies=[Depends(verify_api_key("viewer"))],
)
async def list_finished_scans(
    manager: Optional[ModuleManager] = Depends(get_optional_manager),
    state: ApiState = Depends(get_api_state),
) -> FinishedScansResponse:
    """Return mapping of finished run UUID to module name."""
    module_manager = require_manager(manager)
    finished = dict(state.finished_runs)
    try:
        # SC-01: blocking cleanup/finalize path — offload from the event loop.
        finished.update(
            await asyncio.to_thread(module_manager.get_all_finished_modules)
        )
    except Exception:
        # Non-fatal — the local ``finished_runs`` mapping already contains
        # every run the API callback observed; only orchestrator-internal
        # bookkeeping might be missing. Log so the divergence is
        # diagnosable rather than silently swallowed.
        logger.exception(
            "get_all_finished_modules failed; returning API-side view only"
        )
    return FinishedScansResponse(finished=finished)


@router.get(
    "/scans/modules/{name}/schema",
    response_model=ModuleSchemaResponse,
    dependencies=[Depends(verify_api_key("viewer"))],
)
async def get_module_schema(name: str) -> ModuleSchemaResponse:
    """Return the override schema metadata for a single module.

    ``accepted_keys`` lists every field accepted by the module's override
    Pydantic model today (``extra="forbid"``). ``requires_auth`` is read
    from the schema class itself (``ClassVar``) — no hard-coded mapping.
    """
    slug = resolve_module_slug(name)
    schema = MODULE_SCHEMA_REGISTRY.get(slug)
    if schema is None:
        raise HTTPException(status_code=404, detail=f"module {name!r} not found")

    accepted_keys: List[ModuleSchemaKeyItem] = []
    for key, field_info in schema.model_fields.items():
        accepted_keys.append(
            ModuleSchemaKeyItem(
                key=key,
                type=(
                    str(field_info.annotation)
                    if field_info.annotation is not None
                    else "Any"
                ),
                required=field_info.is_required(),
                description=field_info.description or "",
            )
        )

    return ModuleSchemaResponse(
        module=slug,
        accepted_keys=accepted_keys,
        requires_auth=getattr(schema, "requires_auth", False),
        extensible=False,
    )


@router.api_route(
    "/scans/{scan_id}",
    methods=["GET", "DELETE"],
)
async def get_or_delete_scan_by_id(scan_id: str, request: Request) -> Response:
    """Return (GET) or hard-delete (DELETE) a single scan by its UUID.

    GET and DELETE share one :class:`APIRoute`. Registering them as two
    separate same-path routes left Starlette matching only the first
    (GET) and shadowing the second (DELETE) behind a 405, because
    Starlette inspects only the first path-matching route's methods.
    Carrying both verbs on one route keeps both reachable.

    Auth is enforced per-method inside the handler (the per-method
    ``dependencies=`` of split decorators cannot be expressed on a
    single multi-method route): ``viewer`` for GET, ``operator`` for
    the mutating DELETE.

    GET returns the :class:`ScanItem` JSON (404 when absent, 400 when
    the id is not a parseable UUID). DELETE removes the scan and its
    cascaded observations, returning HTTP 204 with no body (404 when no
    row matches).

    SCAN-035: because FastAPI derives ``operationId`` per *route* rather
    than per route/method, this two-verb route cannot express a unique
    id per operation through ``operation_id=`` here. The deterministic
    ids are synthesised at schema-generation time by
    :mod:`otalon_scan.api.openapi`; do not add an ``operation_id=`` to
    the decorator above, it would be applied to both verbs alike.
    """
    repo = get_api_state(request).repo
    if request.method == "DELETE":
        verify_api_key("operator")(request)
        repository = require_repo(repo)
        deleted = await repository.delete_scan(scan_id)
        if not deleted:
            raise HTTPException(status_code=404, detail="Scan not found")
        return Response(status_code=204)
    verify_api_key("viewer")(request)
    repository = require_repo(repo)
    try:
        row = await repository.get_scan(scan_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"invalid scan_id: {exc}") from exc
    if row is None:
        raise HTTPException(status_code=404, detail=f"scan {scan_id!r} not found")
    return JSONResponse(
        content=scan_row_to_item(row, include_findings=True).model_dump(mode="json")
    )


@router.delete(
    "/scans",
    response_model=BulkDeleteScansResponse,
    status_code=200,
    dependencies=[Depends(verify_api_key("operator"))],
)
async def delete_scans_bulk(
    payload: BulkDeleteScansRequest,
    repo: Optional[ScannerPostgresRepo] = Depends(get_optional_repo),
) -> BulkDeleteScansResponse:
    """Hard-delete a batch of scans atomically in a single transaction.

    Bulk counterpart to ``DELETE /scans/{scan_id}``. Observations
    referencing the removed scans are cascaded automatically via the
    FK ``ON DELETE CASCADE`` declarations.

    The endpoint returns HTTP 200 (not 204) because the response body
    carries the per-id outcome so the caller can surface a
    ``"X deleted, Y not found"`` notice without an extra round-trip.

    Returns:
        :class:`BulkDeleteScansResponse` with the two id arrays.

    Raises:
        HTTPException: 500 when the repository is not initialised.
    """
    repository = require_repo(repo)
    scan_ids: List[Union[UUID, str]] = list(payload.ids)
    result = await repository.delete_scans(scan_ids)
    logger.bind(
        requested=len(payload.ids),
        deleted=len(result["deleted"]),
        not_found=len(result["not_found"]),
    ).info("scans bulk deleted")
    return BulkDeleteScansResponse(
        deleted=result["deleted"], not_found=result["not_found"]
    )
