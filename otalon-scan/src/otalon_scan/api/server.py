"""CyberScan-ICS API Server — composition root (SCAN-033).

This module owns application *construction*, not request handling. It:

- builds the :class:`fastapi.FastAPI` instance and its OpenAPI metadata,
- creates the shared :class:`~otalon_scan.api.state.ApiState` container on
  ``app.state.api_state``,
- defines the :func:`lifespan` startup/shutdown context manager,
- mounts the Prometheus ``/metrics`` endpoint,
- includes the resource-scoped routers from :mod:`otalon_scan.api.routers`.

Route handlers live in ``src/otalon_scan/api/routers/``, wire models in
``src/otalon_scan/api/schemas/``, row projections in :mod:`otalon_scan.api.serializers`, and
the orchestrator persistence sinks in :mod:`otalon_scan.api.scan_sink`. Handlers
reach runtime objects exclusively through the typed dependencies in
:mod:`otalon_scan.api.dependencies` — there are no module-level state globals
here any more.

The exported ``app`` symbol is pinned by the container entrypoint
(``uvicorn otalon_scan.api.server:app``); do not move or rename it.

The service provides REST + SSE endpoints to:

- list available scanner modules
- start/stop scans with runtime configuration overrides
- inspect running and finished scans
- stream live ``ScanProgress`` / ``ScanResult`` events via SSE
  (``GET /scans/{scan_id}/events``) — Mission Q9 prerequisite
- persist scan results into PostgreSQL using a normalized schema

Architecture:

- All HTTP handlers are ``async def``; the event loop is unblocked.
- Database access goes through :class:`ScannerPostgresRepo`, an async
  repository over SQLAlchemy 2.x :class:`AsyncSession` + ``asyncpg``
  (D1 resolved 2026-05-17).
- Startup / shutdown live in a FastAPI lifespan context manager (HC21).
- The persistence sink wired into :meth:`ModuleManager._persist_batch`
  runs in the parent-process monitor thread. To call async repo methods
  from that thread it dispatches the coroutine onto the captured FastAPI
  event loop via :func:`asyncio.run_coroutine_threadsafe`.

Configuration loaded from ``config/config.json`` with ``$ENV_VAR`` placeholder
substitution (see :mod:`otalon_scan.settings`):

- ``server.host`` / ``server.port``
- ``postgres.dsn`` — accepts sync (``postgresql://``) or async
  (``postgresql+asyncpg://``) form; sync DSNs are transparently rewritten.
- ``modules.path`` — root directory containing module folders

Logging note (SCAN-034): this module deliberately stays on stdlib
``logging``; converting the otalon-scan API layer to loguru is tracked
separately.
"""

from __future__ import annotations

import asyncio
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

from fastapi import FastAPI
from loguru import logger
from sqlalchemy.exc import SQLAlchemyError

from ..core.auth import parse_allowed_keys, set_allowed_keys
from ..core.module_config import validate_module_default_configs
from ..core.module_manager import ModuleManager
from ..repositories.postgres_repo import ScannerPostgresRepo
from ..settings import Settings
from .metrics import PERSISTENCE_ERRORS, module_label, mount_metrics
from .openapi import install_openapi
from .routers import (
    devices_router,
    health_router,
    interfaces_router,
    modules_router,
    scan_events_router,
    scans_router,
    vulnerabilities_router,
)
from .scan_sink import ScanSink
from .state import ApiState

__all__ = ["app", "lifespan"]

# Phase 5 / scan--api-auth: name of the env var that carries the API-key
# allow-list. The lifespan startup reads it and refuses to start the
# service if it is empty or malformed.
_ALLOWED_KEYS_ENV = "OTALON_SCAN_ALLOWED_KEYS"


def _resolve_config_path() -> str:
    """Resolve config/config.json relative to project structure (both local and container)."""
    src_dir = Path(__file__).resolve().parents[2]
    cfg_path = src_dir.parent / "config" / "config.json"
    return str(cfg_path)


def _load_allowed_keys() -> None:
    """Load and install the API-key allow-list, or exit the process.

    Phase 5 / scan--api-auth: an unconfigured or malformed allow-list is a
    fatal startup error — the service must not run with auth disabled
    because that would silently regress the security boundary that
    ``harden-otalon-scan-security`` introduces.
    """
    raw_keys = os.environ.get(_ALLOWED_KEYS_ENV, "")
    try:
        allowed = parse_allowed_keys(raw_keys)
    except ValueError as exc:
        logger.error(
            "FATAL: {} is empty or malformed: {}; refusing to start otalon-scan",
            _ALLOWED_KEYS_ENV,
            exc,
        )
        sys.exit(1)
    set_allowed_keys(allowed)
    logger.info(
        "CyberScan-ICS: auth allow-list loaded ({} keys across {} distinct callers)",
        len(allowed),
        len({name for name, _ in allowed.values()}),
    )


def _build_manager(
    loop: asyncio.AbstractEventLoop,
    sink: ScanSink,
    modules_path: str,
) -> ModuleManager:
    """Construct the :class:`ModuleManager` and wire its orchestrator sinks.

    Args:
        loop: The event loop captured at startup; the progress bus needs it
            to forward events from the orchestrator's monitor thread.
        sink: The orchestrator persistence boundary bound to the app state.
        modules_path: Root directory containing the module folders.

    Returns:
        The wired manager, ready to accept ``start_module`` calls.
    """
    manager = ModuleManager(modules_path=modules_path, callback=sink.on_module_finished)
    manager.progress_bus.attach_loop(loop)
    # Wire the orchestrator-owned persistence boundary (HC6 / Phase 2 seam).
    manager.set_persist_sink(sink.persist_findings)
    # Wire the terminal-status sink (Phase 5 / HC16 / 6.3 / D4).
    manager.set_finish_sink(sink.finish_scan)
    # L-02: wire the per-scan findings-snapshot sink.
    manager.set_findings_sink(sink.persist_scan_findings)
    # F-02 / scan--observability: wire the discriminator-mismatch
    # counter to the Prometheus counter.
    manager.set_persistence_error_callback(
        lambda module_slug: PERSISTENCE_ERRORS.labels(
            module=module_label(module_slug)
        ).inc()
    )
    return manager


async def _build_repo(state: ApiState) -> ScannerPostgresRepo:
    """Construct and probe the PostgreSQL repository, or exit the process.

    HC4 (2026-05-18): fail-fast on PostgreSQL connectivity issues at
    startup. The previous silent fallback to an in-memory store let the
    service run while losing every scan result on the next container
    restart while ``/health`` kept reporting ``ok``. A missing DB
    connection is now a fatal startup error.

    Args:
        state: The shared runtime state carrying the parsed settings.

    Returns:
        The repository whose schema has been ensured.
    """
    settings = state.settings
    dsn = (
        settings.postgres.dsn
        if settings and settings.postgres and settings.postgres.dsn
        else None
    )
    try:
        candidate = ScannerPostgresRepo(dsn=dsn)
        await candidate.ensure_schema()
    except Exception as exc:
        logger.error(
            "FATAL: PostgreSQL repository initialisation failed ({}); refusing to start otalon-scan. "
            "Configure 'postgres.dsn' in config/config.json (or POSTGRES_DSN) to a reachable instance.",
            exc,
        )
        sys.exit(1)
    logger.info("CyberScan-ICS: PostgreSQL repository ready")
    return candidate


async def _reconcile_orphans(state: ApiState) -> None:
    """Finalize records left non-terminal by a previous process.

    SCAN-026 (WA.5) — an in-process CVE-lookup registry task does not
    survive a restart, so any ``cve_lookups`` row left ``running`` from a
    previous process has no live task to finalize it. E2E-B2 — the same
    holds for ``scans`` rows left ``RUNNING``/``finished_at NULL``, whose
    ``ModuleManager`` run died with the process. Both orphan classes are
    failed/aborted on startup so they never strand (design.md § D2 Risk).
    At a cold start nothing is in flight, so every such row is orphaned.

    Args:
        state: The shared runtime state carrying the repo and registry.
    """
    repo = state.repo
    if repo is None:
        return
    try:
        reconciled = await repo.reconcile_interrupted_lookups(
            active_job_ids=state.lookup_registry.active_job_ids()
        )
        if reconciled:
            logger.info(
                "CyberScan-ICS: reconciled {} interrupted CVE-lookup job(s) to failed",
                reconciled,
            )
    except SQLAlchemyError:
        logger.exception("CVE-lookup reconcile on startup failed")

    try:
        reconciled_scans = await repo.reconcile_interrupted_scans()
        if reconciled_scans:
            logger.info(
                "CyberScan-ICS: reconciled {} interrupted scan(s) to aborted",
                reconciled_scans,
            )
    except SQLAlchemyError:
        logger.exception("Scan reconcile on startup failed")


# ---- Lifespan (HC21: replaces @app.on_event startup/shutdown) ----


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Initialize and tear down service state.

    Startup:
    - Capture the running event loop onto the shared state (the
      orchestrator monitor thread dispatches coroutines back onto it).
    - Load and install the API-key allow-list (fatal if missing).
    - Load settings and validate every module's ``config.json``.
    - Construct the async :class:`ScannerPostgresRepo` (fatal if the DB
      is unreachable) and run ``await repo.ensure_schema()``.
    - Construct the :class:`ModuleManager`, attach the FastAPI event loop
      to its :attr:`progress_bus` (SSE forwarder uses it), and wire the
      persistence sinks.
    - Reconcile records orphaned by a previous process.

    Shutdown:
    - Terminate any in-flight modules cleanly.
    - Dispose the repository engine.

    The :class:`ApiState` container is created at app construction time and
    is mutated in place here — never rebound — so objects that must exist
    before startup (the CVE-lookup registry, the run/finished mappings)
    survive it.
    """
    state: ApiState = getattr(app.state, "api_state", None) or ApiState()
    app.state.api_state = state

    main_loop = asyncio.get_running_loop()
    state.main_loop = main_loop

    _load_allowed_keys()

    cfg_path = _resolve_config_path()
    state.settings = Settings.from_json(cfg_path)

    modules_path = str(state.settings.modules.path)

    # F-02 / scan--module-config-schemas: validate every module's
    # ``config.json`` against its registered ``*Config`` schema before
    # we accept any traffic. Any drift fails startup loud — same
    # contract as the Postgres probe below (HC4 fail-loud).
    try:
        validate_module_default_configs(Path(modules_path))
    except Exception as exc:
        logger.error(
            "FATAL: module config.json default failed schema validation ({}); "
            "refusing to start otalon-scan. Fix the offending config.json or "
            "update the corresponding src/otalon_scan/modules/<name>/config.py schema.",
            exc,
        )
        sys.exit(1)

    sink = ScanSink(state)
    state.manager = _build_manager(main_loop, sink, modules_path)
    state.repo = await _build_repo(state)
    await _reconcile_orphans(state)

    try:
        yield
    finally:
        logger.info("CyberScan-ICS: shutdown — disposing resources")
        if state.manager is not None:
            try:
                state.manager.shutdown()
            except Exception:
                # Best-effort shutdown — log but keep tearing down the
                # event loop so other resources still get disposed.
                logger.exception("ModuleManager.shutdown raised")
        if state.repo is not None:
            try:
                await state.repo.dispose()
            except SQLAlchemyError:
                logger.exception("Repo.dispose raised")


app = FastAPI(
    title="OTALON Scan API",
    version="0.3.0",
    description=(
        "Active ICS/OT discovery and vulnerability scanning (ARP, port, "
        "OPC UA, PROFINET, SNMP) for the OTALON network monitoring suite. "
        "Internal service; the UI reaches it through the otalon-api proxy."
    ),
    lifespan=lifespan,
)

# SCAN-033: the shared runtime state is created here, at app construction
# time, not inside the lifespan. Members the API needs before startup
# completes — the CVE-lookup registry (so ``POST /vulnerabilities/lookup``
# can dispatch without waiting on the lifespan) and the run/finished
# mappings — must already exist. The lifespan mutates this instance in
# place; it never rebinds it.
app.state.api_state = ApiState()

# F-02 / scan--observability: mount the Prometheus /metrics endpoint
# *at app construction time* (not inside the lifespan) so it is
# available even before the lifespan startup completes — useful for
# scrapers that hit /metrics during the brief window between process
# start and Postgres-probe success.
mount_metrics(app)

# Include order is load-bearing: every literal ``/scans/<segment>`` route
# must be registered before the catch-all ``/scans/{scan_id}`` in
# ``scans_router``, otherwise Starlette matches ``interfaces`` as a scan id.
app.include_router(health_router)
app.include_router(modules_router)
app.include_router(interfaces_router)
app.include_router(scans_router)
app.include_router(scan_events_router)
app.include_router(devices_router)
app.include_router(vulnerabilities_router)

# SCAN-035: must run AFTER every ``include_router`` above — the override
# reads ``app.routes`` at generation time to expand the multi-method
# ``GET|DELETE /scans/{scan_id}`` route (UI-014) into one operation per
# verb. Without it both verbs share a single route-derived operationId,
# which is both a duplicate and hash-seed dependent (``list(set)[0]``).
install_openapi(app)
