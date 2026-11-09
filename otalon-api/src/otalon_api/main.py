"""FastAPI application entry point with lifespan management."""

from __future__ import annotations

import asyncio
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger
from otalon_common.logging import configure_logging

from otalon_api.api.v1.admin import router as admin_router
from otalon_api.api.v1.admin_users import router as admin_users_router
from otalon_api.api.v1.anomalies import router as anomalies_router
from otalon_api.api.v1.anomalies_mac_proto import (
    mac_router as anomalies_mac_router,
    proto_router as anomalies_proto_router,
)
from otalon_api.api.v1.auth import router as auth_router
from otalon_api.api.v1.baselines import router as baselines_router
from otalon_api.api.v1.dashboard import router as dashboard_router
from otalon_api.api.v1.events import router as events_router
from otalon_api.api.v1.frequency import router as frequency_router
from otalon_api.api.v1.operations import router as operations_router
from otalon_api.api.v1.operations_config import router as operations_config_router
from otalon_api.api.v1.pcap import router as pcap_router
from otalon_api.api.v1.pcap_import import (
    internal_router as pcap_import_internal_router,
    router as pcap_import_router,
)
from otalon_api.api.v1.scans import router as scans_router
from otalon_api.api.v1.status import router as status_router
from otalon_api.api.v1.subagent_jobs import router as subagent_jobs_router
from otalon_api.api.v1.timeseries import router as timeseries_router
from otalon_api.api.v1.timeseries_mac_proto import (
    mac_router as timeseries_mac_router,
    proto_router as timeseries_proto_router,
)
from otalon_api.api.v1.topology import router as topology_router
from otalon_api.api.v1.training import router as training_router
from otalon_api.dependencies import (
    get_event_bus,
    get_health_incident_service,
    get_health_service,
    get_influx_repo,
    get_pcap_import_service,
    get_postgres_repo,
    get_settings,
)
from otalon_api.domain.time.time_policy import configure_timezone
from otalon_api.middleware.audit import AuditLoggingMiddleware
from otalon_api.middleware.auth import ApiKeyAuthMiddleware
from otalon_api.middleware.perf import RequestTimingMiddleware
from otalon_api.middleware.security_headers import SecurityHeadersMiddleware
from otalon_api.middleware.session_auth import SessionAuthMiddleware
from otalon_api.repositories.identity_repo import bootstrap_identity
from otalon_api.repositories.identity_schema import ensure_identity_schema
from otalon_api.repositories.operations_schema import (
    bootstrap_bounds_history_backfill,
    ensure_operations_schema,
)
from otalon_api.repositories.runtime_retrain_repo import RuntimeRetrainRepo
from otalon_api.services.anomaly_service import AnomalyService
from otalon_api.services.baseline_service import BaselineService
from otalon_api.services.dashboard_kpi_service import DashboardKpiService
from otalon_api.services.device_type_override_store import DeviceTypeOverrideStore
from otalon_api.services.emitters import (
    anomaly_emitter,
    health_emitter,
    kpi_emitter,
    topology_emitter,
)
from otalon_api.services.pcap_proxy_service import PcapProxyService
from otalon_api.services.scan_proxy_service import ScanProxyService
from otalon_api.services.subagent_service import SubagentService
from otalon_api.services.topology_service import TopologyService
from otalon_api.settings import LoggingConfig


def _configure_logging(log_config: LoggingConfig) -> None:
    """Set up loguru with file and stderr sinks.

    Args:
        log_config: Logging configuration with level and file path.
    """
    log_path = Path(log_config.file)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    level = log_config.level.upper()
    configure_logging(
        log_file=log_path,
        console_level=level,
        file_level=level,
        rotation="10 MB",
        retention="14 days",
        stream=sys.stderr,
        console_format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <white>{file}:{line}</white> | "
        "<level>{level:<8}</level> | <level>{message}</level>",
        colorize=True,
    )
    logger.info("Logging configured (file={}).", log_config.file)


async def _start_pcap_import_reconciler() -> asyncio.Task[None]:
    """Recover orphaned import jobs at boot and start the dispatch loop.

    UI-078 B10: the import worker keeps its slot **in memory only**. If it
    restarts mid-import, the job stays ``running`` in PostgreSQL with
    nobody working on it — the worker cannot report that, so the api has
    to collect it. The startup sweep runs once immediately; the loop then
    repeats it on a cadence together with delivery of queued jobs.

    Returns:
        The long-lived reconciliation task, cancelled on shutdown.
    """
    service = get_pcap_import_service()
    try:
        recovered = await service.reap_orphans()
        if recovered:
            logger.warning("pcap-import: recovered {} orphaned import job(s) at startup", recovered)
    except Exception:
        logger.opt(exception=True).warning("pcap-import: startup orphan sweep failed — continuing")
    return asyncio.create_task(service.run_dispatch_loop(), name="pcap-import-dispatch")


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncIterator[None]:
    """Application lifespan: startup and shutdown hooks.

    Args:
        application: The FastAPI application instance.

    Yields:
        None after startup is complete; shutdown runs after the yield.
    """
    settings = get_settings()
    _configure_logging(settings.log_config)
    configure_timezone(settings.timezone_name)
    logger.info(
        "OTALON API starting up … (timezone: {})",
        settings.timezone_name,
    )
    # Wave C / scan--api-proxy — fail loud if the outbound operator key
    # for otalon-scan is missing. The proxy refuses to start up in an
    # unauthenticated state (mirrors the Wave-B F-02 fail-loud pattern
    # on the upstream allow-list side).
    if not settings.otalon_scan_api_key.strip():
        logger.error(
            "OTALON_SCAN_API_KEY is unset or empty. otalon-api refuses to "
            "start without an operator-level key for outbound calls to "
            "otalon-scan:8091. Set OTALON_SCAN_API_KEY in .env / .env.compose "
            "to a value present in OTALON_SCAN_ALLOWED_KEYS on the upstream side."
        )
        raise RuntimeError("OTALON_SCAN_API_KEY is required for otalon-api startup")
    try:
        get_postgres_repo().ensure_indexes()
    except Exception:
        logger.opt(exception=True).warning("Failed to ensure PostgreSQL indexes on startup — continuing.")

    try:
        RuntimeRetrainRepo(get_postgres_repo()).ensure_schema()
    except Exception:
        logger.opt(exception=True).warning("Failed to ensure retrain_jobs schema on startup — continuing.")

    postgres_repo = get_postgres_repo()
    try:
        ensure_identity_schema(postgres_repo)
        bootstrap_identity(postgres_repo)
    except Exception as exc:
        logger.opt(exception=True).error("Could not ensure product identity schema")
        raise RuntimeError("Product identity schema bootstrap failed") from exc
    try:
        ensure_operations_schema(postgres_repo)
    except Exception as exc:
        logger.opt(exception=True).error("Could not ensure operations schema before emitters")
        raise RuntimeError("Operations schema bootstrap failed") from exc

    bus = get_event_bus()
    influx_repo = get_influx_repo()
    override_store = DeviceTypeOverrideStore()
    kpi_service = DashboardKpiService(postgres_repo, influx_repo, settings)
    anomaly_service = AnomalyService(postgres_repo, settings)
    topo_service = TopologyService(postgres_repo, influx_repo, settings, override_store)

    tasks = [
        asyncio.create_task(kpi_emitter(bus, kpi_service), name="kpi-emitter"),
        asyncio.create_task(
            health_emitter(bus, get_health_service(), get_health_incident_service()),
            name="health-emitter",
        ),
        asyncio.create_task(anomaly_emitter(bus, anomaly_service), name="anomaly-emitter"),
        asyncio.create_task(topology_emitter(bus, topo_service), name="topology-emitter"),
    ]
    logger.info("SSE emitters started ({} tasks)", len(tasks))

    tasks.append(await _start_pcap_import_reconciler())
    logger.info(
        "PCAP import reconciler started (upstream worker on port {})",
        settings.pcap_import_worker_port,
    )

    application.state.subagent_service = SubagentService(
        base_url=settings.ai_url,
        api_key=settings.otalon_ai_api_key,
        timeout=settings.ai_timeout_s,
    )
    logger.info("SubagentService configured with ai_url={}", settings.ai_url)

    # Wave C / scan--api-proxy — outbound proxy to otalon-scan:8091.
    scan_base = f"http://{settings.otalon_scan_host}:{settings.otalon_scan_port}"
    application.state.scan_proxy_service = ScanProxyService(
        base_url=scan_base,
        api_key=settings.otalon_scan_api_key,
        timeout=settings.health_check_timeout_s,
    )
    logger.info("ScanProxyService configured (upstream={})", scan_base)

    # TODO B-05 — outbound proxy to the PCAP recorder on port 9090.
    pcap_base = f"http://{settings.pcap_recorder_host}:{settings.pcap_recorder_port}"
    application.state.pcap_proxy_service = PcapProxyService(
        base_url=pcap_base,
        api_key=settings.pcap_recorder_api_key,
        timeout=settings.pcap_recorder_timeout_s,
    )
    logger.info("PcapProxyService configured (upstream={})", pcap_base)

    baseline_svc = BaselineService(settings=settings, influx=influx_repo)
    try:
        baseline_svc.ensure_schema()
    except Exception:
        logger.opt(exception=True).warning("Could not ensure baselines schema (continuing anyway)")

    # UI-075 Wave B (task 3.2): surface historical bounds_history corrections
    # in Change Audit via a one-time idempotent backfill. Runs after the
    # operations schema exists; a missing bounds_history table is a safe
    # no-op, and the UNIQUE (source, source_id) key keeps repeated boots
    # duplicate-free. Failure is non-fatal for startup.
    try:
        bootstrap_bounds_history_backfill(postgres_repo)
    except Exception:
        logger.opt(exception=True).warning("Could not backfill bounds_history audit rows (continuing anyway)")

    application.state.baseline_service = baseline_svc
    logger.info(
        "BaselineService configured (buffer={}, archive={}, baseline={})",
        settings.pcap_buffer_dir,
        settings.pcap_archive_dir,
        settings.pcap_baseline_dir,
    )

    yield

    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    logger.info("SSE emitters stopped")

    for repo_factory, name in (
        (get_influx_repo, "InfluxDB"),
        (get_postgres_repo, "PostgreSQL"),
    ):
        try:
            repo_factory().close()
            logger.info("Closed {} connection.", name)
        except Exception:
            logger.opt(exception=True).warning("Failed to close {} connection.", name)
    logger.info("OTALON API shutting down …")


app = FastAPI(
    title="OTALON API",
    version="0.1.0",
    description="REST API backend for the OTALON network monitoring suite.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(RequestTimingMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(AuditLoggingMiddleware)
app.add_middleware(ApiKeyAuthMiddleware)
app.add_middleware(SessionAuthMiddleware)

app.include_router(status_router)
app.include_router(auth_router)
app.include_router(admin_users_router)
app.include_router(operations_router)
app.include_router(operations_config_router)
# MSAP Wave C — mac/proto subrouters mounted BEFORE the existing conn routers
# so that static routes like /timeseries/mac/data register ahead of any
# future catch-all variable route (E-C3 shadowing guard).
app.include_router(timeseries_mac_router)
app.include_router(timeseries_proto_router)
app.include_router(anomalies_mac_router)
app.include_router(anomalies_proto_router)
app.include_router(timeseries_router)
app.include_router(anomalies_router)
app.include_router(frequency_router)
app.include_router(dashboard_router)
app.include_router(events_router)
app.include_router(topology_router)
app.include_router(admin_router)
app.include_router(subagent_jobs_router)
app.include_router(baselines_router)
app.include_router(scans_router)
app.include_router(pcap_router)
app.include_router(training_router)
app.include_router(pcap_import_router)
app.include_router(pcap_import_internal_router)
