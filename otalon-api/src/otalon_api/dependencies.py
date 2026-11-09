"""FastAPI dependency injection setup.

Provides ``Depends``-compatible factories that wire up the
Settings → Repositories → Services dependency chain.
"""

from __future__ import annotations

import os
from functools import lru_cache

from fastapi import Depends, HTTPException, Security
from fastapi.security import APIKeyHeader

from otalon_api.domain.netcap.proto_resolver import ProtoHashResolver
from otalon_api.repositories.cache import CacheManager
from otalon_api.repositories.dashboard_user_state_repo import DashboardUserStateRepository
from otalon_api.repositories.health_incidents_repo import HealthIncidentRepository
from otalon_api.repositories.identity_repo import SessionRepository, UserRepository
from otalon_api.repositories.influx_repo import InfluxRepository
from otalon_api.repositories.operations_jobs_repo import OperationsJobsRepository
from otalon_api.repositories.port_collapse_repo import PortCollapseRepository
from otalon_api.repositories.postgres_repo import PostgresRepository
from otalon_api.repositories.runtime_config_repo import (
    PassiveSeederStatusRepo,
    RuntimeConfigRepo,
)
from otalon_api.services.aggregation_service import NetcapAggregationService
from otalon_api.services.ai_connection_service import AIConnectionService
from otalon_api.services.ai_model_catalog_service import AIModelCatalogService
from otalon_api.services.ai_runtime_client import AIRuntimeClient
from otalon_api.services.anomaly_details_service import AnomalyDetailsService
from otalon_api.services.anomaly_service import AnomalyService
from otalon_api.services.bounds_service import BoundsService
from otalon_api.services.capture_status_service import CaptureStatusService
from otalon_api.services.compose_runner import ComposeRunner
from otalon_api.services.dashboard_kpi_service import DashboardKpiService
from otalon_api.services.detection_readiness_service import DetectionReadinessService
from otalon_api.services.device_type_override_store import DeviceTypeOverrideStore
from otalon_api.services.docker_service import DockerService
from otalon_api.services.env_compose_service import EnvComposeService
from otalon_api.services.event_bus import EventBus, get_event_bus as _get_event_bus_singleton
from otalon_api.services.frequency_service import FrequencyService
from otalon_api.services.health_incident_service import HealthIncidentService
from otalon_api.services.health_service import HealthService
from otalon_api.services.label_source_service import LabelSourceService
from otalon_api.services.operations_backup_service import OperationsBackupService
from otalon_api.services.operations_jobs_service import OperationsJobsService
from otalon_api.services.operations_maintenance_service import OperationsMaintenanceService
from otalon_api.services.operations_pipeline_service import OperationsPipelineService
from otalon_api.services.operations_reset_service import OperationsResetService
from otalon_api.services.passive_discovery_service import PassiveDiscoveryService
from otalon_api.services.pcap_import_service import PcapImportConfig, PcapImportService
from otalon_api.services.pcap_import_worker_client import PcapImportWorkerClient
from otalon_api.services.pcap_upload_service import PcapUploadService
from otalon_api.services.runtime_retrain_service import RuntimeRetrainService
from otalon_api.services.source_timeseries_service import SourceTimeseriesService
from otalon_api.services.timeseries_service import TimeseriesService
from otalon_api.services.topology_service import TopologyService
from otalon_api.settings import Settings

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

_proto_hash_resolver: ProtoHashResolver | None = None


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the singleton application settings.

    Returns:
        The resolved Settings instance.
    """
    return Settings.from_config_json()


@lru_cache(maxsize=1)
def get_influx_repo() -> InfluxRepository:
    """Return a singleton InfluxDB repository wired to the application settings.

    The repository instance is cached so that the underlying client
    connection is reused across requests.

    Returns:
        A fully configured :class:`InfluxRepository`.
    """
    settings = get_settings()
    return InfluxRepository(
        host=settings.influxdb_host,
        port=settings.influxdb_port,
        token=settings.influxdb_token,
        org=settings.influxdb_org,
        database=settings.influxdb_database,
    )


@lru_cache(maxsize=1)
def get_postgres_repo() -> PostgresRepository:
    """Return a singleton PostgreSQL repository wired to the application settings.

    The repository instance is cached so that the underlying connection
    is reused across requests.

    Returns:
        A fully configured :class:`PostgresRepository`.
    """
    settings = get_settings()
    return PostgresRepository(
        host=settings.postgres_host,
        port=settings.postgres_port,
        user=settings.postgres_user,
        password=settings.postgres_password,
        database=settings.postgres_database,
    )


def get_user_repo() -> UserRepository:
    """Return product-user repository over shared PostgreSQL."""
    return UserRepository(get_postgres_repo())


def get_session_repo() -> SessionRepository:
    """Return product-session repository over shared PostgreSQL."""
    return SessionRepository(get_postgres_repo())


def get_runtime_config_repo() -> RuntimeConfigRepo:
    """Return row-level access to shared runtime configuration."""
    return RuntimeConfigRepo(get_postgres_repo())


def get_passive_seeder_status_repo() -> PassiveSeederStatusRepo:
    """Return row-level access to passive-seeder status."""
    return PassiveSeederStatusRepo(get_postgres_repo())


@lru_cache(maxsize=1)
def get_port_collapse_repo() -> PortCollapseRepository:
    """Return a singleton PortCollapseRepository wired to the application settings.

    Constructs a libpq-style DSN from the individual PostgreSQL settings
    fields used by the existing ``PostgresRepository``.

    Returns:
        A fully configured :class:`PortCollapseRepository`.
    """
    settings = get_settings()
    dsn = (
        f"host={settings.postgres_host} "
        f"port={settings.postgres_port} "
        f"user={settings.postgres_user} "
        f"password={settings.postgres_password} "
        f"dbname={settings.postgres_database}"
    )
    return PortCollapseRepository(dsn=dsn)


@lru_cache(maxsize=1)
def get_cache_manager() -> CacheManager:
    """Return the singleton :class:`CacheManager` used by services.

    All read-path caches (dashboard KPIs, topology graph, ...) share
    this instance so hit/miss counters surfaced in the health endpoint
    aggregate every cached call site.

    Returns:
        A process-wide :class:`CacheManager` with default TTLs.
    """
    return CacheManager()


def get_proto_hash_resolver(
    influx_repo: InfluxRepository = Depends(get_influx_repo),
) -> ProtoHashResolver:
    """Return the singleton :class:`ProtoHashResolver`.

    The resolver is cached at module level because it maintains an
    in-memory hash → protocol vocabulary that should be shared across
    requests.

    Args:
        influx_repo: InfluxDB repository dependency.

    Returns:
        A configured :class:`ProtoHashResolver` instance.

    Raises:
        TypeError: If called manually (outside FastAPI dependency
            injection) without a resolved :class:`InfluxRepository`, i.e.
            with the unresolved ``Depends`` default still in place. Seeding
            the shared singleton with that sentinel would poison protocol
            hash resolution for every later request.
    """
    global _proto_hash_resolver
    if not isinstance(influx_repo, InfluxRepository):
        raise TypeError(
            "get_proto_hash_resolver must be called with a resolved InfluxRepository; "
            f"got {type(influx_repo).__name__}. Under FastAPI this is injected via Depends; "
            "manual callers must pass get_influx_repo() explicitly."
        )
    if _proto_hash_resolver is None:
        _proto_hash_resolver = ProtoHashResolver(influx_repo=influx_repo)
    return _proto_hash_resolver


def get_timeseries_service(
    influx_repo: InfluxRepository = Depends(get_influx_repo),
    settings: Settings = Depends(get_settings),
    postgres_repo: PostgresRepository = Depends(get_postgres_repo),
) -> TimeseriesService:
    """Build a TimeseriesService with injected repository and settings.

    Args:
        influx_repo: InfluxDB repository dependency.
        settings: Application settings dependency.

    Returns:
        A configured :class:`TimeseriesService` instance.
    """
    return TimeseriesService(influx_repo, settings, postgres_repo)


def get_mac_timeseries_service(
    influx_repo: InfluxRepository = Depends(get_influx_repo),
    settings: Settings = Depends(get_settings),
) -> SourceTimeseriesService:
    """Build a SourceTimeseriesService wired for MAC traffic.

    Args:
        influx_repo: InfluxDB repository dependency.
        settings: Application settings dependency.

    Returns:
        A configured :class:`SourceTimeseriesService` instance for
        ``mac_traffic``.
    """
    from otalon_api.domain.netcap.models import MAC_FEATURES

    return SourceTimeseriesService(
        influx_repo=influx_repo,
        settings=settings,
        measurement="mac_traffic",
        id_tag="mac_address",
        features=MAC_FEATURES,
    )


def get_proto_timeseries_service(
    influx_repo: InfluxRepository = Depends(get_influx_repo),
    settings: Settings = Depends(get_settings),
) -> SourceTimeseriesService:
    """Build a SourceTimeseriesService wired for protocol traffic.

    Args:
        influx_repo: InfluxDB repository dependency.
        settings: Application settings dependency.

    Returns:
        A configured :class:`SourceTimeseriesService` instance for
        ``proto_traffic``.
    """
    from otalon_api.domain.netcap.models import PROTO_FEATURES

    return SourceTimeseriesService(
        influx_repo=influx_repo,
        settings=settings,
        measurement="proto_traffic",
        id_tag="protocol",
        features=PROTO_FEATURES,
    )


def get_aggregation_service(
    influx_repo: InfluxRepository = Depends(get_influx_repo),
    settings: Settings = Depends(get_settings),
    port_collapse_repo: PortCollapseRepository = Depends(get_port_collapse_repo),
) -> NetcapAggregationService:
    """Build a NetcapAggregationService with injected repository and settings.

    Args:
        influx_repo: InfluxDB repository dependency.
        settings: Application settings dependency.
        port_collapse_repo: Port-collapse rules repository dependency.

    Returns:
        A configured :class:`NetcapAggregationService` instance.
    """
    return NetcapAggregationService(influx_repo, settings, port_collapse_repo)


def get_bounds_service(
    influx_repo: InfluxRepository = Depends(get_influx_repo),
    postgres_repo: PostgresRepository = Depends(get_postgres_repo),
    settings: Settings = Depends(get_settings),
    port_collapse_repo: PortCollapseRepository = Depends(get_port_collapse_repo),
    proto_resolver: ProtoHashResolver = Depends(get_proto_hash_resolver),
) -> BoundsService:
    """Build a BoundsService with injected repositories and settings.

    Includes an aggregation service for wildcard UCI resolution
    in the timeseries-with-bounds pipeline.

    Args:
        influx_repo: InfluxDB repository dependency.
        postgres_repo: PostgreSQL repository dependency.
        settings: Application settings dependency.
        port_collapse_repo: Port-collapse rules repository dependency.
        proto_resolver: Proto hash → protocol resolver dependency.

    Returns:
        A configured :class:`BoundsService` instance.
    """
    agg_service = NetcapAggregationService(influx_repo, settings, port_collapse_repo)
    return BoundsService(influx_repo, postgres_repo, settings, agg_service, proto_resolver)


def get_anomaly_service(
    postgres_repo: PostgresRepository = Depends(get_postgres_repo),
    settings: Settings = Depends(get_settings),
    proto_resolver: ProtoHashResolver = Depends(get_proto_hash_resolver),
) -> AnomalyService:
    """Build an AnomalyService with injected repository and settings.

    Args:
        postgres_repo: PostgreSQL repository dependency.
        settings: Application settings dependency.
        proto_resolver: Proto hash → protocol resolver dependency.

    Returns:
        A configured :class:`AnomalyService` instance.
    """
    return AnomalyService(postgres_repo, settings, proto_resolver)


def get_frequency_service(
    postgres_repo: PostgresRepository = Depends(get_postgres_repo),
    settings: Settings = Depends(get_settings),
    proto_resolver: ProtoHashResolver = Depends(get_proto_hash_resolver),
) -> FrequencyService:
    """Build a FrequencyService with injected repository and settings.

    The two global detector defaults come from settings so the API
    reports the same effective factors the detector applies; they must
    be kept in step with ``otalon-clas/config/config.json``.

    Args:
        postgres_repo: PostgreSQL repository dependency.
        settings: Application settings dependency.

    Returns:
        A configured :class:`FrequencyService` instance.
    """
    return FrequencyService(
        postgres_repo,
        proto_resolver=proto_resolver,
        tolerance_default=settings.frequency_tolerance_factor,
        absence_default=settings.absence_timeout_factor,
        last_seen_write_lag_seconds=settings.frequency_last_seen_flush_interval_s,
        absence_timeout_floor_seconds=settings.absence_timeout_floor_s,
        absence_interval_cap_seconds=settings.absence_interval_cap_s,
        relative_floor_factor=settings.frequency_relative_floor_factor,
    )


def get_anomaly_details_service(
    postgres_repo: PostgresRepository = Depends(get_postgres_repo),
    settings: Settings = Depends(get_settings),
    proto_resolver: ProtoHashResolver = Depends(get_proto_hash_resolver),
) -> AnomalyDetailsService:
    """Build an AnomalyDetailsService with injected repository and settings.

    Args:
        postgres_repo: PostgreSQL repository dependency.
        settings: Application settings dependency.
        proto_resolver: Proto hash → protocol resolver dependency.

    Returns:
        A configured :class:`AnomalyDetailsService` instance.
    """
    return AnomalyDetailsService(postgres_repo, settings, proto_resolver)


def get_dashboard_kpi_service(
    postgres_repo: PostgresRepository = Depends(get_postgres_repo),
    influx_repo: InfluxRepository = Depends(get_influx_repo),
    settings: Settings = Depends(get_settings),
    cache_manager: CacheManager = Depends(get_cache_manager),
) -> DashboardKpiService:
    """Build a DashboardKpiService with injected repositories and settings.

    Args:
        postgres_repo: PostgreSQL repository dependency.
        influx_repo: InfluxDB repository dependency.
        settings: Application settings dependency.
        cache_manager: Shared cache manager for TTL-based caching of
            the expensive ``get_kpis`` aggregate.

    Returns:
        A configured :class:`DashboardKpiService` instance.
    """
    return DashboardKpiService(postgres_repo, influx_repo, settings, cache_manager)


def get_dashboard_user_state_repo() -> DashboardUserStateRepository:
    """Return per-account dashboard-state repository over shared PostgreSQL.

    Returns:
        A :class:`DashboardUserStateRepository` over the singleton
        PostgreSQL repository (replaces the retired JSON-file layout store).
    """
    return DashboardUserStateRepository(get_postgres_repo())


@lru_cache(maxsize=1)
def get_health_service() -> HealthService:
    """Return a singleton HealthService wired to the application settings.

    Returns:
        A configured :class:`HealthService` instance.
    """
    return HealthService(get_settings())


@lru_cache(maxsize=1)
def get_health_incident_service() -> HealthIncidentService:
    """Return singleton backend-owned health incident service."""
    return HealthIncidentService(HealthIncidentRepository(get_postgres_repo()))


def get_operations_pipeline_service(
    influx_repo: InfluxRepository = Depends(get_influx_repo),
    postgres_repo: PostgresRepository = Depends(get_postgres_repo),
    settings: Settings = Depends(get_settings),
) -> OperationsPipelineService:
    """Build an OperationsPipelineService with injected repositories.

    Args:
        influx_repo: InfluxDB repository dependency.
        postgres_repo: PostgreSQL repository dependency.
        settings: Application settings dependency.

    Returns:
        A configured :class:`OperationsPipelineService` instance.
    """
    return OperationsPipelineService(influx_repo, postgres_repo, settings)


def get_passive_discovery_service(
    postgres_repo: PostgresRepository = Depends(get_postgres_repo),
    settings: Settings = Depends(get_settings),
) -> PassiveDiscoveryService:
    """Build a PassiveDiscoveryService with injected repositories.

    Args:
        postgres_repo: PostgreSQL repository dependency.
        settings: Application settings dependency.

    Returns:
        A configured :class:`PassiveDiscoveryService` instance.
    """
    return PassiveDiscoveryService(postgres_repo, settings)


@lru_cache(maxsize=1)
def get_capture_status_service() -> CaptureStatusService:
    """Return a singleton CaptureStatusService wired to app settings.

    The settings are resolved via the cached :func:`get_settings` singleton
    rather than injected through ``Depends``. Mixing ``@lru_cache`` with a
    ``Depends`` default argument is a bug: the unresolved ``Depends`` marker
    object becomes the cache key, so FastAPI never resolves the real
    settings and the cache keys on a sentinel. A fresh ``httpx.AsyncClient``
    is created per request inside the service, so caching the service itself
    is safe.

    Returns:
        A configured :class:`CaptureStatusService` instance.
    """
    return CaptureStatusService(get_settings())


@lru_cache(maxsize=1)
def get_docker_service() -> DockerService:
    """Return a singleton DockerService wired to the application settings.

    Returns:
        A configured :class:`DockerService` instance.
    """
    return DockerService(get_settings())


@lru_cache(maxsize=1)
def get_compose_runner() -> ComposeRunner:
    """Return a singleton ComposeRunner wired to the application settings.

    Returns:
        A configured :class:`ComposeRunner` instance.
    """
    return ComposeRunner(get_settings())


@lru_cache(maxsize=1)
def get_runtime_retrain_service() -> RuntimeRetrainService:
    """Return the singleton :class:`RuntimeRetrainService` orchestrator.

    The orchestrator needs to be cached so the in-memory last job ref
    and DB-backed single-flight state persist between start and status
    calls.

    Returns:
        A fully wired :class:`RuntimeRetrainService` instance.
    """
    return RuntimeRetrainService(
        settings=get_settings(),
        postgres_repo=get_postgres_repo(),
        operations_repo=OperationsJobsRepository(get_postgres_repo()),
        stale_timeout_s=get_settings().training_timeout_s,
    )


@lru_cache(maxsize=1)
def get_env_compose_service() -> EnvComposeService:
    """Return a singleton EnvComposeService wired to the application settings.

    Returns:
        A configured :class:`EnvComposeService` instance.
    """
    return EnvComposeService(get_settings())


@lru_cache(maxsize=1)
def get_ai_connection_service() -> AIConnectionService:
    """Return the singleton server-side AI connection service.

    Cached because the service holds the transient connection ``state``
    (``testing``/``ready``/``failed``) in-process. A per-request instance
    would forget the result of a prior ``test`` call between requests. The
    underlying env service is re-read on every ``metadata``/``test`` call,
    so caching the service does not stale the configuration.

    Returns:
        A configured :class:`AIConnectionService` singleton.
    """
    return AIConnectionService(get_env_compose_service(), runtime_repo=get_runtime_config_repo())


@lru_cache(maxsize=1)
def get_ai_model_catalog_service() -> AIModelCatalogService:
    """Return the singleton model-catalog service (AI-045 Task 2.2).

    Stateless over ``.env.compose`` (re-read on every call), cached so the
    operations-config router resolves the same instance every request.

    Returns:
        A configured :class:`AIModelCatalogService` singleton.
    """
    return AIModelCatalogService(get_env_compose_service(), runtime_repo=get_runtime_config_repo())


@lru_cache(maxsize=1)
def get_ai_runtime_client() -> AIRuntimeClient:
    """Return the singleton client for the otalon-ai internal surface.

    Targets the configured otalon-ai base URL with the fixed 5 s push
    timeout from the AIRuntimeClient default (AI-045 Task 2.3).

    Returns:
        A configured :class:`AIRuntimeClient` singleton.
    """
    settings = get_settings()
    return AIRuntimeClient(settings.ai_url)


@lru_cache(maxsize=1)
def get_override_store() -> DeviceTypeOverrideStore:
    """Return a singleton DeviceTypeOverrideStore.

    Returns:
        A :class:`DeviceTypeOverrideStore` backed by the default JSON file.
    """
    return DeviceTypeOverrideStore()


def get_topology_service(
    postgres_repo: PostgresRepository = Depends(get_postgres_repo),
    influx_repo: InfluxRepository = Depends(get_influx_repo),
    settings: Settings = Depends(get_settings),
    override_store: DeviceTypeOverrideStore = Depends(get_override_store),
    cache_manager: CacheManager = Depends(get_cache_manager),
) -> TopologyService:
    """Build a TopologyService with injected repositories and settings.

    Args:
        postgres_repo: PostgreSQL repository dependency.
        influx_repo: InfluxDB repository dependency.
        settings: Application settings dependency.
        override_store: Device type override store dependency.
        cache_manager: Shared cache manager for TTL-based caching of
            the expensive ``get_topology`` aggregate.

    Returns:
        A configured :class:`TopologyService` instance.
    """
    return TopologyService(postgres_repo, influx_repo, settings, override_store, cache_manager)


def get_event_bus() -> EventBus:
    """Return the singleton EventBus instance.

    Delegates to the module-level singleton factory in
    :mod:`otalon_api.services.event_bus`.

    Returns:
        The global :class:`EventBus` instance.
    """
    return _get_event_bus_singleton()


@lru_cache(maxsize=1)
def get_operations_jobs_service() -> OperationsJobsService:
    """Return the singleton :class:`OperationsJobsService`.

    Caches the service because it wraps the shared PostgresRepository
    and EventBus instances.

    Returns:
        A configured :class:`OperationsJobsService`.
    """
    return OperationsJobsService(postgres_repo=get_postgres_repo(), event_bus=get_event_bus())


@lru_cache(maxsize=1)
def get_pcap_upload_service() -> PcapUploadService:
    """Return the singleton streaming upload sink for capture files.

    Returns:
        A :class:`PcapUploadService` bound to the configured import volume
        and the server-side size budget.
    """
    from pathlib import Path

    settings = get_settings()
    return PcapUploadService(Path(settings.pcap_import_dir), settings.pcap_import_max_upload_bytes)


@lru_cache(maxsize=1)
def get_pcap_import_worker_client() -> PcapImportWorkerClient:
    """Return the singleton client for the netcap pcap-import worker."""
    settings = get_settings()
    base = f"http://{settings.pcap_import_worker_host}:{settings.pcap_import_worker_port}"
    return PcapImportWorkerClient(
        base,
        timeout=settings.pcap_import_worker_timeout_s,
        api_key=settings.admin_api_key,
    )


@lru_cache(maxsize=1)
def get_pcap_import_service() -> PcapImportService:
    """Return the singleton PCAP import job owner.

    Cached because the dispatch loop and the request path must share the
    same instance (and therefore the same delivery lock), so a background
    pass and an inbound upload cannot both hand a job to the single-slot
    worker at once.
    """
    from pathlib import Path

    settings = get_settings()
    config = PcapImportConfig(
        import_dir=Path(settings.pcap_import_dir),
        measurement=settings.netcap_measurement,
        dispatch_interval_s=settings.pcap_import_dispatch_interval_s,
        orphan_grace_s=settings.pcap_import_orphan_grace_s,
        archive_keep=settings.pcap_import_archive_keep,
    )
    return PcapImportService(
        jobs_service=get_operations_jobs_service(),
        influx_repo=get_influx_repo(),
        worker=get_pcap_import_worker_client(),
        config=config,
    )


@lru_cache(maxsize=1)
def get_operations_maintenance_service() -> OperationsMaintenanceService:
    """Return the local, non-destructive maintenance service."""
    return OperationsMaintenanceService(get_settings())


@lru_cache(maxsize=1)
def get_operations_backup_service() -> OperationsBackupService:
    """Return the local backup manifest service.

    No ``restore_executor`` is wired: a real restore is destructive and MUST NOT
    run in the unattended deployment, so the live restore path fails closed with
    :class:`RestoreNotAvailable` while the precheck/dry-run path stays available.
    """
    from pathlib import Path

    settings = get_settings()
    return OperationsBackupService(Path(settings.backup_dir), restore_executor=None, settings=settings)


def get_operations_reset_service(
    postgres_repo: PostgresRepository = Depends(get_postgres_repo),
) -> OperationsResetService:
    """Return the domain-scoped reset executor over the narrow PG surface."""
    return OperationsResetService(postgres_repo)


@lru_cache(maxsize=1)
def get_detection_readiness_service() -> DetectionReadinessService:
    """Return the derived detection-readiness service.

    Resolves the singleton :class:`InfluxRepository` once and passes the
    same instance both as ``influx=`` and into :func:`get_proto_hash_resolver`.
    The resolver provider carries a ``Depends`` default for FastAPI request
    injection, so it MUST be called with the concrete repository here; calling
    it without an argument would seed the shared resolver with the unresolved
    ``Depends`` sentinel and break protocol hash resolution for every request.
    """
    # Raw environment read on purpose (API-043): this is the path to *another*
    # subproject's config file, the same category the settings idiom exempts for
    # a service's own config path. Container-vs-local layout is per-deployment
    # (Compose points it at the real host workspace path).
    config_path = os.environ.get(
        "OTALON_CLAS_CONFIG_PATH",
        "/home/user/otalon-github/otalon-clas/config/config.json",
    )
    influx_repo = get_influx_repo()
    return DetectionReadinessService(
        get_postgres_repo(),
        config_path,
        get_settings().model_dir,
        influx=influx_repo,
        settings=get_settings(),
        proto_resolver=get_proto_hash_resolver(influx_repo),
    )


@lru_cache(maxsize=1)
def get_label_source_service() -> LabelSourceService:
    """Return the shared-folder label-source service."""
    settings = get_settings()
    return LabelSourceService(settings.model_dir, settings.model_worker_dir)


async def require_api_key(
    api_key: str | None = Security(_api_key_header),
    settings: Settings = Depends(get_settings),
) -> None:
    """Validate the X-API-Key header against the configured admin key.

    Use as a FastAPI dependency on individual endpoints that require
    API-key authentication.

    Args:
        api_key: The X-API-Key header value (injected).
        settings: Application settings (injected).

    Raises:
        HTTPException: 401 if the key is missing or does not match.
    """
    if not settings.admin_api_key:
        return
    if not api_key or api_key != settings.admin_api_key:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
