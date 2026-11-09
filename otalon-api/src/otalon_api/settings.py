"""Pydantic-Settings based application configuration.

Loads settings from environment variables (via local ``.env.compose`` for
source runs and Compose injection in containers) and from
``config/config.json`` with ``$ENV_VAR`` placeholder substitution.

This service is the one documented exception to the suite-wide settings idiom
(SUITE-038): it keeps ``pydantic_settings.BaseSettings`` because it genuinely
sources fields from ``../.env`` via ``env_file`` and flattens ``config.json``
sections onto those same flat fields. Only the *placeholder resolution* is
shared — ``load_config_json`` delegates to ``otalon_common.config`` under
``MissingEnvVarPolicy.WARN_AND_DROP``, which drops an unresolved key so the
Pydantic field default applies, exactly as the local resolver used to.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from loguru import logger
from otalon_common.config import MissingEnvVarPolicy, resolve_env_placeholders
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# ``settings.py`` sits at ``src/otalon_api/settings.py`` since SUITE-032, so
# the subproject root is three levels up, not two.
_PROJECT_DIR = Path(__file__).resolve().parents[2]
_CONFIG_PATH = _PROJECT_DIR / "config" / "config.json"
_ENV_PATH = _PROJECT_DIR.parent / ".env.compose"


def load_config_json(config_path: Path = _CONFIG_PATH) -> dict[str, Any]:
    """Load and resolve ``config.json`` with environment-variable substitution.

    A placeholder whose variable is unset is warned about and its key is
    dropped, so the consuming Pydantic field falls back to its default.

    Args:
        config_path: Path to the JSON configuration file.

    Returns:
        The fully resolved configuration dictionary.
    """
    with open(config_path, encoding="utf-8") as fh:
        raw = json.load(fh)
    resolved = resolve_env_placeholders(
        raw,
        policy=MissingEnvVarPolicy.WARN_AND_DROP,
        json_arrays=True,
        expand_nested=True,
    )
    return cast(dict[str, Any], resolved)


class LoggingConfig(BaseModel):
    """Logging configuration."""

    level: str = "INFO"
    file: str = "api.log"


class Settings(BaseSettings):
    """Application settings sourced from environment variables and config.json."""

    influxdb_host: str = Field(default="localhost", description="InfluxDB hostname")
    influxdb_port: int = Field(default=8181, description="InfluxDB port")
    influxdb_token: str = Field(
        default="",
        description="InfluxDB access token",
        alias="influx_token",
        validation_alias="influx_token",
    )
    influxdb_org: str = Field(default="", description="InfluxDB organization")
    influxdb_database: str = Field(default="netcap", description="InfluxDB database / bucket name")

    postgres_host: str = Field(default="localhost", description="PostgreSQL hostname")
    postgres_port: int = Field(default=5432, description="PostgreSQL port")
    postgres_user: str = Field(default="postgres", description="PostgreSQL user")
    postgres_password: str = Field(default="", description="PostgreSQL password")
    postgres_database: str = Field(default="otalon", description="PostgreSQL database name")

    admin_api_key: str = Field(default="", description="API key for admin endpoints")
    otalon_api_allowed_keys: str = Field(
        default="",
        description="Comma-separated name:role:key entries for API authentication",
    )
    retrain_cooldown_minutes: float = Field(
        default=30.0,
        ge=0,
        description="Minimum minutes between terminal runtime retrains",
    )
    api_port: int = Field(default=8090, description="Port the API listens on")

    pcap_recorder_host: str = Field(default="localhost", description="PCAP Recorder hostname")
    pcap_recorder_port: int = Field(default=9090, description="PCAP Recorder port")
    pcap_recorder_timeout_s: float = Field(
        default=10.0,
        description="HTTP timeout (seconds) for outbound calls to the PCAP recorder",
    )
    pcap_recorder_api_key: str = Field(
        default="",
        description=(
            "Optional X-API-Key forwarded to the PCAP recorder. The recorder "
            "currently has no auth layer; this field is reserved so the proxy "
            "is ready when the recorder gains one (see audit findings)."
        ),
    )
    pcap_buffer_dir: str = Field(
        default="/app/baseline/../buffer",
        description=(
            "Filesystem path to the live PCAP ringbuffer. Used by the baseline "
            "service for hardlink lookup. Inside containers normally pointing to "
            "the shared/pcap/buffer mount."
        ),
    )
    pcap_archive_dir: str = Field(
        default="/app/baseline/../archive",
        description="Filesystem path to the PCAP archive (older chunks).",
    )
    pcap_baseline_dir: str = Field(
        default="/app/baseline",
        description="Filesystem path where curated baseline-PCAP-hardlinks live.",
    )
    operations_artifact_dir: str = Field(
        default="/app/operations",
        description="Suite-owned bounded directory for maintenance artifacts.",
    )
    pcap_import_dir: str = Field(
        default="/import",
        description=(
            "Shared import volume for uploaded capture files. MUST be mounted "
            "under the SAME path in otalon-api and the pcap-import worker: "
            "the api hands the worker an absolute path which the worker opens "
            "verbatim."
        ),
    )
    pcap_import_max_upload_bytes: int = Field(
        default=536_870_912,
        gt=0,
        description=(
            "Hard server-side upload limit for capture files in bytes "
            "(default 512 MiB, deliberately conservative). Enforced while "
            "streaming, not from the client-declared Content-Length."
        ),
    )
    pcap_import_worker_host: str = Field(
        default="localhost",
        description="Hostname of the netcap pcap-import worker.",
    )
    pcap_import_worker_port: int = Field(
        default=9092,
        description="Port of the netcap pcap-import worker (Wave A: 9092).",
    )
    pcap_import_worker_timeout_s: float = Field(
        default=10.0,
        gt=0,
        description="HTTP timeout in seconds for outbound calls to the import worker.",
    )
    pcap_import_worker_token: str = Field(
        default="",
        description=(
            "Shared secret the import worker presents on the PATCH "
            "/internal/jobs/{display_id} report channel. The same value must be "
            "configured on the worker side as PCAP_IMPORT_WORKER_TOKEN. The "
            "channel fails closed when this is empty."
        ),
    )
    pcap_import_dispatch_interval_s: float = Field(
        default=5.0,
        gt=0,
        description="Cadence of the delivery/orphan-recovery reconciliation loop.",
    )
    pcap_import_orphan_grace_s: float = Field(
        default=120.0,
        gt=0,
        description=(
            "Minimum age of a 'running' import job before it may be treated as "
            "orphaned. Protects a freshly delivered job from being re-queued "
            "because of a health-probe race."
        ),
    )
    pcap_import_archive_keep: int = Field(
        default=20,
        ge=0,
        description="Number of failed/cancelled uploads retained in the import archive.",
    )
    backup_dir: str = Field(
        default="/app/operations/backups",
        description=(
            "Persistent suite-owned directory for backup archives and manifests. "
            "Compose supplies BACKUP_DIR=/app/operations/backups. This is the "
            "single source for the backup location: the maintenance storage "
            "footprint used to carry an independent /var/backups fallback "
            "(API-043) which disagreed with this default whenever the variable "
            "was unset."
        ),
    )
    backup_config_source: str = Field(
        default="/home/user/otalon-github",
        description=(
            "Root the config-backup allowlist is resolved against. Compose sets "
            "BACKUP_CONFIG_SOURCE to the real host path the workspace is bind-"
            "mounted at, keeping the container-path == host-path invariant so "
            "the config backup reads the live worktree."
        ),
    )
    backup_postgres_source: str = Field(
        default="/var/lib/postgresql/data",
        description=(
            "Source directory of the 'postgresql' backup scope. Compose points "
            "BACKUP_POSTGRES_SOURCE at a bind that is absent by default, so the "
            "scope fails closed instead of producing a false-verified empty "
            "archive."
        ),
    )
    pcap_config_path: str = Field(
        default="/app/netcap-config/config_pcap.json",
        description="Shipped Netcap PCAP configuration visible to the API runtime.",
    )
    baseline_min_uci_count: int = Field(
        default=10,
        description="Minimum distinct UCIs required to accept a baseline window",
    )
    baseline_min_pcap_chunks: int = Field(
        default=50,
        description="Minimum number of PCAP chunks required to accept a baseline window",
    )
    otalon_scan_host: str = Field(default="localhost", description="OTALON Scan hostname")
    otalon_scan_port: int = Field(default=8091, description="OTALON Scan port")
    otalon_scan_api_key: str = Field(
        default="",
        description="Operator-level X-API-Key for outbound calls to otalon-scan:8091",
    )
    mcp_host: str = Field(default="localhost", description="OTALON-MCP hostname")
    mcp_port: int = Field(default=9000, description="OTALON-MCP port")
    ai_url: str = Field(
        default="http://localhost:9100",
        description="OTALON-AI base URL (chat orchestration + subagent classification jobs)",
    )
    ai_timeout_s: float = Field(
        default=5.0,
        description="HTTP timeout for synchronous AI service calls (job creation, list, get)",
    )
    otalon_ai_api_key: str = Field(
        default="",
        description=(
            "X-API-Key for outbound calls to otalon-ai:9100. Must match an entry "
            "in the AI service's OTALON_AI_ALLOWED_KEYS allow-list, which protects "
            "the /jobs and /api/v1/chat prefixes."
        ),
    )
    otalon_ai_internal_key: str = Field(
        default="",
        description=(
            "X-API-Key for the internal live-LLM-config push from this API to "
            "OTALON_AI_INTERNAL_KEY on otalon-ai:9100 (AI-045). Must match an "
            "operator-role entry in the AI service's OTALON_AI_ALLOWED_KEYS "
            "allow-list. When empty the push step is skipped and the save "
            "response reports live_applied=false (the .env.compose file stays "
            "the source for the next start). Injected by Compose; not part "
            "of config.json."
        ),
    )
    frequency_tolerance_factor: float = Field(
        default=2.0,
        gt=0,
        description=(
            "Global default frequency-tolerance factor mirroring "
            "otalon-clas/config/config.json. Only used to report the "
            "effective factor for profiles that carry no operator override."
        ),
    )
    absence_timeout_factor: float = Field(
        default=3.0,
        gt=0,
        description=(
            "Global default absence-timeout factor mirroring "
            "otalon-clas/config/config.json. Multiplied with a profile's "
            "mean_interval to derive the absence deadline."
        ),
    )
    absence_timeout_floor_s: float = Field(
        default=45.0,
        ge=0,
        description=(
            "Absence-timeout floor mirroring otalon-clas poll_interval + "
            "delay + margin. This API setting and the detector floor MUST "
            "be kept in sync."
        ),
    )
    absence_interval_cap_s: float = Field(
        default=86400.0,
        ge=0,
        description=(
            "Upper bound on mean_interval for which absence monitoring is "
            "active. Profiles exceeding this cap have no deadline computed; "
            "mirrors otalon-clas absence_interval_cap_seconds."
        ),
    )
    frequency_relative_floor_factor: float = Field(
        default=0.5,
        ge=0,
        description=(
            "Detector deviation-threshold floor multiplier on mean_interval, "
            "mirroring otalon-clas frequency_monitor.relative_floor_factor. "
            "The detector applies max(tolerance * std, factor * mean); this "
            "value lets the correction Preview name a tolerance change the "
            "floor would make a no-op. Must be kept in sync with the detector."
        ),
    )
    frequency_last_seen_flush_interval_s: float = Field(
        default=60.0,
        gt=0,
        description=(
            "Tolerated staleness of frequency_profiles.last_seen, mirroring "
            "otalon-clas frequency_monitor.last_seen_flush_interval_seconds. "
            "The detector keeps last_seen exact in memory but persists it in "
            "batches, so a fast series' persisted value legitimately trails "
            "its own absence deadline; absence is only derived from the "
            "deadline once the silence exceeds this budget."
        ),
    )
    health_check_timeout_s: float = Field(default=3.0, description="Timeout for health probes in seconds")
    otalon_clas_container_name: str = Field(
        default="otalon-clas",
        description="OTALON Clas Docker container name",
    )
    training_timeout_s: float = Field(
        default=3600.0,
        description=(
            "Hard upper bound (seconds) on a otalon-clas training run. "
            "Observed production runs are ~5–15 min; the default 60 min is "
            "generous and never silent — the orchestrator fails loud past it."
        ),
    )
    model_dir: str = Field(
        default="/app/models",
        description="API-visible shared model directory; Compose maps it to the host shared/models folder.",
    )
    model_worker_dir: str = Field(
        default="/app/models",
        description="Canonical model directory visible to the otalon-clas worker.",
    )

    host_storage_root: str = Field(
        default="/",
        description=(
            "Container-visible path of the host '/' mount. The API runs in a "
            "container whose own filesystem is not the operator's; Compose "
            "bind-mounts the host root read-only at /host-storage/root and sets "
            "HOST_STORAGE_ROOT accordingly. Unset (local run) the default '/' "
            "correctly measures the developer's own root."
        ),
    )
    host_storage_home: str = Field(
        default="/home",
        description="Container-visible path of the host '/home' mount (Compose: /host-storage/home).",
    )
    host_storage_var: str = Field(
        default="/var",
        description="Container-visible path of the host '/var' mount (Compose: /host-storage/var).",
    )
    host_influx_data_path: str = Field(
        default="/host-storage/var/lib/docker",
        description=(
            "Container-visible path of the InfluxDB data volume, used only for "
            "the storage-footprint estimate. Compose narrows it to the concrete "
            "volume _data directory; the coarser default keeps the estimate "
            "non-fatal when the variable is unset."
        ),
    )
    host_postgres_data_path: str = Field(
        default="/host-storage/var/lib/docker",
        description=(
            "Container-visible path of the PostgreSQL data volume for the "
            "storage-footprint estimate. See host_influx_data_path."
        ),
    )
    host_log_path: str = Field(
        default="/host-storage/var/log",
        description="Container-visible path of the host log directory for the storage-footprint estimate.",
    )

    compose_image: str = Field(default="docker:24.0.9-cli", description="Docker image for compose runner")
    compose_file: str = Field(
        default="/home/user/otalon-github/docker-compose.yml",
        description="Path to docker-compose.yml",
    )
    env_compose_path: str = Field(
        default="/home/user/otalon-github/.env.compose",
        description="Path to .env.compose file",
    )

    logging_level: str = Field(default="INFO", description="Log level")
    logging_file: str = Field(default="api.log", description="Log file path")

    netcap_measurement: str = Field(
        default="network_metrics",
        description="InfluxDB measurement name for Netcap data",
    )
    netcap_id_tag: str = Field(
        default="uci",
        description="Tag column used as unique communication identifier",
    )
    netcap_sparse_port_threshold: int = Field(
        default=10,
        description="Minimum distinct port count to consider a UCI sparse",
    )
    timezone_name: str = Field(
        default="Europe/Berlin",
        description="IANA timezone name for local time conversions (e.g. Europe/Berlin)",
    )
    default_sample_max_points: int = Field(
        default=500,
        description="Default maximum data points for aggregated time-series queries",
    )
    pipeline_poll_interval_seconds: int = Field(
        default=5,
        description=(
            "API-side expected freshness interval in seconds between source "
            "records, used to derive the freshness 'stale' threshold "
            "(stale when age > k x this interval, k=3). This is an "
            "independent, deployer-aligned API setting "
            "(env PIPELINE_POLL_INTERVAL_SECONDS); it is NOT read live from "
            "the otalon-clas runtime. Keep it aligned with the CLAS "
            "prediction.live.poll_interval_seconds cadence at deploy time. "
            "The default 5s matches the shipped CLAS config default."
        ),
    )
    pipeline_lookback_hours: int = Field(
        default=24,
        description=(
            "Maximum lookback window in hours for judging whether a pipeline "
            "source has never received data ('no-data' state)."
        ),
    )
    topology_subnet_protocols_lookback_hours: int = Field(
        default=168,
        description=(
            "Number of hours to look back in InfluxDB when computing "
            "subnet-level protocol lists for the PROFINET heuristic."
        ),
    )

    session_cookie_secure: bool = Field(
        default=True,
        description=(
            "Enables Secure cookies for HTTPS requests. The API derives the "
            "response flag from the direct or X-Forwarded-Proto scheme, so "
            "plain-HTTP development requests remain browser-compatible while "
            "HTTPS requests retain cookie hardening. Keep true in production."
        ),
    )

    @property
    def log_config(self) -> LoggingConfig:
        """Return a LoggingConfig from the flattened settings."""
        return LoggingConfig(level=self.logging_level, file=self.logging_file)

    # Re-declared explicitly per the otalon-api row of the settings policy table
    # (backend.md § "Config & Settings idiom"). otalon-api is the one documented
    # exception that keeps ``pydantic_settings.BaseSettings`` because it really
    # sources fields from ``../.env`` via ``env_file``. ``extra="ignore"`` is
    # required, not cosmetic: ``from_config_json`` flattens *every* config.json
    # key onto the model, so an unmapped section key must be dropped rather than
    # turn boot into a ValidationError.
    model_config = SettingsConfigDict(
        env_file=str(_ENV_PATH),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @classmethod
    def from_config_json(cls, config_path: Path = _CONFIG_PATH) -> "Settings":
        """Create a Settings instance by merging config.json values with env vars.

        Args:
            config_path: Path to the JSON configuration file.

        Returns:
            A fully populated Settings instance.
        """
        try:
            cfg = load_config_json(config_path)
        except Exception as exc:
            logger.warning("Could not load config.json, falling back to env-only settings: {}", exc)
            return cls()

        field_names = set(cls.model_fields.keys())
        flat: dict[str, Any] = {}
        for section_key, section in cfg.items():
            if isinstance(section, dict):
                for key, value in section.items():
                    prefixed = f"{section_key}_{key}"
                    if prefixed in field_names:
                        flat[prefixed] = value
                    elif key in field_names:
                        flat[key] = value
                    else:
                        flat[prefixed] = value
            else:
                flat[section_key] = section

        return cls(**flat)
