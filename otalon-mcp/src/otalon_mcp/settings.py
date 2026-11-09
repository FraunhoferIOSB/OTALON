"""Settings loader for the OTALON MCP server.

Configuration is loaded from ``config/config.json`` with ``$ENV_VAR``
placeholders resolved by the shared ``otalon_common.config`` resolver
(SUITE-038). A missing variable is a hard error, as it was before the
convergence.

MCP-014 additionally made this module the *single* place where the
service's configuration values are resolved. Every value the server and
the tool modules consume is a typed field below; no call site reads the
process environment for a configuration value any more.

Two resolution layers exist, in this order (last one wins):

1. ``config/config.json`` — file values, ``$ENV_VAR`` placeholders
   resolved under :data:`MissingEnvVarPolicy.RAISE`.
2. The optional environment overrides in :func:`_apply_env_overrides`.

Layer 2 exists because layer 1 is fail-hard by policy: a ``$VAR``
placeholder in ``config.json`` makes that variable *mandatory*, and the
overrides below are all optional tuning knobs that no environment file in
the suite defines. Modelling them as placeholders would turn every
deployment that omits them into a boot failure. They are therefore read
once, here, instead of at the 20 scattered call sites MCP-014 removed.

Credentials (``otalon_api.api_key``, ``pcap_recorder.api_key``) are
deliberately absent from ``config.json``: they are environment-only and
carry no default.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Final, Self

from otalon_common.config import BaseSettings, MissingEnvVarPolicy
from pydantic import BaseModel, ConfigDict, Field

DEFAULT_INFLUX_FIELDS: Final[tuple[str, ...]] = (
    "packet_count",
    "total_volume",
    "mean_packet_size",
    "min_packet_size",
    "max_packet_size",
    "std_packet_size",
    "mean_interarrival_time",
    "min_interarrival_time",
    "max_interarrival_time",
    "std_interarrival_time",
)
"""Field set queried from ``network_metrics`` when nothing overrides it."""

VALID_TRANSPORTS: Final[frozenset[str]] = frozenset({"stdio", "streamable-http"})
"""Transports FastMCP is started with; anything else is ignored."""


def _env_first(*names: str) -> str | None:
    """Return the first non-blank environment value among ``names``.

    Raw environment access is intentional and confined to this module:
    these are the optional overrides documented at the top of the file.

    Args:
        names: Environment variable names, highest precedence first.

    Returns:
        The stripped value, or ``None`` when none of them is set.
    """
    for name in names:
        value = os.environ.get(name)
        if value is not None and value.strip():
            return value.strip()
    return None


def _env_float(fallback: float, *names: str, minimum: float | None = None) -> float:
    """Return an environment override coerced to float, or ``fallback``.

    A malformed value falls back instead of raising, matching the
    ``try/except ValueError`` guards that surrounded these reads before
    MCP-014.

    Args:
        fallback: Value used when unset or unparsable.
        names: Environment variable names, highest precedence first.
        minimum: Optional lower clamp applied to the resolved value.

    Returns:
        The resolved timeout/TTL in seconds.
    """
    raw = _env_first(*names)
    if raw is None:
        resolved = fallback
    else:
        try:
            resolved = float(raw)
        except ValueError:
            resolved = fallback
    if minimum is not None:
        return max(minimum, resolved)
    return resolved


def parse_influx_fields(raw: str | None) -> list[str] | None:
    """Parse an Influx field list from JSON or a comma-separated string.

    Args:
        raw: The raw override value, or ``None``.

    Returns:
        The parsed field names, or ``None`` when the value carries no
        usable list (the caller then keeps the configured default).
    """
    if not raw or not raw.strip():
        return None
    text = raw.strip()
    try:
        parsed = json.loads(text)
    except ValueError:
        parsed = None
    if isinstance(parsed, list):
        return [str(item) for item in parsed if str(item).strip()]
    if "," in text:
        return [part.strip() for part in text.split(",") if part.strip()]
    return None


class ServerConfig(BaseModel):
    """MCP server runtime configuration."""

    name: str = "otalon-mcp"
    host: str = "0.0.0.0"
    port: int = 9000
    transport: str = "streamable-http"
    force_timeout_seconds: float = 8.0


class PostgresConfig(BaseModel):
    """PostgreSQL connection configuration."""

    dsn: str


class InfluxConfig(BaseModel):
    """InfluxDB connection and default-query configuration."""

    url: str
    token: str | None = None
    database: str = "netcap"
    measurement: str = "network_metrics"
    id_tag: str = "uci"
    fields: list[str] = Field(default_factory=lambda: list(DEFAULT_INFLUX_FIELDS))


class LoggingConfig(BaseModel):
    """Logging configuration for the MCP server."""

    level: str = "DEBUG"
    file: str = "otalon-mcp.log"


class PcapRecorderConfig(BaseModel):
    """PCAP recorder REST API connection configuration.

    ``api_key`` is the operator credential the recorder requires on
    ``/anomalies/flag``, ``/chunks`` and ``/chunks/{id}`` (audit MCP-04).
    It has no ``config.json`` counterpart and no default.
    """

    url: str = "http://localhost:9090"
    timeout_seconds: int = 30
    api_key: str = ""


class BaselineConfig(BaseModel):
    """Curated baseline-PCAP directory written by otalon-api."""

    directory: str = "/app/pcap/baseline"


class AgentConfig(BaseModel):
    """Connection to the otalon-ai subagent service."""

    url: str = ""
    timeout_seconds: float = 5.0


class OtalonApiConfig(BaseModel):
    """Connection to otalon-api used by the training and rhythm proxies.

    ``api_key`` is forwarded as ``X-API-Key``; it is environment-only and
    has no default.
    """

    url: str = "http://otalon-api:8090"
    api_key: str = ""
    timeout_seconds: float = 10.0
    confirm_nonce_ttl_seconds: float = 300.0


class MitreConfig(BaseModel):
    """MITRE ATT&CK ICS STIX bundle configuration."""

    stix_bundle_path: str = "data/ics-attack.json"


class Settings(BaseSettings):
    """Root configuration model parsed from config/config.json."""

    # Declared explicitly rather than inherited: the shared base forbids
    # extra keys, while this model has always ignored them (SUITE-038).
    model_config = ConfigDict(extra="ignore")

    server: ServerConfig = Field(default_factory=ServerConfig)
    postgres: PostgresConfig
    influx: InfluxConfig
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    pcap_recorder: PcapRecorderConfig = Field(default_factory=PcapRecorderConfig)
    baseline: BaselineConfig = Field(default_factory=BaselineConfig)
    agent: AgentConfig = Field(default_factory=AgentConfig)
    otalon_api: OtalonApiConfig = Field(default_factory=OtalonApiConfig)
    mitre: MitreConfig = Field(default_factory=MitreConfig)

    @classmethod
    def from_json(
        cls,
        path: str | Path,
        env_policy: MissingEnvVarPolicy = MissingEnvVarPolicy.RAISE,
        default: str | None = None,
        json_arrays: bool = True,
        expand_nested: bool = True,
    ) -> Self:
        """Load settings from a JSON config file, resolving ``$ENV_VAR``.

        Args:
            path: Path to the JSON configuration file.
            env_policy: Policy for missing variables; RAISE by default.
            default: Fallback value when env_policy is USE_DEFAULT.
            json_arrays: Parse JSON-looking values as JSON.
            expand_nested: Expand nested ``$`` references in resolved values.

        Returns:
            A validated settings instance with environment overrides applied.
        """
        settings = super().from_json(
            path,
            env_policy=env_policy,
            default=default,
            json_arrays=json_arrays,
            expand_nested=expand_nested,
        )
        return settings.with_env_overrides()

    def with_env_overrides(self) -> Self:
        """Return a copy with the optional environment overrides applied.

        Returns:
            A new settings instance; the receiver is left untouched.
        """
        return self.model_copy(
            update={
                "server": _override_server(self.server),
                "influx": _override_influx(self.influx),
                "pcap_recorder": _override_pcap_recorder(self.pcap_recorder),
                "baseline": _override_baseline(self.baseline),
                "agent": _override_agent(self.agent),
                "otalon_api": _override_otalon_api(self.otalon_api),
            }
        )


def _override_server(config: ServerConfig) -> ServerConfig:
    """Apply ``OTALON_MCP_TRANSPORT`` / ``OTALON_MCP_FORCE_TIMEOUT``.

    Args:
        config: The configured server section.

    Returns:
        The section with environment overrides applied.
    """
    transport = _env_first("OTALON_MCP_TRANSPORT")
    return config.model_copy(
        update={
            "transport": (transport if transport in VALID_TRANSPORTS else config.transport),
            "force_timeout_seconds": _env_float(config.force_timeout_seconds, "OTALON_MCP_FORCE_TIMEOUT"),
        }
    )


def _override_influx(config: InfluxConfig) -> InfluxConfig:
    """Apply the ``OTALON_MCP_INFLUX_*`` overrides.

    ``OTALON_MCP_INFLUX_DB`` and its legacy alias ``INFLUX_DATABASE`` are
    resolved here once, instead of per call site.

    Args:
        config: The configured influx section.

    Returns:
        The section with environment overrides applied.
    """
    fields = parse_influx_fields(_env_first("OTALON_MCP_INFLUX_FIELDS"))
    return config.model_copy(
        update={
            "database": _env_first("OTALON_MCP_INFLUX_DB", "INFLUX_DATABASE") or config.database,
            "measurement": _env_first("OTALON_MCP_INFLUX_MEASUREMENT") or config.measurement,
            "id_tag": _env_first("OTALON_MCP_INFLUX_ID_TAG") or config.id_tag,
            "fields": fields if fields is not None else config.fields,
        }
    )


def _override_pcap_recorder(config: PcapRecorderConfig) -> PcapRecorderConfig:
    """Resolve the recorder operator credential from the environment.

    ``PCAP_RECORDER_API_KEY`` wins over the suite-wide ``ADMIN_API_KEY``
    (audit MCP-04).

    Args:
        config: The configured pcap_recorder section.

    Returns:
        The section with the resolved credential.
    """
    api_key = _env_first("PCAP_RECORDER_API_KEY", "ADMIN_API_KEY")
    return config.model_copy(update={"api_key": api_key or config.api_key})


def _override_baseline(config: BaselineConfig) -> BaselineConfig:
    """Apply ``PCAP_BASELINE_DIR``.

    Args:
        config: The configured baseline section.

    Returns:
        The section with environment overrides applied.
    """
    return config.model_copy(update={"directory": _env_first("PCAP_BASELINE_DIR") or config.directory})


def _override_agent(config: AgentConfig) -> AgentConfig:
    """Apply the otalon-ai connection overrides.

    ``AGENT_URL`` is the legacy alias and keeps the precedence it had at
    runtime before MCP-014: the server read ``AGENT_URL`` and passed a
    non-empty value straight into ``tools.agent.init``, where it won over
    the ``AI_URL`` fallback.

    Args:
        config: The configured agent section.

    Returns:
        The section with environment overrides applied.
    """
    return config.model_copy(
        update={
            "url": _env_first("AGENT_URL", "AI_URL") or config.url,
            "timeout_seconds": _env_float(config.timeout_seconds, "AGENT_PROXY_TIMEOUT_SECONDS"),
        }
    )


def _override_otalon_api(config: OtalonApiConfig) -> OtalonApiConfig:
    """Apply the otalon-api connection overrides.

    Args:
        config: The configured otalon_api section.

    Returns:
        The section with environment overrides applied.
    """
    return config.model_copy(
        update={
            "url": _env_first("OTALON_API_URL") or config.url,
            "api_key": _env_first("OTALON_API_KEY") or config.api_key,
            "timeout_seconds": _env_float(config.timeout_seconds, "OTALON_MCP_API_TIMEOUT_SECONDS"),
            "confirm_nonce_ttl_seconds": _env_float(
                config.confirm_nonce_ttl_seconds,
                "OTALON_MCP_CONFIRM_NONCE_TTL",
                minimum=1.0,
            ),
        }
    )
