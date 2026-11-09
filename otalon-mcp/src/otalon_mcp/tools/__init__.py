"""Tools package for MCP helpers (core, web, influx, postgres, pcap).

This package provides a central init() to inject runtime dependencies
(PostgresRepo, InfluxRepo, Defaults, pcap_url) into individual helper modules.

Modules:
- tools.core: capabilities, ping
- tools.web: DuckDuckGo search and web-related helpers
- tools.influx: InfluxDB time series helpers
- tools.postgres: PostgreSQL data access helpers
- tools.pcap: PCAP recorder REST API helpers

Docstrings are written in English as per workspace rules.
"""

from __future__ import annotations

from typing import Any

from loguru import logger

# Relative imports inside the package
from . import agent as agent_tools  # noqa: F401
from . import baseline as baseline_tools  # noqa: F401
from . import core as core_tools  # noqa: F401
from . import frequency as frequency_tools  # noqa: F401
from . import influx as influx_tools  # noqa: F401
from . import mitre as mitre_tools  # noqa: F401
from . import pcap as pcap_tools  # noqa: F401
from . import postgres as postgres_tools  # noqa: F401
from . import training as training_tools  # noqa: F401
from . import web as web_tools  # noqa: F401


def init(
    pg_repo: Any,
    influx_repo: Any,
    defaults: Any,
    pcap_url: str = "",
    pcap_timeout: int = 30,
    pcap_api_key: str = "",
    stix_path: str = "",
    agent_url: str = "",
    agent_timeout: float = 5.0,
    pg_dsn: str = "",
    baseline_dir: str = "/app/pcap/baseline",
    api_url: str = "",
    api_key: str = "",
    api_timeout: float = 10.0,
    confirm_nonce_ttl: float = 300.0,
) -> None:
    """Initialize all helper modules with shared runtime dependencies.

    Every value below is resolved once in ``otalon_mcp.settings`` and
    injected from ``server.create_server`` (MCP-014); no helper module
    reads the process environment for configuration.

    Parameters
    ----------
    pg_repo : Any
        Postgres repository instance used by postgres helpers.
    influx_repo : Any
        Influx repository instance used by influx helpers.
    defaults : Any
        Default configuration object (measurement, id_tag, fields).
    pcap_url : str
        Base URL of the pcap_recorder REST API (default empty).
    pcap_timeout : int
        Request timeout in seconds for pcap_recorder calls (default 30).
    pcap_api_key : str
        Operator key sent to pcap_recorder as ``X-API-Key``.
    stix_path : str
        Filesystem path to the MITRE ATT&CK ICS STIX bundle.
    agent_url : str
        Base URL of otalon-ai; empty disables the agent proxy tools.
    agent_timeout : float
        Proxy-call timeout in seconds for agent tools.
    pg_dsn : str
        PostgreSQL DSN used by the baseline helpers.
    baseline_dir : str
        Directory holding curated baseline PCAP chunks.
    api_url : str
        Base URL of otalon-api used by training/frequency proxies.
    api_key : str
        Operator key forwarded to otalon-api as ``X-API-Key``.
    api_timeout : float
        Outbound request timeout in seconds for otalon-api calls.
    confirm_nonce_ttl : float
        Lifetime in seconds of a retrain confirmation nonce.
    """
    try:
        core_tools.init(defaults=defaults)
    except Exception as exc:
        logger.error("tools.core.init failed: {exc}", exc=exc)
        raise

    try:
        web_tools.init()
    except Exception as exc:
        logger.error("tools.web.init failed: {exc}", exc=exc)
        raise

    try:
        influx_tools.init(influx_repo=influx_repo, defaults=defaults)
    except Exception as exc:
        logger.error("tools.influx.init failed: {exc}", exc=exc)
        raise

    try:
        postgres_tools.init(pg_repo=pg_repo, defaults=defaults)
    except Exception as exc:
        logger.error("tools.postgres.init failed: {exc}", exc=exc)
        raise

    try:
        pcap_tools.init(pcap_url=pcap_url, timeout=pcap_timeout, api_key=pcap_api_key)
    except Exception as exc:
        logger.error("tools.pcap.init failed: {exc}", exc=exc)
        raise

    try:
        mitre_tools.init(stix_path=stix_path)
    except Exception as exc:
        logger.error("tools.mitre.init failed: {exc}", exc=exc)
        raise

    try:
        agent_tools.init(agent_url=agent_url, timeout=agent_timeout)
    except Exception as exc:
        logger.error("tools.agent.init failed: {exc}", exc=exc)
        raise

    try:
        baseline_tools.init(dsn=pg_dsn, baseline_dir=baseline_dir)
    except Exception as exc:
        logger.error("tools.baseline.init failed: {exc}", exc=exc)
        raise

    try:
        training_tools.init(
            api_url=api_url,
            api_key=api_key,
            timeout=api_timeout,
            confirm_nonce_ttl=confirm_nonce_ttl,
        )
    except Exception as exc:
        logger.error("tools.training.init failed: {exc}", exc=exc)
        raise

    try:
        frequency_tools.init(api_url=api_url, api_key=api_key, timeout=api_timeout)
    except Exception as exc:
        logger.error("tools.frequency.init failed: {exc}", exc=exc)
        raise

    logger.info("tools.init completed: core, web, influx, postgres, pcap, mitre, agent, baseline, training initialized")


__all__ = [
    "init",
    "core_tools",
    "web_tools",
    "influx_tools",
    "postgres_tools",
    "pcap_tools",
    "mitre_tools",
    "agent_tools",
    "baseline_tools",
    "training_tools",
    "frequency_tools",
]
