"""Core helper functions for MCP tools.

This module encapsulates logic for core-level tools like ping and capabilities.
It is initialized via tools.__init__.init() which passes the Defaults object.

Docstrings are written in English as per workspace rules.
"""

from __future__ import annotations

from typing import Any, Dict, List

from loguru import logger

DEFAULTS: Any | None = None


def init(defaults: Any) -> None:
    """Initialize core helpers with shared defaults."""
    global DEFAULTS
    DEFAULTS = defaults
    logger.debug("tools.core.init: defaults injected")


def ping() -> Dict[str, Any]:
    """Return a simple pong response to verify reachability."""
    result = {"ok": True, "message": "pong"}
    logger.info("tools.core.ping -> {result}", result=result)
    return result


def capabilities() -> Dict[str, Any]:
    """List capability groups and the current default configuration."""
    if DEFAULTS is None:
        err = {"ok": False, "error": "Defaults not initialized"}
        logger.error("tools.core.capabilities error: {err}", err=err)
        return err

    groups: List[Dict[str, str]] = [
        {"group": "core.*", "description": "Server metadata and health probes"},
        {"group": "postgres.*", "description": "OTALON PostgreSQL data access"},
        {"group": "influx.*", "description": "OTALON InfluxDB data access"},
        {
            "group": "pcap.*",
            "description": (
                "PCAP recorder tools: list/inspect PCAP chunks, "
                "look up chunks by alarm ID, "
                "run tshark analyses, retrieve protocol/conversation/IO stats, "
                "flag anomaly time windows"
            ),
        },
        {
            "group": "mitre.*",
            "description": (
                "MITRE ICS ATT&CK framework lookups: tactics, techniques, "
                "sub-techniques, full-text search, data updates"
            ),
        },
    ]
    result: Dict[str, Any] = {
        "ok": True,
        "groups": groups,
        "defaults": {
            "measurement": DEFAULTS.measurement,
            "id_tag": DEFAULTS.id_tag,
            "fields": list(DEFAULTS.fields),
        },
    }
    logger.info("tools.core.capabilities -> {result}", result=result)
    return result
