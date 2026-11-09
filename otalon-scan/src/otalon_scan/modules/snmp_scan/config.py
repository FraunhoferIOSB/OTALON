"""Per-module full-config Pydantic schema for ``snmp_scan``.

See :mod:`otalon_scan.modules.arp_scan.config` for the design rationale shared
across all ``*Config`` schemas introduced by F-02.

Module-type discriminator: ``"snmp_scan"``.

The ``communities`` field is a list of ``[cidr, community_string, version]``
tuples preserved as a generic 3-element shape to match the legacy
``config.json``. A future change (``scan--module-completion`` /
``scan--mcp-tools``) MAY tighten this into a named structured model;
the placeholder here is sufficient for the current strict-validation gate.
"""

from __future__ import annotations

from typing import List, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field


class SnmpScanConfig(BaseModel):
    """Full configuration for the ``snmp_scan`` module."""

    model_config = ConfigDict(extra="forbid", strict=True)

    module_type: Literal["snmp_scan"] = "snmp_scan"

    network_interface: Optional[str] = None
    target_ip: Optional[str] = None
    # ``communities`` is a list of ``[cidr, community_string, snmp_version]``
    # entries; JSON arrays decode to Python lists so we type the inner
    # element as ``list[str | int]`` rather than ``tuple`` (Pydantic
    # ``strict=True`` rejects list→tuple coercion). A future change MAY
    # tighten the shape into a named structured model.
    communities: List[List[Union[str, int]]] = Field(
        default_factory=list,
        description="List of [cidr, community_string, snmp_version] entries.",
    )
    # P8 Welle G (F-09): the per-OID walk timeout. A single snmp_scan runs
    # six sequential walks (system, PNO-LLDP, plus the four LLDP/FDB
    # neighbor tables); each unanswered walk costs ``timeout × (retries+1)``
    # on the pysnmp UDP transport. A non-switch target (e.g. a PLC) does not
    # expose the LLDP/FDB tables, so those walks always run to full timeout.
    # With the old 30s/2-retry default that was ~90s per dead table → an
    # observed 3m6s single-target scan. 5s is ~100× a normal LAN SNMP RTT,
    # so a genuinely reachable device still answers on the first attempt,
    # while the worst case drops to ~10s per dead walk (~60s all-dead, ~20s
    # for the typical PLC with two dead tables). See wave-G-report.md for the
    # full time-budget math. Bounds unchanged so an operator MAY raise it.
    operation_timeout: int = Field(default=5, ge=1, le=600)
    retry_attempts: int = Field(default=1, ge=0, le=10)
