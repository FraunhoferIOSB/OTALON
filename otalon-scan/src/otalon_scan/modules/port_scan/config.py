"""Per-module full-config Pydantic schema for ``port_scan``.

See :mod:`otalon_scan.modules.arp_scan.config` for the design rationale shared
across all ``*Config`` schemas introduced by F-02
(``scan--module-config-schemas`` capability).

Module-type discriminator: ``"port_scan"``.

The shape mirrors ``config/config.json`` to satisfy startup-time
validation. Boolean toggles are accepted as strings (``"True"`` /
``"False"``) because the legacy module reads them that way; the schema
preserves the contract while still rejecting unknown fields.
"""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class PortScanConfig(BaseModel):
    """Full configuration for the ``port_scan`` module."""

    model_config = ConfigDict(extra="forbid", strict=True)

    module_type: Literal["port_scan"] = "port_scan"

    network_interface: Optional[str] = None
    target_ip: str = Field(..., description="Single IPv4 or IPv6 target address.")
    port_range: str = Field(
        default="1-1024,1089-1091,1105,1200,1911,1962,2222,2404,2455,4000,4840,4843,4911,5007,5094,9600,10000,11740,11741,18245,19999,20000,20256,20547,34962-34964,34980,44818,46823,46824,47808,55000-55003",
        description="nmap-style port range expression.",
    )
    timing_template: str = Field(default="4", description="nmap -T<n> selector (0-5).")
    udp_scan: str = Field(default="False")
    detection_and_traceroute: str = Field(default="False")
    # SCAN-010: service/version detection (``-sV``) is opt-in; a plain
    # port scan stays fast. Lower host-timeout default matches the
    # cheaper no-``-sV`` probe.
    service_version_info: str = Field(default="False")
    host_timeout_ms: str = Field(default="5000")
    hard_timeout_s: str = Field(default="120")
