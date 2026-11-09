"""Per-module full-config Pydantic schema for ``opcua_discover``.

See :mod:`otalon_scan.modules.arp_scan.config` for the design rationale shared
across all ``*Config`` schemas introduced by F-02.

Module-type discriminator: ``"opcua_discover"``.
"""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class OpcUaDiscoverConfig(BaseModel):
    """Full configuration for the ``opcua_discover`` module."""

    model_config = ConfigDict(extra="forbid", strict=True)

    module_type: Literal["opcua_discover"] = "opcua_discover"

    network_interface: Optional[str] = None
    target_ip: str = Field(..., description="OPC UA server address (IPv4 or IPv6).")
    target_port: int = Field(default=4840, ge=1, le=65535)
    discovery_timeout: int = Field(default=10, ge=1, le=300)
