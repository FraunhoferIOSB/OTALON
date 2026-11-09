"""Per-module override schema for the ``opcua_discover`` scanner.

Minimal schema for Phase 2 of ``harden-otalon-scan-security``. Unknown
keys are rejected (``extra="forbid"``); the ``target_port`` field has no
dedicated Phase-1 validator yet — it is bounded inline here to the IANA
range ``[1, 65535]``.
"""

from __future__ import annotations

from typing import ClassVar, Optional

from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator

from otalon_scan.core.validators import (
    mirror_override_allowed,
    validate_network_interface,
    validate_target_ip,
)


class OpcuaDiscoverOverrides(BaseModel):
    """Caller-controlled override fields for the ``opcua_discover`` module.

    Fields:
        network_interface: Host network interface to probe from
            (validated against ``psutil.net_if_addrs()``).
        target_ip: Single IPv4 or IPv6 OPC UA server address.
        target_port: TCP port (1-65535). Defaults to the module config
            when omitted.
    """

    model_config = ConfigDict(extra="forbid")

    requires_auth: ClassVar[bool] = False

    network_interface: Optional[str] = None
    target_ip: Optional[str] = None
    target_port: Optional[int] = Field(default=4840, ge=1, le=65535)

    @field_validator("network_interface")
    @classmethod
    def _validate_network_interface(cls, value: Optional[str], info: ValidationInfo) -> Optional[str]:
        """Reject a mirror/SPAN bind interface unless deliberately overridden (SCAN-037)."""
        if value is None:
            return None
        return validate_network_interface(value, allow_mirror=mirror_override_allowed(info))

    @field_validator("target_ip")
    @classmethod
    def _validate_target_ip(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        return validate_target_ip(value)
