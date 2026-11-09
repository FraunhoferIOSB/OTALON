"""Per-module override schema for the ``arp_scan`` scanner.

This schema is the **authoritative shape** for the ``overrides`` payload
that the API layer accepts in ``POST /scans/start`` when ``module_name``
resolves to ``arp_scan``. Every field is wired to its corresponding
validator in :mod:`otalon_scan.core.validators` via a ``field_validator``;
unknown keys are rejected (``extra="forbid"``).

Normative reference: ``scan--input-validation`` spec, Phase 2 of the
``harden-otalon-scan-security`` OpenSpec change.
"""

from __future__ import annotations

from typing import ClassVar, Optional

from pydantic import BaseModel, ConfigDict, ValidationInfo, field_validator

from otalon_scan.core.validators import (
    mirror_override_allowed,
    validate_network_interface,
    validate_target_subnet,
)


class ArpScanOverrides(BaseModel):
    """Caller-controlled override fields for the ``arp_scan`` module.

    Fields:
        network_interface: Host network interface to scan from (validated
            against ``psutil.net_if_addrs()``).
        target_subnet: IPv4 or IPv6 subnet in CIDR notation; host bits are
            tolerated and the canonical network form is stored.
    """

    model_config = ConfigDict(extra="forbid")

    requires_auth: ClassVar[bool] = False

    network_interface: Optional[str] = None
    target_subnet: Optional[str] = None

    @field_validator("network_interface")
    @classmethod
    def _validate_network_interface(cls, value: Optional[str], info: ValidationInfo) -> Optional[str]:
        """Reject a mirror/SPAN bind interface unless deliberately overridden (SCAN-037)."""
        if value is None:
            return None
        return validate_network_interface(value, allow_mirror=mirror_override_allowed(info))

    @field_validator("target_subnet")
    @classmethod
    def _validate_target_subnet(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        return validate_target_subnet(value)
