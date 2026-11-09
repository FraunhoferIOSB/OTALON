"""Per-module override schema for the ``snmp_scan`` scanner.

This schema is the **authoritative shape** for the ``overrides`` payload
the API layer accepts in ``POST /scans/start`` when ``module_name``
resolves to ``snmp_scan``. Every field exposed here is genuinely consumed
by :mod:`otalon_scan.modules.snmp_scan.start` (and, for the timeout/retry pair,
the underlying :mod:`otalon_scan.modules.snmp_scan.walker` pysnmp transport) — no
decorative fields. Unknown keys are rejected (``extra="forbid"``).

Each field is caller-controllable attack surface on a NET_RAW/NET_ADMIN
process, so each carries a bounded validator in
:mod:`otalon_scan.core.validators` that rejects abusive values at the API
boundary. The ``communities`` payload is structurally validated (every
CIDR MUST parse, community strings are length-bounded, versions limited
to ``{0, 1}``) so a caller cannot smuggle arbitrary data into the
community-matching logic.

Normative reference: ``scan--input-validation`` spec, extended by
SCAN-003 (snmp half) of the overnight override-schema batch.
"""

from __future__ import annotations

from typing import ClassVar, List, Optional, Union

from pydantic import BaseModel, ConfigDict, ValidationInfo, field_validator

from otalon_scan.core.validators import (
    mirror_override_allowed,
    validate_network_interface,
    validate_operation_timeout,
    validate_retry_attempts,
    validate_snmp_communities,
    validate_target_ip,
)


class SnmpScanOverrides(BaseModel):
    """Caller-controlled override fields for the ``snmp_scan`` module.

    Fields:
        network_interface: Host network interface to bind the SNMP socket
            to (validated against ``psutil.net_if_addrs()``).
        target_ip: Single IPv4 or IPv6 target address.
        communities: List of ``[cidr, community_string, snmp_version]``
            triples; each CIDR MUST parse, each community is a non-empty
            string (<=128 chars), and each version is ``0`` or ``1``.
        operation_timeout: pysnmp UDP transport ``timeout=`` value in
            seconds, bounded to ``[1, 600]``.
        retry_attempts: pysnmp UDP transport ``retries=`` value, bounded
            to ``[0, 10]`` (``0`` means a single attempt).
    """

    model_config = ConfigDict(extra="forbid")

    requires_auth: ClassVar[bool] = True

    network_interface: Optional[str] = None
    target_ip: Optional[str] = None
    communities: Optional[List[List[Union[str, int]]]] = None
    operation_timeout: Optional[int] = None
    retry_attempts: Optional[int] = None

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

    @field_validator("communities")
    @classmethod
    def _validate_communities(
        cls, value: Optional[List[List[Union[str, int]]]]
    ) -> Optional[List[List[Union[str, int]]]]:
        if value is None:
            return None
        validate_snmp_communities(value)
        return value

    @field_validator("operation_timeout")
    @classmethod
    def _validate_operation_timeout(cls, value: Optional[int]) -> Optional[int]:
        if value is None:
            return None
        return validate_operation_timeout(value)

    @field_validator("retry_attempts")
    @classmethod
    def _validate_retry_attempts(cls, value: Optional[int]) -> Optional[int]:
        if value is None:
            return None
        return validate_retry_attempts(value)
