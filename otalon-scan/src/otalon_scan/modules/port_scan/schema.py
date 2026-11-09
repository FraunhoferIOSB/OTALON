"""Per-module override schema for the ``port_scan`` scanner.

This schema is the **authoritative shape** for the ``overrides`` payload
that the API layer accepts in ``POST /scans/start`` when ``module_name``
resolves to ``port_scan``. Every field is wired to its corresponding
validator in :mod:`otalon_scan.core.validators` via a ``field_validator``;
unknown keys are rejected (``extra="forbid"``).

Every field exposed here is genuinely consumed by
:mod:`otalon_scan.modules.port_scan.start` — no decorative fields. Each is
caller-controllable attack surface on a NET_RAW/NET_ADMIN process, so
each carries a bounded validator that rejects abusive values before any
argv element reaches :func:`subprocess.run` (``shell=False``).

Normative reference: ``scan--input-validation`` spec, extended by
SCAN-003/009/010/014 of the overnight override-schema batch.
"""

from __future__ import annotations

from typing import ClassVar, Optional

from pydantic import BaseModel, ConfigDict, ValidationInfo, field_validator

from otalon_scan.core.validators import (
    mirror_override_allowed,
    validate_hard_timeout_s,
    validate_host_timeout_ms,
    validate_network_interface,
    validate_port_range,
    validate_target_ip,
    validate_timing_template,
)


class PortScanOverrides(BaseModel):
    """Caller-controlled override fields for the ``port_scan`` module.

    Fields:
        target_ip: Single IPv4 or IPv6 target address; the canonical form
            returned by :func:`ipaddress.ip_address` is stored.
        port_range: nmap-style port-range expression. Accepted grammar:
            ``^\\d+(-\\d+)?(,\\d+(-\\d+)?)*$`` with each numeric token in
            ``[1, 65535]`` and ascending ranges only.
        timing_template: nmap ``-T<n>`` selector; single decimal digit
            ``0``-``5``.
        network_interface: Host interface to bind the scan to (nmap
            ``-e <iface>``); validated against ``psutil.net_if_addrs()``.
        udp_scan: When true, nmap runs a UDP scan (``-sU``).
        service_version_info: When true, nmap performs service/version
            detection (``-sV``); opt-in only — the plain TCP connect scan
            is the fast default.
        detection_and_traceroute: When true (and not UDP), nmap runs
            aggressive detection + traceroute (``-A``).
        host_timeout_ms: nmap ``--host-timeout`` value in milliseconds,
            bounded to ``[100, 3_600_000]``.
        hard_timeout_s: Hard subprocess timeout (seconds) wrapping the
            whole nmap invocation, bounded to ``[1, 3_600]``.
    """

    model_config = ConfigDict(extra="forbid")

    requires_auth: ClassVar[bool] = False

    target_ip: Optional[str] = None
    port_range: Optional[str] = None
    timing_template: Optional[str] = None
    network_interface: Optional[str] = None
    udp_scan: Optional[bool] = None
    service_version_info: Optional[bool] = None
    detection_and_traceroute: Optional[bool] = None
    host_timeout_ms: Optional[int] = None
    hard_timeout_s: Optional[int] = None

    @field_validator("target_ip")
    @classmethod
    def _validate_target_ip(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        return validate_target_ip(value)

    @field_validator("port_range")
    @classmethod
    def _validate_port_range(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        return validate_port_range(value)

    @field_validator("timing_template")
    @classmethod
    def _validate_timing_template(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        return validate_timing_template(value)

    @field_validator("network_interface")
    @classmethod
    def _validate_network_interface(cls, value: Optional[str], info: ValidationInfo) -> Optional[str]:
        """Reject a mirror/SPAN bind interface unless deliberately overridden (SCAN-037)."""
        if value is None:
            return None
        return validate_network_interface(value, allow_mirror=mirror_override_allowed(info))

    @field_validator("host_timeout_ms")
    @classmethod
    def _validate_host_timeout_ms(cls, value: Optional[int]) -> Optional[int]:
        if value is None:
            return None
        return validate_host_timeout_ms(value)

    @field_validator("hard_timeout_s")
    @classmethod
    def _validate_hard_timeout_s(cls, value: Optional[int]) -> Optional[int]:
        if value is None:
            return None
        return validate_hard_timeout_s(value)
