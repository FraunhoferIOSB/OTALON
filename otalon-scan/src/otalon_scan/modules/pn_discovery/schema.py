"""Per-module override schema for the ``pn_discovery`` scanner.

PROFINET discovery is largely L2-broadcast-driven. The bind interface is
the long-standing override; P8 Welle E (F-11) adds an optional
``target_mac`` so a scan launched from a single asset can be restricted to
that one PROFINET station instead of returning every responder.

PROFINET DCP Identify is an inherently *multicast* discovery frame
(``01:0e:cf:00:00:00``); the protocol has no reliable unicast-targeted
Identify that all stations honour. ``target_mac`` is therefore applied as
a **result filter** — the multicast Identify is still sent, but only the
response whose source MAC matches ``target_mac`` is surfaced. This keeps
the discovery correct (no fabricated unicast that a device might ignore)
while delivering the single-asset targeting the operator asked for. The
decision is documented at the module (``pn_discovery/start.py``).

Unknown keys are rejected (``extra="forbid"``).
"""

from __future__ import annotations

from typing import ClassVar, Optional

from pydantic import BaseModel, ConfigDict, ValidationInfo, field_validator

from otalon_scan.core.validators import (
    mirror_override_allowed,
    validate_network_interface,
    validate_target_mac,
)


class PnDiscoveryOverrides(BaseModel):
    """Caller-controlled override fields for the ``pn_discovery`` module.

    Fields:
        network_interface: Host network interface used for the PROFINET
            DCP broadcast (validated against ``psutil.net_if_addrs()``).
        target_mac: Optional single PROFINET station MAC to restrict the
            results to (P8 Welle E / F-11). Canonicalised to lowercase
            colon-separated form. When set, the DCP Identify is still sent
            as a multicast, but only the responder matching this MAC is
            surfaced (see module docstring for the multicast-vs-unicast
            rationale).
    """

    model_config = ConfigDict(extra="forbid")

    requires_auth: ClassVar[bool] = False

    network_interface: Optional[str] = None
    target_mac: Optional[str] = None

    @field_validator("network_interface")
    @classmethod
    def _validate_network_interface(cls, value: Optional[str], info: ValidationInfo) -> Optional[str]:
        """Reject a mirror/SPAN bind interface unless deliberately overridden (SCAN-037)."""
        if value is None:
            return None
        return validate_network_interface(value, allow_mirror=mirror_override_allowed(info))

    @field_validator("target_mac")
    @classmethod
    def _validate_target_mac(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        return validate_target_mac(value)
