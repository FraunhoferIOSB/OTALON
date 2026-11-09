"""Per-module full-config Pydantic schema for ``arp_scan``.

This schema is the authoritative shape for the *merged* configuration
that ``arp_scan`` consumes: the module's ``config.json`` defaults plus
any caller-supplied overrides from a ``POST /scans/start`` request.

Distinct from :mod:`otalon_scan.modules.arp_scan.schema` (``ArpScanOverrides``),
which validates only the partial-override payload at the API boundary
and is intentionally permissive about ``None`` values.

Both schemas reject unknown fields (``extra="forbid"``). ``ArpScanConfig``
additionally sets ``strict=True`` so type coercion is rejected (e.g. a
JSON-encoded ``"30"`` string for an integer field fails fast).

Module-type discriminator: ``"arp_scan"`` — symmetric with the
discriminator used in ``ArpScanResult`` (see
``scan--scanresult-contract``).

Normative reference: ``scan--module-config-schemas`` spec, F-02
(``refactor-otalon-scan-code-quality-v1``).
"""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class ArpScanConfig(BaseModel):
    """Full configuration for the ``arp_scan`` module."""

    model_config = ConfigDict(extra="forbid", strict=True)

    module_type: Literal["arp_scan"] = "arp_scan"

    network_interface: Optional[str] = None
    target_subnet: str = Field(..., description="IPv4/IPv6 subnet in CIDR notation.")

    host_timeout_ms: int = Field(default=1000, ge=1, le=600_000)
    max_retries: int = Field(default=1, ge=0, le=10)
    min_parallelism: int = Field(default=1, ge=1, le=1024)
    hard_timeout_s: int = Field(default=120, ge=1, le=3600)
