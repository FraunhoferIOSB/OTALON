"""Per-module full-config Pydantic schema for ``pn_discovery``.

See :mod:`otalon_scan.modules.arp_scan.config` for the design rationale shared
across all ``*Config`` schemas introduced by F-02.

Module-type discriminator: ``"pn_discovery"``.
"""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class PnDiscoveryConfig(BaseModel):
    """Full configuration for the ``pn_discovery`` module."""

    model_config = ConfigDict(extra="forbid", strict=True)

    module_type: Literal["pn_discovery"] = "pn_discovery"

    network_interface: Optional[str] = None
    broadcast: str = Field(
        default="01:0e:cf:00:00:00",
        description="L2 broadcast MAC for PROFINET DCP IDENTIFY frames.",
    )
    sniff_time: int = Field(default=2, ge=1, le=120)
    filter_net: bool = Field(default=False)
    # P8 Welle E (F-11): optional single-station result filter. Carried
    # through the merged-config re-validation (module_manager) so a
    # caller-supplied ``target_mac`` override does not trip ``extra=forbid``.
    # PROFINET DCP Identify is multicast; this is a response filter, not a
    # unicast destination (see ``pn_discovery/schema.py`` /
    # ``pn_discovery/start.py``).
    target_mac: Optional[str] = Field(
        default=None,
        description="Optional single PROFINET station MAC to filter results to.",
    )
