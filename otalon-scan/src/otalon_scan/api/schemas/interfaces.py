"""Pydantic wire models for the scan-interface endpoint (SCAN-033 extraction).

Moved verbatim out of :mod:`otalon_scan.api.server`; shapes unchanged.
"""

from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel

__all__ = ["InterfaceItem", "InterfacesResponse"]


class InterfaceItem(BaseModel):
    """Single interface row for ``GET /scans/interfaces``.

    Angereichertes Host-Interface mit Scan-Rolle (``active_scan``,
    ``mirror``, ``other``).
    """

    name: str
    ipv4: Optional[str] = None
    subnet: Optional[str] = None
    is_up: bool
    role: str
    mac: Optional[str] = None
    is_default: bool = False


class InterfacesResponse(BaseModel):
    """Envelope for ``GET /scans/interfaces``."""

    interfaces: List[InterfaceItem]
