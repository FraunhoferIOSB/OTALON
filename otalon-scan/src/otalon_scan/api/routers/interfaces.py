"""Scan-interface router — ``GET /scans/interfaces`` (SCAN-033 extraction).

Kept as its own module (rather than folded into ``routers/scans.py``)
because it depends on no application state at all: it reads the host's
network interfaces directly. It MUST still be included before the
scan router so ``/scans/interfaces`` is registered ahead of the catch-all
``/scans/{scan_id}``.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from ...core.auth import verify_api_key
from ...core.interface_roles import list_interfaces
from ..schemas.interfaces import InterfaceItem, InterfacesResponse

__all__ = ["router"]

router = APIRouter()


@router.get(
    "/scans/interfaces",
    response_model=InterfacesResponse,
    dependencies=[Depends(verify_api_key("viewer"))],
)
async def list_scan_interfaces() -> InterfacesResponse:
    """Return host network interfaces enriched with scan roles.

    Sourced from :func:`psutil.net_if_addrs` and :func:`psutil.net_if_stats`.
    Mirror interfaces (``OTALON_SCAN_MIRROR_INTERFACES`` env) are never
    classified as ``active_scan``.
    """
    return InterfacesResponse(interfaces=[InterfaceItem(**iface) for iface in list_interfaces()])
