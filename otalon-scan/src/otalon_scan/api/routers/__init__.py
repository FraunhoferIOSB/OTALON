"""Resource-scoped ``APIRouter`` modules for the otalon-scan HTTP surface.

One module per resource, each exporting a module-level ``router``.
Re-exports only — no side effects at import time.

Include order in :mod:`otalon_scan.api.server` is load-bearing: ``interfaces``
MUST be included before ``scans`` so ``/scans/interfaces`` is registered
ahead of the catch-all ``/scans/{scan_id}``.
"""

from .devices import router as devices_router
from .health import router as health_router
from .interfaces import router as interfaces_router
from .modules import router as modules_router
from .scan_events import router as scan_events_router
from .scans import router as scans_router
from .vulnerabilities import router as vulnerabilities_router

__all__ = [
    "devices_router",
    "health_router",
    "interfaces_router",
    "modules_router",
    "scan_events_router",
    "scans_router",
    "vulnerabilities_router",
]
