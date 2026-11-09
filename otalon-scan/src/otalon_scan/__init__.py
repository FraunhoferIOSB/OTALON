"""CyberScan-ICS package initializer.

This package contains:

- ``core``: scanner infrastructure — the :class:`~otalon_scan.core.protocols.ScanModule`
  Protocol, the :class:`~otalon_scan.core.module_manager.ModuleManager` orchestrator
  (sole writer to scan-result tables), settings, and logging.
- ``api``: FastAPI server to trigger and manage scans.
- ``modules``: concrete scan modules conforming to the ``ScanModule`` Protocol.
- ``repositories``: PostgreSQL persistence layer (used exclusively by the
  orchestrator, never by modules).

Usage:
    - Serve API: ``uvicorn otalon_scan.api.server:app --host 0.0.0.0 --port 8091``
    - Programmatic: import helpers from subpackages
"""

from __future__ import annotations

__all__ = [
    "core",
    "api",
    "repositories",
]
