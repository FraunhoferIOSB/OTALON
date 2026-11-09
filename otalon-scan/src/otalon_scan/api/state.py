"""Shared runtime state for the otalon-scan HTTP surface (SCAN-033).

Replaces the seven module-level globals that used to live in
:mod:`otalon_scan.api.server` (``_manager``, ``_repo``, ``_settings``,
``_main_loop``, ``_run_to_scan_map``, ``_finished_runs``,
``_lookup_registry``) with a single mutable container stored on
``app.state.api_state``.

Two consumer classes read the same instance:

- **Request-scoped handlers** reach it through the typed FastAPI
  dependencies in :mod:`otalon_scan.api.dependencies`.
- **Non-request-scoped orchestrator callbacks** (the ``ModuleManager``
  monitor-thread sinks in :mod:`otalon_scan.api.scan_sink`) receive the instance
  explicitly at lifespan wiring time — they have no ``Request`` to
  resolve a dependency from.

The container is constructed at *application construction* time, not
inside the lifespan, so the eagerly-needed members
(:attr:`ApiState.lookup_registry`, :attr:`ApiState.run_to_scan_map`,
:attr:`ApiState.finished_runs`) exist before startup completes — matching
the pre-SCAN-033 import-time semantics. The lifespan mutates the instance
in place and never rebinds it.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Dict, Optional

from ..core.module_manager import ModuleManager
from ..cve_lookup import LookupJobRegistry
from ..repositories.postgres_repo import ScannerPostgresRepo
from ..settings import Settings

__all__ = ["ApiState"]


@dataclass
class ApiState:
    """Mutable runtime state shared by handlers and orchestrator sinks.

    Attributes:
        manager: The scanner :class:`ModuleManager`; ``None`` until the
            lifespan startup constructs it.
        repo: The async :class:`ScannerPostgresRepo`; ``None`` until the
            lifespan startup has validated PostgreSQL connectivity.

            HC4 (2026-05-18): the previous Silent-Fallback ``_MemoryRepo``
            was removed. otalon-scan refuses to start when PostgreSQL is
            unreachable instead of pretending to run while losing all scan
            results on the next container restart, so the production path
            only ever sees :class:`ScannerPostgresRepo`. Tests that want an
            in-memory fake build their own.
        settings: The parsed :class:`Settings`; ``None`` before startup.
        main_loop: The FastAPI event loop captured at lifespan startup.
            The orchestrator monitor thread dispatches coroutines onto it
            with :func:`asyncio.run_coroutine_threadsafe`.
        run_to_scan_map: Mapping of orchestrator ``run_id`` to persisted
            ``scan_id``. Written by ``POST /scans/start``, read by the
            module-finished callback on the monitor thread.
        finished_runs: Mapping of finished ``run_id`` to module name.
            Written by the module-finished callback on the monitor thread,
            read by ``GET /scans/finished``.
        lookup_registry: In-process registry of running CVE-lookup jobs
            (SCAN-026 WA.3/WA.4). Holds the asyncio task plus progress bus
            per ``job_id``. Created eagerly so the POST handler can
            dispatch a job without waiting on the lifespan, and reconciled
            on startup (WA.5).
    """

    manager: Optional[ModuleManager] = None
    repo: Optional[ScannerPostgresRepo] = None
    settings: Optional[Settings] = None
    main_loop: Optional[asyncio.AbstractEventLoop] = None
    run_to_scan_map: Dict[str, str] = field(default_factory=dict)
    finished_runs: Dict[str, str] = field(default_factory=dict)
    lookup_registry: LookupJobRegistry = field(default_factory=LookupJobRegistry)
