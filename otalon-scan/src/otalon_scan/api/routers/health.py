"""Health router — ``GET /health`` (SCAN-033 extraction).

Deliberately does NOT use the raising state dependencies: ``/health`` must
answer even when the lifespan startup has not completed. A missing module
manager degrades to ``0`` counts, a missing settings object to a
``"unknown"`` port label, and a missing repository yields **503** with a
structured detail dict — not the 500 the other routers raise.

Logging note (SCAN-034): stdlib ``logging`` call site moved verbatim.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from loguru import logger

from ...core.module_manager import ModuleManager
from ...repositories.postgres_repo import ScannerPostgresRepo
from ...settings import Settings
from ..dependencies import (
    get_optional_manager,
    get_optional_repo,
    get_optional_settings,
)

__all__ = ["router"]

router = APIRouter()


@router.get("/health")
async def health(
    deep: bool = False,
    manager: Optional[ModuleManager] = Depends(get_optional_manager),
    repo: Optional[ScannerPostgresRepo] = Depends(get_optional_repo),
    settings: Optional[Settings] = Depends(get_optional_settings),
) -> Dict[str, Any]:
    """Liveness + (optional) deep dependency probe.

    F-02 / scan--observability:

    - **Plain** ``GET /health`` — sub-millisecond liveness check.
      Returns 200 with ``{"status": "ok"}`` whenever the FastAPI
      process is alive, regardless of Postgres availability or active
      scans. Performs no I/O. This is the Docker ``HEALTHCHECK``
      target.

    - ``GET /health?deep=true`` — dependency probe. Performs the
      ``SELECT 1`` probe against Postgres via
      :meth:`ScannerPostgresRepo.probe` (1 s timeout), reports the
      count of discovered modules and the count of currently active
      scans. Returns 200 with
      ``{"postgres": "ok", "modules_discovered": N, "active_scans": M}``
      on full success or 503 with
      ``{"postgres": "error", "error_message": "...", "modules_discovered": N, "active_scans": M}``
      on Postgres failure.

    HC4 (2026-05-18) compatibility: the previous behaviour folded the
    Postgres ping into the plain ``/health``. F-02 moves that probe
    behind ``?deep=true``; clients that need the DB-aware response (the
    HC4 503 case and recovery flip) MUST opt in via the query
    parameter.
    """
    port = settings.server.port if settings else None
    port_str = str(port) if port else "unknown"

    if not deep:
        return {"status": "ok", "port": port_str}

    # Deep probe — F-02 / scan--observability Requirement "Deep
    # /health?deep=true Endpoint".
    modules_discovered = len(manager.get_module_names()) if manager is not None else 0
    # SC-01: ``get_all_running_modules_status`` runs the blocking
    # cleanup/finalize path; keep it off the event loop.
    active_scans = (
        len(await asyncio.to_thread(manager.get_all_running_modules_status))
        if manager is not None
        else 0
    )

    if repo is None:
        raise HTTPException(
            status_code=503,
            detail={
                "postgres": "error",
                "error_message": "repo_not_initialized",
                "modules_discovered": modules_discovered,
                "active_scans": active_scans,
                "port": port_str,
            },
        )

    ok, err = await repo.probe()
    if not ok:
        logger.warning("/health?deep=true: PostgreSQL probe failed: {}", err)
        raise HTTPException(
            status_code=503,
            detail={
                "postgres": "error",
                "error_message": err or "unknown",
                "modules_discovered": modules_discovered,
                "active_scans": active_scans,
                "port": port_str,
            },
        )

    return {
        "postgres": "ok",
        "modules_discovered": modules_discovered,
        "active_scans": active_scans,
        "port": port_str,
    }
