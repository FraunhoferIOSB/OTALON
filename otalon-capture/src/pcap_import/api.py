"""HTTP surface of the PCAP import worker.

The worker is a passive receiver: the job owner pushes an import to
``POST /import`` and is answered immediately, while the work happens
asynchronously. ``GET /health`` mirrors the recorder's health endpoint so
Compose and the owner can see the worker's state.

Handlers do no blocking IO themselves — the service starts a background thread
and every handler returns from in-memory state.
"""

from __future__ import annotations

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from loguru import logger
from starlette.status import HTTP_409_CONFLICT

from capture_settings_base import OperatorAuthSettings

from .models import HealthResponse, ImportAccepted, ImportRequest, ImportStatus
from .service import ImportService, NoActiveImportError, WorkerBusyError


def create_app(service: ImportService) -> FastAPI:
    """Build the FastAPI application wired to ``service``.

    Args:
        service: The single-slot import service backing all routes.

    Returns:
        The configured application.
    """

    app = FastAPI(
        title="OTALON PCAP Import Worker",
        version="0.1.0",
        description=(
            "Single-slot worker that imports a capture file into InfluxDB "
            "through the shared capture pipeline. Internal service; jobs are "
            "pushed by otalon-api."
        ),
    )

    async def require_operator_api_key(request: Request) -> None:
        """Require the suite ``X-API-Key`` operator credential.

        Shares ``capture_settings_base.OperatorAuthSettings`` with
        ``pcap_recorder.api.require_operator_api_key`` so both capture-side
        services enforce literally the same contract — PCAP-007 replaced the
        two hand-parsed copies that had already drifted. The import routes
        previously had no authentication at all: any party able to reach the
        worker could submit an import and read job status (audit CAP-02).
        """
        auth = OperatorAuthSettings.from_env()
        if not auth.is_configured:
            raise HTTPException(status_code=503, detail="API key authentication unavailable")
        if not auth.matches(request.headers.get("X-API-Key", "")):
            raise HTTPException(status_code=401, detail="Invalid or missing API key")

    def get_service() -> ImportService:
        return service

    @app.get("/health", response_model=HealthResponse)
    async def healthcheck(svc: ImportService = Depends(get_service)) -> HealthResponse:
        """Return liveness plus whether the worker is currently occupied."""

        return svc.health()

    @app.get("/status", response_model=ImportStatus)
    async def status(
        svc: ImportService = Depends(get_service),
        _auth: None = Depends(require_operator_api_key),
    ) -> ImportStatus:
        """Return the detailed status of the current or most recent import."""

        return svc.status

    @app.post("/import", response_model=ImportAccepted, status_code=202)
    async def start_import(
        request: ImportRequest,
        svc: ImportService = Depends(get_service),
        _auth: None = Depends(require_operator_api_key),
    ) -> ImportAccepted:
        """Accept an import job for asynchronous processing.

        Args:
            request: The pushed job (file path, display id, time window).
            svc: The import service.

        Returns:
            An acknowledgement carrying the acceptance timestamp.

        Raises:
            HTTPException: ``409`` when another import is already running, so
                the owner keeps the job and delivers it again later.
        """

        try:
            accepted_at = svc.submit(request)
        except WorkerBusyError as busy:
            logger.info(
                "Refusing job {display_id}: worker busy with {running}.",
                display_id=request.display_id,
                running=busy.display_id,
            )
            raise HTTPException(
                status_code=HTTP_409_CONFLICT,
                detail={
                    "message": "Worker is busy with another import.",
                    "running_display_id": busy.display_id,
                },
            ) from busy
        return ImportAccepted(display_id=request.display_id, accepted_at=accepted_at)

    @app.post("/import/cancel", status_code=202)
    async def cancel_import(
        svc: ImportService = Depends(get_service),
        _auth: None = Depends(require_operator_api_key),
    ) -> JSONResponse:
        """Request cancellation of the running import.

        Cancelling aborts a running job and frees the worker slot, so it is
        a mutation of worker state and carries the same operator credential
        as ``POST /import``. It was the one route CAP-02 left open, so any
        party able to reach the worker could abort an import (audit
        PCAP-005).

        Returns:
            A ``202`` acknowledgement naming the job being cancelled.

        Raises:
            HTTPException: ``409`` when no import is currently running.
        """

        try:
            display_id = svc.cancel()
        except NoActiveImportError as inactive:
            raise HTTPException(
                status_code=HTTP_409_CONFLICT,
                detail={"message": "No import is currently running."},
            ) from inactive
        return JSONResponse(status_code=202, content={"display_id": display_id, "state": "cancelling"})

    return app
