"""Baseline lifecycle REST endpoints."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, cast
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field

from otalon_api.dependencies import get_operations_jobs_service
from otalon_api.domain.operations import OperationsAuditAppend
from otalon_api.services.baseline_service import (
    BaselineConflict,
    BaselineNotFound,
    BaselineService,
    BaselineValidationError,
)
from otalon_api.services.operations_jobs_service import OperationsJobsService

router = APIRouter(prefix="/api/v1/baselines", tags=["baselines"])


class CreateBaselineBody(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: Optional[str] = None
    start_ts: datetime
    end_ts: datetime
    created_by: Optional[str] = None


def _service(request: Request) -> BaselineService:
    svc = getattr(request.app.state, "baseline_service", None)
    if svc is None:
        raise HTTPException(status_code=503, detail="baseline service not configured")
    return cast(BaselineService, svc)


@router.get("", response_model=List[Dict[str, Any]])
async def list_baselines(request: Request) -> List[Dict[str, Any]]:
    return await asyncio.to_thread(_service(request).list)


@router.get("/preview", response_model=Dict[str, Any])
async def preview_baseline(
    request: Request,
    start_ts: datetime = Query(...),
    end_ts: datetime = Query(...),
) -> Dict[str, Any]:
    if start_ts.tzinfo is None:
        start_ts = start_ts.replace(tzinfo=timezone.utc)
    if end_ts.tzinfo is None:
        end_ts = end_ts.replace(tzinfo=timezone.utc)
    return await asyncio.to_thread(_service(request).preview, start_ts, end_ts)


@router.get("/{baseline_id}", response_model=Dict[str, Any])
async def get_baseline(baseline_id: UUID, request: Request) -> Dict[str, Any]:
    try:
        return await asyncio.to_thread(_service(request).get, baseline_id)
    except BaselineNotFound:
        raise HTTPException(status_code=404, detail="baseline not found")


@router.get("/{baseline_id}/activity", response_model=Dict[str, Any])
async def baseline_activity(baseline_id: UUID, request: Request) -> Dict[str, Any]:
    """Placeholder for the Phase-5 sanity-check sparkline."""
    try:
        baseline = await asyncio.to_thread(_service(request).get, baseline_id)
    except BaselineNotFound:
        raise HTTPException(status_code=404, detail="baseline not found")
    return {
        "baseline_id": baseline["id"],
        "start_ts": baseline["start_ts"],
        "end_ts": baseline["end_ts"],
        "series": [],
    }


@router.post("", status_code=201, response_model=Dict[str, Any])
async def create_baseline(body: CreateBaselineBody, request: Request) -> Dict[str, Any]:
    if body.start_ts.tzinfo is None:
        body.start_ts = body.start_ts.replace(tzinfo=timezone.utc)
    if body.end_ts.tzinfo is None:
        body.end_ts = body.end_ts.replace(tzinfo=timezone.utc)
    try:
        # ``create`` does PostgreSQL writes, a directory listing, an Influx
        # query, ``os.link`` and ``shutil.copy2`` — offloaded as one hop so
        # the whole sequence leaves the event loop (API-05).
        return await asyncio.to_thread(
            _service(request).create,
            name=body.name,
            description=body.description,
            start_ts=body.start_ts,
            end_ts=body.end_ts,
            created_by=body.created_by,
        )
    except BaselineValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.payload)
    except BaselineConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc))


@router.post("/{baseline_id}/activate", response_model=Dict[str, Any])
async def activate_baseline(
    baseline_id: UUID,
    request: Request,
    jobs_service: OperationsJobsService = Depends(get_operations_jobs_service),
) -> Dict[str, Any]:
    try:
        result = await asyncio.to_thread(_service(request).activate, baseline_id)
        await jobs_service.append_audit(
            OperationsAuditAppend(
                category="config",
                actor="operator",
                action="activate_baseline",
                target=str(baseline_id),
                reason="baseline activation",
            )
        )
        return result
    except BaselineNotFound:
        raise HTTPException(status_code=404, detail="baseline not found")


@router.delete("/{baseline_id}", status_code=204, response_class=Response, response_model=None)
async def delete_baseline(
    baseline_id: UUID,
    request: Request,
    jobs_service: OperationsJobsService = Depends(get_operations_jobs_service),
) -> None:
    try:
        await asyncio.to_thread(_service(request).delete, baseline_id)
        await jobs_service.append_audit(
            OperationsAuditAppend(
                category="config",
                actor="operator",
                action="delete_baseline",
                target=str(baseline_id),
                reason="baseline deletion",
            )
        )
    except BaselineNotFound:
        raise HTTPException(status_code=404, detail="baseline not found")
    except BaselineConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc))
