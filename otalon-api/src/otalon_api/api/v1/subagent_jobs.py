"""Subagent jobs REST + SSE proxy router.

Forwards UI requests to the otalon-ai service and proxies the
SSE event stream so the browser only needs network access to
``otalon-api``.
"""

from __future__ import annotations

import json
from typing import Any, AsyncIterator, Dict, Optional, cast

import httpx
from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from loguru import logger

from otalon_api.services.subagent_service import SubagentService

router = APIRouter(prefix="/api/v1", tags=["subagent-jobs"])


def _service(request: Request) -> SubagentService:
    svc = getattr(request.app.state, "subagent_service", None)
    if svc is None:
        raise HTTPException(status_code=503, detail="subagent service not configured")
    return cast(SubagentService, svc)


# ── Trigger from alert-detail page ─────────────────────────────────────


@router.post("/alerts/{alarm_id}/classify", status_code=202)
async def classify_alarm(
    alarm_id: str,
    payload: Dict[str, Any],
    request: Request,
) -> Dict[str, Any]:
    svc = _service(request)
    try:
        return await svc.start_classification(alarm_id=alarm_id, payload=payload or {})
    except httpx.HTTPStatusError as exc:
        try:
            detail = exc.response.json()
        except Exception:
            detail = {"detail": exc.response.text}
        raise HTTPException(status_code=exc.response.status_code, detail=detail)
    except httpx.HTTPError as exc:
        logger.error("subagent service unreachable: {}", exc)
        raise HTTPException(status_code=502, detail=f"subagent service unreachable: {exc}")


# ── List / detail / cancel ─────────────────────────────────────────────


@router.get("/subagent-jobs")
async def list_subagent_jobs(
    request: Request,
    alarm_id: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    summary: bool = Query(default=True),
) -> Dict[str, Any]:
    svc = _service(request)
    try:
        return await svc.list_jobs(
            alarm_id=alarm_id,
            status=status,
            limit=limit,
            offset=offset,
            summary=summary,
        )
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"subagent service unreachable: {exc}")


@router.get("/subagent-jobs/{job_id}")
async def get_subagent_job(job_id: str, request: Request) -> Dict[str, Any]:
    svc = _service(request)
    try:
        return await svc.get_job(job_id)
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=exc.response.status_code, detail=exc.response.text)
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"subagent service unreachable: {exc}")


@router.post("/subagent-jobs/{job_id}/cancel")
async def cancel_subagent_job(job_id: str, request: Request) -> Dict[str, Any]:
    svc = _service(request)
    try:
        return await svc.cancel_job(job_id)
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=exc.response.status_code, detail=exc.response.text)
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"subagent service unreachable: {exc}")


# ── SSE proxy ──────────────────────────────────────────────────────────


@router.get("/subagent-jobs/{job_id}/events")
async def stream_subagent_events(job_id: str, request: Request) -> StreamingResponse:
    svc = _service(request)

    async def _proxy_iter() -> AsyncIterator[bytes]:
        try:
            async for chunk in svc.stream_events(job_id):
                yield chunk
        except httpx.HTTPStatusError as exc:
            payload = json.dumps(
                {
                    "type": "error",
                    "reason": "upstream_status",
                    "status": exc.response.status_code,
                }
            )
            yield f"event: error\ndata: {payload}\n\n".encode("utf-8")
        except Exception as exc:
            # ``json.dumps`` escapes quotes and newlines in the exception
            # text; the previous f-string interpolation produced a
            # malformed SSE frame whenever the message contained either
            # (API-07).
            payload = json.dumps(
                {
                    "type": "error",
                    "reason": "upstream_disconnected",
                    "detail": f"{type(exc).__name__}: {exc}",
                }
            )
            yield f"event: error\ndata: {payload}\n\n".encode("utf-8")

    return StreamingResponse(
        _proxy_iter(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
