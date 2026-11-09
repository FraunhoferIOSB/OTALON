"""REST + SSE endpoints for subagent jobs."""

from __future__ import annotations

import asyncio
import json
from typing import Any, AsyncIterator, Dict, Optional
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, Request
from sse_starlette.sse import EventSourceResponse

from otalon_ai.jobs.domain.events import ToolCallCompletedEvent
from otalon_ai.jobs.domain.job import (
    CreateJobRequest,
    CreateJobResponse,
    JobFilter,
    JobListResponse,
    JobRecord,
    JobStatus,
)
from otalon_ai.jobs.events_bus import EventsBus
from otalon_ai.jobs.repositories.postgres_repo import AlarmsRepo, BaselineRepo, SubagentJobsRepo, run_db
from otalon_ai.jobs.worker_pool import JobSpec, WorkerPool
from otalon_ai.settings import Settings

router = APIRouter(tags=["jobs"])


# ── POST /jobs ─────────────────────────────────────────────────────────


@router.post(
    "/jobs",
    response_model=CreateJobResponse,
    status_code=202,
)
async def create_job(payload: CreateJobRequest, request: Request) -> CreateJobResponse:
    """Enqueue a new subagent classification job.

    Returns 202 with the assigned ``job_id`` immediately. The actual worker
    runs asynchronously and pushes progress to ``GET /jobs/{id}/events``.
    """
    # AI-045: read the live-applied settings (llm_config.settings), not the boot-time
    # app.state.settings. A live model switch updates llm_config; the boot snapshot
    # would otherwise stamp the old model onto every new job row.
    live_state = getattr(request.app.state, "llm_config", None) or {}
    settings: Settings = live_state.get("settings") or request.app.state.settings
    pool: WorkerPool = request.app.state.worker_pool
    jobs_repo: SubagentJobsRepo = request.app.state.jobs_repo
    alarms_repo: AlarmsRepo = request.app.state.alarms_repo
    baseline_repo: BaselineRepo = request.app.state.baseline_repo
    prompts = request.app.state.prompts

    # Validate alarm exists (AI-03: blocking SQLAlchemy off the loop)
    alarm = await run_db(alarms_repo.get_by_id, payload.alarm_id)
    if alarm is None:
        raise HTTPException(
            status_code=404,
            detail={"detail": "alarm not found", "alarm_id": payload.alarm_id},
        )

    # Resolve baseline_id
    baseline_id = payload.baseline_id
    if baseline_id is not None:
        if await run_db(baseline_repo.get_by_id, baseline_id) is None:
            raise HTTPException(
                status_code=404,
                detail={
                    "detail": "baseline not found",
                    "baseline_id": str(baseline_id),
                },
            )

    prompt_variant = payload.prompt_variant or settings.jobs.default_prompt

    # Per tasks.md Phase 9 (replace-n8n-chat-orchestration): the jobs
    # surface now routes exclusively through the LiteLLM proxy.
    #
    # - ``llm_provider`` is legacy/optional. It is still accepted in the
    #   request body for payload backward-compat with chat-MCP callers,
    #   but is no longer used to dispatch between Azure / OpenAI-compat
    #   providers. It is recorded verbatim on the job row for traceability
    #   and defaults to the literal ``"litellm"`` when absent.
    # - ``llm_model`` is a LiteLLM model identifier (e.g.
    #   ``litellm/gpt-5.4``, ``litellm/claude-opus-4-7``,
    #   ``litellm/gpt-5.5-2``). Falls back to ``settings.jobs.llm_model``.
    # - ``llm_endpoint`` is the LiteLLM proxy base URL from settings only;
    #   per Cluster d / B1 (SSRF close) it is NOT caller-controllable.
    llm_provider: str = payload.llm_provider or "litellm"
    llm_model = payload.llm_model or settings.jobs.llm_model
    llm_endpoint = settings.litellm.base_url

    reasoning_effort = payload.reasoning_effort or settings.jobs.llm_reasoning_effort

    timeout_seconds = payload.timeout_seconds or settings.jobs.timeout_seconds

    # Insert pending row (AI-03: blocking SQLAlchemy off the loop)
    job_id = await run_db(
        jobs_repo.insert_pending,
        alarm_id=payload.alarm_id,
        prompt_variant=prompt_variant,
        prompt_hash=prompts.get_hash(prompt_variant),
        llm_provider=llm_provider,
        llm_model=llm_model,
        llm_endpoint=llm_endpoint,
        reasoning_effort=reasoning_effort,
        baseline_id=baseline_id,
        timeout_seconds=timeout_seconds,
        trigger_source=payload.trigger_source,
    )

    pool.enqueue(
        JobSpec(
            job_id=job_id,
            alarm_id=payload.alarm_id,
            prompt_variant=prompt_variant,
            llm_provider=llm_provider,
            llm_model=llm_model,
            llm_endpoint=llm_endpoint,
            reasoning_effort=reasoning_effort,
            timeout_seconds=timeout_seconds,
        )
    )

    eta = await run_db(pool.estimate_eta_seconds)
    return CreateJobResponse(
        job_id=job_id,
        status=JobStatus.PENDING,
        eta_seconds=eta,
        events_url=f"/jobs/{job_id}/events",
    )


# ── GET /jobs ──────────────────────────────────────────────────────────


@router.get("/jobs", response_model=JobListResponse)
async def list_jobs(
    request: Request,
    alarm_id: Optional[str] = Query(default=None),
    status: Optional[JobStatus] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    summary: bool = Query(default=True),
) -> JobListResponse:
    """List subagent jobs with optional filtering and pagination.

    Args:
        request: Incoming FastAPI request (used to reach app state).
        alarm_id: Optional exact-match filter on ``alarm_id``.
        status: Optional filter on a single :class:`JobStatus` value.
        limit: Maximum items to return (1-200).
        offset: Pagination offset (>= 0).
        summary: When ``True`` (default) items are :class:`JobSummary`
            objects without the full ``tool_trace``; otherwise full
            :class:`JobRecord` objects are returned.

    Returns:
        A :class:`JobListResponse` carrying the page of items plus the
        unpaginated total count for the same filter.
    """
    jobs_repo: SubagentJobsRepo = request.app.state.jobs_repo
    flt = JobFilter(
        alarm_id=alarm_id,
        status=status,
        limit=limit,
        offset=offset,
        summary=summary,
    )
    items, total = await run_db(jobs_repo.list_jobs, flt)
    return JobListResponse(items=items, total=total, limit=limit, offset=offset)


# ── GET /jobs/{id} ─────────────────────────────────────────────────────


@router.get("/jobs/{job_id}", response_model=JobRecord)
async def get_job(job_id: UUID, request: Request) -> JobRecord:
    """Fetch one full job record by id.

    Args:
        job_id: UUID of the job.
        request: Incoming FastAPI request (used to reach app state).

    Returns:
        The full :class:`JobRecord` including the persisted tool trace.

    Raises:
        HTTPException: 404 when no row matches ``job_id``.
    """
    jobs_repo: SubagentJobsRepo = request.app.state.jobs_repo
    rec = await run_db(jobs_repo.get_by_id, job_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="job not found")
    return rec


# ── POST /jobs/{id}/cancel ─────────────────────────────────────────────


@router.post("/jobs/{job_id}/cancel")
async def cancel_job(job_id: UUID, request: Request) -> Dict[str, Any]:
    """Request cooperative cancellation of an in-flight job.

    Sets the worker pool's cancel flag for the job; the worker checks the
    flag between rounds and emits a terminal ``cancelled`` event when it
    next yields.

    Args:
        job_id: UUID of the active (running) job.
        request: Incoming FastAPI request (used to reach app state).

    Returns:
        A small JSON dict echoing the job id and the cancellation flag.

    Raises:
        HTTPException: 404 when the job is not currently active in the
            worker pool (already terminal or never enqueued).
    """
    pool: WorkerPool = request.app.state.worker_pool
    ok = pool.cancel(job_id)
    if not ok:
        raise HTTPException(status_code=404, detail="job not active")
    return {"job_id": str(job_id), "cancellation_requested": True}


# ── GET /jobs/{id}/events (SSE) ────────────────────────────────────────


def _serialise_event(event: Any) -> str:
    """Serialise a Pydantic event model to JSON for SSE."""
    if hasattr(event, "model_dump"):
        return json.dumps(event.model_dump(mode="json"))
    return json.dumps(event)


@router.get("/jobs/{job_id}/events")
async def stream_events(job_id: UUID, request: Request) -> EventSourceResponse:
    """Stream SSE events for a job (replay + live tail).

    The stream first replays the persisted ``tool_trace`` as
    ``tool_call_completed`` events. If the job is already terminal a
    synthetic ``final`` event is emitted and the connection closes.
    Otherwise the handler subscribes to :class:`EventsBus` and forwards
    live events until a ``final`` / ``error`` event arrives, the client
    disconnects, or the worker drops the subscription.

    A keep-alive ``ping`` event is emitted every 15 s of inactivity so
    proxies don't time out the connection.

    Args:
        job_id: UUID of the job to stream.
        request: Incoming FastAPI request (used to detect disconnects).

    Returns:
        An :class:`EventSourceResponse` producing newline-delimited SSE
        frames whose ``data`` payloads are JSON-encoded event models.

    Raises:
        HTTPException: 404 when no job row matches ``job_id``.
    """
    jobs_repo: SubagentJobsRepo = request.app.state.jobs_repo
    bus: EventsBus = request.app.state.bus

    rec = await run_db(jobs_repo.get_by_id, job_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="job not found")

    async def _stream() -> AsyncIterator[Dict[str, Any]]:
        # 1) replay persisted trace
        for entry in rec.tool_trace:
            replay_event = ToolCallCompletedEvent(
                job_id=str(job_id),
                round=entry.round,
                tool=entry.tool,
                args=entry.args,
                result_chars=entry.result_chars,
                duration_ms=entry.duration_ms,
                error=entry.error,
            )
            yield {"event": "tool_call_completed", "data": _serialise_event(replay_event)}

        # If terminal, emit a synthetic final and exit
        if rec.status in {
            JobStatus.COMPLETED,
            JobStatus.DEGRADED,
            JobStatus.FAILED,
            JobStatus.TIMEOUT,
            JobStatus.CANCELLED,
        }:
            yield {
                "event": "final",
                "data": json.dumps(
                    {
                        "type": "final",
                        "job_id": str(job_id),
                        "status": rec.status.value,
                        "step1_technical": rec.step1_technical,
                        "step2_classification": rec.step2_classification,
                        "duration_seconds": rec.duration_seconds,
                        "tokens_prompt": rec.tokens_prompt,
                        "tokens_completion": rec.tokens_completion,
                        "error": rec.error_message,
                    },
                    default=str,
                ),
            }
            return

        # 2) live stream
        queue = await bus.subscribe(job_id)
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15.0)
                except asyncio.TimeoutError:
                    yield {"event": "ping", "data": "{}"}
                    continue
                if event is None:
                    return
                event_type = getattr(event, "type", "message")
                yield {"event": event_type, "data": _serialise_event(event)}
                if event_type in {"final", "error"}:
                    return
        finally:
            await bus.unsubscribe(job_id, queue)

    return EventSourceResponse(_stream())
