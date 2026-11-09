"""Asyncio worker pool that consumes pending jobs and runs the worker loop.

Each consumer task:
1. dequeues a job-id from a shared :class:`asyncio.Queue`,
2. opens its own MCP streamable-http session,
3. instantiates an LLM provider per-job (factory),
4. runs :func:`src.worker.classify_alarm` with an event sink that publishes
   to :class:`EventsBus` and persists trace entries to PostgreSQL,
5. writes the terminal job state.
"""

from __future__ import annotations

import asyncio
import statistics
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set
from uuid import UUID

from loguru import logger

from otalon_ai.jobs.domain.events import ErrorEvent, SubagentEvent
from otalon_ai.jobs.domain.job import JobStatus
from otalon_ai.jobs.events_bus import EventsBus
from otalon_ai.jobs.repositories.postgres_repo import AlarmsRepo, BaselineRepo, SubagentJobsRepo
from otalon_ai.jobs.worker import classify_alarm
from otalon_ai.llm.factory import build_jobs_provider
from otalon_ai.mcp.client import (
    acquire_session,
    apply_allow_list,
    mcp_tool_to_openai_function,
)
from otalon_ai.mcp.schema import build_name_mapping
from otalon_ai.prompts.loader import PromptLoader
from otalon_ai.settings import Settings


@dataclass
class JobSpec:
    """Concrete instructions for the worker pool to execute a job."""

    job_id: UUID
    alarm_id: str
    prompt_variant: str
    llm_provider: str
    llm_model: str
    llm_endpoint: Optional[str]
    reasoning_effort: Optional[str]
    timeout_seconds: int


class WorkerPool:
    """Run N concurrent workers that drain a shared job queue."""

    def __init__(
        self,
        *,
        settings: Settings,
        prompts: PromptLoader,
        bus: EventsBus,
        jobs_repo: SubagentJobsRepo,
        alarms_repo: AlarmsRepo,
        baseline_repo: BaselineRepo,
    ) -> None:
        """Wire the pool with its shared dependencies.

        Args:
            settings: Resolved service settings (``jobs.n_workers``,
                LLM provider config, MCP url, etc.).
            prompts: System-prompt loader used to materialise the
                worker's prompt variant for each job.
            bus: In-process event bus that fans out worker events to SSE
                subscribers.
            jobs_repo: PostgreSQL repository for the ``subagent_jobs``
                table.
            alarms_repo: Read-only repository for the existing
                ``alarms`` table.
            baseline_repo: Read-only repository for the ``baselines``
                table.
        """
        self._settings = settings
        self._prompts = prompts
        self._bus = bus
        self._jobs_repo = jobs_repo
        self._alarms_repo = alarms_repo
        self._baseline_repo = baseline_repo
        self._queue: asyncio.Queue[JobSpec] = asyncio.Queue()
        self._tasks: List[asyncio.Task[None]] = []
        self._cancel_flags: Dict[UUID, bool] = {}
        self._active_jobs: Set[UUID] = set()
        self._lock = asyncio.Lock()

    # ── Lifecycle ───────────────────────────────────────────────────

    async def start(self) -> None:
        """Spawn ``settings.jobs.n_workers`` consumer tasks.

        Each task drains :attr:`_queue` until the pool is stopped. Safe
        to call once during app startup; calling it twice on the same
        instance leaks the prior task set.
        """
        n = max(1, self._settings.jobs.n_workers)
        for i in range(n):
            task = asyncio.create_task(self._worker_loop(i), name=f"agent-w{i:02d}")
            self._tasks.append(task)
        logger.info("WorkerPool started with {} workers", n)

    async def stop(self) -> None:
        """Cancel all consumer tasks and await their teardown.

        Pending jobs in :attr:`_queue` are dropped on the floor — they
        stay ``pending`` in PostgreSQL and will be picked up only if a
        new pool is started against the same database.
        """
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        logger.info("WorkerPool stopped")

    # ── Public API ──────────────────────────────────────────────────

    def update_settings(self, new: Settings) -> None:
        """Replace the settings reference used to build per-job providers (AI-045 D3).

        The jobs provider is constructed per job from ``self._settings``
        (see :meth:`_run_job`), so a plain reference swap is sufficient:
        the next enqueued job already builds against the new settings.
        In-flight jobs keep their already-built provider/endpoint.

        Args:
            new: The updated settings instance (result of
                ``Settings.with_llm_overrides``).
        """
        self._settings = new
        logger.info("WorkerPool settings updated: jobs model={}", new.jobs.llm_model)

    def enqueue(self, spec: JobSpec) -> int:
        """Enqueue a job and return the *prior* queue length."""
        prior = self._queue.qsize()
        self._queue.put_nowait(spec)
        return prior

    def queue_size(self) -> int:
        """Return the number of jobs currently waiting to be picked up."""
        return self._queue.qsize()

    def active_count(self) -> int:
        """Return the number of jobs currently executing on a worker."""
        return len(self._active_jobs)

    def cancel(self, job_id: UUID) -> bool:
        """Request cooperative cancellation of an active job.

        Args:
            job_id: UUID of the job to cancel.

        Returns:
            ``True`` if the job was active and the cancel flag was set;
            ``False`` if it was not currently running (already terminal,
            still queued, or unknown).
        """
        if job_id not in self._active_jobs:
            return False
        self._cancel_flags[job_id] = True
        return True

    def estimate_eta_seconds(self) -> int:
        """Estimate seconds until a newly enqueued job would complete.

        Uses the mean of the last 20 completed-job durations (falling
        back to 240 s when no history exists) and the current queue
        depth plus active overflow divided by ``n_workers``.

        Returns:
            An integer second estimate (lower bound: one slot's mean).
        """
        recent = self._jobs_repo.get_recent_durations(20)
        avg = statistics.mean(recent) if recent else 240.0
        n = max(1, self._settings.jobs.n_workers)
        ahead = self._queue.qsize() + max(0, len(self._active_jobs) - n)
        slot = ahead // n + 1
        return int(slot * avg)

    # ── Internals ──────────────────────────────────────────────────

    async def _worker_loop(self, worker_id: int) -> None:
        log_tag = f"[W{worker_id:02d}]"
        logger.info("{} worker started", log_tag)
        while True:
            try:
                spec = await self._queue.get()
            except asyncio.CancelledError:
                logger.info("{} worker cancelled, exiting", log_tag)
                return
            try:
                async with self._lock:
                    self._active_jobs.add(spec.job_id)
                    self._cancel_flags.setdefault(spec.job_id, False)
                await self._run_job(spec, log_tag=log_tag)
            except Exception as exc:
                logger.exception("{} worker raised on job {}: {}", log_tag, spec.job_id, exc)
                await self._mark_job_failed(spec.job_id, f"worker_exception: {exc}")
            finally:
                async with self._lock:
                    self._active_jobs.discard(spec.job_id)
                    self._cancel_flags.pop(spec.job_id, None)
                await self._bus.mark_closed(spec.job_id)
                self._queue.task_done()

    async def _run_job(self, spec: JobSpec, *, log_tag: str) -> None:
        # Mark running (AI-03: blocking SQLAlchemy off the loop)
        await asyncio.to_thread(self._jobs_repo.mark_running, spec.job_id)

        # Fetch alarm (AI-03: blocking SQLAlchemy off the loop)
        alarm = await asyncio.to_thread(self._alarms_repo.get_by_id, spec.alarm_id)
        if alarm is None:
            logger.error("{} alarm {} not found, marking failed", log_tag, spec.alarm_id)
            await self._mark_job_failed(spec.job_id, f"alarm not found: {spec.alarm_id}")
            return

        # Build LLM provider.
        # Per tasks.md Phase 9: the jobs surface now routes exclusively
        # through the LiteLLM proxy. ``spec.llm_provider`` is retained on
        # the JobSpec for traceability + payload backward-compat (chat-MCP
        # callers may still send it) but is otherwise ignored — the model
        # itself is a LiteLLM identifier (e.g. ``litellm/gpt-5.4``).
        # ``spec.llm_endpoint`` is likewise recorded but never forwarded:
        # Cluster d / B1 (SSRF close) requires endpoints to come from
        # server settings only.
        try:
            provider = build_jobs_provider(
                self._settings,
                model=spec.llm_model or None,
            )
        except Exception as exc:
            logger.error("{} provider build failed: {}", log_tag, exc)
            await self._mark_job_failed(spec.job_id, f"provider_build: {exc}")
            return

        # Open MCP session and discover tools
        try:
            async with acquire_session(self._settings.mcp.url, api_key=self._settings.mcp.api_key) as session:
                tools_result = await session.list_tools()
                mcp_tools = list(tools_result.tools)
                filtered, unknown = apply_allow_list(mcp_tools, self._settings.jobs.allowed_tools)
                if unknown:
                    logger.warning(
                        "{} {} MCP tools not in allow-list: {}",
                        log_tag,
                        len(unknown),
                        unknown[:5],
                    )
                openai_tools = [mcp_tool_to_openai_function(t) for t in filtered]
                # Build the sanitized→raw mapping the worker needs to route
                # LLM-emitted tool calls (which use the sanitized name) back
                # to the real MCP tool name (which may contain dots).
                sanitized_to_raw, _ = build_name_mapping(t.name for t in filtered)
                logger.info(
                    "{} MCP ready: {} tools available, {} allowed",
                    log_tag,
                    len(mcp_tools),
                    len(filtered),
                )

                async def _sink(event: SubagentEvent) -> None:
                    await self._bus.publish(spec.job_id, event)

                async def _trace_persist(entry: dict[str, Any]) -> None:
                    await asyncio.to_thread(self._jobs_repo.append_trace_entry, spec.job_id, entry)

                def _check_cancel() -> bool:
                    return self._cancel_flags.get(spec.job_id, False)

                system_prompt = self._prompts.get(spec.prompt_variant)  # type: ignore[arg-type]  # reason: spec.prompt_variant is str at the JobSpec boundary but validated upstream to be a PromptVariant Literal

                record = await classify_alarm(
                    job_id=spec.job_id,
                    session=session,
                    provider=provider,
                    alarm=alarm,
                    openai_tools=openai_tools,
                    system_prompt=system_prompt,
                    temperature=0.1,
                    timeout_seconds=spec.timeout_seconds,
                    event_sink=_sink,
                    trace_persist=None,  # we keep trace in-memory and persist at end
                    cancellation_check=_check_cancel,
                    reasoning_effort=spec.reasoning_effort,
                    tool_name_map=sanitized_to_raw,
                    # AI-01: execution-time allow-list gate — the exact set
                    # of raw MCP names that survived advertisement filtering.
                    allowed_tools=frozenset(t.name for t in filtered),
                    prompt_variant=spec.prompt_variant,  # type: ignore[arg-type]  # reason: spec.prompt_variant is str at the JobSpec boundary but validated upstream to be a PromptVariant Literal
                    log_tag=log_tag,
                )
        except Exception as exc:
            logger.exception("{} MCP session/exec failed: {}", log_tag, exc)
            await self._mark_job_failed(spec.job_id, f"mcp_exec: {exc}")
            return

        # Persist terminal state
        await asyncio.to_thread(
            self._jobs_repo.mark_terminal,
            spec.job_id,
            status=record["status"],
            duration_seconds=record["duration_seconds"],
            step1_technical=record.get("step1_technical"),
            step2_classification=record.get("step2_classification"),
            verdict=record.get("verdict"),
            tool_trace=record.get("tool_trace") or [],
            tokens_prompt=record["tokens_prompt"],
            tokens_completion=record["tokens_completion"],
            error_message=record.get("error_message"),
        )
        logger.info(
            "{} job {} done status={} dur={:.1f}s tools={}",
            log_tag,
            spec.job_id,
            record["status"],
            record["duration_seconds"],
            len(record.get("tool_trace") or []),
        )

    async def _mark_job_failed(self, job_id: UUID, error: str) -> None:
        await asyncio.to_thread(
            self._jobs_repo.mark_terminal,
            job_id,
            status=JobStatus.FAILED.value,
            duration_seconds=0.0,
            step1_technical=None,
            step2_classification=None,
            verdict=None,
            tool_trace=[],
            tokens_prompt=0,
            tokens_completion=0,
            error_message=error,
        )
        await self._bus.publish(
            job_id,
            ErrorEvent(job_id=str(job_id), reason="failed", detail=error),
        )
