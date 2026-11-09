"""Service layer for operations jobs and Change Audit."""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any

from loguru import logger

from otalon_api.domain.operations import (
    AuditCategory,
    AuditQueryFilters,
    JobType,
    OperationsAuditAppend,
    OperationsAuditEntry,
    OperationsJob,
    OperationsJobCreate,
    OperationsJobSummary,
    OperationsJobUpdate,
    redact_sensitive,
    redact_text,
)
from otalon_api.repositories.operations_audit_repo import OperationsAuditRepository
from otalon_api.repositories.operations_jobs_repo import OperationsJobsRepository
from otalon_api.repositories.postgres_repo import PostgresRepository
from otalon_api.services.event_bus import EventBus


class OperationsJobsService:
    """Async facade over the operations jobs + audit repositories."""

    def __init__(
        self,
        postgres_repo: PostgresRepository,
        event_bus: EventBus,
    ) -> None:
        self._jobs = OperationsJobsRepository(postgres_repo)
        self._audit = OperationsAuditRepository(postgres_repo)
        self._bus = event_bus
        # Strong references to in-flight publish tasks so the event loop
        # does not garbage-collect them before completion (avoids the
        # "Task was destroyed but it is pending" warning).
        self._pending_events: set[asyncio.Task[None]] = set()

    async def record_job(
        self,
        type_: JobType,
        title: str,
        trigger: str,
        params: dict[str, Any] | None = None,
        actor: str | None = None,
        can_cancel: bool = False,
        can_retry: bool = False,
        idempotency_key: str | None = None,
    ) -> OperationsJob:
        """Create a job --- primary producer hook entry point.

        ``params`` are recursively redacted before persistence via the
        key-structured :func:`redact_sensitive` (values under a sensitive
        *key* are masked; arbitrary value scanning is out of scope --- see
        ``domain/operations/redaction.py``). Defense-in-depth for all
        current and future producers.
        """
        payload = OperationsJobCreate(
            type=type_,
            title=title,
            trigger=trigger,
            actor=actor,
            params=redact_sensitive(params or {}),
            can_cancel=can_cancel,
            can_retry=can_retry,
            idempotency_key=idempotency_key,
        )
        job = await asyncio.to_thread(self._jobs.create, payload)
        self._schedule_job_event(job)
        return job

    async def update_job(
        self,
        job_id: int,
        update: OperationsJobUpdate,
        allowed_from: set[str] | None = None,
    ) -> OperationsJob | None:
        """Advance a job and emit an event on state/phase changes.

        Any ``log_append`` payload is redacted so log lines carrying an
        accidental secret are never persisted or streamed.
        """
        if update.log_append is not None:
            update = update.model_copy(update={"log_append": redact_sensitive(update.log_append)})
        job = await asyncio.to_thread(self._jobs.advance, job_id, update, allowed_from)
        if job is not None:
            self._schedule_job_event(job)
        return job

    async def get_job(self, job_id: int) -> OperationsJob | None:
        return await asyncio.to_thread(self._jobs.get, job_id)

    async def get_job_by_display_id(self, display_id: str) -> OperationsJob | None:
        return await asyncio.to_thread(self._jobs.get_by_display_id, display_id)

    async def list_jobs(
        self,
        state: str | None = None,
        type_: str | None = None,
        actor: str | None = None,
        since: datetime | None = None,
        limit: int = 1000,
    ) -> list[OperationsJob]:
        return await asyncio.to_thread(self._jobs.list_jobs, state, type_, actor, since, limit)

    async def list_summaries(
        self,
        state: str | None = None,
        type_: str | None = None,
        actor: str | None = None,
        since: datetime | None = None,
        limit: int = 1000,
    ) -> list[OperationsJobSummary]:
        jobs = await self.list_jobs(state, type_, actor, since, limit)
        return [OperationsJobSummary.model_validate(j) for j in jobs]

    # Job types whose underlying work cannot be interrupted instantly and
    # therefore transition through the cooperative ``cancelling`` state
    # before reaching terminal ``cancelled`` (F-010).
    _COOPERATIVE_CANCEL_TYPES: frozenset[str] = frozenset({"service", "maintenance", "backup"})

    async def cancel_job(
        self,
        job_id: int,
        stops_immediately: bool | None = None,
        actor: str | None = None,
    ) -> OperationsJob | None:
        """Cooperatively cancel a job and write an audit row.

        When *stops_immediately* is ``None`` the decision is derived from
        the job type: infrastructure actions (service/maintenance/backup)
        cannot stop at once and enter ``cancelling``; fast jobs go straight
        to terminal ``cancelled``. Returns ``None`` for a non-cancellable or
        already-terminal job (idempotent no-op).
        """
        if stops_immediately is None:
            current = await self.get_job(job_id)
            stops_immediately = bool(current is None or current.type not in self._COOPERATIVE_CANCEL_TYPES)
        job = await asyncio.to_thread(self._jobs.cancel, job_id, stops_immediately, actor)
        if job is not None:
            await self.append_audit(
                OperationsAuditAppend(
                    category="job",
                    actor=actor or "operator",
                    action="cancel",
                    target=f"job:{job.display_id}",
                    reason=f"state={job.state}",
                )
            )
            self._schedule_job_event(job)
        return job

    async def finish_cancelling_job(self, job_id: int) -> OperationsJob | None:
        """Advance a cooperatively-cancelling job to terminal ``cancelled``."""
        job = await asyncio.to_thread(self._jobs.finish_cancelling, job_id)
        if job is not None:
            self._schedule_job_event(job)
        return job

    async def is_cancellation_requested(self, job_id: int) -> bool:
        """Return whether a cooperative stop has been requested for a job.

        Cooperative producers poll this from their work loop to learn that
        an operator has cancelled a still-running job. When it returns
        ``True`` the job is in the non-terminal ``cancelling`` state and the
        producer should stop at its next safe point and then call
        :meth:`acknowledge_cancellation`. This is the read side of the
        cooperative-cancel ack contract; it never mutates lifecycle state.
        """
        job = await self.get_job(job_id)
        return job is not None and job.state == "cancelling"

    async def acknowledge_cancellation(
        self,
        job_id: int,
        log_append: list[Any] | Any | None = None,
    ) -> OperationsJob | None:
        """Producer completion/ack hook for a cooperative stop (F-010).

        A cooperative producer (service-restart, maintenance, backup, …)
        calls this once it has actually stopped its work in response to a
        cancellation request, driving the job from the non-terminal
        ``cancelling`` state to terminal ``cancelled``. The transition is
        the atomic, state-guarded :meth:`finish_cancelling_job`, so it is a
        safe no-op when the job is not (or no longer) ``cancelling``.

        This is the production-grade internal hook that later producer waves
        (C/D/F) wire into their work loops; Wave B's service-lifecycle
        producer stays intentionally non-cancellable and does not call it,
        but the contract is proven end-to-end by a controlled cooperative
        test producer.

        Args:
            job_id: The cooperative job being acknowledged as stopped.
            log_append: Optional log entries to record (redacted).

        Returns:
            The terminal ``cancelled`` job, or ``None`` if it was not in the
            ``cancelling`` state.
        """
        if log_append is not None:
            redacted = redact_sensitive(log_append)
            await asyncio.to_thread(
                self._jobs.advance,
                job_id,
                OperationsJobUpdate(log_append=redacted),
                {"cancelling"},
            )
        return await self.finish_cancelling_job(job_id)

    async def retry_job(
        self,
        job_id: int,
        actor: str | None = None,
        idempotency_key: str | None = None,
    ) -> OperationsJob | None:
        """Atomic retry with audit trail."""
        new_job = await asyncio.to_thread(self._jobs.retry, job_id, actor, idempotency_key)
        if new_job is not None:
            source = await asyncio.to_thread(self._jobs.get, job_id)
            await self.append_audit(
                OperationsAuditAppend(
                    category="job",
                    actor=actor or "operator",
                    action="retry",
                    target=f"job:{source.display_id if source else job_id}->{new_job.display_id}",
                    reason=f"retried job {job_id}",
                )
            )
            self._schedule_job_event(new_job)
        return new_job

    async def complete_job(
        self,
        job_id: int,
        result: str | None = None,
        log_append: list[Any] | Any | None = None,
    ) -> OperationsJob | None:
        """Mark a job completed, redacting any completion log payload.

        ``log_append`` is routed through :func:`redact_sensitive` before
        persistence so a completion log line carrying an accidental secret
        (e.g. a backup job logging a connection string under a sensitive
        key) is never persisted or streamed --- matching ``update_job``.
        """
        if log_append is not None:
            log_append = redact_sensitive(log_append)
        job = await asyncio.to_thread(self._jobs.complete, job_id, result, log_append)
        if job is not None:
            self._schedule_job_event(job)
        return job

    async def fail_job(self, job_id: int, error: str | None = None) -> OperationsJob | None:
        job = await asyncio.to_thread(self._jobs.fail, job_id, error)
        if job is not None:
            self._schedule_job_event(job)
        return job

    async def start_job(self, job_id: int) -> OperationsJob | None:
        return await self.update_job(
            job_id,
            OperationsJobUpdate(state="running"),
            allowed_from={"queued"},
        )

    async def append_audit(self, entry: OperationsAuditAppend) -> None:
        """Append a Change Audit row, redacting free-text fields.

        The immutable audit row's free-text payload (``action``/``target``/
        ``reason``/``detail``) is passed through the key-structured
        :func:`redact_text` scrubber at the service boundary so a
        ``key=value`` pair naming a sensitive key never persists its value.
        Redaction is key-structured, not arbitrary value scanning (see
        ``domain/operations/redaction.py``); current writers pass safe
        values, this is defense-in-depth for future producers.
        """
        redacted = entry.model_copy(
            update={
                "action": redact_text(entry.action) or entry.action,
                "target": redact_text(entry.target) or entry.target,
                "reason": redact_text(entry.reason),
                "detail": redact_text(entry.detail),
            }
        )
        await asyncio.to_thread(self._audit.append, redacted)

    async def query_audit(
        self,
        category: AuditCategory | None = None,
        actor: str | None = None,
        since: datetime | None = None,
        q: str | None = None,
        limit: int = 1000,
    ) -> list[OperationsAuditEntry]:
        filters = AuditQueryFilters(category=category, actor=actor, since=since, q=q)
        return await asyncio.to_thread(self._audit.query, filters, limit)

    async def get_audit(self, entry_id: int) -> OperationsAuditEntry | None:
        """Return one audit entry by identifier."""
        return await asyncio.to_thread(self._audit.get, entry_id)

    async def backfill_bounds_history(self) -> int:
        return await asyncio.to_thread(self._audit.backfill_bounds_history)

    def _schedule_job_event(self, job: OperationsJob) -> None:
        payload = {"job_id": job.id, "display_id": job.display_id, "state": job.state}
        try:
            task = asyncio.create_task(self._bus.publish("jobs", payload))
        except RuntimeError:
            logger.warning("no running event loop, dropping job event for job_id={}", job.id)
            return
        # Retain a strong reference until the task finishes, then discard it
        # and surface any failure without letting the exception escape.
        self._pending_events.add(task)
        task.add_done_callback(self._on_event_task_done)

    def _on_event_task_done(self, task: asyncio.Task[None]) -> None:
        self._pending_events.discard(task)
        if not task.cancelled():
            exc = task.exception()
            if exc is not None:
                logger.opt(exception=exc).warning("failed to emit job event")

    async def maybe_finish_service_job(
        self,
        job_id: int,
        exit_code: int,
    ) -> OperationsJob | None:
        """Reconcile a service-lifecycle job after the Docker command finishes.

        Avoids holding a long transaction around the Docker call; the job
        is created with ``state='running'`` and later advanced to
        ``completed``/``failed`` via this method.
        """
        if exit_code == 0:
            return await self.complete_job(job_id, result="Compose action finished successfully")
        return await self.fail_job(job_id, error=f"Compose action exited with code {exit_code}")
