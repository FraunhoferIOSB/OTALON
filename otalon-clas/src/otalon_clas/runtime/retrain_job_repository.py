"""Repository for runtime retrain jobs.

Wraps the shared ``retrain_jobs`` table. otalon-api inserts queued
jobs; otalon-clas claims, heartbeats, and transitions them to terminal
states. All operations are transactional through
:class:`PostgresConnector` sessions.

Every read returns an immutable :class:`RetrainJobDTO` copied out of the
row while the session is still open, so callers never hold a detached
ORM instance (audit A-04 / B-11 / F1). State transitions are guarded by
the expected prior state AND the owning ``worker_id`` so a reaped or
terminal job cannot be resurrected by a worker that lost ownership
(audit B-05).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import text

from otalon_clas.common.postgres_connector import PostgresConnector, RetrainJob
from otalon_clas.runtime.job_dto import RetrainJobDTO

_RETRAIN_NOTIFY_CHANNEL: str = "cyberclas_retrain_job"
_NON_TERMINAL_STATES: tuple[str, ...] = ("queued", "running", "publishing")
_OPERATION_STATE_MAP: dict[str, str] = {
    "queued": "queued",
    "running": "running",
    "publishing": "running",
    "succeeded": "completed",
    "failed": "failed",
}

_OPERATIONS_SYNC_SQL_POSTGRESQL: str = """
    UPDATE operations_jobs
    SET state = :state, phase_label = :phase_label,
        latest_event = :latest_event, error = :error,
        result = COALESCE(:result, result),
        log = COALESCE(log, '[]'::jsonb) || jsonb_build_array(CAST(:log_entry AS jsonb)),
        ended_at = COALESCE(:ended_at, ended_at),
        can_cancel = false,
        can_retry = (:state = 'failed')
    WHERE id = :job_id
"""

_OPERATIONS_SYNC_SQL_SQLITE: str = """
    UPDATE operations_jobs
    SET state = :state, phase_label = :phase_label,
        latest_event = :latest_event, error = :error,
        result = COALESCE(:result, result),
        log = json_insert(COALESCE(log, '[]'), '$[#]', json(:log_entry)),
        ended_at = COALESCE(:ended_at, ended_at),
        can_cancel = 0,
        can_retry = (:state = 'failed')
    WHERE id = :job_id
"""


def _operations_sync_sql(dialect: str) -> str:
    """Return the operations-job projection SQL for the active dialect.

    The PostgreSQL statement uses native JSONB concatenation; the SQLite
    equivalent uses ``json_insert(..., '$[#]', ...)`` so the projection
    semantics (append one structured log entry, preserve prior result)
    match on both backends without hiding the real producer boundary.
    """
    if dialect == "postgresql":
        return _OPERATIONS_SYNC_SQL_POSTGRESQL
    return _OPERATIONS_SYNC_SQL_SQLITE


def emit_retrain_notify(connector: PostgresConnector, job_ref: str) -> None:
    """Emit the ``cyberclas_retrain_job`` NOTIFY with a JSON payload.

    Uses parameterized ``pg_notify`` so the channel is a constant and the
    payload value is bound, never string-interpolated (audit B-10).
    Silently returns on non-PostgreSQL backends so tests against SQLite
    do not fail on ``NOTIFY`` syntax.

    Args:
        connector: PostgreSQL connector.
        job_ref: Job reference to embed in the JSON payload.
    """
    if connector.engine.dialect.name != "postgresql":
        return
    with connector.engine.begin() as conn:
        conn.execute(
            text("SELECT pg_notify(:channel, :payload)"),
            {
                "channel": _RETRAIN_NOTIFY_CHANNEL,
                "payload": f'{{"job_ref": "{job_ref}"}}',
            },
        )


class RetrainJobClaimError(RuntimeError):
    """Raised when a worker loses ownership of a job mid-flight.

    A guarded transition (heartbeat, ``set_state``, ``set_terminal``) that
    affects zero rows means the reaper or another worker already changed
    the row, so the current worker MUST abort rather than overwrite a
    terminal or reassigned state (audit B-05).
    """


class RetrainJobRepository:
    """ORM-backed accessor for ``retrain_jobs``.

    Args:
        connector: PostgreSQL connector providing SQLAlchemy sessions.
    """

    def __init__(self, connector: PostgresConnector) -> None:
        """Initialize the repository."""
        self._connector = connector

    def insert_queued(
        self,
        job_ref: str,
        scope: str,
        window_start: str,
        window_stop: str,
        *,
        mitre_file: str | None = None,
        requested_by: str | None = None,
        detail: str = "queued",
        metrics: dict[str, Any] | None = None,
        intervals: list[tuple[str, str]] | None = None,
    ) -> None:
        """Insert a new queued job."""
        now = datetime.now(tz=timezone.utc)
        with self._connector.session() as session:
            session.add(
                RetrainJob(
                    job_ref=job_ref,
                    scope=scope,
                    state="queued",
                    window_start=window_start,
                    window_stop=window_stop,
                    intervals=[list(item) for item in (intervals or [(window_start, window_stop)])],
                    mitre_file=mitre_file,
                    requested_by=requested_by,
                    requested_at=now,
                    detail=detail,
                    metrics=metrics,
                )
            )

    def claim_next(
        self,
        job_ref: str,
        worker_id: str,
    ) -> RetrainJobDTO | None:
        """Atomically claim a queued job.

        Uses ``UPDATE ... WHERE state='queued'`` so only one worker wins.
        Returns a detached snapshot of the claimed row or ``None`` if the
        job was already claimed.
        """
        now = datetime.now(tz=timezone.utc)
        with self._connector.session() as session:
            updated = (
                session.query(RetrainJob)
                .filter(RetrainJob.job_ref == job_ref, RetrainJob.state == "queued")
                .update(
                    {
                        RetrainJob.state: "running",
                        RetrainJob.worker_id: worker_id,
                        RetrainJob.started_at: now,
                        RetrainJob.heartbeat_at: now,
                        RetrainJob.detail: "claimed by worker",
                    },
                    synchronize_session=False,
                )
            )
            if updated == 0:
                return None
            row = session.query(RetrainJob).filter_by(job_ref=job_ref).one()
            self._sync_operations_job(session, row)
            return RetrainJobDTO.from_orm_row(row)

    def set_state(
        self,
        job_ref: str,
        state: str,
        *,
        worker_id: str,
        expected_states: tuple[str, ...],
        detail: str | None = None,
        error: str | None = None,
        metrics: dict[str, Any] | None = None,
    ) -> None:
        """Transition a job to a new state, guarded by state + worker.

        The update only fires when the row still belongs to *worker_id*
        AND is in one of *expected_states*. If it affects zero rows the
        worker has lost ownership (reaped / reassigned) and a
        :class:`RetrainJobClaimError` is raised so the caller aborts
        (audit B-05).
        """
        now = datetime.now(tz=timezone.utc)
        values: dict[Any, Any] = {
            RetrainJob.state: state,
            RetrainJob.heartbeat_at: now,
        }
        if detail is not None:
            values[RetrainJob.detail] = detail
        if error is not None:
            values[RetrainJob.error] = error
        if metrics is not None:
            values[RetrainJob.metrics] = metrics
        with self._connector.session() as session:
            updated = (
                session.query(RetrainJob)
                .filter(
                    RetrainJob.job_ref == job_ref,
                    RetrainJob.worker_id == worker_id,
                    RetrainJob.state.in_(list(expected_states)),
                )
                .update(values, synchronize_session=False)
            )
            if updated == 0:
                raise RetrainJobClaimError(
                    f"RetrainJob {job_ref!r}: lost ownership transitioning to {state!r} "
                    f"(expected one of {expected_states} owned by {worker_id!r})"
                )
            row = session.query(RetrainJob).filter_by(job_ref=job_ref).one()
            self._sync_operations_job(session, row)

    def heartbeat(self, job_ref: str, worker_id: str) -> bool:
        """Update ``heartbeat_at`` only for a non-terminal row we own.

        Returns ``True`` when the heartbeat landed; ``False`` when the row
        is no longer owned/non-terminal (the worker should abort).
        """
        now = datetime.now(tz=timezone.utc)
        with self._connector.session() as session:
            updated = (
                session.query(RetrainJob)
                .filter(
                    RetrainJob.job_ref == job_ref,
                    RetrainJob.worker_id == worker_id,
                    RetrainJob.state.in_(list(_NON_TERMINAL_STATES)),
                )
                .update({RetrainJob.heartbeat_at: now}, synchronize_session=False)
            )
        return updated > 0

    def set_terminal(
        self,
        job_ref: str,
        state: str,
        *,
        detail: str,
        worker_id: str | None = None,
        expected_states: tuple[str, ...] = _NON_TERMINAL_STATES,
        error: str | None = None,
        metrics: dict[str, Any] | None = None,
    ) -> bool:
        """Mark a job ``succeeded`` or ``failed`` from an expected state.

        When *worker_id* is provided the transition is additionally scoped
        to the owning worker, so a job already reaped to ``failed`` cannot
        later flap to ``succeeded`` (audit B-05). Returns ``True`` when the
        transition landed, ``False`` otherwise. A ``worker_id=None`` call
        (used for the paused fast-fail before a claim) is unscoped.
        """
        now = datetime.now(tz=timezone.utc)
        with self._connector.session() as session:
            query = session.query(RetrainJob).filter(
                RetrainJob.job_ref == job_ref,
                RetrainJob.state.in_(list(expected_states)),
            )
            if worker_id is not None:
                query = query.filter(RetrainJob.worker_id == worker_id)
            updated = query.update(
                {
                    RetrainJob.state: state,
                    RetrainJob.detail: detail,
                    RetrainJob.error: error,
                    RetrainJob.metrics: metrics,
                    RetrainJob.finished_at: now,
                    RetrainJob.heartbeat_at: now,
                },
                synchronize_session=False,
            )
            if updated:
                row = session.query(RetrainJob).filter_by(job_ref=job_ref).one()
                self._sync_operations_job(session, row)
        return updated > 0

    @staticmethod
    def _sync_operations_job(session: Any, row: RetrainJob) -> None:
        """Project retrain lifecycle into its canonical operations job."""
        if row.operations_job_id is None:
            return
        operation_state = _OPERATION_STATE_MAP.get(str(row.state))
        if operation_state is None:
            return
        metrics: dict[str, Any] = row.metrics if isinstance(row.metrics, dict) else {}
        detail = str(row.detail)
        log_entry = {
            "state": str(row.state),
            "phase": detail,
            "metrics": _bounded_metrics(metrics),
        }
        values: dict[str, Any] = {
            "state": operation_state,
            "phase_label": detail,
            "latest_event": detail,
            "error": row.error,
            "result": _result_text(detail, metrics) if operation_state == "completed" else None,
            "log_entry": json.dumps(log_entry),
            "ended_at": row.finished_at,
            "job_id": row.operations_job_id,
        }
        dialect = session.get_bind().dialect.name
        session.execute(text(_operations_sync_sql(dialect)), values)

    def fetch_queued_refs(self) -> list[str]:
        """Return all queued job refs ordered by request time."""
        with self._connector.session() as session:
            rows = (
                session.query(RetrainJob.job_ref)
                .filter(RetrainJob.state == "queued")
                .order_by(RetrainJob.requested_at)
                .all()
            )
            return [str(row.job_ref) for row in rows]

    def get(self, job_ref: str) -> RetrainJobDTO | None:
        """Return a detached job snapshot by reference, or ``None``."""
        with self._connector.session() as session:
            row = session.query(RetrainJob).filter_by(job_ref=job_ref).one_or_none()
            if row is None:
                return None
            return RetrainJobDTO.from_orm_row(row)

    def list_non_terminal(self) -> list[RetrainJobDTO]:
        """Return detached snapshots of all non-terminal jobs."""
        with self._connector.session() as session:
            rows = (
                session.query(RetrainJob)
                .filter(RetrainJob.state.in_(list(_NON_TERMINAL_STATES)))
                .order_by(RetrainJob.requested_at)
                .all()
            )
            return [RetrainJobDTO.from_orm_row(row) for row in rows]


def _bounded_metrics(metrics: dict[str, Any]) -> dict[str, Any]:
    """Keep operation logs useful without persisting unbounded worker data."""
    return {str(key): value for key, value in list(metrics.items())[:12]}


def _result_text(detail: str, metrics: dict[str, Any]) -> str:
    """Build bounded completion truth for the Operations detail view."""
    metric_names = ", ".join(str(key) for key in list(metrics)[:8])
    return f"{detail}; metrics: {metric_names}" if metric_names else detail
