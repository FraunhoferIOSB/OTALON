"""PostgreSQL repository for runtime retrain job rows.

Wraps the ``retrain_jobs`` table that is DDL-owned by otalon-clas.
otalon-api only operates rows (INSERT/UPDATE/SELECT/NOTIFY) so the
schema definition stays in one place.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from otalon_api.repositories.postgres_repo import PostgresRepository

_CHANNEL: str = "cyberclas_retrain_job"
_NON_TERMINAL_STATES: tuple[str, ...] = ("queued", "running", "publishing")


class RuntimeRetrainRepo:
    """Row-level operations for ``retrain_jobs``.

    Args:
        postgres_repo: Existing shared repository that provides pooled
            psycopg2 connections.
    """

    def __init__(self, postgres_repo: PostgresRepository) -> None:
        """Initialize with a shared repository."""
        self._repo = postgres_repo

    def ensure_schema(self) -> None:
        """Create ``retrain_jobs`` idempotently if otalon-clas has not yet.

        otalon-clas owns the canonical ORM DDL, but the api may receive a
        retrain request or status poll before otalon-clas has booted its
        ``create_tables()`` step. To make api behavior deterministic rather
        than raising ``UndefinedTable`` (audit A-06), the api ensures the
        same table shape with ``CREATE TABLE IF NOT EXISTS`` — column types
        chosen to match the SQLAlchemy model in
        ``otalon-clas/.../postgres_connector.py`` — plus the partial
        unique index that enforces single-flight at the DB level (audit
        B-01). All statements are ``IF NOT EXISTS`` so running this on every
        start is safe and never diverges from or drops the owner's table.
        """
        statements = (
            """
            CREATE TABLE IF NOT EXISTS retrain_jobs (
                job_ref TEXT PRIMARY KEY,
                scope TEXT NOT NULL,
                state TEXT NOT NULL DEFAULT 'queued',
                window_start TEXT NOT NULL,
                window_stop TEXT NOT NULL,
                mitre_file TEXT,
                requested_by TEXT,
                requested_at TIMESTAMPTZ NOT NULL,
                started_at TIMESTAMPTZ,
                finished_at TIMESTAMPTZ,
                detail TEXT NOT NULL DEFAULT '',
                error TEXT,
                metrics JSONB,
                history_snapshot_rows INTEGER NOT NULL DEFAULT 0,
                worker_id TEXT,
                heartbeat_at TIMESTAMPTZ,
                CONSTRAINT ck_retrain_job_scope
                    CHECK (scope IN ('bounds_frequency', 'classifier')),
                CONSTRAINT ck_retrain_job_state
                    CHECK (state IN ('queued','running','publishing','succeeded','failed','rejected'))
            )
            """,
            "CREATE INDEX IF NOT EXISTS ix_retrain_jobs_state_requested_at " "ON retrain_jobs (state, requested_at)",
            # Single-flight at the DB level: at most one non-terminal row.
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_retrain_jobs_single_flight "
            "ON retrain_jobs ((TRUE)) "
            "WHERE state IN ('queued','running','publishing')",
            "ALTER TABLE retrain_jobs ADD COLUMN IF NOT EXISTS operations_job_id BIGINT",
            "ALTER TABLE retrain_jobs ADD COLUMN IF NOT EXISTS intervals JSONB",
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_retrain_jobs_operations_job "
            "ON retrain_jobs (operations_job_id) WHERE operations_job_id IS NOT NULL",
            # API-025 follow-up: `CREATE TABLE IF NOT EXISTS` above is a no-op
            # on a table that otalon-clas already created with the old
            # 5-state constraint, so an existing deployment keeps rejecting
            # the additive 'rejected' state with a CheckViolation. Rebuild the
            # constraint explicitly, mirroring the operations_jobs migration.
            "ALTER TABLE retrain_jobs DROP CONSTRAINT IF EXISTS ck_retrain_job_state",
            "ALTER TABLE retrain_jobs ADD CONSTRAINT ck_retrain_job_state "
            "CHECK (state IN ('queued','running','publishing','succeeded','failed','rejected'))",
        )
        for stmt in statements:
            self._repo._execute_update(stmt)

    def try_reserve_queued(
        self,
        job_ref: str,
        scope: str,
        window_start: str,
        window_stop: str,
        *,
        mitre_file: str | None = None,
        requested_by: str | None = None,
        detail: str = "queued",
        history_snapshot_rows: int = 0,
        operations_job_id: int | None = None,
        intervals: list[tuple[str, str]] | None = None,
    ) -> bool:
        """Atomically insert a queued job iff no non-terminal job exists.

        The ``INSERT ... SELECT ... WHERE NOT EXISTS`` runs as one
        statement so two concurrent api requests cannot both reserve — the
        second sees zero rows inserted and is rejected (audit B-01). The
        partial unique index created by :meth:`ensure_schema` is the
        second line of defense (a unique violation also means "busy").

        Returns:
            ``True`` when this call reserved the slot, ``False`` when a
            non-terminal job already existed.
        """
        sql = """
            INSERT INTO retrain_jobs
            (job_ref, scope, state, window_start, window_stop, mitre_file,
             requested_by, requested_at, detail, history_snapshot_rows, operations_job_id, intervals)
            SELECT
             %(job_ref)s, %(scope)s, 'queued',
             %(window_start)s, %(window_stop)s, %(mitre_file)s,
             %(requested_by)s, %(requested_at)s, %(detail)s,
             %(history_snapshot_rows)s, %(operations_job_id)s, %(intervals)s::jsonb
            WHERE NOT EXISTS (
                SELECT 1 FROM retrain_jobs
                WHERE state IN ('queued','running','publishing')
            )
        """
        params = {
            "job_ref": job_ref,
            "scope": scope,
            "window_start": window_start,
            "window_stop": window_stop,
            "mitre_file": mitre_file,
            "requested_by": requested_by,
            "requested_at": datetime.now(tz=timezone.utc),
            "detail": detail,
            "history_snapshot_rows": history_snapshot_rows,
            "operations_job_id": operations_job_id,
            "intervals": json.dumps(intervals or [(window_start, window_stop)]),
        }
        try:
            inserted = self._repo._execute_update(sql, params)
        except Exception as exc:
            # A unique-violation on the single-flight partial index also
            # means "busy" — treat it as a failed reservation, not a 500.
            if _is_unique_violation(exc):
                return False
            raise
        return inserted > 0

    def set_history_snapshot_rows(self, job_ref: str, rows: int) -> None:
        """Record the bounds-snapshot count on an already-reserved row."""
        self._repo._execute_update(
            "UPDATE retrain_jobs SET history_snapshot_rows = %(rows)s " "WHERE job_ref = %(job_ref)s",
            {"rows": rows, "job_ref": job_ref},
        )

    def emit_notify(self, job_ref: str) -> None:
        """Emit the ``cyberclas_retrain_job`` NOTIFY for *job_ref*.

        Uses parameterized ``pg_notify`` so the channel is a constant and
        the payload value is bound, never string-interpolated (audit B-10).
        """
        self._repo._execute_update(
            "SELECT pg_notify(%(channel)s, %(payload)s)",
            {"channel": _CHANNEL, "payload": f'{{"job_ref": "{job_ref}"}}'},
        )

    def fail_reserved_job(self, job_ref: str, error: str) -> bool:
        """Fail a queued reservation before it can be notified."""
        updated = self._repo._execute_update(
            """
            UPDATE retrain_jobs
            SET state = 'failed', finished_at = %(now)s, worker_id = NULL,
                error = %(error)s, detail = 'bounds snapshot failed'
            WHERE job_ref = %(job_ref)s AND state = 'queued'
            """,
            {"job_ref": job_ref, "now": datetime.now(tz=timezone.utc), "error": error},
        )
        if updated:
            self._sync_operation(job_ref, "failed", error)
        return updated > 0

    def reject_reserved_job(self, job_ref: str, detail: str) -> bool:
        """Close a queued reservation as a protection-rule rejection."""
        updated = self._repo._execute_update(
            """
            UPDATE retrain_jobs
            SET state = 'rejected', finished_at = %(now)s, worker_id = NULL,
                error = NULL, detail = %(detail)s
            WHERE job_ref = %(job_ref)s AND state = 'queued'
            """,
            {"job_ref": job_ref, "now": datetime.now(tz=timezone.utc), "detail": detail},
        )
        if updated:
            self._sync_operation(job_ref, "rejected", detail)
        return updated > 0

    def get_latest_status(self) -> dict[str, Any] | None:
        """Return the most recent job row, or None when the table is empty."""
        sql = """
            SELECT *
            FROM retrain_jobs
            ORDER BY requested_at DESC
            LIMIT 1
        """
        rows = self._repo._execute_query(sql)
        if not rows:
            return None
        return dict(rows[0])

    def get_latest_terminal_finished_at(self, *, exclude_job_ref: str | None = None) -> datetime | None:
        """Return latest terminal completion time, excluding a fresh reservation."""
        rows = self._repo._execute_query(
            """
            SELECT finished_at FROM retrain_jobs
            WHERE state IN ('succeeded', 'failed')
              AND finished_at IS NOT NULL
              AND (%(exclude_job_ref)s IS NULL OR job_ref <> %(exclude_job_ref)s)
            ORDER BY finished_at DESC LIMIT 1
            """,
            {"exclude_job_ref": exclude_job_ref},
        )
        if not rows:
            return None
        value = rows[0].get("finished_at")
        return value if isinstance(value, datetime) else None

    def reap_stale_jobs(self, stale_timeout_seconds: float) -> int:
        """Mark non-terminal jobs without a fresh heartbeat as failed.

        Only rows whose ``heartbeat_at`` is older than the cutoff (or never
        set) are transitioned, and the reaping clears ``worker_id`` so a
        late worker's ownership-guarded transition definitively fails and
        the job cannot flap ``failed → succeeded`` (audit B-05). ``queued``
        rows are also covered: a job whose worker died before its first
        heartbeat, using ``requested_at`` as the age reference.

        Returns the number of rows transitioned.
        """
        cutoff = datetime.now(tz=timezone.utc) - _seconds(stale_timeout_seconds)
        sql = """
            UPDATE retrain_jobs
            SET state = 'failed',
                finished_at = %(now)s,
                worker_id = NULL,
                error = 'heartbeat timeout: worker appears dead',
                detail = 'reaped to failed by timeout'
            WHERE state IN ('queued', 'running', 'publishing')
              AND COALESCE(heartbeat_at, requested_at) < %(cutoff)s
        """
        updated = self._repo._execute_update(
            sql,
            {"cutoff": cutoff, "now": datetime.now(tz=timezone.utc)},
        )
        if updated:
            self._repo._execute_update(
                """
                UPDATE operations_jobs
                SET state = 'failed', ended_at = now(), can_cancel = false,
                    can_retry = true, error = 'heartbeat timeout: worker appears dead',
                    latest_event = 'reaped to failed by timeout'
                WHERE id IN (
                    SELECT operations_job_id FROM retrain_jobs
                    WHERE state = 'failed' AND error = 'heartbeat timeout: worker appears dead'
                ) AND state IN ('queued', 'running')
                """
            )
        return updated

    def _sync_operation(self, job_ref: str, state: str, error: str | None = None) -> None:
        """Synchronize a pre-worker retrain transition into Operations."""
        self._repo._execute_update(
            """
            UPDATE operations_jobs
            SET state = %(state)s, ended_at = now(), can_cancel = false,
                can_retry = (%(state)s = 'failed'), error = %(error)s,
                latest_event = COALESCE(%(error)s, latest_event)
            WHERE id = (SELECT operations_job_id FROM retrain_jobs WHERE job_ref = %(job_ref)s)
              AND state IN ('queued', 'running')
            """,
            {"job_ref": job_ref, "state": state, "error": error},
        )

    def snapshot_bounds_to_history(self, module: str, reason: str) -> int:
        """Passthrough to the shared repository's bounds snapshot."""
        return self._repo.snapshot_bounds_to_history(module=module, reason=reason)

    def generate_job_ref(self) -> str:
        """Generate a unique job reference string."""
        return uuid.uuid4().hex


def _seconds(value: float) -> Any:
    """Create a timedelta without importing it at module scope."""
    from datetime import timedelta

    return timedelta(seconds=value)


def _is_unique_violation(exc: Exception) -> bool:
    """Return True when *exc* is (or wraps) a PostgreSQL unique violation."""
    pgcode = getattr(exc, "pgcode", None)
    if pgcode == "23505":
        return True
    cause = getattr(exc, "__cause__", None)
    if cause is not None and getattr(cause, "pgcode", None) == "23505":
        return True
    return "23505" in str(exc) or "unique" in str(exc).lower()
