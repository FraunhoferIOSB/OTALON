"""Repository for canonical operations jobs.

All writes use conditional state guards so concurrent cancel / retry /
advance requests cannot race into an illegal lifecycle state.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from psycopg2.extras import RealDictCursor

from otalon_api.domain.operations import OperationsJob, OperationsJobCreate, OperationsJobUpdate
from otalon_api.repositories.postgres_repo import PostgresRepository


class OperationsJobsRepository:
    """CRUD + atomic lifecycle transitions for operations_jobs."""

    def __init__(self, postgres_repo: PostgresRepository) -> None:
        self._pg = postgres_repo

    def _row_to_model(self, row: dict[str, Any]) -> OperationsJob:
        return OperationsJob.model_validate(row)

    def create(self, payload: OperationsJobCreate) -> OperationsJob:
        """Insert a new job and return the full row."""
        sql = """
            INSERT INTO operations_jobs
                (type, title, trigger, actor, state, params, can_cancel, can_retry, idempotency_key)
            VALUES (%(type)s, %(title)s, %(trigger)s, %(actor)s, COALESCE(%(state)s, 'queued'),
                    %(params)s::jsonb, %(can_cancel)s, %(can_retry)s, %(idempotency_key)s)
            ON CONFLICT (idempotency_key) DO UPDATE
                SET idempotency_key = EXCLUDED.idempotency_key
            RETURNING *
        """
        params = payload.model_dump(mode="json")
        params["state"] = "queued"
        params["params"] = json.dumps(params.get("params") or {})
        rows = self._pg._execute_query(sql, params)
        if not rows:
            raise RuntimeError("operations_jobs insert returned no row")
        return self._row_to_model(rows[0])

    def get(self, job_id: int) -> OperationsJob | None:
        """Fetch a single job by internal id."""
        rows = self._pg._execute_query("SELECT * FROM operations_jobs WHERE id = %(id)s", {"id": job_id})
        return self._row_to_model(rows[0]) if rows else None

    def get_by_display_id(self, display_id: str) -> OperationsJob | None:
        """Fetch a job by its human-readable display id."""
        rows = self._pg._execute_query(
            "SELECT * FROM operations_jobs WHERE display_id = %(display_id)s",
            {"display_id": display_id},
        )
        return self._row_to_model(rows[0]) if rows else None

    def list_jobs(
        self,
        state: str | None = None,
        type_: str | None = None,
        actor: str | None = None,
        since: datetime | None = None,
        limit: int = 1000,
    ) -> list[OperationsJob]:
        """Return jobs most-recent first, with optional filters."""
        clauses: list[str] = []
        params: dict[str, Any] = {"limit": limit}
        if state:
            clauses.append("state = %(state)s")
            params["state"] = state
        if type_:
            clauses.append("type = %(type)s")
            params["type"] = type_
        if actor:
            clauses.append("actor = %(actor)s")
            params["actor"] = actor
        if since:
            clauses.append("started_at >= %(since)s")
            params["since"] = since.isoformat()
        where = " AND ".join(clauses)
        sql = f"""
            SELECT * FROM operations_jobs
            {f"WHERE {where}" if where else ""}
            ORDER BY started_at DESC
            LIMIT %(limit)s
        """
        return [self._row_to_model(r) for r in self._pg._execute_query(sql, params)]

    def advance(
        self,
        job_id: int,
        update: OperationsJobUpdate,
        allowed_from: set[str] | None = None,
    ) -> OperationsJob | None:
        """Apply a guarded update to a job.

        Only rows whose current state is in *allowed_from* are modified;
        the call returns the updated row or ``None`` if the guard did not
        match (late event, terminal job, etc.).
        """
        allowed = allowed_from or {"queued", "running", "cancelling"}
        sets: list[str] = []
        params: dict[str, Any] = {"id": job_id}
        data = update.model_dump(exclude_unset=True, mode="json")

        if "state" in data:
            sets.append("state = %(state)s")
            params["state"] = data["state"]
        if "phase_current" in data:
            sets.append("phase_current = %(phase_current)s")
            params["phase_current"] = data["phase_current"]
        if "phase_total" in data:
            sets.append("phase_total = %(phase_total)s")
            params["phase_total"] = data["phase_total"]
        if "phase_label" in data:
            sets.append("phase_label = %(phase_label)s")
            params["phase_label"] = data["phase_label"]
        if "latest_event" in data:
            sets.append("latest_event = %(latest_event)s")
            params["latest_event"] = data["latest_event"]
        if "error" in data:
            sets.append("error = %(error)s")
            params["error"] = data["error"]
        if "result" in data:
            sets.append("result = %(result)s")
            params["result"] = data["result"]
        if "can_cancel" in data:
            sets.append("can_cancel = %(can_cancel)s")
            params["can_cancel"] = data["can_cancel"]
        if "can_retry" in data:
            sets.append("can_retry = %(can_retry)s")
            params["can_retry"] = data["can_retry"]
        if "ended_at" in data:
            sets.append("ended_at = %(ended_at)s")
            params["ended_at"] = data["ended_at"]
        if "log_append" in data:
            sets.append("log = COALESCE(log, '[]'::jsonb) || %(log_append)s::jsonb")
            params["log_append"] = json.dumps(data["log_append"])

        if not sets:
            return self.get(job_id)

        sql = f"""
            UPDATE operations_jobs
            SET {", ".join(sets)}
            WHERE id = %(id)s AND state = ANY(%(allowed)s)
            RETURNING *
        """
        params["allowed"] = list(allowed)
        rows = self._pg._execute_query(sql, params)
        return self._row_to_model(rows[0]) if rows else None

    def cancel(
        self,
        job_id: int,
        stops_immediately: bool = True,
        actor: str | None = None,
    ) -> OperationsJob | None:
        """Cooperative cancel with an atomic state guard.

        If *stops_immediately* is true the job becomes terminal
        ``cancelled`` and ``ended_at`` is set. Otherwise it enters the
        non-terminal ``cancelling`` state and must be advanced to
        ``cancelled`` later when the underlying stop lands.

        Returns the updated row, or ``None`` if the job is not
        cancellable / already terminal (idempotent no-op).
        """
        if stops_immediately:
            sql = """
                UPDATE operations_jobs
                SET state = 'cancelled',
                    ended_at = COALESCE(ended_at, now()),
                    can_retry = true,
                    can_cancel = false,
                    latest_event = COALESCE(latest_event, 'Cancelled')
                WHERE id = %(id)s AND can_cancel = true
                  AND state IN ('queued', 'running', 'cancelling')
                RETURNING *
            """
        else:
            sql = """
                UPDATE operations_jobs
                SET state = 'cancelling',
                    latest_event = COALESCE(latest_event, 'Cancelling')
                WHERE id = %(id)s AND can_cancel = true
                  AND state IN ('queued', 'running')
                RETURNING *
            """
        rows = self._pg._execute_query(sql, {"id": job_id})
        return self._row_to_model(rows[0]) if rows else None

    def finish_cancelling(self, job_id: int) -> OperationsJob | None:
        """Move a ``cancelling`` job to terminal ``cancelled``."""
        sql = """
            UPDATE operations_jobs
            SET state = 'cancelled',
                ended_at = COALESCE(ended_at, now()),
                can_retry = true,
                can_cancel = false,
                latest_event = COALESCE(latest_event, 'Cancelled')
            WHERE id = %(id)s AND state = 'cancelling'
            RETURNING *
        """
        rows = self._pg._execute_query(sql, {"id": job_id})
        return self._row_to_model(rows[0]) if rows else None

    def retry(self, job_id: int, actor: str | None = None, idempotency_key: str | None = None) -> OperationsJob | None:
        """Create exactly one successor job atomically.

        The transaction locks the source row, verifies it is retryable
        and has no successor, inserts a new ``running`` job copying the
        original type/params/actor, and links ``retried_as_id``. The
        ``retried_as_id`` UNIQUE constraint plus the explicit IS NULL
        guard guarantees concurrent retries yield a single successor.

        Idempotency-key handling (F-007, B-F01): the successor INSERT uses
        ``ON CONFLICT (idempotency_key) DO NOTHING``. A ``None`` key is
        distinct in PostgreSQL, so every keyless retry inserts a fresh row.
        When a non-null key is supplied and *already belongs to a row*, the
        conflict is resolved by **verifying** the pre-existing row rather
        than blindly linking whatever ``RETURNING`` yields:

        * If the colliding row is *already this source's successor*
          (``retried_as_id`` points at it), the call is an idempotent
          replay and returns that successor without re-linking.
        * Otherwise the key collides with an **unrelated** job; the retry
          is rejected (``None``) instead of cross-linking the source to a
          foreign row. The source keeps ``retried_as_id IS NULL`` so a
          corrected retry can still succeed.

        Returns the new job, the existing successor on an idempotent
        replay, or ``None`` if the source is not retryable, a successor
        already exists, or the key collides with an unrelated job.
        """
        with self._pg.connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT * FROM operations_jobs
                    WHERE id = %(id)s AND can_retry = true
                      AND state IN ('failed', 'cancelled')
                      AND retried_as_id IS NULL
                    FOR UPDATE
                """,
                    {"id": job_id},
                )
                row = cur.fetchone()
                if not row:
                    conn.commit()
                    return None

                original = self._row_to_model(dict(row))
                # ON CONFLICT DO NOTHING inserts nothing on an idempotency_key
                # collision, so a missing RETURNING row unambiguously signals
                # the collision (handled by _resolve_retry_conflict below).
                cur.execute(
                    """
                    INSERT INTO operations_jobs
                        (type, title, trigger, actor, state, params, can_cancel, can_retry, idempotency_key)
                    VALUES (%(type)s, %(title)s, %(trigger)s, %(actor)s, 'running',
                            %(params)s::jsonb, %(can_cancel)s, %(can_retry)s, %(idempotency_key)s)
                    ON CONFLICT (idempotency_key) DO NOTHING
                    RETURNING *
                """,
                    {
                        "type": original.type,
                        "title": original.title,
                        "trigger": original.trigger,
                        "actor": actor or original.actor,
                        "params": json.dumps(original.model_dump(mode="json")["params"] or {}),
                        "can_cancel": original.can_cancel,
                        "can_retry": original.can_retry,
                        "idempotency_key": idempotency_key,
                    },
                )
                new_row = cur.fetchone()

                if new_row is None:
                    # Insert was suppressed by an idempotency_key collision.
                    # Resolve it safely: only treat the colliding row as the
                    # successor when it is genuinely THIS source's successor
                    # (idempotent replay). Never link an unrelated row. The
                    # ``FOR UPDATE`` lock on the source is still held, so the
                    # read of its ``retried_as_id`` is consistent.
                    resolved = self._resolve_retry_conflict(cur, job_id, idempotency_key)
                    conn.commit()
                    return resolved

                new_id = new_row["id"]
                cur.execute(
                    """
                    UPDATE operations_jobs SET retried_as_id = %(new_id)s
                    WHERE id = %(id)s AND retried_as_id IS NULL
                    """,
                    {"new_id": new_id, "id": job_id},
                )
            conn.commit()
            return self._row_to_model(dict(new_row))

    def _resolve_retry_conflict(
        self,
        cur: Any,
        job_id: int,
        idempotency_key: str | None,
    ) -> OperationsJob | None:
        """Resolve an idempotency-key collision without cross-linking.

        Called (with the source row still locked ``FOR UPDATE``) when the
        successor INSERT hit ``ON CONFLICT DO NOTHING``. Returns the
        pre-existing row **only** when it is already the source's own
        successor (a genuine idempotent replay); otherwise the key belongs
        to an unrelated job and the retry is rejected with ``None`` so no
        foreign lineage link is written. The caller owns the commit.
        """
        if idempotency_key is None:
            # A NULL key never conflicts in PostgreSQL, so reaching here
            # would indicate an unexpected state; treat as no successor.
            return None
        cur.execute(
            "SELECT retried_as_id FROM operations_jobs WHERE id = %(id)s",
            {"id": job_id},
        )
        source = cur.fetchone()
        if source is None:
            return None
        cur.execute(
            "SELECT * FROM operations_jobs WHERE idempotency_key = %(key)s",
            {"key": idempotency_key},
        )
        colliding = cur.fetchone()
        if colliding is None:
            return None
        if source["retried_as_id"] == colliding["id"]:
            return self._row_to_model(dict(colliding))
        return None

    def complete(
        self,
        job_id: int,
        result: str | None = None,
        log_append: list[Any] | Any | None = None,
    ) -> OperationsJob | None:
        """Mark a running job as completed."""
        sql = """
            UPDATE operations_jobs
            SET state = 'completed',
                ended_at = now(),
                result = COALESCE(%(result)s, result),
                can_retry = false,
                can_cancel = false,
                log = COALESCE(log, '[]'::jsonb) || COALESCE(%(log_append)s, '[]'::jsonb)::jsonb
            WHERE id = %(id)s AND state = 'running'
            RETURNING *
        """
        rows = self._pg._execute_query(
            sql,
            {"id": job_id, "result": result, "log_append": json.dumps(log_append) if log_append is not None else None},
        )
        return self._row_to_model(rows[0]) if rows else None

    def fail(self, job_id: int, error: str | None = None) -> OperationsJob | None:
        """Mark a running/queued job as failed."""
        sql = """
            UPDATE operations_jobs
            SET state = 'failed',
                ended_at = now(),
                error = COALESCE(%(error)s, error),
                can_retry = true,
                can_cancel = false,
                latest_event = COALESCE(latest_event, 'Failed')
            WHERE id = %(id)s AND state IN ('queued', 'running', 'cancelling')
            RETURNING *
        """
        rows = self._pg._execute_query(sql, {"id": job_id, "error": error})
        return self._row_to_model(rows[0]) if rows else None
