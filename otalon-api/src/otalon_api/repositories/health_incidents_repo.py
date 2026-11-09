"""PostgreSQL repository for backend-owned health incidents."""

from __future__ import annotations

import json
import uuid
import zlib
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

import psycopg2.extras

from otalon_api.repositories.postgres_repo import PostgresRepository

SAMPLE_EXCERPT_MAX = 10
RETENTION_DAYS = 7
RETENTION_ROWS = 50

# Module-level alias so return annotations do not resolve to the ``list``
# *method* defined on the repository class (which shadows the ``list`` builtin
# inside the class body under ``from __future__ import annotations``).
RowList = list[dict[str, Any]]


class HealthIncidentRepository:
    """Persist and query bounded health incident evidence.

    Correlation runs inside one serialized transaction guarded by a
    per-service PostgreSQL advisory lock so that concurrent API workers can
    never open duplicate active incidents or lose sample/failure counters.
    """

    def __init__(self, postgres: PostgresRepository) -> None:
        """Initialize repository with shared PostgreSQL access."""
        self._postgres = postgres

    def active(self, service: str) -> dict[str, Any] | None:
        """Return active incident for service, if one exists."""
        rows = self._postgres._execute_query(
            "SELECT * FROM health_incidents WHERE service = %(service)s AND status = 'active' "
            "ORDER BY first_seen DESC LIMIT 1",
            {"service": service},
        )
        return rows[0] if rows else None

    def list(self, status: str | None = None, service: str | None = None, limit: int = 50) -> RowList:
        """Return incidents newest first within bounded retention."""
        params: dict[str, Any] = {"limit": min(max(limit, 1), RETENTION_ROWS)}
        clause = ""
        if status:
            clause = " AND status = %(status)s"
            params["status"] = status
        if service:
            clause += " AND service = %(service)s"
            params["service"] = service
        return self._postgres._execute_query(
            "SELECT * FROM health_incidents WHERE last_seen >= now() - interval '7 days'"
            f"{clause} ORDER BY first_seen DESC LIMIT %(limit)s",
            params,
        )

    def unacknowledged(self) -> RowList:
        """Return every unacknowledged incident within the retention window.

        CAPTURE 45 requires Overview reminders to persist until the operator
        acknowledges them. Deriving that projection from the 50-row history page
        (:meth:`list`) truncates it: 50 newer incidents could push an
        unacknowledged reminder off the page while it is still well inside the
        7-day retention window, silently hiding it. This query returns ALL
        active/recovered rows with ``acknowledged_at IS NULL`` bounded ONLY by
        the 7-day operational-retention window (the intentional upper bound from
        CAPTURE follow-up 5 "at most 50 incidents / 7 days"), independent of the
        50-item history page size. Rows older than 7 days are legitimately
        pruned; that retention exception is documented and tested, not silent.
        """
        return self._postgres._execute_query(
            "SELECT * FROM health_incidents "
            "WHERE last_seen >= now() - interval '7 days' "
            "AND status IN ('active', 'recovered') AND acknowledged_at IS NULL "
            "ORDER BY first_seen DESC"
        )

    def get(self, incident_id: UUID) -> dict[str, Any] | None:
        """Return one incident by stable identifier."""
        rows = self._postgres._execute_query(
            "SELECT * FROM health_incidents WHERE id = %(id)s", {"id": str(incident_id)}
        )
        return rows[0] if rows else None

    def acknowledge(self, incident_id: UUID, actor: str, acknowledged_at: datetime) -> dict[str, Any] | None:
        """Acknowledge incident and append one idempotent Change Audit row."""
        with self._postgres.connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT * FROM health_incidents WHERE id = %(id)s FOR UPDATE",
                    {"id": str(incident_id)},
                )
                row = cur.fetchone()
                if row is None:
                    # The SELECT ... FOR UPDATE opened a transaction. Roll it
                    # back explicitly before returning so the pooled connection
                    # is NOT handed back idle-in-transaction (which would pin a
                    # snapshot, block VACUUM, and eventually exhaust the pool on
                    # every unknown/pruned-incident acknowledge). This is a
                    # normal event under CAPTURE 44/45 (a deep-link to an id
                    # that has aged out of the 7-day/50-row window).
                    conn.rollback()
                    return None
                if row["acknowledged_at"] is None:
                    cur.execute(
                        "UPDATE health_incidents SET acknowledged_at = %(at)s, acknowledged_by = %(actor)s "
                        "WHERE id = %(id)s RETURNING *",
                        {"at": acknowledged_at, "actor": actor, "id": str(incident_id)},
                    )
                    row = cur.fetchone()
                    cur.execute(
                        "INSERT INTO operations_audit "
                        "(category, actor, action, target, detail, source, source_id) "
                        "VALUES ('access', %(actor)s, 'acknowledge', %(target)s, "
                        "'Health incident acknowledged', 'health_incident', %(source_id)s) "
                        "ON CONFLICT (source, source_id) DO NOTHING",
                        {"actor": actor, "target": str(incident_id), "source_id": str(incident_id)},
                    )
            conn.commit()
        return dict(row)

    def upsert_sample(self, sample: dict[str, Any], now: datetime) -> dict[str, Any]:
        """Atomically correlate one canonical sample into an incident.

        A per-service advisory lock plus a single transaction guarantee that
        the SELECT/INSERT/UPDATE sequence is serialized across API workers, so
        no duplicate active incident is created and no counter update is lost.
        """
        with self._postgres.connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT pg_advisory_xact_lock(%(key)s)",
                    {"key": self._advisory_key(str(sample["service"]))},
                )
                cur.execute(
                    "SELECT * FROM health_incidents WHERE service = %(service)s AND status = 'active' "
                    "ORDER BY first_seen DESC LIMIT 1 FOR UPDATE",
                    {"service": sample["service"]},
                )
                active = cur.fetchone()
                if active is None:
                    result = self._insert_locked(cur, sample, now)
                else:
                    result = self._update_locked(cur, dict(active), sample, now)
            conn.commit()
        return result

    def _update_locked(self, cur: Any, active: dict[str, Any], sample: dict[str, Any], now: datetime) -> dict[str, Any]:
        """Update an existing active incident within the locked transaction."""
        in_budget = bool(sample["running"]) and float(sample["latency_ms"]) <= float(sample["latency_budget_ms"])
        successes = active["consecutive_successes"] + 1 if in_budget else 0
        status = "recovered" if successes >= 2 else "active"
        recovered_at = now if status == "recovered" else None
        samples = (list(active.get("samples") or []) + [sample])[-SAMPLE_EXCERPT_MAX:]
        cur.execute(
            "UPDATE health_incidents SET last_seen = %(last_seen)s, recovered_at = %(recovered_at)s, "
            "status = %(status)s, sample_count = sample_count + 1, "
            "failure_count = failure_count + %(failure)s, consecutive_successes = %(successes)s, "
            "worst_latency_ms = GREATEST(worst_latency_ms, %(latency)s), samples = %(samples)s::jsonb "
            "WHERE id = %(id)s RETURNING *",
            {
                "id": str(active["id"]),
                "last_seen": now,
                "recovered_at": recovered_at,
                "status": status,
                "failure": int(not in_budget),
                "successes": successes,
                "latency": sample["latency_ms"],
                "samples": json.dumps(samples),
            },
        )
        return dict(cur.fetchone())

    def _insert_locked(self, cur: Any, sample: dict[str, Any], now: datetime) -> dict[str, Any]:
        """Insert an initial failed sample within the locked transaction."""
        cur.execute(
            "INSERT INTO health_incidents (id, service, owning_service, probe_target, category, cause, "
            "status, first_seen, last_seen, sample_count, failure_count, consecutive_successes, latency_budget_ms, "
            "worst_latency_ms, samples) VALUES (%(id)s, %(service)s, %(owning)s, %(target)s, %(category)s, "
            "%(cause)s, 'active', %(now)s, %(now)s, 1, 1, %(successes)s, %(budget)s, %(latency)s, %(samples)s::jsonb) "
            "RETURNING *",
            {
                "id": str(uuid.uuid4()),
                "service": sample["service"],
                "owning": sample.get("owning_service", ""),
                "target": sample.get("probe_target", ""),
                "category": sample["category"],
                "cause": sample["cause"],
                "now": now,
                "budget": sample["latency_budget_ms"],
                "latency": sample["latency_ms"],
                "samples": json.dumps([sample]),
                "successes": 0,
            },
        )
        return dict(cur.fetchone())

    @staticmethod
    def _advisory_key(service: str) -> int:
        """Map a service name to a stable signed 32-bit advisory-lock key."""
        return zlib.crc32(service.encode("utf-8")) - 2**31

    def prune(self, now: datetime | None = None) -> None:
        """Delete evidence older than seven days and retain newest 50 rows."""
        cutoff = (now or datetime.now(timezone.utc)) - timedelta(days=RETENTION_DAYS)
        self._postgres._execute_command(
            "DELETE FROM health_incidents WHERE last_seen < %(cutoff)s",
            {"cutoff": cutoff},
        )
        self._postgres._execute_command(
            "DELETE FROM health_incidents WHERE id IN (SELECT id FROM health_incidents "
            f"ORDER BY first_seen DESC OFFSET {RETENTION_ROWS})",
        )
