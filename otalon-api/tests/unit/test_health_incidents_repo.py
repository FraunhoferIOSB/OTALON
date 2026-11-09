"""Repository-level tests for atomic health incident correlation.

These exercise the real :class:`HealthIncidentRepository` correlation SQL flow
(advisory lock -> ``SELECT ... FOR UPDATE`` -> INSERT/UPDATE -> commit) against
an in-memory fake cursor, so the transactional guarantees introduced for
multi-worker safety are covered without a live PostgreSQL server.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator

import pytest

from otalon_api.repositories.health_incidents_repo import (
    RETENTION_ROWS,
    SAMPLE_EXCERPT_MAX,
    HealthIncidentRepository,
)


class _FakeCursor:
    """Minimal RealDictCursor stand-in recording SQL and serving rows."""

    def __init__(self, fetch_queue: list[dict[str, Any] | None]) -> None:
        self._fetch_queue = fetch_queue
        self.executed: list[tuple[str, dict[str, Any] | None]] = []

    def __enter__(self) -> "_FakeCursor":
        return self

    def __exit__(self, *_: Any) -> bool:
        return False

    def execute(self, sql: str, params: dict[str, Any] | None = None) -> None:
        self.executed.append((sql, params))

    def fetchone(self) -> dict[str, Any] | None:
        return self._fetch_queue.pop(0)


class _FakeConn:
    """Connection stand-in that hands out one prepared cursor and commits.

    Models both ``commit`` and ``rollback`` so tests can prove the 404 path
    closes its ``SELECT ... FOR UPDATE`` transaction (rollback) rather than
    leaving it open (the idle-in-transaction pool leak the audit flagged).
    """

    def __init__(self, cursor: _FakeCursor) -> None:
        self._cursor = cursor
        self.committed = False
        self.rolled_back = False

    def cursor(self, cursor_factory: Any = None) -> _FakeCursor:
        return self._cursor

    def commit(self) -> None:
        self.committed = True

    def rollback(self) -> None:
        self.rolled_back = True


class _FakePostgres:
    """PostgresRepository stand-in exposing a context-managed connection."""

    def __init__(self, cursor: _FakeCursor) -> None:
        self.conn = _FakeConn(cursor)
        self.commands: list[tuple[str, dict[str, Any] | None]] = []

    @contextmanager
    def connection(self) -> Iterator[_FakeConn]:
        yield self.conn

    def _execute_command(self, sql: str, params: dict[str, Any] | None = None) -> None:
        self.commands.append((sql, params))


def _sample(running: bool, latency: float = 4200.0) -> dict[str, Any]:
    """Build a canonical normalized incident sample."""
    return {
        "service": "Network Traffic Recorder",
        "owning_service": "otalon-capture",
        "probe_target": "Network Traffic Recorder",
        "running": running,
        "category": "probe_timeout",
        "cause": "health probe timeout",
        "latency_ms": latency,
        "latency_budget_ms": 3000.0,
        "timestamp": 1.0,
        "detail": "probe timeout after 4200 ms",
    }


def _active_row(**overrides: Any) -> dict[str, Any]:
    """Build a persisted active incident row for the UPDATE path."""
    row: dict[str, Any] = {
        "id": "11111111-1111-1111-1111-111111111111",
        "service": "Network Traffic Recorder",
        "status": "active",
        "consecutive_successes": 0,
        "samples": [],
    }
    row.update(overrides)
    return row


@pytest.mark.unit
def test_upsert_first_failure_inserts_and_commits() -> None:
    """A first failure with no active row inserts a fresh incident row."""
    inserted = {"id": "abc", "status": "active"}
    cursor = _FakeCursor([None, inserted])  # SELECT -> None, INSERT RETURNING
    postgres = _FakePostgres(cursor)
    repo = HealthIncidentRepository(postgres)  # type: ignore[arg-type]

    result = repo.upsert_sample(_sample(False), datetime.now(timezone.utc))

    assert result == inserted
    assert postgres.conn.committed is True
    joined = " ".join(sql for sql, _ in cursor.executed)
    assert "pg_advisory_xact_lock" in joined
    assert "FOR UPDATE" in joined
    assert "INSERT INTO health_incidents" in joined


@pytest.mark.unit
def test_upsert_failure_on_active_updates_same_incident() -> None:
    """A repeated failure updates the locked active row, not a new one."""
    active = _active_row(consecutive_successes=0)
    updated = {"id": active["id"], "status": "active"}
    cursor = _FakeCursor([active, updated])
    postgres = _FakePostgres(cursor)
    repo = HealthIncidentRepository(postgres)  # type: ignore[arg-type]

    result = repo.upsert_sample(_sample(False), datetime.now(timezone.utc))

    assert result == updated
    update_sql, params = cursor.executed[-1]
    assert "UPDATE health_incidents" in update_sql
    assert params is not None and params["successes"] == 0
    assert params["failure"] == 1


@pytest.mark.unit
def test_upsert_second_success_marks_recovered() -> None:
    """A success on an incident already at one success recovers it."""
    active = _active_row(consecutive_successes=1)
    cursor = _FakeCursor([active, {"id": active["id"], "status": "recovered"}])
    postgres = _FakePostgres(cursor)
    repo = HealthIncidentRepository(postgres)  # type: ignore[arg-type]

    repo.upsert_sample(_sample(True, latency=90.0), datetime.now(timezone.utc))

    _, params = cursor.executed[-1]
    assert params is not None
    assert params["successes"] == 2
    assert params["status"] == "recovered"
    assert params["recovered_at"] is not None
    assert params["failure"] == 0


@pytest.mark.unit
def test_upsert_single_success_stays_active_and_resets_on_failure() -> None:
    """One success advances the counter but keeps the incident active."""
    active = _active_row(consecutive_successes=0)
    cursor = _FakeCursor([active, {"id": active["id"], "status": "active"}])
    postgres = _FakePostgres(cursor)
    repo = HealthIncidentRepository(postgres)  # type: ignore[arg-type]

    repo.upsert_sample(_sample(True, latency=90.0), datetime.now(timezone.utc))

    _, params = cursor.executed[-1]
    assert params is not None
    assert params["successes"] == 1
    assert params["status"] == "active"
    assert params["recovered_at"] is None


@pytest.mark.unit
def test_upsert_running_but_over_budget_resets_successes_and_counts_failure() -> None:
    """A running sample over budget is not a recovery success."""
    active = _active_row(consecutive_successes=1)
    cursor = _FakeCursor([active, {"id": active["id"], "status": "active"}])
    postgres = _FakePostgres(cursor)
    repo = HealthIncidentRepository(postgres)  # type: ignore[arg-type]

    repo.upsert_sample(_sample(True, latency=4200.0), datetime.now(timezone.utc))

    _, params = cursor.executed[-1]
    assert params is not None
    assert params["successes"] == 0
    assert params["failure"] == 1


@pytest.mark.unit
def test_upsert_bounds_sample_excerpt() -> None:
    """The persisted sample excerpt is capped at SAMPLE_EXCERPT_MAX newest."""
    prior = [{"detail": f"s{i}", "running": False} for i in range(SAMPLE_EXCERPT_MAX + 5)]
    active = _active_row(samples=prior)
    cursor = _FakeCursor([active, {"id": active["id"], "status": "active"}])
    postgres = _FakePostgres(cursor)
    repo = HealthIncidentRepository(postgres)  # type: ignore[arg-type]

    repo.upsert_sample(_sample(False), datetime.now(timezone.utc))

    import json

    _, params = cursor.executed[-1]
    assert params is not None
    persisted = json.loads(params["samples"])
    assert len(persisted) == SAMPLE_EXCERPT_MAX
    assert persisted[-1]["detail"] == "probe timeout after 4200 ms"


@pytest.mark.unit
def test_advisory_key_is_stable_signed_32bit() -> None:
    """The advisory-lock key is deterministic and fits a signed 32-bit int."""
    key_a = HealthIncidentRepository._advisory_key("Network Traffic Recorder")
    key_b = HealthIncidentRepository._advisory_key("Network Traffic Recorder")
    other = HealthIncidentRepository._advisory_key("Postgres")

    assert key_a == key_b
    assert key_a != other
    assert -(2**31) <= key_a < 2**31


@pytest.mark.unit
def test_prune_enforces_days_and_row_retention() -> None:
    """Pruning deletes stale rows and enforces the row-count ceiling."""
    cursor = _FakeCursor([])
    postgres = _FakePostgres(cursor)
    repo = HealthIncidentRepository(postgres)  # type: ignore[arg-type]

    now = datetime.now(timezone.utc)
    repo.prune(now)

    assert len(postgres.commands) == 2
    cutoff_params = postgres.commands[0][1]
    assert cutoff_params is not None
    assert cutoff_params["cutoff"] <= now - timedelta(days=6)
    assert f"OFFSET {RETENTION_ROWS}" in postgres.commands[1][0]


@pytest.mark.unit
def test_acknowledge_updates_row_and_audits_once() -> None:
    """Acknowledgement locks, updates, audits, and commits in one transaction."""
    incident_id = "11111111-1111-1111-1111-111111111111"
    row = _active_row(id=incident_id, acknowledged_at=None)
    updated = {**row, "acknowledged_at": datetime.now(timezone.utc), "acknowledged_by": "alice"}
    cursor = _FakeCursor([row, updated])
    postgres = _FakePostgres(cursor)
    repo = HealthIncidentRepository(postgres)  # type: ignore[arg-type]

    result = repo.acknowledge(__import__("uuid").UUID(incident_id), "alice", datetime.now(timezone.utc))

    assert result == updated
    assert postgres.conn.committed
    assert "FOR UPDATE" in cursor.executed[0][0]
    assert "UPDATE health_incidents" in cursor.executed[1][0]
    assert "INSERT INTO operations_audit" in cursor.executed[2][0]


@pytest.mark.unit
def test_acknowledge_missing_incident_rolls_back_and_does_not_audit() -> None:
    """Missing incident returns None, issues no mutation, and CLOSES the tx.

    The ``SELECT ... FOR UPDATE`` opens a transaction; the 404 branch MUST roll
    it back before returning so the pooled connection is not handed back
    idle-in-transaction (audit B-3). It must also neither commit nor audit.
    """
    cursor = _FakeCursor([None])
    postgres = _FakePostgres(cursor)
    repo = HealthIncidentRepository(postgres)  # type: ignore[arg-type]

    result = repo.acknowledge(__import__("uuid").uuid4(), "alice", datetime.now(timezone.utc))

    assert result is None
    assert not postgres.conn.committed
    # The transaction is explicitly rolled back (no idle-in-transaction leak).
    assert postgres.conn.rolled_back is True
    # Only the SELECT ran; no UPDATE / INSERT audit SQL.
    assert len(cursor.executed) == 1
    assert "FOR UPDATE" in cursor.executed[0][0]
