"""Unit tests for ``PostgresRepository.snapshot_bounds_to_history``.

Covers OpenSpec change ``add-chat-triggered-boundary-retraining`` § 1.4
and the corresponding spec scenario "A pre-training snapshot row is
written". A real PostgreSQL instance is not required: we exercise the
SQL pipeline by faking the connection pool's cursor.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

import pytest

from otalon_api.repositories.postgres_repo import PostgresRepository


class _FakeCursor:
    """Captures every executed statement; never actually runs SQL."""

    def __init__(self) -> None:
        self.executions: list[tuple[str, dict[str, Any] | None]] = []

    def __enter__(self) -> "_FakeCursor":
        return self

    def __exit__(self, *exc: Any) -> None:
        return None

    def execute(self, sql: str, params: dict[str, Any] | None = None) -> None:
        self.executions.append((sql, params))


class _FakeConn:
    def __init__(self) -> None:
        self.autocommit = False
        self.committed = False
        self.rolled_back = False
        self._cursor = _FakeCursor()

    def cursor(self, **_kwargs: Any) -> _FakeCursor:
        return self._cursor

    def commit(self) -> None:
        self.committed = True

    def rollback(self) -> None:
        self.rolled_back = True


class _FakePool:
    def __init__(self, conn: _FakeConn) -> None:
        self.closed = False
        self._conn = conn
        self.returned: list[_FakeConn] = []

    def getconn(self) -> _FakeConn:
        return self._conn

    def putconn(self, conn: _FakeConn, close: bool = False) -> None:
        self.returned.append(conn)


@pytest.fixture()
def repo() -> PostgresRepository:
    """A repo whose pool is replaced by a fake; no real DB access."""
    return PostgresRepository(
        host="x",
        port=5432,
        user="u",
        password="p",
        database="d",
    )


def _install_fake_pool(repo: PostgresRepository, conn: _FakeConn) -> _FakePool:
    fake_pool = _FakePool(conn)
    repo._pool = fake_pool  # type: ignore[assignment]  # noqa: SLF001
    return fake_pool


def test_snapshot_requires_non_empty_reason(repo: PostgresRepository) -> None:
    """An empty reason aborts BEFORE any DB access."""
    with pytest.raises(ValueError, match="non-empty"):
        repo.snapshot_bounds_to_history(module="conn", reason="")


def test_snapshot_returns_zero_when_bounds_empty(
    repo: PostgresRepository,
) -> None:
    """No productive bounds → snapshot is a no-op returning 0."""
    repo._query_bounds_single = MagicMock(return_value=[])  # type: ignore[method-assign]  # noqa: SLF001
    rows_written = repo.snapshot_bounds_to_history(module="conn", reason="test")
    assert rows_written == 0


def test_snapshot_inserts_one_row_per_bounds_row(
    repo: PostgresRepository,
) -> None:
    """Each productive bounds row produces exactly one bounds_history row."""
    bounds_rows = [
        {
            "module": "conn",
            "series_id": "uci-a",
            "lower_bounds": {"packet_count": 0, "total_volume": 0},
            "upper_bounds": {"packet_count": 1000, "total_volume": 2000},
        },
        {
            "module": "conn",
            "series_id": "uci-b",
            "lower_bounds": '{"packet_count": 0}',  # already-serialised JSON
            "upper_bounds": '{"packet_count": 50}',
        },
    ]
    repo._query_bounds_single = MagicMock(return_value=bounds_rows)  # type: ignore[method-assign]  # noqa: SLF001

    conn = _FakeConn()
    _install_fake_pool(repo, conn)

    rows_written = repo.snapshot_bounds_to_history(
        module="conn",
        reason="pre-training snapshot before retrain",
    )

    assert rows_written == 2
    # Two INSERT statements were issued, one per productive bounds row.
    insert_statements = [
        (sql, params) for sql, params in conn._cursor.executions if "INSERT INTO bounds_history" in sql
    ]
    assert len(insert_statements) == 2

    # Each insert references the correct series_id and a snapshot action.
    series_ids = {params["series_id"] for _, params in insert_statements}
    assert series_ids == {"uci-a", "uci-b"}
    for _, params in insert_statements:
        assert params["module"] == "conn"
        assert params["reason"] == "pre-training snapshot before retrain"
        # old/new payloads are equal — this is a snapshot of the
        # current envelope, not a mutation.
        assert params["old_lower"] == params["new_lower"]
        assert params["old_upper"] == params["new_upper"]
        # JSON-serialised regardless of whether the source row was a
        # dict or a string.
        json.loads(params["new_lower"])  # must round-trip
        json.loads(params["new_upper"])
    assert conn.committed is True
    assert conn.rolled_back is False


def test_snapshot_module_alias_fallback(repo: PostgresRepository) -> None:
    """When ``module`` yields zero rows, fall back through the alias.

    The repository already aliases ``conn`` ↔ ``netcap`` in
    :meth:`query_bounds`; the snapshot helper must follow the same
    convention so we never silently snapshot an empty set when the
    productive data lives under the alias.
    """
    alias_rows = [
        {
            "module": "netcap",
            "series_id": "legacy-uci",
            "lower_bounds": {"a": 1},
            "upper_bounds": {"a": 2},
        }
    ]

    call_log: list[tuple[str, str | None]] = []

    def _fake_query(module: str, series_id: str | None) -> list[dict[str, Any]]:
        call_log.append((module, series_id))
        if module == "conn":
            return []
        if module == "netcap":
            return alias_rows
        return []

    repo._query_bounds_single = MagicMock(side_effect=_fake_query)  # type: ignore[method-assign]  # noqa: SLF001

    conn = _FakeConn()
    _install_fake_pool(repo, conn)

    rows_written = repo.snapshot_bounds_to_history(module="conn", reason="reason")
    assert rows_written == 1
    # The repo MUST have asked for ``conn`` first, then fallen back to
    # ``netcap`` (the documented alias).
    assert ("conn", None) in call_log
    assert ("netcap", None) in call_log
    insert_statements = [params for sql, params in conn._cursor.executions if "INSERT INTO bounds_history" in sql]
    # The snapshot is recorded under the EFFECTIVE module (the alias
    # that had data) so a later restore lookup matches.
    assert insert_statements and insert_statements[0]["module"] == "netcap"
