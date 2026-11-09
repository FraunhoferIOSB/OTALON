"""Direct API repository contract tests for bounds correction."""

from unittest.mock import MagicMock

import pytest

from otalon_api.repositories.postgres_repo import PostgresRepository


def _repo() -> PostgresRepository:
    repo = PostgresRepository("localhost", 5432, "user", "password", "db")
    conn = MagicMock()
    cursor = MagicMock()
    cursor.fetchone.return_value = {"lower_bounds": {"a": 5}, "upper_bounds": {"a": 10}}
    conn.cursor.return_value.__enter__.return_value = cursor
    repo._pool = MagicMock()
    repo._pool.closed = False
    repo._pool.getconn.return_value = conn
    return repo


def test_correct_bounds_allows_optional_empty_reason() -> None:
    # The one-click correction contract makes reason optional; an empty reason
    # is persisted verbatim rather than rejected or fabricated.
    result = _repo().correct_bounds("conn", "series", "expand", {"a": 1}, {"a": 20}, "", "operator")
    assert result["lower_bounds"] == {"a": 1}
    assert result["upper_bounds"] == {"a": 20}


def test_correct_bounds_delegates_widening_semantics() -> None:
    result = _repo().correct_bounds("conn", "series", "expand", {"a": 1}, {"a": 20}, "ticket", "operator")
    assert result["lower_bounds"] == {"a": 1}
    assert result["upper_bounds"] == {"a": 20}
    assert result["prior"] == {"lower_bounds": {"a": 5}, "upper_bounds": {"a": 10}}


def test_correct_bounds_discards_connection_after_rollback() -> None:
    repo = _repo()
    assert repo._pool is not None
    pool = repo._pool
    conn = pool.getconn.return_value
    cursor = conn.cursor.return_value.__enter__.return_value
    cursor.execute.side_effect = RuntimeError("database failure")

    with pytest.raises(RuntimeError, match="database failure"):
        repo.correct_bounds("conn", "series", "expand", {"a": 1}, {"a": 20}, "ticket", "operator")

    pool.putconn.assert_called_once_with(conn, close=True)
