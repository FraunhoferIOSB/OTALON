"""Regression: shared cleanup safeguards refuse a live database.

Root cause under test: an autouse cleanup fixture used to issue ``DELETE FROM
operations_audit`` / ``DELETE FROM operations_jobs`` unconditionally, so a test
run against the default live ``otalon-clas`` database erased real operator
history.

These tests exercise the shared guard through a spy repository that records
every executed statement. They prove the guard rejects a non-disposable target
before issuing any DELETE and permits scoped test-database cleanup.
"""

from __future__ import annotations

from typing import Any

import pytest

from tests.helpers.db_isolation import (
    guarded_clean_operations_tables,
    is_disposable_test_db,
    target_database_name,
)

pytestmark = [pytest.mark.unit]


class _SpyRepo:
    """PostgresRepository stand-in recording every executed update statement."""

    def __init__(self, dbname: str) -> None:
        self._dsn: dict[str, Any] = {"dbname": dbname}
        self.updates: list[str] = []

    def _execute_update(self, sql: str, params: dict[str, Any] | None = None) -> int:
        self.updates.append(sql)
        return 0


def test_cleanup_guard_refuses_live_otalon_clas() -> None:
    """The shared cleanup guard issues no DELETE on a non-test database."""
    repo = _SpyRepo("otalon-clas")
    with pytest.raises(RuntimeError):
        guarded_clean_operations_tables(repo)
    assert repo.updates == [], "live database must never receive DELETE"


def test_cleanup_guard_runs_on_disposable_test_db() -> None:
    """A test database allows scoped cleanup on two guarded passes."""
    repo = _SpyRepo("cyberclas_test")
    guarded_clean_operations_tables(repo)
    guarded_clean_operations_tables(repo)
    assert repo.updates == [
        "DELETE FROM operations_audit",
        "DELETE FROM operations_jobs",
        "DELETE FROM operations_audit",
        "DELETE FROM operations_jobs",
    ]


def test_cleanup_guard_runs_with_explicit_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    """An explicit ``OPERATIONS_TEST_DB_OK=1`` opt-in permits cleanup."""
    monkeypatch.setenv("OPERATIONS_TEST_DB_OK", "1")
    repo = _SpyRepo("otalon-clas")
    guarded_clean_operations_tables(repo)
    guarded_clean_operations_tables(repo)
    assert len(repo.updates) == 4


def test_guard_helper_is_fail_closed_by_default() -> None:
    """The shared guard refuses a live db name and raises before any DELETE."""
    repo = _SpyRepo("otalon-clas")
    assert is_disposable_test_db(repo) is False
    assert target_database_name(repo) == "otalon-clas"
    with pytest.raises(RuntimeError):
        guarded_clean_operations_tables(repo)
    assert repo.updates == [], "guard must raise before issuing any DELETE"


def test_guard_helper_reads_repo_dsn_not_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """The guard checks the repo's actual target db, not the environment.

    Even if ``POSTGRES_DATABASE`` points at a test db, a repository actually
    wired to the live ``otalon-clas`` database must still be refused.
    """
    monkeypatch.setenv("POSTGRES_DATABASE", "some_test_db")
    repo = _SpyRepo("otalon-clas")
    assert is_disposable_test_db(repo) is False
