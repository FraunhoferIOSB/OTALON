"""Unit tests for admin endpoint logic (truncate, delete, compose validation).

Tests SQL-identifier escaping via the PostgresRepository allowlist and
ComposeRunner validation logic without requiring actual database or Docker connections.
"""

from __future__ import annotations

from types import TracebackType
from typing import Any

import pytest

from otalon_api.repositories.postgres_repo import DB_TABLE_ALLOWLIST, PostgresRepository
from otalon_api.services.compose_runner import ComposeRunner
from otalon_api.settings import Settings


def _test_settings() -> Settings:
    """Create a Settings instance for testing.

    Returns:
        Settings configured with test defaults.
    """
    return Settings(
        influxdb_host="localhost",
        influxdb_port=8181,
        influxdb_token="test-token",
        influxdb_org="test-org",
        influxdb_database="netcap",
        postgres_host="localhost",
        postgres_port=5432,
        postgres_user="test",
        postgres_password="test",
        postgres_database="test",
        admin_api_key="admin-key",
        api_port=8090,
        netcap_measurement="network_metrics",
        netcap_id_tag="uci",
        netcap_sparse_port_threshold=10,
        utc_offset_hours=1,
        default_sample_max_points=500,
    )


class TestTruncateTableValidation:
    """Tests for PostgresRepository.truncate_table() allowlist enforcement."""

    @pytest.mark.unit
    def test_truncate_invalid_table_raises_value_error(self) -> None:
        """truncate_table() with a table name not in the allowlist raises ValueError."""
        repo = PostgresRepository.__new__(PostgresRepository)
        with pytest.raises(ValueError, match="not in the allowed table list"):
            repo.truncate_table("users; DROP TABLE anomalies")

    @pytest.mark.unit
    def test_truncate_sql_injection_blocked(self) -> None:
        """truncate_table() blocks SQL injection attempts via the allowlist."""
        repo = PostgresRepository.__new__(PostgresRepository)
        with pytest.raises(ValueError, match="not in the allowed table list"):
            repo.truncate_table("anomalies; DROP TABLE bounds")

    @pytest.mark.unit
    def test_truncate_empty_name_blocked(self) -> None:
        """truncate_table() blocks empty table names."""
        repo = PostgresRepository.__new__(PostgresRepository)
        with pytest.raises(ValueError, match="not in the allowed table list"):
            repo.truncate_table("")

    @pytest.mark.unit
    def test_truncate_allowed_tables_are_valid(self) -> None:
        """All tables in DB_TABLE_ALLOWLIST are valid identifiers."""
        for table in DB_TABLE_ALLOWLIST:
            assert table.isidentifier(), f"Table '{table}' is not a valid Python identifier"


class TestDeleteAllRowsValidation:
    """Tests for PostgresRepository.delete_all_rows() allowlist enforcement."""

    @pytest.mark.unit
    def test_delete_invalid_table_raises_value_error(self) -> None:
        """delete_all_rows() with a table not in the allowlist raises ValueError."""
        repo = PostgresRepository.__new__(PostgresRepository)
        with pytest.raises(ValueError, match="not in the allowed table list"):
            repo.delete_all_rows("evil_table")

    @pytest.mark.unit
    def test_delete_empty_name_blocked(self) -> None:
        """delete_all_rows() blocks empty table names."""
        repo = PostgresRepository.__new__(PostgresRepository)
        with pytest.raises(ValueError, match="not in the allowed table list"):
            repo.delete_all_rows("")


class _FakeCursor:
    """A minimal psycopg2-style cursor with a scripted DELETE outcome."""

    def __init__(self, rowcounts: list[int], fail_on_index: int | None) -> None:
        self._rowcounts = rowcounts
        self._fail_on_index = fail_on_index
        self._calls = 0
        self.executed: list[str] = []
        self.rowcount: int | None = None

    def __enter__(self) -> "_FakeCursor":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        return None

    def execute(self, stmt: Any, *args: Any) -> None:
        index = self._calls
        self._calls += 1
        self.executed.append(str(stmt))
        if self._fail_on_index is not None and index == self._fail_on_index:
            raise RuntimeError("simulated DELETE failure")
        self.rowcount = self._rowcounts[index]


class _FakeConn:
    """A fake connection recording commit/rollback and autocommit flips."""

    def __init__(self, cursor: _FakeCursor) -> None:
        self._cursor = cursor
        self.autocommit = True
        self.committed = 0
        self.rolled_back = 0

    def cursor(self) -> _FakeCursor:
        return self._cursor

    def commit(self) -> None:
        self.committed += 1

    def rollback(self) -> None:
        self.rolled_back += 1


class _FakePool:
    """A fake connection pool recording getconn/putconn traffic."""

    def __init__(self, conn: _FakeConn) -> None:
        self._conn = conn
        self.gotten = 0
        self.returned: list[_FakeConn] = []

    def getconn(self) -> _FakeConn:
        self.gotten += 1
        return self._conn

    def putconn(self, conn: _FakeConn, close: bool = False) -> None:
        self.returned.append(conn)


def _batch_repo(pool: _FakePool | None) -> PostgresRepository:
    """Build a repository whose ``_get_pool`` returns the given fake pool."""
    repo = PostgresRepository.__new__(PostgresRepository)
    repo._get_pool = lambda: pool  # type: ignore[assignment,return-value]
    return repo


class TestDeleteAllRowsBatch:
    """Transaction semantics for PostgresRepository.delete_all_rows_batch()."""

    @pytest.mark.unit
    def test_success_commits_once_and_returns_row_counts(self) -> None:
        """A fully successful batch commits exactly once with correct counts."""
        cursor = _FakeCursor(rowcounts=[3, 5], fail_on_index=None)
        conn = _FakeConn(cursor)
        pool = _FakePool(conn)
        repo = _batch_repo(pool)
        deleted = repo.delete_all_rows_batch(("anomalies", "alarms"))
        assert deleted == {"anomalies": 3, "alarms": 5}
        assert conn.committed == 1
        assert conn.rolled_back == 0
        assert conn.autocommit is False
        assert pool.returned == [conn]

    @pytest.mark.unit
    def test_second_delete_failure_rolls_back_and_does_not_commit(self) -> None:
        """A failure on the second DELETE rolls back and never commits."""
        cursor = _FakeCursor(rowcounts=[3, 0], fail_on_index=1)
        conn = _FakeConn(cursor)
        pool = _FakePool(conn)
        repo = _batch_repo(pool)
        with pytest.raises(RuntimeError, match="simulated DELETE failure"):
            repo.delete_all_rows_batch(("anomalies", "alarms"))
        assert conn.committed == 0
        assert conn.rolled_back == 1
        assert pool.returned == [conn]

    @pytest.mark.unit
    def test_disallowed_table_rejected_before_acquiring_connection(self) -> None:
        """A table outside the allowlist is rejected before any pool access."""
        pool = _FakePool(_FakeConn(_FakeCursor(rowcounts=[], fail_on_index=None)))
        repo = _batch_repo(pool)
        with pytest.raises(ValueError, match="outside the allowed table list"):
            repo.delete_all_rows_batch(("anomalies", "users"))
        assert pool.gotten == 0
        assert pool.returned == []


class TestComposeRunnerValidation:
    """Tests for ComposeRunner action and service validation."""

    @pytest.mark.unit
    def test_invalid_action_raises_value_error(self) -> None:
        """run_action() with invalid action raises ValueError."""
        runner = ComposeRunner(settings=_test_settings())
        with pytest.raises(ValueError, match="Action .* is not allowed"):
            runner.run_action("rm", "postgres")

    @pytest.mark.unit
    def test_invalid_service_raises_value_error(self) -> None:
        """run_action() with invalid service raises ValueError."""
        runner = ComposeRunner(settings=_test_settings())
        with pytest.raises(ValueError, match="Service .* is not allowed"):
            runner.run_action("restart", "evil-service")

    @pytest.mark.unit
    def test_shell_injection_in_action_blocked(self) -> None:
        """Shell injection via action name is blocked by the allowlist."""
        runner = ComposeRunner(settings=_test_settings())
        with pytest.raises(ValueError, match="Action .* is not allowed"):
            runner.run_action("up && rm -rf /", "postgres")

    @pytest.mark.unit
    def test_shell_injection_in_service_blocked(self) -> None:
        """Shell injection via service name is blocked by the allowlist."""
        runner = ComposeRunner(settings=_test_settings())
        with pytest.raises(ValueError, match="Service .* is not allowed"):
            runner.run_action("restart", "postgres && rm -rf /")

    @pytest.mark.unit
    def test_build_compose_args_up(self) -> None:
        """_build_compose_args() for 'up' action produces '-d' flag."""
        runner = ComposeRunner(settings=_test_settings())
        args = runner._build_compose_args("up", "postgres")
        assert args == ["up", "-d", "postgres"]

    @pytest.mark.unit
    def test_build_compose_args_recreate(self) -> None:
        """_build_compose_args() for 'recreate' includes force-recreate flags."""
        runner = ComposeRunner(settings=_test_settings())
        args = runner._build_compose_args("recreate", "postgres")
        assert "--force-recreate" in args
        assert "--no-deps" in args

    @pytest.mark.unit
    def test_build_compose_args_stop(self) -> None:
        """_build_compose_args() for 'stop' produces simple stop command."""
        runner = ComposeRunner(settings=_test_settings())
        args = runner._build_compose_args("stop", "postgres")
        assert args == ["stop", "postgres"]

    @pytest.mark.unit
    def test_build_compose_args_no_service(self) -> None:
        """_build_compose_args() without service omits service name."""
        runner = ComposeRunner(settings=_test_settings())
        args = runner._build_compose_args("restart", None)
        assert args == ["restart"]
