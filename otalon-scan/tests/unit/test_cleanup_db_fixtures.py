"""Unit tests for ``scripts/cleanup_db_fixtures.py``.

The script's I/O surface is a single asyncpg.Connection. The tests fake
that connection with an in-memory stub so we can assert behaviour without
a live Postgres. A separate manual run against the real DB validates the
SQL syntax (see the dry-run output captured in
``.dev/STATUS.md``-equivalent reports).

Scope:

* :func:`test_dry_run_empty_db_exits_zero` — smoke: empty DB → exit 0.
* :func:`test_dry_run_reports_estimates` — non-empty estimates surface in
  stdout without DELETEs being issued.
* :func:`test_apply_executes_deletes_in_transaction` — ``--apply`` issues
  three DELETEs inside one ``transaction()`` block.
* :func:`test_normalise_dsn_strips_sqlalchemy_driver` — DSN normalisation
  for asyncpg.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any, Iterator
from unittest.mock import patch

import pytest

_SCRIPT_PATH = Path(__file__).resolve().parents[2] / "scripts" / "cleanup_db_fixtures.py"


def _load_script_module() -> Any:
    """Import the script as a module without invoking its CLI entry point."""
    spec = importlib.util.spec_from_file_location("cleanup_db_fixtures", _SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Avoid name clashes if the test re-runs in the same process.
    sys.modules["cleanup_db_fixtures"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def script() -> Any:
    return _load_script_module()


class _FakeTransaction:
    def __init__(self, conn: "_FakeConnection") -> None:
        self._conn = conn

    async def __aenter__(self) -> "_FakeTransaction":
        self._conn.in_transaction = True
        return self

    async def __aexit__(self, *args: object) -> None:
        self._conn.in_transaction = False


class _FakeRow:
    def __init__(self, value: int) -> None:
        self._value = value

    def __getitem__(self, idx: int) -> int:
        assert idx == 0
        return self._value


class _FakeConnection:
    """Minimal asyncpg.Connection stand-in for the cleanup script."""

    def __init__(
        self,
        counts: dict[str, int] | None = None,
        estimates: dict[str, int] | None = None,
        delete_rows: dict[str, int] | None = None,
    ) -> None:
        self._counts = counts or {"devices": 0, "network_interfaces": 0, "scans": 0}
        self._estimates = estimates or {
            "devices_to_delete": 0,
            "interfaces_of_test_devices": 0,
            "orphan_interfaces": 0,
        }
        # Sequence of DELETE statuses returned by execute(); the script
        # issues exactly three DELETEs in order: iface-of-test-dev,
        # orphan-iface, devices.
        self._delete_rows = delete_rows or {
            "interfaces_of_test_devices": 0,
            "orphan_interfaces": 0,
            "devices": 0,
        }
        self._executed: list[str] = []
        self.in_transaction = False
        self._closed = False

    async def fetchrow(self, query: str) -> _FakeRow:
        q = " ".join(query.split())
        if "FROM devices WHERE" in q:
            return _FakeRow(self._estimates["devices_to_delete"])
        if "JOIN devices d" in q:
            return _FakeRow(self._estimates["interfaces_of_test_devices"])
        if "FROM network_interfaces WHERE" in q:
            return _FakeRow(self._estimates["orphan_interfaces"])
        if q.startswith("SELECT COUNT(*) FROM devices"):
            return _FakeRow(self._counts["devices"])
        if q.startswith("SELECT COUNT(*) FROM network_interfaces"):
            return _FakeRow(self._counts["network_interfaces"])
        if q.startswith("SELECT COUNT(*) FROM scans"):
            return _FakeRow(self._counts["scans"])
        raise AssertionError(f"unexpected query: {q}")

    async def execute(self, query: str) -> str:
        self._executed.append(query)
        q = " ".join(query.split())
        if q.startswith("DELETE FROM network_interfaces ni USING devices d"):
            return f"DELETE {self._delete_rows['interfaces_of_test_devices']}"
        if q.startswith("DELETE FROM network_interfaces WHERE"):
            return f"DELETE {self._delete_rows['orphan_interfaces']}"
        if q.startswith("DELETE FROM devices WHERE"):
            return f"DELETE {self._delete_rows['devices']}"
        raise AssertionError(f"unexpected execute: {q}")

    def transaction(self) -> _FakeTransaction:
        return _FakeTransaction(self)

    async def close(self) -> None:
        self._closed = True


@pytest.fixture
def fake_conn() -> _FakeConnection:
    return _FakeConnection()


@pytest.fixture
def patched_connect(script: Any, fake_conn: _FakeConnection) -> Iterator[_FakeConnection]:
    async def _fake_connect(dsn: str) -> _FakeConnection:  # noqa: ARG001
        return fake_conn

    with patch.object(script.asyncpg, "connect", _fake_connect):
        with patch.object(script, "_resolve_dsn", lambda: "postgresql://u:p@h/db"):
            yield fake_conn


def test_dry_run_empty_db_exits_zero(
    script: Any, patched_connect: _FakeConnection, capsys: pytest.CaptureFixture[str]
) -> None:
    """Empty DB + default ``--dry-run`` SHALL return exit code 0."""
    rc = script.main([])
    assert rc == 0
    captured = capsys.readouterr()
    assert "BEFORE:" in captured.out
    assert "Would delete:" in captured.out
    assert "[dry-run]" in captured.out
    # No DELETE statements should have been issued.
    assert patched_connect._executed == []
    assert patched_connect._closed is True


def test_dry_run_reports_estimates(script: Any, capsys: pytest.CaptureFixture[str]) -> None:
    """Non-zero estimates SHALL surface in the report; still no DELETEs."""
    conn = _FakeConnection(
        counts={"devices": 5, "network_interfaces": 8, "scans": 42},
        estimates={
            "devices_to_delete": 3,
            "interfaces_of_test_devices": 4,
            "orphan_interfaces": 2,
        },
    )

    async def _fake_connect(dsn: str) -> _FakeConnection:  # noqa: ARG001
        return conn

    with patch.object(script.asyncpg, "connect", _fake_connect):
        with patch.object(script, "_resolve_dsn", lambda: "postgresql://u:p@h/db"):
            rc = script.main([])

    assert rc == 0
    out = capsys.readouterr().out
    assert "devices_to_delete                   3" in out
    assert "interfaces_of_test_devices          4" in out
    assert "orphan_interfaces                   2" in out
    assert conn._executed == []  # dry-run path issues no DELETEs


def test_apply_executes_deletes_in_transaction(script: Any, capsys: pytest.CaptureFixture[str]) -> None:
    """``--apply`` SHALL run three DELETEs inside a single transaction."""
    conn = _FakeConnection(
        counts={"devices": 5, "network_interfaces": 8, "scans": 42},
        estimates={
            "devices_to_delete": 3,
            "interfaces_of_test_devices": 4,
            "orphan_interfaces": 2,
        },
        delete_rows={
            "interfaces_of_test_devices": 4,
            "orphan_interfaces": 2,
            "devices": 3,
        },
    )

    async def _fake_connect(dsn: str) -> _FakeConnection:  # noqa: ARG001
        return conn

    with patch.object(script.asyncpg, "connect", _fake_connect):
        with patch.object(script, "_resolve_dsn", lambda: "postgresql://u:p@h/db"):
            rc = script.main(["--apply"])

    assert rc == 0
    assert len(conn._executed) == 3
    assert conn._executed[0].lstrip().startswith("DELETE FROM network_interfaces ni")
    assert conn._executed[1].lstrip().startswith("DELETE FROM network_interfaces WHERE")
    assert conn._executed[2].lstrip().startswith("DELETE FROM devices WHERE")
    out = capsys.readouterr().out
    assert "Deleted:" in out
    assert "devices                             3" in out


def test_normalise_dsn_strips_sqlalchemy_driver(script: Any) -> None:
    """SQLAlchemy-form DSNs SHALL be rewritten for asyncpg."""
    fn = script._normalise_dsn_for_asyncpg
    assert fn("postgresql+asyncpg://u:p@h/db") == "postgresql://u:p@h/db"
    assert fn("postgresql+psycopg2://u:p@h/db") == "postgresql://u:p@h/db"
    assert fn("postgresql://u:p@h/db") == "postgresql://u:p@h/db"


def test_safe_dsn_for_log_redacts_password(script: Any) -> None:
    """Logged DSN MUST NOT include the password."""
    redacted = script._safe_dsn_for_log("postgresql://operator:s3cr3t@db.example:5432/otalon-clas")
    assert "s3cr3t" not in redacted
    assert "operator" in redacted
    assert "***" in redacted
