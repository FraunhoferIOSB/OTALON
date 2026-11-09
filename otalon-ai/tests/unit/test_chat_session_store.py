"""Unit tests for :mod:`src.chat.session_store`.

These tests use an in-memory fake psycopg2 connection so they run without a
live PostgreSQL. The fake is intentionally minimal — it stores rows as a
dict and replays the SQL through a tiny pattern matcher. Behaviours covered:

- load() returns ``[]`` for unknown session IDs
- save() truncates to ``history_window``
- save() drops ``role == "system"`` messages
- save() upserts (insert + update path)
- prune() removes only stale rows, respects ``retention_days <= 0``

The integration test against a real Postgres lives in
``tests/integration/`` (skipped when no DSN is configured).
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Tuple

import pytest

from otalon_ai.chat.session_store import ChatSessionStore


@dataclass
class _FakeRow:
    session_id: str
    messages: List[Dict[str, Any]]
    updated_at_days_ago: int = 0  # negative ages count as "in the past"


@dataclass
class _FakeDatabase:
    rows: Dict[str, _FakeRow] = field(default_factory=dict)

    @contextmanager
    def chat_connection(self) -> Iterator["_FakeConnection"]:
        yield _FakeConnection(self)


@dataclass
class _FakeConnection:
    db: _FakeDatabase
    last_rowcount: int = 0

    @contextmanager
    def cursor(self) -> Iterator["_FakeCursor"]:
        yield _FakeCursor(self.db, self)


@dataclass
class _FakeCursor:
    db: _FakeDatabase
    conn: _FakeConnection
    _last_result: Optional[Tuple[Any, ...]] = None
    rowcount: int = 0

    def execute(self, sql: str, params: Tuple[Any, ...] = ()) -> None:
        sql_compact = " ".join(sql.split())
        if sql_compact.startswith("SELECT messages FROM chat_sessions WHERE session_id"):
            session_id = params[0]
            row = self.db.rows.get(session_id)
            self._last_result = (row.messages,) if row is not None else None
            return
        if sql_compact.startswith("INSERT INTO chat_sessions"):
            session_id, payload = params
            self.db.rows[session_id] = _FakeRow(session_id=session_id, messages=json.loads(payload))
            return
        if sql_compact.startswith("DELETE FROM chat_sessions WHERE updated_at <"):
            (retention_days,) = params
            stale = [k for k, v in self.db.rows.items() if v.updated_at_days_ago > retention_days]
            for k in stale:
                self.db.rows.pop(k)
            self.rowcount = len(stale)
            return
        raise AssertionError(f"Unexpected SQL: {sql_compact!r}")

    def fetchone(self) -> Optional[Tuple[Any, ...]]:
        return self._last_result


# --- tests ---------------------------------------------------------------


@pytest.fixture
def db() -> _FakeDatabase:
    return _FakeDatabase()


@pytest.fixture
def store(db: _FakeDatabase) -> ChatSessionStore:
    return ChatSessionStore(db, history_window=5)  # type: ignore[arg-type]


def test_load_empty_returns_empty_list(store: ChatSessionStore) -> None:
    assert store.load("never-seen") == []


def test_save_round_trip(store: ChatSessionStore) -> None:
    msgs = [
        {"role": "user", "content": "hi"},
        {"role": "assistant", "content": "hello"},
    ]
    store.save("s1", msgs)
    assert store.load("s1") == msgs


def test_save_truncates_to_history_window(store: ChatSessionStore) -> None:
    msgs = [{"role": "user", "content": f"msg-{i}"} for i in range(10)]
    store.save("s1", msgs)
    persisted = store.load("s1")
    assert len(persisted) == 5
    assert persisted[0]["content"] == "msg-5"
    assert persisted[-1]["content"] == "msg-9"


def test_save_drops_system_messages(store: ChatSessionStore) -> None:
    msgs = [
        {"role": "system", "content": "[loaded system prompt]"},
        {"role": "user", "content": "hi"},
        {"role": "assistant", "content": "hello"},
    ]
    store.save("s1", msgs)
    persisted = store.load("s1")
    assert all(m.get("role") != "system" for m in persisted)
    assert len(persisted) == 2


def test_save_upserts_overwrite(store: ChatSessionStore) -> None:
    store.save("s1", [{"role": "user", "content": "first"}])
    store.save("s1", [{"role": "user", "content": "second"}])
    persisted = store.load("s1")
    assert persisted == [{"role": "user", "content": "second"}]


def test_prune_removes_only_stale_rows(db: _FakeDatabase, store: ChatSessionStore) -> None:
    db.rows["fresh"] = _FakeRow(session_id="fresh", messages=[], updated_at_days_ago=5)
    db.rows["stale"] = _FakeRow(session_id="stale", messages=[], updated_at_days_ago=45)
    deleted = store.prune(retention_days=30)
    assert deleted == 1
    assert "fresh" in db.rows
    assert "stale" not in db.rows


def test_prune_disabled_when_retention_zero(db: _FakeDatabase, store: ChatSessionStore) -> None:
    db.rows["stale"] = _FakeRow(session_id="stale", messages=[], updated_at_days_ago=999)
    deleted = store.prune(retention_days=0)
    assert deleted == 0
    assert "stale" in db.rows


def test_empty_session_id_rejected(store: ChatSessionStore) -> None:
    with pytest.raises(ValueError):
        store.load("")
    with pytest.raises(ValueError):
        store.save("", [{"role": "user", "content": "x"}])


def test_history_window_must_be_positive(db: _FakeDatabase) -> None:
    with pytest.raises(ValueError):
        ChatSessionStore(db, history_window=0)  # type: ignore[arg-type]
