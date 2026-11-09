"""Regression tests for :mod:`src.chat.session_store` orphan-tool-call safety.

Covers the Cluster b A1 fix: when the rolling-window truncation in
``ChatSessionStore.save`` cuts the head of the message list, an
``assistant`` message carrying ``tool_calls`` may survive without the
matching ``tool`` reply messages. LiteLLM / OpenAI then reject the next
request with ``"tool_call_id missing"``. The store SHALL advance the
kept head past such orphan assistants (and any orphan ``tool`` replies)
until the first persisted message is internally consistent.

Boundary-mocked against the same fake psycopg2 surface used by
``tests/unit/test_chat_session_store.py``.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Tuple

from otalon_ai.chat.session_store import ChatSessionStore, _drop_orphan_tool_call_head


@dataclass
class _FakeRow:
    session_id: str
    messages: List[Dict[str, Any]]


@dataclass
class _FakeDatabase:
    rows: Dict[str, _FakeRow] = field(default_factory=dict)

    @contextmanager
    def chat_connection(self) -> Iterator["_FakeConnection"]:
        yield _FakeConnection(self)


@dataclass
class _FakeConnection:
    db: _FakeDatabase

    @contextmanager
    def cursor(self) -> Iterator["_FakeCursor"]:
        yield _FakeCursor(self.db)


@dataclass
class _FakeCursor:
    db: _FakeDatabase
    _last_result: Optional[Tuple[Any, ...]] = None
    rowcount: int = 0

    def execute(self, sql: str, params: Tuple[Any, ...] = ()) -> None:
        sql_compact = " ".join(sql.split())
        if sql_compact.startswith("INSERT INTO chat_sessions"):
            session_id, payload = params
            self.db.rows[session_id] = _FakeRow(
                session_id=session_id,
                messages=json.loads(payload),
            )
            return
        raise AssertionError(f"Unexpected SQL: {sql_compact!r}")

    def fetchone(self) -> Optional[Tuple[Any, ...]]:
        return self._last_result


# ── Helpers ───────────────────────────────────────────────────────────


def _build_long_history_ending_on_orphan(history_window: int) -> List[Dict[str, Any]]:
    """Build ~21 turns where truncation lands on an orphan assistant-tool-call.

    Layout (oldest first):

    1. ``history_window - 1`` padding messages (clean user/assistant
       turns) that the rolling window will discard.
    2. An ``assistant(tool_calls=[...])`` message at the kept head — its
       matching ``tool`` reply lives in the discarded prefix so the new
       head is genuinely an orphan.
    3. ``history_window - 1`` clean tail messages that fill the rest of
       the persisted window.

    Total length: ``2 * history_window`` (>= 21 for the default
    ``history_window=20``). The truncation cut therefore lands at the
    orphan assistant exactly.
    """
    history: List[Dict[str, Any]] = []
    # Pre-truncation padding: ``history_window - 1`` messages that will
    # be discarded by the rolling window. We include the matching ``tool``
    # reply for the orphan invitation here so the cut genuinely strands
    # the assistant.
    history.append(
        {
            "role": "tool",
            "tool_call_id": "call_orphan_42",
            "content": "[]",
        }
    )
    for i in range(history_window - 2):
        role = "user" if i % 2 == 0 else "assistant"
        history.append({"role": role, "content": f"pad{i}"})

    # Boundary anchor — the orphan assistant-tool-call that becomes the
    # new head after truncation.
    history.append(
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": "call_orphan_42",
                    "type": "function",
                    "function": {"name": "postgres.read_anomalies", "arguments": "{}"},
                }
            ],
        }
    )

    # Post-boundary tail filling the rest of the kept window.
    for i in range(history_window - 1):
        role = "user" if i % 2 == 0 else "assistant"
        history.append({"role": role, "content": f"tail{i}"})
    return history


# ── _drop_orphan_tool_call_head ─────────────────────────────────────────


def test_drop_orphan_head_removes_assistant_tool_call() -> None:
    msgs = [
        {"role": "assistant", "tool_calls": [{"id": "c1"}]},
        {"role": "user", "content": "next turn"},
    ]
    cleaned = _drop_orphan_tool_call_head(msgs)
    assert cleaned[0] == {"role": "user", "content": "next turn"}


def test_drop_orphan_head_removes_leading_tool_reply() -> None:
    msgs = [
        {"role": "tool", "tool_call_id": "c1", "content": "ok"},
        {"role": "user", "content": "next"},
    ]
    cleaned = _drop_orphan_tool_call_head(msgs)
    assert cleaned[0]["role"] == "user"


def test_drop_orphan_head_keeps_safe_head_unchanged() -> None:
    msgs = [
        {"role": "user", "content": "hi"},
        {"role": "assistant", "content": "hello"},
    ]
    assert _drop_orphan_tool_call_head(msgs) == msgs


def test_drop_orphan_head_advances_past_multiple_orphans() -> None:
    msgs = [
        {"role": "assistant", "tool_calls": [{"id": "a"}]},
        {"role": "tool", "tool_call_id": "a", "content": "x"},
        {"role": "assistant", "tool_calls": [{"id": "b"}]},
        {"role": "user", "content": "finally"},
    ]
    cleaned = _drop_orphan_tool_call_head(msgs)
    # Everything before the user message is treated as orphan-prefix and
    # dropped; the kept head is the user message.
    assert cleaned[0] == {"role": "user", "content": "finally"}


def test_drop_orphan_head_treats_plain_assistant_as_safe() -> None:
    msgs = [
        {"role": "assistant", "content": "thinking"},
        {"role": "user", "content": "ok"},
    ]
    assert _drop_orphan_tool_call_head(msgs) == msgs


def test_drop_orphan_head_treats_empty_tool_calls_as_safe() -> None:
    msgs = [
        {"role": "assistant", "content": "ack", "tool_calls": []},
        {"role": "user", "content": "ok"},
    ]
    assert _drop_orphan_tool_call_head(msgs) == msgs


# ── save() integration ─────────────────────────────────────────────────


def test_save_drops_orphan_tool_call_at_truncation_boundary() -> None:
    """Regression: 21-turn history truncated to window=20 must not strand
    an orphan ``assistant(tool_calls=...)`` at the new head."""

    history_window = 20
    history = _build_long_history_ending_on_orphan(history_window)
    # Sanity: the history is longer than the window so truncation engages.
    assert len(history) > history_window
    # Sanity: the message that *would* sit at the truncation boundary is
    # the orphan assistant-tool-call we anchored.
    boundary_msg = history[-history_window]
    assert boundary_msg["role"] == "assistant"
    assert boundary_msg.get("tool_calls"), "test setup error: boundary is not an orphan"

    db = _FakeDatabase()
    store = ChatSessionStore(db, history_window=history_window)
    store.save("sess-orphan", history)

    persisted = db.rows["sess-orphan"].messages
    # No system messages persisted.
    assert all(m.get("role") != "system" for m in persisted)
    # Head MUST NOT be an orphan assistant-tool-call.
    head = persisted[0]
    assert not (
        head.get("role") == "assistant" and head.get("tool_calls")
    ), "persisted head is an orphan assistant-tool-call; LiteLLM would reject it"
    # Persisted length never exceeds the configured window.
    assert len(persisted) <= history_window
