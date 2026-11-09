"""Session-store for the chat surface.

Persists the per-session OpenAI message list in the ``chat_sessions``
PostgreSQL table created by ``migrations/001_chat_sessions.sql``. The system
prompt is NEVER stored — it is always re-prepended fresh from disk on every
turn (see ``otalon_ai/chat/agent_loop.py``).

Buffer-window semantics (per design.md § Decision 4 / spec ``chat--orchestration``):
``save()`` keeps only the last ``history_window`` messages so the column
cannot grow unboundedly for long-running sessions.

Implementation note: we use psycopg2 against the shared pool from
``src.db.Database``. Writes are wrapped in the connection's transaction so
crashes mid-save cannot corrupt the row.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from loguru import logger

from otalon_ai.db import Database


def _drop_orphan_tool_call_head(messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Strip leading orphan ``assistant(tool_calls=...)`` entries.

    After a rolling-window truncation the kept head may start with an
    ``assistant`` message that advertises ``tool_calls`` whose matching
    ``tool`` reply messages were cut away. Sending such a head to
    LiteLLM / OpenAI causes a ``"tool_call_id missing"`` rejection. The
    safe fix is to drop those orphan assistants (and any orphan ``tool``
    replies that may now lead the list) until the first kept entry is a
    ``system`` / ``user`` / plain ``assistant`` message — at which point
    the history is internally consistent again.

    A plain ``assistant`` (one without ``tool_calls``) is always safe at
    the head; only ``assistant`` messages carrying a non-empty
    ``tool_calls`` field are orphans here.
    """
    head = 0
    while head < len(messages):
        msg = messages[head]
        role = msg.get("role")
        tool_calls = msg.get("tool_calls")
        if role == "assistant" and tool_calls:
            head += 1
            continue
        if role == "tool":
            # A leading ``tool`` reply without its assistant invitation is
            # equally invalid; drop it too.
            head += 1
            continue
        break
    return messages[head:] if head else messages


class ChatSessionStore:
    """Repository for the ``chat_sessions`` table."""

    def __init__(self, database: Database, *, history_window: int = 20) -> None:
        """Bind the store to a shared :class:`Database` handle.

        Args:
            database: Shared connection-pool wrapper providing
                ``chat_connection()`` context managers.
            history_window: Maximum number of non-system messages to
                keep per session on :meth:`save`. Must be >= 1.

        Raises:
            ValueError: If ``history_window`` is less than 1.
        """
        if history_window < 1:
            raise ValueError("history_window must be >= 1")
        self._db = database
        self._history_window = history_window

    # --- read ----------------------------------------------------------

    def load(self, session_id: str) -> List[Dict[str, Any]]:
        """Return the persisted message list for ``session_id`` (may be empty)."""
        if not session_id:
            raise ValueError("session_id must not be empty")
        with self._db.chat_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT messages FROM chat_sessions WHERE session_id = %s",
                    (session_id,),
                )
                row = cur.fetchone()
        if row is None:
            return []
        messages = row[0]
        # psycopg2 returns JSONB as a Python list already, but defensively
        # support a string payload too.
        if isinstance(messages, str):
            try:
                messages = json.loads(messages)
            except json.JSONDecodeError:
                logger.warning("ChatSessionStore: malformed messages JSON for session={}", session_id)
                return []
        if not isinstance(messages, list):
            return []
        return messages

    # --- write ---------------------------------------------------------

    def save(self, session_id: str, messages: List[Dict[str, Any]]) -> None:
        """Upsert the row, truncating to ``history_window`` entries.

        The system prompt (``role == "system"``) is dropped before persistence
        per spec ``chat--orchestration`` § "Chat service SHALL preserve
        message history per session in PostgreSQL".

        Orphan-tool-call safety: when the rolling window cuts the head of
        the list, an ``assistant`` message that carries ``tool_calls`` MUST
        be followed by one ``tool`` reply per call. If the truncation
        boundary lands on such an assistant without its replies, LiteLLM /
        OpenAI rejects the next request with ``"tool_call_id missing"``.
        We therefore advance the head past any orphan
        ``assistant(tool_calls=...)`` messages until the first kept entry
        is safe (``system`` / ``user`` / clean ``assistant`` / ``tool``
        with no preceding orphan).
        """
        if not session_id:
            raise ValueError("session_id must not be empty")
        filtered = [msg for msg in messages if msg.get("role") != "system"]
        if len(filtered) > self._history_window:
            filtered = filtered[-self._history_window :]
        filtered = _drop_orphan_tool_call_head(filtered)
        payload = json.dumps(filtered)
        with self._db.chat_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO chat_sessions (session_id, messages, updated_at)
                    VALUES (%s, %s::jsonb, NOW())
                    ON CONFLICT (session_id) DO UPDATE
                        SET messages = EXCLUDED.messages,
                            updated_at = NOW()
                    """,
                    (session_id, payload),
                )

    # --- pruning -------------------------------------------------------

    def prune(self, retention_days: int) -> int:
        """Delete sessions older than ``retention_days``. Returns deleted count.

        Setting ``retention_days <= 0`` disables pruning (see spec
        ``chat--postgres-schema`` § "chat_sessions SHALL be pruned").
        """
        if retention_days <= 0:
            logger.info("ChatSessionStore.prune: retention disabled (days={})", retention_days)
            return 0
        with self._db.chat_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM chat_sessions WHERE updated_at < NOW() - make_interval(days => %s)",
                    (retention_days,),
                )
                deleted: Optional[int] = cur.rowcount
        result = deleted if deleted is not None else 0
        logger.info("ChatSessionStore.prune: deleted {} rows (retention_days={})", result, retention_days)
        return result
