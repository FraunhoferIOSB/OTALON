"""Unit tests for ``GET /api/v1/chat/sessions/{session_id}``."""

from __future__ import annotations

from typing import Any, Dict, List

import pytest
from fastapi.testclient import TestClient

from otalon_ai.chat.router import _strip_kontext_prefix
from otalon_ai.chat.session_store import ChatSessionStore


class _MemoryStore(ChatSessionStore):
    """In-memory session store for testing."""

    def __init__(self) -> None:  # noqa: D107
        self._data: Dict[str, List[Dict[str, Any]]] = {}

    def load(self, session_id: str) -> List[Dict[str, Any]]:
        return self._data.get(session_id, [])

    def save(self, session_id: str, messages: List[Dict[str, Any]]) -> None:
        self._data[session_id] = messages

    def prune(self, retention_days: int) -> int:
        return 0


@pytest.fixture
def client_with_store() -> Any:
    """Yield a TestClient with an in-memory chat store."""
    import os

    os.environ.setdefault("JOBS_LLM_MODEL", "azure/gpt-5.4")
    from otalon_ai.main import create_app
    from otalon_ai.settings import (
        ChatConfig,
        DbConfig,
        JobsConfig,
        LiteLLMConfig,
        Settings,
    )

    app = create_app()

    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def _noop(_app: Any) -> Any:
        yield

    app.router.lifespan_context = _noop

    store = _MemoryStore()
    settings = Settings(
        db=DbConfig(dsn="postgresql://x:x@h/d"),
        chat=ChatConfig(
            llm_model="azure/gpt-5.4",
            history_window=20,
            retention_days=30,
            max_tool_rounds=12,
            fallback_message="LLM proxy unreachable.",
        ),
        jobs=JobsConfig(llm_model="azure/gpt-5.4", allowed_tools=["x.y"]),
        litellm=LiteLLMConfig(base_url="http://litellm:4000/v1", api_key="sk-x"),
    )
    app.state.chat_store = store
    app.state.settings = settings
    return TestClient(app, headers={"X-API-Key": "test-ai-key"}), store


def test_empty_session_returns_empty_messages(client_with_store: Any) -> None:
    client, _store = client_with_store
    r = client.get("/api/v1/chat/sessions/unknown-id")
    assert r.status_code == 200
    body = r.json()
    assert body["session_id"] == "unknown-id"
    assert body["messages"] == []


def test_filters_non_displayable_roles(client_with_store: Any) -> None:
    client, store = client_with_store
    store.save(
        "s1",
        [
            {"role": "system", "content": "You are a bot."},
            {"role": "user", "content": "Hello"},
            {"role": "assistant", "content": "Hi there", "tool_calls": []},
            {"role": "tool", "content": '{"ok": true}'},
        ],
    )
    r = client.get("/api/v1/chat/sessions/s1")
    assert r.status_code == 200
    msgs = r.json()["messages"]
    assert len(msgs) == 2
    assert msgs[0]["role"] == "user"
    assert msgs[0]["content"] == "Hello"
    assert msgs[1]["role"] == "assistant"
    assert msgs[1]["content"] == "Hi there"


def test_skips_assistant_with_tool_calls(client_with_store: Any) -> None:
    client, store = client_with_store
    store.save(
        "s2",
        [
            {"role": "user", "content": "Query"},
            {"role": "assistant", "content": "", "tool_calls": [{"id": "tc1"}]},
            {"role": "tool", "content": "result"},
            {"role": "assistant", "content": "Done"},
        ],
    )
    r = client.get("/api/v1/chat/sessions/s2")
    msgs = r.json()["messages"]
    assert len(msgs) == 2
    assert msgs[0]["role"] == "user"
    assert msgs[1]["role"] == "assistant"
    assert msgs[1]["content"] == "Done"


def test_strips_kontext_prefix(client_with_store: Any) -> None:
    client, store = client_with_store
    store.save(
        "s3",
        [
            {"role": "user", "content": "[Kontext: /alarms]\n\nWhat is this?"},
            {"role": "assistant", "content": "It is an alarm."},
        ],
    )
    r = client.get("/api/v1/chat/sessions/s3")
    msgs = r.json()["messages"]
    assert msgs[0]["content"] == "What is this?"


def test_strip_kontext_prefix_no_match() -> None:
    """When the pattern is absent the content is unchanged."""
    text = "[Kontext: /alarms] What is this?"
    assert _strip_kontext_prefix(text) == text


def test_strip_kontext_prefix_not_starting() -> None:
    """Only strips when the prefix is at the very start."""
    text = "Hello [Kontext: /alarms]\n\nWhat?"
    assert _strip_kontext_prefix(text) == text


class _ThreadRecordingStore(_MemoryStore):
    """Store that records the thread id ``load`` ran on."""

    def __init__(self) -> None:
        super().__init__()
        import threading

        self._threading = threading
        self.load_thread_ids: List[int] = []

    def load(self, session_id: str) -> List[Dict[str, Any]]:
        self.load_thread_ids.append(self._threading.get_ident())
        return super().load(session_id)


def test_history_endpoint_loads_off_the_handler_thread() -> None:
    """AI-02 (router): ``GET /sessions/{id}`` MUST wrap the blocking
    psycopg2 ``store.load`` in ``asyncio.to_thread`` instead of running
    it on the event-loop thread.
    """
    import os
    import threading
    from contextlib import asynccontextmanager

    os.environ.setdefault("JOBS_LLM_MODEL", "azure/gpt-5.4")
    from otalon_ai.main import create_app
    from otalon_ai.settings import ChatConfig, DbConfig, JobsConfig, LiteLLMConfig, Settings

    app = create_app()

    @asynccontextmanager
    async def _noop(_app: Any) -> Any:
        yield

    app.router.lifespan_context = _noop

    store = _ThreadRecordingStore()
    app.state.chat_store = store
    app.state.settings = Settings(
        db=DbConfig(dsn="postgresql://x:x@h/d"),
        chat=ChatConfig(llm_model="azure/gpt-5.4"),
        jobs=JobsConfig(llm_model="azure/gpt-5.4", allowed_tools=["x.y"]),
        litellm=LiteLLMConfig(base_url="http://litellm:4000/v1", api_key="sk-x"),
    )

    handler_thread_ids: List[int] = []

    @app.get("/api/v1/chat/_probe_thread")
    async def _probe() -> Dict[str, int]:
        handler_thread_ids.append(threading.get_ident())
        return {"tid": threading.get_ident()}

    client = TestClient(app, headers={"X-API-Key": "test-ai-key"})
    r_probe = client.get("/api/v1/chat/_probe_thread")
    assert r_probe.status_code == 200
    r = client.get("/api/v1/chat/sessions/s1")
    assert r.status_code == 200

    assert handler_thread_ids, "probe endpoint never ran"
    assert store.load_thread_ids, "store.load was never called"
    loop_tid = handler_thread_ids[0]
    assert all(
        tid != loop_tid for tid in store.load_thread_ids
    ), "ChatSessionStore.load ran on the event-loop thread (blocking psycopg2)"
