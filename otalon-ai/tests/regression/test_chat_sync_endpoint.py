"""Integration tests for ``POST /api/v1/chat`` and ``/chat/stream/{id}``.

Spins up the FastAPI app with mocked llm + mcp + session-store + system-
prompt (the lifespan is bypassed so no live DB / MCP / proxy is needed).
Asserts:

- Request-body shape matches the n8n contract (``session_id`` /
  ``message`` / ``history`` / ``metadata``).
- Response-body shape matches what the UI's
  ``otalon-ui/server/api/chat.post.ts`` expects.
- ``APIConnectionError`` degrades to ``source: "fallback"`` HTTP 200.
- SSE endpoint emits the documented event names in order.
"""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Dict, List, Optional

import pytest
from fastapi.testclient import TestClient
from openai import APIConnectionError

from otalon_ai.chat.agent_loop import ChatTurnResult, StreamEvent

# --- helpers identical to the unit-test mocks --------------------------


@dataclass
class _ScriptedTurnResult:
    """A pre-built ChatTurnResult to return for the next run_chat_turn call."""

    content: str = "ok"
    tool_calls_count: int = 0
    tokens_used: Optional[int] = 7
    prompt_tokens: Optional[int] = 3
    completion_tokens: Optional[int] = 4
    duration_ms: int = 12
    cap_reached: bool = False
    tool_calls_log: List[Dict[str, Any]] = field(default_factory=list)


class _StubLoop:
    """ChatAgentLoop stand-in that returns scripted ChatTurnResults or raises.

    Also exposes :meth:`run_chat_turn_stream` for the SSE endpoint; the
    scripted ``stream_events`` (a list of typed event dicts) are yielded
    in order. If ``stream_events`` is empty, the loop derives a minimal
    event sequence from the scripted ``ChatTurnResult`` so the simpler
    tests do not need to spell every event out.
    """

    def __init__(self) -> None:
        self.calls: List[Dict[str, Any]] = []
        self._scripted: List[ChatTurnResult] = []
        self._scripted_streams: List[List[StreamEvent]] = []
        self._raise: Optional[Exception] = None

    def script(self, *results: ChatTurnResult) -> None:
        self._scripted.extend(results)

    def script_stream(self, *event_lists: List[StreamEvent]) -> None:
        self._scripted_streams.extend(event_lists)

    def fail_with(self, exc: Exception) -> None:
        self._raise = exc

    async def run_chat_turn(
        self,
        session_id: str,
        user_message: str,
        *,
        ui_context_markdown: Optional[str] = None,
    ) -> ChatTurnResult:
        self.calls.append(
            {
                "session_id": session_id,
                "user_message": user_message,
                "ui_context_markdown": ui_context_markdown,
            }
        )
        if self._raise is not None:
            raise self._raise
        if not self._scripted:
            raise AssertionError("StubLoop script exhausted")
        return self._scripted.pop(0)

    async def run_chat_turn_stream(
        self,
        session_id: str,
        user_message: str,
        *,
        ui_context_markdown: Optional[str] = None,
    ) -> AsyncIterator[StreamEvent]:
        self.calls.append(
            {
                "session_id": session_id,
                "user_message": user_message,
                "ui_context_markdown": ui_context_markdown,
                "stream": True,
            }
        )
        if self._raise is not None:
            raise self._raise
        if self._scripted_streams:
            events = self._scripted_streams.pop(0)
        elif self._scripted:
            # Derive a minimal event sequence from the scripted result.
            result = self._scripted.pop(0)
            events = []
            for entry in result.tool_calls_log:
                events.append({"type": "tool_call_started", "name": entry["name"], "args": entry.get("args", {})})
                if entry.get("ok", True):
                    events.append(
                        {"type": "tool_call_completed", "name": entry["name"], "ok": True, "result_preview": ""}
                    )
                else:
                    events.append(
                        {
                            "type": "tool_call_completed",
                            "name": entry["name"],
                            "ok": False,
                            "error": entry.get("error", "unknown"),
                        }
                    )
            if result.content:
                events.append({"type": "token", "delta": result.content})
            events.append(
                {
                    "type": "final",
                    "content": result.content,
                    "tokens_used": result.tokens_used,
                    "prompt_tokens": result.prompt_tokens,
                    "completion_tokens": result.completion_tokens,
                    "tool_calls_count": result.tool_calls_count,
                    "duration_ms": result.duration_ms,
                    "cap_reached": result.cap_reached,
                }
            )
        else:
            raise AssertionError("StubLoop stream script exhausted")
        for event in events:
            yield event


@pytest.fixture
def app_with_stub_loop() -> Any:
    """Yield (app, stub_loop) with a no-op lifespan + mocked chat state."""
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

    @asynccontextmanager
    async def _noop(_app: Any) -> Any:
        yield

    app.router.lifespan_context = _noop

    stub_loop = _StubLoop()
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
    app.state.chat_loop = stub_loop
    app.state.settings = settings
    return app, stub_loop


# --- tests --------------------------------------------------------------


def test_chat_sync_returns_n8n_compatible_shape(app_with_stub_loop) -> None:  # type: ignore[no-untyped-def]
    app, stub = app_with_stub_loop
    stub.script(
        ChatTurnResult(
            content="Hello operator",
            tool_calls_count=0,
            tokens_used=42,
            prompt_tokens=30,
            completion_tokens=12,
            duration_ms=120,
        )
    )
    with TestClient(app, headers={"X-API-Key": "test-ai-key"}) as client:
        r = client.post(
            "/api/v1/chat",
            json={
                "session_id": "s1",
                "message": "Hi",
                "history": [],
                "metadata": {"source": "otalon-ui"},
            },
        )
    assert r.status_code == 200
    body = r.json()
    assert body["role"] == "assistant"
    assert body["content"] == "Hello operator"
    assert body["source"] == "otalon-ai"
    assert body["tokens_used"] == 42
    assert body["prompt_tokens"] == 30
    assert body["completion_tokens"] == 12
    assert body["context_window"] == 128000
    assert body["tool_calls_count"] == 0
    assert body["duration_ms"] == 120

    # Loop received the n8n contract intact.
    assert stub.calls[0]["session_id"] == "s1"
    assert stub.calls[0]["user_message"] == "Hi"
    assert stub.calls[0]["ui_context_markdown"] is None


def test_chat_sync_with_ui_context_markdown(app_with_stub_loop) -> None:  # type: ignore[no-untyped-def]
    app, stub = app_with_stub_loop
    stub.script(ChatTurnResult(content="x"))
    with TestClient(app, headers={"X-API-Key": "test-ai-key"}) as client:
        r = client.post(
            "/api/v1/chat",
            json={
                "session_id": "s2",
                "message": "what's selected?",
                "metadata": {"ui_context_markdown": "**Active tab:** alarms"},
            },
        )
    assert r.status_code == 200
    assert stub.calls[0]["ui_context_markdown"] == "**Active tab:** alarms"


def test_chat_sync_legacy_ui_context_object(app_with_stub_loop) -> None:  # type: ignore[no-untyped-def]
    app, stub = app_with_stub_loop
    stub.script(ChatTurnResult(content="x"))
    with TestClient(app, headers={"X-API-Key": "test-ai-key"}) as client:
        r = client.post(
            "/api/v1/chat",
            json={
                "session_id": "s3",
                "message": "x",
                "metadata": {"ui_context": {"active_tab": "alarms", "selected_entity": None}},
            },
        )
    assert r.status_code == 200
    forwarded = stub.calls[0]["ui_context_markdown"]
    assert forwarded is not None
    assert "active_tab" in forwarded


def test_chat_sync_falls_back_on_proxy_unreachable(app_with_stub_loop) -> None:  # type: ignore[no-untyped-def]
    app, stub = app_with_stub_loop
    stub.fail_with(APIConnectionError(request=None))  # type: ignore[arg-type]
    with TestClient(app, headers={"X-API-Key": "test-ai-key"}) as client:
        r = client.post(
            "/api/v1/chat",
            json={"session_id": "s4", "message": "x"},
        )
    assert r.status_code == 200
    body = r.json()
    assert body["source"] == "fallback"
    assert body["content"] == "LLM proxy unreachable."
    assert body["role"] == "assistant"


def test_chat_sync_rejects_missing_session_id(app_with_stub_loop) -> None:  # type: ignore[no-untyped-def]
    app, _stub = app_with_stub_loop
    with TestClient(app, headers={"X-API-Key": "test-ai-key"}) as client:
        r = client.post("/api/v1/chat", json={"message": "hi"})
    assert r.status_code == 422


def _parse_sse_events(body: str) -> List[Dict[str, Any]]:
    """Split an SSE response body into a list of (event_name, json_payload) dicts.

    Each event is the JSON-envelope payload with the parsed ``data:``
    line merged with the ``event:`` name so callers can assert on both
    the wire name and the structured payload.
    """
    events: List[Dict[str, Any]] = []
    for block in body.split("\n\n"):
        block = block.strip("\n")
        if not block:
            continue
        ev_name = None
        data_line = None
        for line in block.split("\n"):
            if line.startswith("event: "):
                ev_name = line[len("event: ") :]
            elif line.startswith("data: "):
                data_line = line[len("data: ") :]
        assert ev_name is not None and data_line is not None, f"malformed SSE block: {block!r}"
        payload = json.loads(data_line)
        payload["_event"] = ev_name
        events.append(payload)
    return events


def test_chat_sse_emits_documented_events_with_json_envelope(app_with_stub_loop) -> None:  # type: ignore[no-untyped-def]
    """SSE endpoint yields token / tool_call_* / final events as JSON payloads.

    Order now reflects real streaming: token deltas arrive first, then
    the tool-call boundary, then more deltas, then ``final``. The stub
    scripts an explicit event sequence to keep the assertion stable.
    """
    app, stub = app_with_stub_loop
    stub.script_stream(
        [
            {"type": "token", "delta": "Hello "},
            {"type": "tool_call_started", "name": "postgres.read_anomalies", "args": {"limit": 5}},
            {
                "type": "tool_call_completed",
                "name": "postgres.read_anomalies",
                "ok": True,
                "result_preview": "5 rows",
            },
            {"type": "token", "delta": "operator"},
            {
                "type": "final",
                "content": "Hello operator",
                "tokens_used": 9,
                "prompt_tokens": 6,
                "completion_tokens": 3,
                "tool_calls_count": 1,
                "duration_ms": 7,
                "cap_reached": False,
            },
        ]
    )
    with TestClient(app, headers={"X-API-Key": "test-ai-key"}) as client:
        with client.stream(
            "POST",
            "/api/v1/chat/stream/s-sse-1",
            json={"message": "Hi"},
        ) as r:
            assert r.status_code == 200
            assert r.headers["content-type"].startswith("text/event-stream")
            body = "".join(r.iter_text())

    events = _parse_sse_events(body)
    event_names = [e["_event"] for e in events]
    assert event_names == [
        "token",
        "tool_call_started",
        "tool_call_completed",
        "token",
        "final",
    ]
    # Each payload is a valid JSON envelope with a ``type`` matching the event name.
    for evt in events:
        assert evt["type"] == evt["_event"]
    assert events[0]["delta"] == "Hello "
    assert events[1]["name"] == "postgres.read_anomalies"
    assert events[2]["result_preview"] == "5 rows"
    assert events[-1]["content"] == "Hello operator"
    assert events[-1]["source"] == "otalon-ai"
    assert events[-1]["tokens_used"] == 9
    assert events[-1]["prompt_tokens"] == 6
    assert events[-1]["completion_tokens"] == 3
    assert events[-1]["context_window"] == 128000


def test_chat_sse_emits_error_on_proxy_unreachable(app_with_stub_loop) -> None:  # type: ignore[no-untyped-def]
    app, stub = app_with_stub_loop
    stub.fail_with(APIConnectionError(request=None))  # type: ignore[arg-type]
    with TestClient(app, headers={"X-API-Key": "test-ai-key"}) as client:
        with client.stream(
            "POST",
            "/api/v1/chat/stream/s-err",
            json={"message": "x"},
        ) as r:
            assert r.status_code == 200
            body = "".join(r.iter_text())
    events = _parse_sse_events(body)
    assert any(e["_event"] == "error" for e in events)
    error_evt = next(e for e in events if e["_event"] == "error")
    assert error_evt["message"] == "LLM proxy unreachable"
    assert error_evt["source"] == "fallback"
    assert not any(e["_event"] == "final" for e in events)


def test_chat_sse_preserves_null_usage_fields(app_with_stub_loop) -> None:  # type: ignore[no-untyped-def]
    """SSE final event keeps unknown usage values null, not synthetic zeroes."""
    app, stub = app_with_stub_loop
    stub.script_stream(
        [
            {
                "type": "final",
                "content": "x",
                "tokens_used": None,
                "prompt_tokens": None,
                "completion_tokens": None,
                "tool_calls_count": 0,
                "duration_ms": 1,
                "cap_reached": False,
            }
        ]
    )
    with TestClient(app, headers={"X-API-Key": "test-ai-key"}) as client:
        with client.stream("POST", "/api/v1/chat/stream/s-null", json={"message": "x"}) as response:
            events = _parse_sse_events("".join(response.iter_text()))

    final = events[-1]
    assert final["tokens_used"] is None
    assert final["prompt_tokens"] is None
    assert final["completion_tokens"] is None


def test_chat_sse_preserves_multiline_content_in_json_envelope(app_with_stub_loop) -> None:  # type: ignore[no-untyped-def]
    """A3 regression: multi-line content (code blocks) survives the SSE framing.

    The old ``_format_sse`` collapsed newlines to literal ``\\n``,
    breaking Markdown code blocks in the chat UI. The new JSON-envelope
    format puts the full payload onto one ``data:`` line as JSON, so
    ``\\n`` is encoded as the JSON escape ``\\n`` and ``JSON.parse(data)``
    recovers the original string with real newlines.
    """
    app, stub = app_with_stub_loop
    multiline = "Here is code:\n```python\nx = 1\nprint(x)\n```\nDone."
    stub.script_stream(
        [
            {"type": "token", "delta": multiline},
            {
                "type": "final",
                "content": multiline,
                "tokens_used": 4,
                "tool_calls_count": 0,
                "duration_ms": 3,
                "cap_reached": False,
            },
        ]
    )
    with TestClient(app, headers={"X-API-Key": "test-ai-key"}) as client:
        with client.stream(
            "POST",
            "/api/v1/chat/stream/s-a3",
            json={"message": "show me code"},
        ) as r:
            body = "".join(r.iter_text())

    events = _parse_sse_events(body)
    # The token delta round-trips with newlines intact.
    token_evt = next(e for e in events if e["_event"] == "token")
    assert token_evt["delta"] == multiline
    assert "```python" in token_evt["delta"]
    # The final content also preserves newlines.
    final_evt = next(e for e in events if e["_event"] == "final")
    assert final_evt["content"] == multiline
    # And the raw wire body contains exactly one data: line per event
    # (no literal newlines inside the JSON payload).
    for block in body.split("\n\n"):
        if "data:" in block:
            data_lines = [ln for ln in block.split("\n") if ln.startswith("data: ")]
            assert len(data_lines) == 1, f"multi-line data: in block: {block!r}"
