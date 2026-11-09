"""HC3: streaming chat-turn disconnect-cancel regression tests.

These tests pin the cost-leak fix: when the SSE consumer goes away (or
the ``run_chat_turn_stream`` coroutine is cancelled), the upstream LLM
stream MUST be closed (its async iterator's ``finally`` block runs) so
the upstream HTTP request is aborted and the LLM stops billing.

The tests use a hand-rolled async-iterator stub for the LLM that
records when ``close()`` is invoked and slowly yields chunks so the
test has time to cancel mid-stream.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Dict, List, Optional

import pytest

from otalon_ai.chat.agent_loop import ChatAgentLoop

# --- LLM stream stub ----------------------------------------------------


@dataclass
class _DeltaChunkChoice:
    """SDK-shaped Choice with a ``delta`` attribute."""

    delta: Any
    finish_reason: Optional[str] = None
    index: int = 0


@dataclass
class _DeltaContent:
    content: Optional[str] = None
    tool_calls: Optional[List[Any]] = None


@dataclass
class _StreamUsage:
    prompt_tokens: Optional[int] = 0
    completion_tokens: Optional[int] = 0
    total_tokens: Optional[int] = 0


@dataclass
class _StreamChunk:
    choices: List[_DeltaChunkChoice] = field(default_factory=list)
    usage: Optional[_StreamUsage] = None


class _SlowStream:
    """Async iterator that yields chunks slowly + records close()."""

    def __init__(self, chunks: List[_StreamChunk], delay: float = 0.05) -> None:
        self._chunks = list(chunks)
        self._delay = delay
        self.closed = False
        # An asyncio.Event so the test can confirm the stream entered
        # its ``finally`` block (provider semantics: close() on
        # cancellation).
        self.close_event = asyncio.Event()

    def __aiter__(self) -> "_SlowStream":
        return self

    async def __anext__(self) -> _StreamChunk:
        if not self._chunks:
            raise StopAsyncIteration
        await asyncio.sleep(self._delay)
        return self._chunks.pop(0)


class _RecordingStreamingLlm:
    """LLM provider stub with a streaming method that supports cancellation.

    The provider returns an async generator whose ``finally`` block sets
    ``close_event`` — this is the canonical pattern that
    :class:`LiteLLMProvider.chat_completion_stream` uses (the
    ``finally`` calls ``await stream.close()``). The test asserts the
    event fires on cancel.
    """

    name = "stub-stream"
    model = "azure/gpt-5.4"

    def __init__(self, chunks: List[_StreamChunk], delay: float = 0.05) -> None:
        self._chunks = chunks
        self._delay = delay
        self.close_event = asyncio.Event()
        self.calls: List[Dict[str, Any]] = []

    def chat_completion(self, *_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("chat_completion (sync) must not be called for streaming turn")

    async def chat_completion_stream(
        self,
        messages: List[Dict[str, Any]],
        tools: List[Dict[str, Any]],
        *,
        temperature: float = 0.1,
        reasoning_effort: Optional[str] = None,
    ) -> AsyncIterator[_StreamChunk]:
        self.calls.append({"messages": list(messages), "tools": list(tools)})
        try:
            for chunk in list(self._chunks):
                await asyncio.sleep(self._delay)
                yield chunk
        finally:
            # This is the cost-leak guard: when the consumer is cancelled,
            # control passes here, the upstream HTTP response would be
            # closed in the real provider, and we record the event.
            self.close_event.set()


# --- minimal MCP + session stubs ---------------------------------------


class _EmptyMcp:
    """McpRegistry stand-in with no tools."""

    async def list_openai_tools(
        self,
        *,
        force_refresh: bool = False,
        allow_list: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        return []

    async def call_tool(
        self,
        name: str,
        arguments: Dict[str, Any],
        *,
        allow_list: Optional[List[str]] = None,
    ) -> str:
        raise AssertionError("call_tool must not be invoked in cancel test")


class _InMemoryStore:
    """ChatSessionStore stand-in that captures save() calls."""

    def __init__(self) -> None:
        self.saved: List[List[Dict[str, Any]]] = []

    def load(self, session_id: str) -> List[Dict[str, Any]]:
        return []

    def save(self, session_id: str, messages: List[Dict[str, Any]]) -> None:
        self.saved.append([dict(m) for m in messages])


def _build_loop(llm: _RecordingStreamingLlm, store: _InMemoryStore) -> ChatAgentLoop:
    return ChatAgentLoop(
        llm=llm,
        mcp_registry=_EmptyMcp(),  # type: ignore[arg-type]
        session_store=store,  # type: ignore[arg-type]
        system_prompt="SYSTEM PROMPT",
        max_tool_rounds=4,
    )


def _text_chunk(text: str) -> _StreamChunk:
    return _StreamChunk(choices=[_DeltaChunkChoice(delta=_DeltaContent(content=text))])


# --- tests --------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_chat_turn_stream_cancellation_closes_upstream() -> None:
    """HC3: cancelling the consumer triggers the provider stream's finally block.

    Simulates the SSE client disconnect: a consumer task pulls events
    from ``run_chat_turn_stream`` and is cancelled mid-stream while
    awaiting the next token. The test asserts:

    1. The provider stream's ``finally`` block ran (``close_event`` set).
    2. The session was NOT persisted (no save on a half-completed turn).
    """
    chunks = [_text_chunk(f"token{i}") for i in range(20)]
    llm = _RecordingStreamingLlm(chunks, delay=0.02)
    store = _InMemoryStore()
    loop = _build_loop(llm, store)

    received: List[Dict[str, Any]] = []
    got_two = asyncio.Event()

    async def consumer() -> None:
        async for event in loop.run_chat_turn_stream("s-cancel", "Hello"):
            received.append(event)
            if len(received) >= 2:
                got_two.set()
            # After the 2nd token the consumer is suspended at
            # ``await __anext__()`` — this is where the external cancel
            # arrives, matching the real SSE disconnect path.

    task = asyncio.create_task(consumer())
    await got_two.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    # The provider stream entered its finally → upstream would have been
    # closed (in the real LiteLLMProvider this is ``await stream.close()``).
    assert llm.close_event.is_set(), "upstream LLM stream was not closed on cancel"

    # The half-completed turn was NOT persisted.
    assert store.saved == []

    # We received at least one token before cancel.
    assert any(e["type"] == "token" for e in received)


@pytest.mark.asyncio
async def test_run_chat_turn_stream_external_cancel_closes_upstream() -> None:
    """HC3 (variant): an external ``task.cancel()`` also closes the upstream.

    Mirrors the SSE endpoint's disconnect handler which calls
    ``producer.cancel()``. The cancel arrives while the consumer is
    suspended at ``await __anext__()`` (the real disconnect path).
    The test asserts the same ``close_event`` fires.
    """
    chunks = [_text_chunk(f"tok{i}") for i in range(50)]
    llm = _RecordingStreamingLlm(chunks, delay=0.02)
    store = _InMemoryStore()
    loop = _build_loop(llm, store)

    started = asyncio.Event()

    async def consumer() -> None:
        async for _evt in loop.run_chat_turn_stream("s-ext-cancel", "Hi"):
            started.set()
            # Consumer is now suspended at ``await __anext__()``, which
            # is exactly where FastAPI injects ``CancelledError`` on
            # client disconnect.

    task = asyncio.create_task(consumer())
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert llm.close_event.is_set()
    assert store.saved == []


@pytest.mark.asyncio
async def test_run_chat_turn_stream_normal_completion_persists() -> None:
    """Baseline: a clean stream completion DOES persist the session.

    Counterpart to the cancellation tests — verifies the persistence
    path actually runs when the stream completes normally so a future
    refactor cannot accidentally skip ``save()``.
    """
    chunks = [_text_chunk("Hello "), _text_chunk("world")]
    llm = _RecordingStreamingLlm(chunks, delay=0.0)
    store = _InMemoryStore()
    loop = _build_loop(llm, store)

    events = []
    async for event in loop.run_chat_turn_stream("s-ok", "Hi"):
        events.append(event)

    assert events[-1]["type"] == "final"
    assert events[-1]["content"] == "Hello world"
    assert len(store.saved) == 1
    persisted = store.saved[0]
    # System prompt + user + assistant
    roles = [m["role"] for m in persisted]
    assert "user" in roles and "assistant" in roles
    # The provider stream's finally still fires on normal completion.
    assert llm.close_event.is_set()


async def test_stream_one_round_yields_tokens_inline() -> None:
    """P8: token deltas must be yielded inline, not buffered until round end."""
    from otalon_ai.chat.agent_loop import _RoundResult

    chunks = [_text_chunk("Hello "), _text_chunk("world")]
    llm = _RecordingStreamingLlm(chunks, delay=0.0)
    store = _InMemoryStore()
    loop = _build_loop(llm, store)

    messages: List[Dict[str, Any]] = [
        {"role": "system", "content": "SYS"},
        {"role": "user", "content": "Hi"},
    ]
    result = _RoundResult()
    events: List[Dict[str, Any]] = []
    async for event in loop._stream_one_round(llm, messages, tools=[], out=result):
        events.append(event)

    assert events == [
        {"type": "token", "delta": "Hello "},
        {"type": "token", "delta": "world"},
    ]
    assert result.text == "Hello world"
    assert result.tool_calls == []


async def test_run_chat_turn_stream_tokens_not_batched_after_round() -> None:
    """P8: in a full turn, text tokens must stream live, not appear after round."""
    chunks = [_text_chunk("A"), _text_chunk("B"), _text_chunk("C")]
    llm = _RecordingStreamingLlm(chunks, delay=0.0)
    store = _InMemoryStore()
    loop = _build_loop(llm, store)

    events: List[Dict[str, Any]] = []
    async for event in loop.run_chat_turn_stream("s-abc", "Hi"):
        events.append(event)

    types = [e["type"] for e in events]
    assert types.count("token") == 3
    assert types[-1] == "final"
    # Tokens must appear before the final event, not after.
    token_indices = [i for i, t in enumerate(types) if t == "token"]
    final_index = types.index("final")
    assert all(i < final_index for i in token_indices)
    assert events[-1]["content"] == "ABC"


def _usage_chunk(usage: _StreamUsage) -> _StreamChunk:
    """A terminal usage-only chunk as emitted with ``include_usage=True``."""
    return _StreamChunk(choices=[], usage=usage)


@pytest.mark.asyncio
async def test_stream_prompt_only_usage_keeps_completion_null() -> None:
    """Stream: prompt-only usage MUST leave ``completion_tokens`` null in the
    final event — never a synthetic zero (finding AI-012 #2, streaming path)."""
    chunks = [
        _text_chunk("hi"),
        _usage_chunk(_StreamUsage(prompt_tokens=42, completion_tokens=None, total_tokens=None)),
    ]
    llm = _RecordingStreamingLlm(chunks, delay=0.0)
    store = _InMemoryStore()
    loop = _build_loop(llm, store)

    events: List[Dict[str, Any]] = []
    async for event in loop.run_chat_turn_stream("s-prompt-only", "Hi"):
        events.append(event)

    final = events[-1]
    assert final["type"] == "final"
    assert final["prompt_tokens"] == 42
    assert final["completion_tokens"] is None, "unknown completion usage must stay null"
    assert final["tokens_used"] == 42


@pytest.mark.asyncio
async def test_stream_completion_only_usage_keeps_prompt_null() -> None:
    """Stream: completion-only usage MUST leave ``prompt_tokens`` null."""
    chunks = [
        _text_chunk("hi"),
        _usage_chunk(_StreamUsage(prompt_tokens=None, completion_tokens=9, total_tokens=None)),
    ]
    llm = _RecordingStreamingLlm(chunks, delay=0.0)
    store = _InMemoryStore()
    loop = _build_loop(llm, store)

    events: List[Dict[str, Any]] = []
    async for event in loop.run_chat_turn_stream("s-completion-only", "Hi"):
        events.append(event)

    final = events[-1]
    assert final["type"] == "final"
    assert final["prompt_tokens"] is None, "unknown prompt usage must stay null"
    assert final["completion_tokens"] == 9
    assert final["tokens_used"] == 9


@pytest.mark.asyncio
async def test_stream_no_usage_keeps_all_token_fields_null() -> None:
    """Stream: no usage reported → every token field stays null in the final."""
    chunks = [_text_chunk("hi")]
    llm = _RecordingStreamingLlm(chunks, delay=0.0)
    store = _InMemoryStore()
    loop = _build_loop(llm, store)

    events: List[Dict[str, Any]] = []
    async for event in loop.run_chat_turn_stream("s-no-usage", "Hi"):
        events.append(event)

    final = events[-1]
    assert final["type"] == "final"
    assert final["prompt_tokens"] is None
    assert final["completion_tokens"] is None
    assert final["tokens_used"] is None
