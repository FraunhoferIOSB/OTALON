"""Unit tests for :class:`src.chat.agent_loop.ChatAgentLoop`.

The agent loop is the substantive core of the chat surface (design.md §
Decision 3). These tests mock :class:`LiteLLMProvider` and
:class:`McpRegistry` and validate the five scenarios from
``specs/chat--orchestration/spec.md``:

1. Zero-tool path: model emits content directly, loop exits.
2. One-tool path: one round of tool_calls, then content.
3. Two-round tool path: two consecutive rounds of tool calls, then content.
4. Tool-error path: MCP raises → ``ERROR:`` content surfaced as a tool
   message, loop continues.
5. Cap path: MAX rounds reached → synthetic system note + tool-less final
   call.

Plus the UI-context injection contract (n8n parity) and persistence
contract (system prompt NOT stored).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import pytest

from otalon_ai.chat.agent_loop import CAP_REACHED_NOTE, ChatAgentLoop

# --- mocks --------------------------------------------------------------


@dataclass
class _MockToolCallFunction:
    name: str
    arguments: str


@dataclass
class _MockToolCall:
    id: str
    function: _MockToolCallFunction
    type: str = "function"


@dataclass
class _MockMessage:
    role: str = "assistant"
    content: Optional[str] = None
    tool_calls: Optional[List[_MockToolCall]] = None

    def model_dump(self, *, exclude_none: bool = False) -> Dict[str, Any]:
        out: Dict[str, Any] = {"role": self.role}
        if self.content is not None:
            out["content"] = self.content
        elif not exclude_none:
            out["content"] = None
        if self.tool_calls is not None:
            out["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": tc.type,
                    "function": {"name": tc.function.name, "arguments": tc.function.arguments},
                }
                for tc in self.tool_calls
            ]
        elif not exclude_none:
            out["tool_calls"] = None
        return out


@dataclass
class _MockChoice:
    message: _MockMessage
    finish_reason: str = "stop"
    index: int = 0


@dataclass
class _MockUsage:
    total_tokens: Optional[int] = 0
    prompt_tokens: Optional[int] = 0
    completion_tokens: Optional[int] = 0


@dataclass
class _MockChatCompletion:
    choices: List[_MockChoice]
    usage: _MockUsage = field(default_factory=_MockUsage)
    id: str = "chatcmpl-test"
    model: str = "azure/gpt-5.4"


class _ScriptedLlm:
    """Drives a pre-scripted sequence of LLM responses + records call args."""

    def __init__(self, responses: List[_MockChatCompletion]) -> None:
        self._responses = list(responses)
        self.calls: List[Dict[str, Any]] = []

    def chat_completion(
        self,
        messages: List[Dict[str, Any]],
        tools: List[Dict[str, Any]],
        *,
        temperature: float = 0.1,
        reasoning_effort: Optional[str] = None,
    ) -> _MockChatCompletion:
        if not self._responses:
            raise AssertionError("LLM script exhausted")
        # Deep copy messages so callers can mutate freely after the call.
        self.calls.append(
            {
                "messages": [dict(m) for m in messages],
                "tools": list(tools) if tools else [],
                "temperature": temperature,
                "reasoning_effort": reasoning_effort,
            }
        )
        return self._responses.pop(0)


class _ScriptedMcp:
    """Mock McpRegistry with a fixed tool list + scripted call_tool returns."""

    def __init__(
        self,
        *,
        tool_specs: Optional[List[Dict[str, Any]]] = None,
        call_results: Optional[Dict[str, Any]] = None,
        raise_for: Optional[Dict[str, Exception]] = None,
    ) -> None:
        self._tool_specs = tool_specs or []
        self._call_results = call_results or {}
        self._raise_for = raise_for or {}
        self.invocations: List[Dict[str, Any]] = []

    async def list_openai_tools(
        self,
        *,
        force_refresh: bool = False,
        allow_list: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        if allow_list is None:
            return list(self._tool_specs)
        allowed = set(allow_list)
        return [spec for spec in self._tool_specs if spec.get("function", {}).get("name") in allowed]

    async def call_tool(
        self,
        name: str,
        arguments: Dict[str, Any],
        *,
        allow_list: Optional[List[str]] = None,
    ) -> str:
        if allow_list is not None and name not in set(allow_list):
            raise PermissionError(f"tool {name!r} is not in the caller's allow-list")
        self.invocations.append({"name": name, "args": arguments})
        if name in self._raise_for:
            raise self._raise_for[name]
        return str(self._call_results.get(name, "OK"))


class _InMemoryStore:
    """ChatSessionStore stand-in. Tracks the persisted message list."""

    def __init__(self) -> None:
        self._rows: Dict[str, List[Dict[str, Any]]] = {}
        self.save_calls: List[List[Dict[str, Any]]] = []

    def load(self, session_id: str) -> List[Dict[str, Any]]:
        return list(self._rows.get(session_id, []))

    def save(self, session_id: str, messages: List[Dict[str, Any]]) -> None:
        # Mirror the real store: drop system messages before persistence.
        filtered = [m for m in messages if m.get("role") != "system"]
        self._rows[session_id] = filtered
        self.save_calls.append([dict(m) for m in messages])


# --- helpers -----------------------------------------------------------


def _make_text_response(
    content: str, tokens: int = 5, *, prompt: Optional[int] = None, completion: Optional[int] = None
) -> _MockChatCompletion:
    # Default split: 4/1 prompt/completion, total = tokens. Callers may
    # override either component to probe the (corrected) aggregation.
    p = prompt if prompt is not None else max(tokens - 1, 0)
    c = completion if completion is not None else min(1, tokens)
    return _MockChatCompletion(
        choices=[_MockChoice(message=_MockMessage(content=content))],
        usage=_MockUsage(total_tokens=p + c, prompt_tokens=p, completion_tokens=c),
    )


def _make_tool_call_response(
    *,
    tool_calls: List[_MockToolCall],
    tokens: int = 5,
    prompt: Optional[int] = None,
    completion: Optional[int] = None,
) -> _MockChatCompletion:
    p = prompt if prompt is not None else max(tokens - 1, 0)
    c = completion if completion is not None else min(1, tokens)
    return _MockChatCompletion(
        choices=[_MockChoice(message=_MockMessage(content=None, tool_calls=tool_calls))],
        usage=_MockUsage(total_tokens=p + c, prompt_tokens=p, completion_tokens=c),
    )


def _build_loop(
    llm: _ScriptedLlm,
    mcp: _ScriptedMcp,
    store: _InMemoryStore,
    *,
    max_tool_rounds: int = 4,
) -> ChatAgentLoop:
    return ChatAgentLoop(
        llm=llm,  # type: ignore[arg-type]
        mcp_registry=mcp,  # type: ignore[arg-type]
        session_store=store,  # type: ignore[arg-type]
        system_prompt="SYSTEM PROMPT",
        max_tool_rounds=max_tool_rounds,
    )


# --- scenarios ---------------------------------------------------------


async def test_zero_tool_path_returns_immediately() -> None:
    llm = _ScriptedLlm([_make_text_response("Hello!")])
    mcp = _ScriptedMcp()
    store = _InMemoryStore()
    loop = _build_loop(llm, mcp, store)

    result = await loop.run_chat_turn("s1", "Hi")
    assert result.content == "Hello!"
    assert result.tool_calls_count == 0
    assert result.cap_reached is False
    assert result.tokens_used == 5
    # Persisted history has [user, assistant], no system row.
    persisted = store.load("s1")
    assert [m["role"] for m in persisted] == ["user", "assistant"]
    assert persisted[0]["content"] == "Hi"


async def test_turn_log_names_the_serving_model() -> None:
    """AI-045 Phase 7: each turn logs the model that served it (live-switch proof)."""
    from loguru import logger as _logger

    llm = _ScriptedLlm([_make_text_response("Hello!")])
    llm.model = "claude-opus-5-5"
    mcp = _ScriptedMcp()
    store = _InMemoryStore()
    loop = _build_loop(llm, mcp, store)

    captured: list[str] = []
    sink_id = _logger.add(lambda msg: captured.append(str(msg)), level="INFO")
    try:
        await loop.run_chat_turn("s1", "Hi")
    finally:
        _logger.remove(sink_id)

    lines = [c for c in captured if "chat turn served model=" in c]
    assert lines, "no 'chat turn served model=' log line emitted"
    assert "claude-opus-5-5" in lines[-1]
    assert "tokens=5" in lines[-1]


async def test_one_tool_round_then_answer() -> None:
    tool_call = _MockToolCall(
        id="tc-1", function=_MockToolCallFunction(name="postgres.read_anomalies", arguments='{"limit": 5}')
    )
    llm = _ScriptedLlm(
        [
            _make_tool_call_response(tool_calls=[tool_call], tokens=4),
            _make_text_response("Found 5 anomalies.", tokens=6),
        ]
    )
    mcp = _ScriptedMcp(call_results={"postgres.read_anomalies": '[{"id": 1}]'})
    store = _InMemoryStore()
    loop = _build_loop(llm, mcp, store)

    result = await loop.run_chat_turn("s1", "Show me recent anomalies.")
    assert result.content == "Found 5 anomalies."
    assert result.tool_calls_count == 1
    # tokens_used == last_prompt_tokens + sum(completion_tokens). With the
    # default 4/1 split: round1 (tokens=4) gives prompt=3 completion=1;
    # round2 (tokens=6) gives prompt=5 completion=1. So 5 + (1 + 1) = 7.
    assert result.tokens_used == 7
    assert result.cap_reached is False
    # MCP was invoked once with parsed args.
    assert mcp.invocations == [{"name": "postgres.read_anomalies", "args": {"limit": 5}}]
    # Persisted history includes assistant + tool + assistant.
    roles = [m["role"] for m in store.load("s1")]
    assert roles == ["user", "assistant", "tool", "assistant"]


async def test_two_rounds_of_tool_calls() -> None:
    call1 = _MockToolCall(id="tc-1", function=_MockToolCallFunction(name="t.one", arguments="{}"))
    call2 = _MockToolCall(id="tc-2", function=_MockToolCallFunction(name="t.two", arguments="{}"))
    llm = _ScriptedLlm(
        [
            _make_tool_call_response(tool_calls=[call1]),
            _make_tool_call_response(tool_calls=[call2]),
            _make_text_response("done"),
        ]
    )
    mcp = _ScriptedMcp(call_results={"t.one": "ONE", "t.two": "TWO"})
    store = _InMemoryStore()
    loop = _build_loop(llm, mcp, store)

    result = await loop.run_chat_turn("s1", "do it")
    assert result.content == "done"
    assert result.tool_calls_count == 2
    # Two MCP invocations recorded in order.
    assert [inv["name"] for inv in mcp.invocations] == ["t.one", "t.two"]
    # Three LLM rounds invoked.
    assert len(llm.calls) == 3


async def test_tool_error_does_not_abort_loop() -> None:
    call_bad = _MockToolCall(id="tc-bad", function=_MockToolCallFunction(name="broken", arguments="{}"))
    llm = _ScriptedLlm(
        [
            _make_tool_call_response(tool_calls=[call_bad]),
            _make_text_response("recovered"),
        ]
    )
    mcp = _ScriptedMcp(raise_for={"broken": RuntimeError("boom")})
    store = _InMemoryStore()
    loop = _build_loop(llm, mcp, store)

    result = await loop.run_chat_turn("s1", "x")
    assert result.content == "recovered"
    # The second LLM round saw a tool message with "ERROR: boom" content.
    second_round_msgs = llm.calls[1]["messages"]
    tool_msg = next(m for m in second_round_msgs if m["role"] == "tool")
    assert "ERROR" in tool_msg["content"]
    assert "boom" in tool_msg["content"]


async def test_cap_reached_appends_synthetic_note_and_forces_final_call() -> None:
    repeat = _MockToolCall(id="tc-x", function=_MockToolCallFunction(name="t", arguments="{}"))
    # 4 rounds of tool calls (cap is 4) then a forced tool-less final.
    llm = _ScriptedLlm(
        [
            _make_tool_call_response(tool_calls=[repeat]),
            _make_tool_call_response(tool_calls=[repeat]),
            _make_tool_call_response(tool_calls=[repeat]),
            _make_tool_call_response(tool_calls=[repeat]),
            _make_text_response("forced answer"),
        ]
    )
    mcp = _ScriptedMcp(call_results={"t": "ok"})
    store = _InMemoryStore()
    loop = _build_loop(llm, mcp, store, max_tool_rounds=4)

    result = await loop.run_chat_turn("s1", "x")
    assert result.content == "forced answer"
    assert result.cap_reached is True
    assert result.tool_calls_count == 4
    # The forced final call MUST have been issued with tools=[] (tool-less).
    final_call = llm.calls[-1]
    assert final_call["tools"] == []
    # The synthetic system note must precede the final assistant message
    # in the persisted history.
    persisted = store.load("s1")
    # System rows are filtered out by the store; check the FULL list that
    # was saved (save_calls includes the system row before filtering).
    full = store.save_calls[-1]
    assert any(m.get("role") == "system" and m.get("content") == CAP_REACHED_NOTE for m in full)
    # Persisted history (no systems) still has the forced final assistant.
    assert persisted[-1]["role"] == "assistant"
    assert persisted[-1]["content"] == "forced answer"


# --- additional contract tests ---------------------------------------


async def test_ui_context_injection_matches_n8n_format() -> None:
    llm = _ScriptedLlm([_make_text_response("ok")])
    mcp = _ScriptedMcp()
    store = _InMemoryStore()
    loop = _build_loop(llm, mcp, store)

    await loop.run_chat_turn(
        "s1",
        "What is on screen?",
        ui_context_markdown="**Active tab:** anomalies",
    )
    # Inspect the user message that reached the LLM.
    user_msg = next(m for m in llm.calls[0]["messages"] if m["role"] == "user")
    assert user_msg["content"].startswith("[Kontext: **Active tab:** anomalies]")
    assert "What is on screen?" in user_msg["content"]


async def test_ui_context_empty_omits_prefix() -> None:
    llm = _ScriptedLlm([_make_text_response("ok")])
    mcp = _ScriptedMcp()
    store = _InMemoryStore()
    loop = _build_loop(llm, mcp, store)

    await loop.run_chat_turn("s1", "raw question", ui_context_markdown="   ")
    user_msg = next(m for m in llm.calls[0]["messages"] if m["role"] == "user")
    assert user_msg["content"] == "raw question"
    assert "[Kontext:" not in user_msg["content"]


async def test_system_prompt_prepended_but_not_persisted() -> None:
    llm = _ScriptedLlm([_make_text_response("ok")])
    mcp = _ScriptedMcp()
    store = _InMemoryStore()
    loop = _build_loop(llm, mcp, store)

    await loop.run_chat_turn("s1", "Hi")
    # LLM saw system as the first message; the canonical prompt body
    # appears at the head, followed by the B7 untrusted-content
    # advisory appended by the loop constructor.
    msgs = llm.calls[0]["messages"]
    assert msgs[0]["role"] == "system"
    assert msgs[0]["content"].startswith("SYSTEM PROMPT")
    assert "SECURITY NOTE — Untrusted content boundary" in msgs[0]["content"]
    # Store dropped the system message.
    persisted = store.load("s1")
    assert all(m["role"] != "system" for m in persisted)


async def test_b7_system_prompt_carries_untrusted_marker() -> None:
    """Regression for Cluster d / B7: the system prompt the LLM receives
    SHALL include the untrusted-content advisory covering both the
    ``[Kontext: …]`` UI block and raw tool outputs."""
    llm = _ScriptedLlm([_make_text_response("ok")])
    mcp = _ScriptedMcp()
    store = _InMemoryStore()
    loop = _build_loop(llm, mcp, store)

    await loop.run_chat_turn("s-b7", "hi")
    sys_msg = llm.calls[0]["messages"][0]["content"]
    # The marker mentions BOTH untrusted channels.
    assert "[Kontext:" in sys_msg
    assert "role: tool" in sys_msg or "tool" in sys_msg.lower()
    # Refusal guidance present so the model knows what to do.
    assert "refuse" in sys_msg.lower() or "Ignore" in sys_msg


async def test_existing_history_replayed_into_llm() -> None:
    llm = _ScriptedLlm([_make_text_response("ok")])
    mcp = _ScriptedMcp()
    store = _InMemoryStore()
    # Seed history.
    store.save("s1", [{"role": "user", "content": "first"}, {"role": "assistant", "content": "answer-1"}])
    loop = _build_loop(llm, mcp, store)

    await loop.run_chat_turn("s1", "second")
    msgs = llm.calls[0]["messages"]
    # system / first user / first assistant / new user
    assert [m["role"] for m in msgs] == ["system", "user", "assistant", "user"]
    assert msgs[1]["content"] == "first"
    assert msgs[2]["content"] == "answer-1"
    assert msgs[3]["content"] == "second"


def test_constructor_validation() -> None:
    llm = _ScriptedLlm([])
    mcp = _ScriptedMcp()
    store = _InMemoryStore()
    with pytest.raises(ValueError):
        ChatAgentLoop(llm=llm, mcp_registry=mcp, session_store=store, system_prompt="", max_tool_rounds=4)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        ChatAgentLoop(llm=llm, mcp_registry=mcp, session_store=store, system_prompt="x", max_tool_rounds=0)  # type: ignore[arg-type]


async def test_empty_session_id_rejected() -> None:
    llm = _ScriptedLlm([_make_text_response("ok")])
    mcp = _ScriptedMcp()
    store = _InMemoryStore()
    loop = _build_loop(llm, mcp, store)
    with pytest.raises(ValueError):
        await loop.run_chat_turn("", "x")


async def test_b5_allow_list_filters_discovered_tools() -> None:
    """Regression for Cluster d / B5: the chat agent loop's allow-list
    SHALL hide non-listed tools from the LLM at discovery time.

    The mock MCP advertises three tool specs but the loop is built with
    only one of them in the allow-list, so the LLM sees a single tool
    in the `tools` argument of the chat-completion call.
    """
    llm = _ScriptedLlm([_make_text_response("done")])
    mcp = _ScriptedMcp(
        tool_specs=[
            {"type": "function", "function": {"name": "postgres.read_anomalies", "parameters": {}}},
            {"type": "function", "function": {"name": "pcap.analyze_chunk", "parameters": {}}},
            {"type": "function", "function": {"name": "mitre.list_tactics", "parameters": {}}},
        ]
    )
    store = _InMemoryStore()
    loop = ChatAgentLoop(
        llm=llm,  # type: ignore[arg-type]
        mcp_registry=mcp,  # type: ignore[arg-type]
        session_store=store,  # type: ignore[arg-type]
        system_prompt="SYS",
        max_tool_rounds=4,
        allowed_tools=["postgres.read_anomalies"],
    )

    await loop.run_chat_turn("s-allow", "hi")
    advertised = llm.calls[0]["tools"]
    advertised_names = [t["function"]["name"] for t in advertised]
    assert advertised_names == ["postgres.read_anomalies"]


async def test_b5_default_deny_when_allow_list_empty() -> None:
    """Regression for Cluster d / B5: an explicit empty allow-list means
    ZERO tools — strict default-deny. The LLM SHALL see an empty tool
    list and cannot request any tool call.

    Note: ``[]`` is no longer the production default (that is ``None``
    → passthrough, per the 2026-05-19 fix and design.md § Q2). ``[]``
    is now the explicit operator opt-in to lock chat down. See the
    regression test in ``test_chat_mcp_tool_loop_regression.py``.
    """
    llm = _ScriptedLlm([_make_text_response("no tools used")])
    mcp = _ScriptedMcp(
        tool_specs=[
            {"type": "function", "function": {"name": "postgres.read_anomalies", "parameters": {}}},
        ]
    )
    store = _InMemoryStore()
    loop = ChatAgentLoop(
        llm=llm,  # type: ignore[arg-type]
        mcp_registry=mcp,  # type: ignore[arg-type]
        session_store=store,  # type: ignore[arg-type]
        system_prompt="SYS",
        max_tool_rounds=4,
        allowed_tools=[],
    )

    await loop.run_chat_turn("s-deny", "hi")
    assert llm.calls[0]["tools"] == []


async def test_b5_disallowed_tool_call_is_refused() -> None:
    """Regression for Cluster d / B5: even if the model hallucinates a
    tool call for a tool NOT in the allow-list, the registry SHALL
    refuse to execute it. The chat loop catches the
    :class:`PermissionError` and surfaces an ``ERROR:`` tool message
    instead of reaching the MCP server.
    """
    forbidden_call = _MockToolCall(
        id="tc-forbidden",
        function=_MockToolCallFunction(name="postgres.write_anomalies", arguments="{}"),
    )
    llm = _ScriptedLlm(
        [
            _make_tool_call_response(tool_calls=[forbidden_call]),
            _make_text_response("refused gracefully"),
        ]
    )
    mcp = _ScriptedMcp(
        tool_specs=[
            {"type": "function", "function": {"name": "postgres.read_anomalies", "parameters": {}}},
        ],
        call_results={"postgres.write_anomalies": "should not be reached"},
    )
    store = _InMemoryStore()
    loop = ChatAgentLoop(
        llm=llm,  # type: ignore[arg-type]
        mcp_registry=mcp,  # type: ignore[arg-type]
        session_store=store,  # type: ignore[arg-type]
        system_prompt="SYS",
        max_tool_rounds=4,
        allowed_tools=["postgres.read_anomalies"],
    )

    result = await loop.run_chat_turn("s-deny-exec", "go")
    # The model recovered and produced an answer.
    assert result.content == "refused gracefully"
    # MCP was NEVER invoked — the gate kicked in before any traffic.
    assert mcp.invocations == []
    # The second LLM round saw a tool message reporting the refusal.
    second_round_msgs = llm.calls[1]["messages"]
    tool_msg = next(m for m in second_round_msgs if m["role"] == "tool")
    assert "ERROR" in tool_msg["content"]
    assert "allow-list" in tool_msg["content"] or "PermissionError" in tool_msg["content"]


async def test_b6_concurrent_turns_serialised_no_history_loss() -> None:
    """Regression for Cluster d / B6: two concurrent turns on the SAME
    session_id MUST NOT silently drop either turn's history.

    Without per-session locking, both turns would call
    ``store.load`` against the same baseline (the empty list), each
    append their own user/assistant pair, and save in turn — the
    second write would overwrite the first turn's appended messages.
    The lock makes the cycle mutually exclusive: the second turn
    sees the first turn's persisted messages in its ``load`` and
    persists a strictly longer history.
    """

    import asyncio as _asyncio

    class _SlowSyncStore(_InMemoryStore):
        """Store whose ``load`` yields the event loop so concurrent turns interleave."""

        def __init__(self) -> None:
            super().__init__()
            self.load_call_order: List[str] = []
            self.save_call_order: List[str] = []

        def load(self, session_id: str) -> List[Dict[str, Any]]:
            self.load_call_order.append(session_id)
            return super().load(session_id)

        def save(self, session_id: str, messages: List[Dict[str, Any]]) -> None:
            self.save_call_order.append(session_id)
            super().save(session_id, messages)

    class _SlowLlm(_ScriptedLlm):
        async def _delay(self) -> None:
            # Give the loop a chance to schedule the OTHER turn.
            await _asyncio.sleep(0.01)

        def chat_completion(
            self,
            messages: List[Dict[str, Any]],
            tools: List[Dict[str, Any]],
            *,
            temperature: float = 0.1,
            reasoning_effort: Optional[str] = None,
        ) -> _MockChatCompletion:
            # The agent loop wraps this in ``asyncio.to_thread``; a
            # synchronous time.sleep here would block the whole event
            # loop and prevent any interleaving. We deliberately do
            # nothing here — the to_thread hop itself yields control.
            return super().chat_completion(
                messages,
                tools,
                temperature=temperature,
                reasoning_effort=reasoning_effort,
            )

    llm = _SlowLlm(
        [
            _make_text_response("answer-A"),
            _make_text_response("answer-B"),
        ]
    )
    mcp = _ScriptedMcp()
    store = _SlowSyncStore()
    loop = _build_loop(llm, mcp, store)

    coros = [
        loop.run_chat_turn("shared-session", "turn-A"),
        loop.run_chat_turn("shared-session", "turn-B"),
    ]
    results = await _asyncio.gather(*coros)

    # Both turns produced an answer.
    assert {r.content for r in results} == {"answer-A", "answer-B"}

    persisted = store.load("shared-session")
    # The persisted history MUST include BOTH user turns and BOTH
    # assistant answers — i.e. four messages — proving neither write
    # overwrote the other.
    user_contents = [m["content"] for m in persisted if m.get("role") == "user"]
    assistant_contents = [m.get("content") for m in persisted if m.get("role") == "assistant"]
    assert sorted(user_contents) == ["turn-A", "turn-B"]
    assert sorted(c or "" for c in assistant_contents) == ["answer-A", "answer-B"]
    # And the conversation order is the alternating user/assistant
    # pattern, not interleaved garbage.
    roles = [m["role"] for m in persisted]
    assert roles == ["user", "assistant", "user", "assistant"]


async def test_b6_lock_is_per_session_not_global() -> None:
    """Regression for Cluster d / B6: distinct session_ids MUST NOT
    block each other. Turns on different sessions can interleave."""

    import asyncio as _asyncio

    llm = _ScriptedLlm([_make_text_response("A"), _make_text_response("B")])
    mcp = _ScriptedMcp()
    store = _InMemoryStore()
    loop = _build_loop(llm, mcp, store)

    results = await _asyncio.gather(
        loop.run_chat_turn("session-1", "hi-1"),
        loop.run_chat_turn("session-2", "hi-2"),
    )
    assert {r.content for r in results} == {"A", "B"}
    # Each session has its own row.
    assert len(store.load("session-1")) == 2
    assert len(store.load("session-2")) == 2


async def test_a11_multi_round_total_tokens_not_summed() -> None:
    """Regression for A11: per-round ``total_tokens`` MUST NOT be summed.

    Each round's response carries ``total_tokens = 100`` (prompt 90 +
    completion 10). The old behaviour summed total_tokens across 3 rounds
    and returned 300, inflating billed tokens 2–3x. The correct value is
    ``last_prompt_tokens + sum(completion_tokens)`` = 90 + (10*3) = 120.
    """
    call1 = _MockToolCall(id="tc-1", function=_MockToolCallFunction(name="t.one", arguments="{}"))
    call2 = _MockToolCall(id="tc-2", function=_MockToolCallFunction(name="t.two", arguments="{}"))
    llm = _ScriptedLlm(
        [
            _make_tool_call_response(tool_calls=[call1], prompt=90, completion=10),
            _make_tool_call_response(tool_calls=[call2], prompt=90, completion=10),
            _make_text_response("done", prompt=90, completion=10),
        ]
    )
    mcp = _ScriptedMcp(call_results={"t.one": "ok", "t.two": "ok"})
    store = _InMemoryStore()
    loop = _build_loop(llm, mcp, store)

    result = await loop.run_chat_turn("s1", "go")
    # The buggy implementation would return 300 (= 3 * 100). The fix
    # returns 120 (= last prompt + sum of completions).
    assert result.tokens_used != 300, "per-round total_tokens must not be summed (A11)"
    assert result.tokens_used == 120
    assert result.prompt_tokens == 90
    assert result.completion_tokens == 30
    assert result.tool_calls_count == 2


def _make_text_response_with_usage(content: str, usage: _MockUsage) -> _MockChatCompletion:
    """Build a tool-less text response carrying an explicit usage block."""
    return _MockChatCompletion(
        choices=[_MockChoice(message=_MockMessage(content=content))],
        usage=usage,
    )


async def test_prompt_only_usage_keeps_completion_null() -> None:
    """A provider that reports prompt but not completion usage MUST leave
    ``completion_tokens`` null — never a synthetic zero (finding AI-012 #2).

    ``tokens_used`` backward-compat: prompt observed → ``last_prompt_tokens``
    plus the (zero) completion sum, i.e. the prompt count.
    """
    usage = _MockUsage(total_tokens=None, prompt_tokens=42, completion_tokens=None)
    llm = _ScriptedLlm([_make_text_response_with_usage("hi", usage)])
    loop = _build_loop(llm, _ScriptedMcp(), _InMemoryStore())

    result = await loop.run_chat_turn("s1", "Hi")
    assert result.prompt_tokens == 42
    assert result.completion_tokens is None, "unknown completion usage must stay null"
    assert result.tokens_used == 42


async def test_completion_only_usage_keeps_prompt_null() -> None:
    """A provider that reports completion but not prompt usage MUST leave
    ``prompt_tokens`` null and surface the completion count."""
    usage = _MockUsage(total_tokens=None, prompt_tokens=None, completion_tokens=9)
    llm = _ScriptedLlm([_make_text_response_with_usage("hi", usage)])
    loop = _build_loop(llm, _ScriptedMcp(), _InMemoryStore())

    result = await loop.run_chat_turn("s1", "Hi")
    assert result.prompt_tokens is None, "unknown prompt usage must stay null"
    assert result.completion_tokens == 9
    # tokens_used backward-compat: (last_prompt or 0) + completion sum.
    assert result.tokens_used == 9


async def test_no_usage_reported_keeps_all_token_fields_null() -> None:
    """When no usage is reported at all, every token field stays null."""
    usage = _MockUsage(total_tokens=None, prompt_tokens=None, completion_tokens=None)
    llm = _ScriptedLlm([_make_text_response_with_usage("hi", usage)])
    loop = _build_loop(llm, _ScriptedMcp(), _InMemoryStore())

    result = await loop.run_chat_turn("s1", "Hi")
    assert result.prompt_tokens is None
    assert result.completion_tokens is None
    assert result.tokens_used is None


# --- AI-02: blocking psycopg2 load/save must run off the event loop ---


class _ThreadRecordingStore(_InMemoryStore):
    """Store that records the thread id every load/save ran on."""

    def __init__(self) -> None:
        super().__init__()
        self.load_thread_ids: List[int] = []
        self.save_thread_ids: List[int] = []

    def load(self, session_id: str) -> List[Dict[str, Any]]:
        import threading

        self.load_thread_ids.append(threading.get_ident())
        return super().load(session_id)

    def save(self, session_id: str, messages: List[Dict[str, Any]]) -> None:
        import threading

        self.save_thread_ids.append(threading.get_ident())
        super().save(session_id, messages)


async def test_session_store_load_save_run_off_the_event_loop_thread() -> None:
    """AI-02: blocking psycopg2 ``load``/``save`` MUST NOT run on the
    event-loop thread — they are wrapped in ``asyncio.to_thread`` (the
    pattern already used for ``provider.chat_completion``).

    pytest-asyncio auto mode runs this test coroutine on the event-loop
    thread, so ``threading.get_ident()`` here IS the loop thread. A store
    call executing on the same id proves the blocking regression.
    """
    import threading

    loop_thread = threading.get_ident()
    llm = _ScriptedLlm([_make_text_response("hi")])
    store = _ThreadRecordingStore()
    loop = _build_loop(llm, _ScriptedMcp(), store)

    result = await loop.run_chat_turn("s1", "Hi")
    assert result.content == "hi"

    assert store.load_thread_ids, "load was never called"
    assert store.save_thread_ids, "save was never called"
    assert all(
        tid != loop_thread for tid in store.load_thread_ids
    ), "ChatSessionStore.load ran on the event-loop thread (blocking psycopg2)"
    assert all(
        tid != loop_thread for tid in store.save_thread_ids
    ), "ChatSessionStore.save ran on the event-loop thread (blocking psycopg2)"


async def test_streaming_turn_store_load_save_run_off_the_event_loop_thread() -> None:
    """AI-02 (streaming path): the SSE turn body holds the same contract."""

    import threading

    loop_thread = threading.get_ident()

    class _StreamLlm(_ScriptedLlm):
        async def chat_completion_stream(self, messages: List[Dict[str, Any]], tools: List[Dict[str, Any]]) -> Any:
            chunk = type(
                "Chunk",
                (),
                {
                    "choices": [type("C", (), {"delta": type("D", (), {"content": "hi", "tool_calls": None})()})()],
                    "usage": None,
                },
            )()
            yield chunk

    llm = _StreamLlm([])
    store = _ThreadRecordingStore()
    loop = _build_loop(llm, _ScriptedMcp(), store)

    events = [e async for e in loop.run_chat_turn_stream("s1", "Hi")]
    assert any(e.get("type") == "final" for e in events)

    assert store.load_thread_ids and all(
        tid != loop_thread for tid in store.load_thread_ids
    ), "streaming load ran on the event-loop thread (blocking psycopg2)"
    assert store.save_thread_ids and all(
        tid != loop_thread for tid in store.save_thread_ids
    ), "streaming save ran on the event-loop thread (blocking psycopg2)"
