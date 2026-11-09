"""Regression test for the 2026-05-19 Chat-Agent MCP-tools bug.

**Symptom (operator report 2026-05-19):** the AI Chat says "no real tool
answer in the conversation" when asked to call an MCP tool (e.g. "read
the last 5 alarms from postgres"). The agent never emits a ``tool_call``
because the LLM is told "no tools available".

**Root cause:** ``otalon-ai/config/config.json`` sets
``chat.allowed_tools`` to ``[]``, and the per-Cluster-d B5 semantics in
:class:`McpRegistry` treat ``allow_list=[]`` as **strict default-deny**
(zero tools advertised). Operators following the design.md Q2 default
("no allow-list in chat (full passthrough)") had no obvious way to
express passthrough — the config field was a required ``list[str]``.

**Fix:** ``ChatConfig.allowed_tools`` is now ``Optional[List[str]]`` with
default ``None``. The production ``config/config.json`` sets the field
to ``null`` to mean passthrough. Explicit ``[]`` still means strict
default-deny for operators who want to lock chat down.

This file covers three things:

1. The production ``config/config.json`` carries ``chat.allowed_tools``
   such that the resulting :class:`ChatConfig` is in *passthrough* mode
   (``None``), NOT strict-deny (``[]``).
2. The :class:`ChatAgentLoop` constructed with that config-derived
   ``allowed_tools`` advertises the discovered MCP tools to the LLM and
   actually executes a tool call when the model emits one.
3. The full two-round tool-call sequence (model → tool_call →
   harness MCP result → final assistant message) round-trips correctly
   end-to-end, with the tool result reaching the final assistant
   message.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from otalon_ai.chat.agent_loop import ChatAgentLoop
from otalon_ai.settings import ChatConfig

# --- mocks (copy of the patterns in test_chat_agent_loop.py) ----------


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
    total_tokens: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0


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
    """Mock McpRegistry mirroring the real allow-list semantics."""

    def __init__(
        self,
        *,
        tool_specs: Optional[List[Dict[str, Any]]] = None,
        call_results: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._tool_specs = tool_specs or []
        self._call_results = call_results or {}
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
        return str(self._call_results.get(name, "OK"))


class _InMemoryStore:
    def __init__(self) -> None:
        self._rows: Dict[str, List[Dict[str, Any]]] = {}

    def load(self, session_id: str) -> List[Dict[str, Any]]:
        return list(self._rows.get(session_id, []))

    def save(self, session_id: str, messages: List[Dict[str, Any]]) -> None:
        self._rows[session_id] = [m for m in messages if m.get("role") != "system"]


# --- regression tests --------------------------------------------------


def test_chat_config_default_is_passthrough_not_strict_deny() -> None:
    """Regression: the DEFAULT ``ChatConfig.allowed_tools`` SHALL be
    ``None`` (passthrough), NOT ``[]`` (strict default-deny).

    The design.md Q2 default for chat is "no allow-list (full
    passthrough)". The pre-fix code defaulted to ``[]`` which the
    registry's B5 semantics interpret as "zero tools advertised". That
    silently disabled MCP tools for every operator who did not
    explicitly configure a curated list.
    """
    cfg = ChatConfig()
    assert cfg.allowed_tools is None, (
        "ChatConfig.allowed_tools default MUST be None (passthrough) per design.md Q2; "
        "an empty list was the bug that broke chat MCP tool execution on 2026-05-19."
    )


def test_chat_config_explicit_empty_list_is_strict_deny() -> None:
    """An operator who explicitly writes ``"allowed_tools": []`` in
    config.json STILL gets strict default-deny — the B5 opt-in path
    remains available, it just is no longer the silent default.
    """
    cfg = ChatConfig(allowed_tools=[])
    assert cfg.allowed_tools == [], (
        "Explicit empty list MUST be preserved verbatim so the registry's "
        "default-deny path (B5) stays accessible for operators who want it."
    )


def test_chat_config_explicit_list_passes_through_verbatim() -> None:
    """An operator-supplied curated list survives validation unchanged."""
    cfg = ChatConfig(allowed_tools=["postgres.read_alarm_details", "pcap.list_chunks"])
    assert cfg.allowed_tools == ["postgres.read_alarm_details", "pcap.list_chunks"]


def test_production_config_json_does_not_strict_deny_chat_tools() -> None:
    """Regression: the shipped ``otalon-ai/config/config.json`` MUST
    NOT carry the buggy ``chat.allowed_tools: []`` that silently disabled
    chat MCP tools after the ``replace-n8n-chat-orchestration`` cutover.

    The file SHALL either set the field to ``null`` (passthrough — the
    spec default) or to a non-empty curated list. An empty list is the
    explicit "tools off" state and is wrong for the production default.
    """
    here = Path(__file__).resolve()
    config_path = here.parents[2] / "config" / "config.json"
    assert config_path.exists(), f"production config not found at {config_path}"
    cfg = json.loads(config_path.read_text(encoding="utf-8"))
    chat_cfg = cfg.get("chat", {})
    allowed = chat_cfg.get("allowed_tools")
    # ``null`` in JSON → ``None`` in Python (passthrough).
    # An empty list is the silent-disable bug we are guarding against.
    assert allowed != [], (
        "otalon-ai/config/config.json sets chat.allowed_tools=[] which "
        "the registry interprets as strict default-deny (zero MCP tools "
        "advertised to the chat LLM). This silently broke chat tool execution "
        "after the replace-n8n-chat-orchestration cutover. Set the field to "
        "null (passthrough, per design.md Q2 default) or to a non-empty "
        "curated list."
    )


async def test_chat_loop_with_passthrough_executes_two_round_tool_sequence() -> None:
    """End-to-end behavioural regression: with ``allowed_tools=None``
    (the new production default), the chat loop SHALL drive the full
    two-round tool-calling sequence:

    1. Model emits ``tool_calls`` referencing ``postgres.read_alarm_details``.
    2. Loop executes the tool via the mock MCP, appends the tool reply.
    3. Model emits a final assistant message that incorporates the
       tool result string.

    On the pre-fix production config (``allowed_tools=[]``) the LLM would
    receive an empty tool list, never emit a tool_call, and the loop
    would return whatever the model said with no tool data — exactly the
    "no real tool answer in the conversation" symptom the operator hit.
    """
    tool_call = _MockToolCall(
        id="tc-regression",
        function=_MockToolCallFunction(
            name="postgres_read_alarm_details",  # sanitized (no dots)
            arguments='{"limit": 5}',
        ),
    )
    llm = _ScriptedLlm(
        [
            # Round 1: model decides to call the tool.
            _MockChatCompletion(
                choices=[_MockChoice(message=_MockMessage(content=None, tool_calls=[tool_call]))],
                usage=_MockUsage(total_tokens=20, prompt_tokens=18, completion_tokens=2),
            ),
            # Round 2: model produces final assistant content referencing the result.
            _MockChatCompletion(
                choices=[
                    _MockChoice(
                        message=_MockMessage(
                            content="Found 5 alarms; latest is id=42 severity=high.",
                        )
                    )
                ],
                usage=_MockUsage(total_tokens=40, prompt_tokens=35, completion_tokens=5),
            ),
        ]
    )
    # Mock MCP advertises the real-world dotted tool name (already sanitized
    # by the real registry for OpenAI compatibility).
    mcp = _ScriptedMcp(
        tool_specs=[
            {
                "type": "function",
                "function": {"name": "postgres_read_alarm_details", "parameters": {}},
            },
            {
                "type": "function",
                "function": {"name": "pcap_list_chunks", "parameters": {}},
            },
        ],
        call_results={
            "postgres_read_alarm_details": '[{"id": 42, "severity": "high"}]',
        },
    )
    store = _InMemoryStore()

    # The production default after the fix: pass-through (None), NOT [].
    loop = ChatAgentLoop(
        llm=llm,  # type: ignore[arg-type]
        mcp_registry=mcp,  # type: ignore[arg-type]
        session_store=store,  # type: ignore[arg-type]
        system_prompt="SYS",
        max_tool_rounds=4,
        allowed_tools=ChatConfig().allowed_tools,
    )

    result = await loop.run_chat_turn(
        "regression-session",
        "Read the last 5 alarms from postgres.",
    )

    # 1. The LLM saw the full discovered tool list (passthrough) on round 1.
    advertised_round1 = [t["function"]["name"] for t in llm.calls[0]["tools"]]
    assert "postgres_read_alarm_details" in advertised_round1, (
        "passthrough mode must expose discovered tools to the LLM; " f"got tools={advertised_round1}"
    )
    assert len(advertised_round1) == 2, "all discovered tools must be advertised in passthrough mode"

    # 2. The MCP was actually invoked with the parsed args.
    assert mcp.invocations == [{"name": "postgres_read_alarm_details", "args": {"limit": 5}}]

    # 3. The tool result was fed back into the LLM as a ``role: tool`` message
    #    on round 2.
    round2_msgs = llm.calls[1]["messages"]
    tool_reply = next((m for m in round2_msgs if m.get("role") == "tool"), None)
    assert tool_reply is not None, "tool reply must be present in round 2 messages"
    assert tool_reply["tool_call_id"] == "tc-regression"
    assert "id" in tool_reply["content"] and "severity" in tool_reply["content"]

    # 4. The final assistant message reflects the tool result — i.e. the
    #    loop did not terminate early before the tool round-trip.
    assert "Found 5 alarms" in result.content
    assert result.tool_calls_count == 1
    assert result.cap_reached is False


async def test_chat_loop_with_empty_list_still_default_denies() -> None:
    """Belt-and-braces: the B5 default-deny opt-in path SHALL remain
    intact. An operator who explicitly sets ``allowed_tools=[]`` in the
    config gets ZERO tools advertised even though the registry has
    discovered some.
    """
    llm = _ScriptedLlm(
        [
            _MockChatCompletion(
                choices=[_MockChoice(message=_MockMessage(content="I have no tools to use."))],
                usage=_MockUsage(total_tokens=8, prompt_tokens=7, completion_tokens=1),
            )
        ]
    )
    mcp = _ScriptedMcp(
        tool_specs=[
            {
                "type": "function",
                "function": {"name": "postgres_read_alarm_details", "parameters": {}},
            },
        ]
    )
    store = _InMemoryStore()

    loop = ChatAgentLoop(
        llm=llm,  # type: ignore[arg-type]
        mcp_registry=mcp,  # type: ignore[arg-type]
        session_store=store,  # type: ignore[arg-type]
        system_prompt="SYS",
        max_tool_rounds=4,
        allowed_tools=[],  # explicit opt-in to default-deny
    )

    await loop.run_chat_turn("strict-session", "Read alarms.")
    assert llm.calls[0]["tools"] == [], "explicit [] MUST still mean zero tools (B5 default-deny)"


# Note: async tests in this file are auto-collected by pytest-asyncio via
# the subproject's ``asyncio_mode = "auto"`` setting in ``pyproject.toml``.
# No file-level ``pytestmark`` is needed; adding one would warn on the
# sync ``test_chat_config_*`` tests.
