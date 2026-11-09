"""Regression tests for AI-037 — current-time context in the chat agent.

Live failure being locked down: asked "How many alarms were recorded in
the last hour?" the chat agent called ``postgres.read_alarms`` with
``start=2026-09-01T11:17:00Z / stop=2026-09-01T12:17:00Z`` while real
UTC was ``02:22Z``. The window sat ~9 h in the FUTURE, matched nothing,
and the agent answered "0" although an active alarm existed. The
canonical system prompt actively caused this: it states "You do not
know the current wall-clock time"
(``otalon-mcp/docs/system_promt_agent.md:417``), and nothing in the
chat pipeline ever supplied one.

The end-to-end test below is deliberately NOT a string assertion on the
prompt. It wires:

- a fake ``postgres.read_alarms`` MCP tool that really filters a fixture
  alarm row by the ``start`` / ``stop`` window it is handed, and
- a ``_ClockReadingLlm`` stand-in that resolves "last hour" the way a
  correct model would: by parsing ``now_utc`` out of the system prompt
  it receives and subtracting one hour.

So the assertion is on the observable outcome — the alarm count the
agent reports. Skew the injected clock (as
``test_skewed_clock_makes_the_guard_go_red`` does, reproducing the
original ~9 h offset) and the window stops covering the alarm, the
count drops to 0, and the contract test fails. That is the required
RED behaviour.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import pytest

from otalon_ai.chat.agent_loop import ChatAgentLoop
from otalon_ai.chat.time_context import NOW_UTC_LABEL, TIME_CONTEXT_HEADER, render_time_context, utc_now

# --- fixture instants ---------------------------------------------------

# Pinned "real" now, mirroring the live incident's true UTC clock.
REAL_NOW = datetime(2026, 9, 1, 2, 22, 0, tzinfo=timezone.utc)

# The single alarm on record: 12 minutes before REAL_NOW, so it is inside
# the last hour and outside any window the buggy agent produced.
ALARM_TS = REAL_NOW - timedelta(minutes=12)

# The offset the live agent hallucinated (~9 h into the future).
OBSERVED_SKEW = timedelta(hours=9, minutes=55)


# --- minimal LLM/response doubles ---------------------------------------


@dataclass
class _ToolCallFunction:
    name: str
    arguments: str


@dataclass
class _ToolCall:
    id: str
    function: _ToolCallFunction
    type: str = "function"


@dataclass
class _Message:
    role: str = "assistant"
    content: Optional[str] = None
    tool_calls: Optional[List[_ToolCall]] = None

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
class _Choice:
    message: _Message
    finish_reason: str = "stop"
    index: int = 0


@dataclass
class _Usage:
    total_tokens: Optional[int] = 0
    prompt_tokens: Optional[int] = 0
    completion_tokens: Optional[int] = 0


@dataclass
class _Completion:
    choices: List[_Choice]
    usage: _Usage = field(default_factory=_Usage)
    id: str = "chatcmpl-ai037"
    model: str = "azure/gpt-5.4"


_NOW_UTC_RE = re.compile(rf"•\s*{NOW_UTC_LABEL}:\s*(\d{{4}}-\d{{2}}-\d{{2}}T\d{{2}}:\d{{2}}:\d{{2}}Z)")


class _ClockReadingLlm:
    """Model stand-in that derives its query window from the prompt clock.

    Round 1 emits a ``postgres.read_alarms`` tool call whose ``start`` /
    ``stop`` are computed from the ``now_utc`` line in the system
    prompt. Round 2 reports the row count the tool returned. If no
    ``now_utc`` line is present, it falls back to the hallucinated
    future window from the live incident — which is exactly what the
    real model did when left without a clock.
    """

    FALLBACK_START = "2026-09-01T11:17:00Z"
    FALLBACK_STOP = "2026-09-01T12:17:00Z"

    def __init__(self) -> None:
        self.calls: List[Dict[str, Any]] = []
        self.window_used: Dict[str, str] = {}

    def _window_from_prompt(self, system_prompt: str) -> Dict[str, str]:
        match = _NOW_UTC_RE.search(system_prompt)
        if match is None:
            return {"start": self.FALLBACK_START, "stop": self.FALLBACK_STOP}
        stop = datetime.strptime(match.group(1), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        start = stop - timedelta(hours=1)
        return {
            "start": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "stop": stop.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }

    def chat_completion(
        self,
        messages: List[Dict[str, Any]],
        tools: List[Dict[str, Any]],
        *,
        temperature: float = 0.1,
        reasoning_effort: Optional[str] = None,
    ) -> _Completion:
        self.calls.append({"messages": [dict(m) for m in messages], "tools": list(tools or [])})
        tool_replies = [m for m in messages if m.get("role") == "tool"]
        if not tool_replies:
            system_prompt = messages[0]["content"]
            window = self._window_from_prompt(system_prompt)
            self.window_used = window
            call = _ToolCall(
                id="tc-alarms",
                function=_ToolCallFunction(name="postgres.read_alarms", arguments=json.dumps(window)),
            )
            return _Completion(choices=[_Choice(message=_Message(content=None, tool_calls=[call]))])
        payload = json.loads(tool_replies[-1]["content"])
        return _Completion(choices=[_Choice(message=_Message(content=str(payload["count"])))])


class _AlarmTableMcp:
    """MCP double whose ``postgres.read_alarms`` really filters by window."""

    def __init__(self, alarm_timestamps: List[datetime]) -> None:
        self._alarms = list(alarm_timestamps)
        self.invocations: List[Dict[str, Any]] = []

    async def list_openai_tools(
        self,
        *,
        force_refresh: bool = False,
        allow_list: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        return [{"type": "function", "function": {"name": "postgres.read_alarms", "parameters": {}}}]

    async def call_tool(
        self,
        name: str,
        arguments: Dict[str, Any],
        *,
        allow_list: Optional[List[str]] = None,
    ) -> str:
        self.invocations.append({"name": name, "args": arguments})
        start = datetime.strptime(arguments["start"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        stop = datetime.strptime(arguments["stop"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        hits = [ts for ts in self._alarms if start <= ts <= stop]
        records = [{"id": i + 1, "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%SZ")} for i, ts in enumerate(hits)]
        return json.dumps({"ok": True, "records": records, "count": len(records)})


class _InMemoryStore:
    def __init__(self) -> None:
        self._rows: Dict[str, List[Dict[str, Any]]] = {}

    def load(self, session_id: str) -> List[Dict[str, Any]]:
        return list(self._rows.get(session_id, []))

    def save(self, session_id: str, messages: List[Dict[str, Any]]) -> None:
        self._rows[session_id] = [m for m in messages if m.get("role") != "system"]


def _build_loop(llm: _ClockReadingLlm, mcp: _AlarmTableMcp, now: datetime) -> ChatAgentLoop:
    return ChatAgentLoop(
        llm=llm,  # type: ignore[arg-type]
        mcp_registry=mcp,  # type: ignore[arg-type]
        session_store=_InMemoryStore(),  # type: ignore[arg-type]
        system_prompt="SYSTEM PROMPT. You do not know the current wall-clock time.",
        max_tool_rounds=4,
        clock=lambda: now,
    )


# --- acceptance: the "last hour" question hits the one existing alarm ---


async def test_last_hour_question_hits_the_single_existing_alarm() -> None:
    """AI-037 acceptance: exactly one alarm exists in the last hour and
    the agent's "last hour" query MUST find exactly that one."""
    llm = _ClockReadingLlm()
    mcp = _AlarmTableMcp([ALARM_TS])
    loop = _build_loop(llm, mcp, REAL_NOW)

    result = await loop.run_chat_turn("s-ai037", "How many alarms were recorded in the last hour?")

    assert result.content == "1", (
        "the agent reported "
        f"{result.content!r} alarms for the last hour while exactly one existed at "
        f"{ALARM_TS.isoformat()} (AI-037: the queried window missed the real clock)"
    )
    assert result.tool_calls_count == 1
    window = mcp.invocations[0]["args"]
    assert window["stop"] == "2026-09-01T02:22:00Z"
    assert window["start"] == "2026-09-01T01:22:00Z"


async def test_queried_window_never_lies_in_the_future() -> None:
    """The exact live symptom: the window's ``stop`` MUST NOT be after
    the real current time. The incident used a stop ~9 h ahead."""
    llm = _ClockReadingLlm()
    mcp = _AlarmTableMcp([ALARM_TS])
    loop = _build_loop(llm, mcp, REAL_NOW)

    await loop.run_chat_turn("s-future", "How many alarms were recorded in the last hour?")

    window = mcp.invocations[0]["args"]
    stop = datetime.strptime(window["stop"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    start = datetime.strptime(window["start"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    assert stop <= REAL_NOW, f"query window ends in the future: stop={stop.isoformat()} > now={REAL_NOW.isoformat()}"
    assert start < stop
    assert start <= ALARM_TS <= stop


async def test_skewed_clock_makes_the_guard_go_red() -> None:
    """Proof the guard is load-bearing, not decorative.

    Skewing the injected clock by the observed ~9 h reproduces the
    original bug end-to-end: the agent queries a future window, finds
    nothing, and confidently answers "0" while the alarm exists. This
    test asserts that FAILURE MODE, so it documents precisely what the
    acceptance test above would report if the time context regressed.
    """
    skewed_now = REAL_NOW + OBSERVED_SKEW
    llm = _ClockReadingLlm()
    mcp = _AlarmTableMcp([ALARM_TS])
    loop = _build_loop(llm, mcp, skewed_now)

    result = await loop.run_chat_turn("s-skew", "How many alarms were recorded in the last hour?")

    assert result.content == "0", "a skewed clock must produce the empty-window failure this fix removes"
    window = mcp.invocations[0]["args"]
    stop = datetime.strptime(window["stop"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    assert stop > REAL_NOW, "the skewed run must query a future window (the AI-037 symptom)"


async def test_missing_time_context_reproduces_the_live_failure() -> None:
    """Without a ``now_utc`` line the model falls back to the window it
    actually used live — and misses the alarm. This is the pre-fix
    baseline: it is what the acceptance test looked like before the
    time block existed."""
    llm = _ClockReadingLlm()
    mcp = _AlarmTableMcp([ALARM_TS])
    store = _InMemoryStore()
    loop = ChatAgentLoop(
        llm=llm,  # type: ignore[arg-type]
        mcp_registry=mcp,  # type: ignore[arg-type]
        session_store=store,  # type: ignore[arg-type]
        system_prompt="SYSTEM PROMPT. You do not know the current wall-clock time.",
        max_tool_rounds=4,
        clock=lambda: REAL_NOW,
    )
    # Strip the time block back off to emulate the pre-fix prompt.
    loop._system_prompt_for_turn = lambda: "SYSTEM PROMPT. You do not know the current wall-clock time."  # type: ignore[method-assign]

    result = await loop.run_chat_turn("s-nocontext", "How many alarms were recorded in the last hour?")
    assert result.content == "0"
    assert mcp.invocations[0]["args"]["start"] == _ClockReadingLlm.FALLBACK_START


# --- prompt-contract tests ---------------------------------------------


async def test_system_prompt_carries_now_utc_and_offset() -> None:
    llm = _ClockReadingLlm()
    mcp = _AlarmTableMcp([ALARM_TS])
    loop = _build_loop(llm, mcp, REAL_NOW)

    await loop.run_chat_turn("s-prompt", "How many alarms were recorded in the last hour?")

    system_prompt = llm.calls[0]["messages"][0]["content"]
    assert TIME_CONTEXT_HEADER in system_prompt
    assert f"{NOW_UTC_LABEL}: 2026-09-01T02:22:00Z" in system_prompt
    assert "now_local:" in system_prompt
    assert "UTC+" in system_prompt or "UTC-" in system_prompt
    # The canonical prompt body still precedes the injected block.
    assert system_prompt.startswith("SYSTEM PROMPT.")


async def test_time_block_is_rendered_per_turn_not_frozen() -> None:
    """A long-lived process MUST NOT serve a startup-frozen clock."""
    ticks = iter([REAL_NOW, REAL_NOW + timedelta(hours=3)])
    llm = _ClockReadingLlm()
    mcp = _AlarmTableMcp([ALARM_TS])
    loop = ChatAgentLoop(
        llm=llm,  # type: ignore[arg-type]
        mcp_registry=mcp,  # type: ignore[arg-type]
        session_store=_InMemoryStore(),  # type: ignore[arg-type]
        system_prompt="SYS",
        max_tool_rounds=4,
        clock=lambda: next(ticks),
    )

    await loop.run_chat_turn("s-tick", "How many alarms were recorded in the last hour?")
    await loop.run_chat_turn("s-tick", "How many alarms were recorded in the last hour?")

    first = llm.calls[0]["messages"][0]["content"]
    second = llm.calls[2]["messages"][0]["content"]
    assert f"{NOW_UTC_LABEL}: 2026-09-01T02:22:00Z" in first
    assert f"{NOW_UTC_LABEL}: 2026-09-01T05:22:00Z" in second


async def test_streaming_path_also_carries_the_time_context() -> None:
    """The SSE turn body MUST get the same clock as the sync path."""

    class _StreamLlm(_ClockReadingLlm):
        def __init__(self) -> None:
            super().__init__()
            self.stream_system_prompts: List[str] = []

        async def chat_completion_stream(self, messages: List[Dict[str, Any]], tools: List[Dict[str, Any]]) -> Any:
            self.stream_system_prompts.append(messages[0]["content"])
            chunk = type(
                "Chunk",
                (),
                {
                    "choices": [type("C", (), {"delta": type("D", (), {"content": "1", "tool_calls": None})()})()],
                    "usage": None,
                },
            )()
            yield chunk

    llm = _StreamLlm()
    mcp = _AlarmTableMcp([ALARM_TS])
    loop = _build_loop(llm, mcp, REAL_NOW)

    events = [e async for e in loop.run_chat_turn_stream("s-stream", "alarms last hour?")]

    assert any(e.get("type") == "final" for e in events)
    assert llm.stream_system_prompts, "stream never ran"
    assert f"{NOW_UTC_LABEL}: 2026-09-01T02:22:00Z" in llm.stream_system_prompts[0]


# --- renderer unit tests -----------------------------------------------


def test_render_time_context_precomputes_last_hour_window() -> None:
    block = render_time_context(REAL_NOW)
    assert "start=2026-09-01T01:22:00Z stop=2026-09-01T02:22:00Z" in block
    assert "start=2026-08-31T02:22:00Z stop=2026-09-01T02:22:00Z" in block
    assert "start=2026-09-01T00:00:00Z stop=2026-09-01T02:22:00Z" in block


def test_render_time_context_overrides_the_no_clock_claim() -> None:
    """The block must explicitly contradict the canonical prompt's
    "You do not know the current wall-clock time" statement, otherwise
    the model has two conflicting instructions and may keep guessing."""
    block = render_time_context(REAL_NOW)
    assert "supersedes" in block
    assert "You DO know it" in block
    assert "future" in block


def test_render_time_context_accepts_naive_datetime_as_utc() -> None:
    block = render_time_context(datetime(2026, 9, 1, 2, 22, 0))
    assert f"{NOW_UTC_LABEL}: 2026-09-01T02:22:00Z" in block


def test_render_time_context_normalises_non_utc_input() -> None:
    tokyo = timezone(timedelta(hours=9))
    block = render_time_context(REAL_NOW.astimezone(tokyo))
    assert f"{NOW_UTC_LABEL}: 2026-09-01T02:22:00Z" in block
    assert "unix_epoch_seconds: " + str(int(REAL_NOW.timestamp())) in block


def test_utc_now_is_timezone_aware_utc() -> None:
    moment = utc_now()
    assert moment.tzinfo is not None
    assert moment.utcoffset() == timedelta(0)


def test_default_clock_is_wall_clock() -> None:
    """A loop built without an explicit clock uses the real UTC now."""
    loop = ChatAgentLoop(
        llm=_ClockReadingLlm(),  # type: ignore[arg-type]
        mcp_registry=_AlarmTableMcp([]),  # type: ignore[arg-type]
        session_store=_InMemoryStore(),  # type: ignore[arg-type]
        system_prompt="SYS",
        max_tool_rounds=2,
    )
    before = utc_now() - timedelta(seconds=5)
    rendered = loop._system_prompt_for_turn()
    after = utc_now() + timedelta(seconds=5)

    match = _NOW_UTC_RE.search(rendered)
    assert match is not None, "default clock produced no now_utc line"
    stamped = datetime.strptime(match.group(1), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    assert before <= stamped <= after


@pytest.mark.parametrize("hours", [0, 1, 23])
def test_render_time_context_is_deterministic_for_a_given_instant(hours: int) -> None:
    moment = REAL_NOW + timedelta(hours=hours)
    assert render_time_context(moment) == render_time_context(moment)
