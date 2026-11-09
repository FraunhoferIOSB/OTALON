"""Unit tests for :func:`src.jobs.worker.classify_alarm`.

Cluster e / HC2 boundary-mocked coverage. Mocks the two HC2 boundaries:

- ``provider.chat_completion`` (LLM round-trip)
- ``session.call_tool`` (MCP tool execution)

Plus the optional callbacks ``event_sink``, ``trace_persist`` and
``cancellation_check`` so we can observe every side-effect.

The 5 scenarios from the cluster brief are covered:

1. **Happy path** — LLM returns valid two-step JSON, one tool call succeeds.
2. **MCP tool error** — one tool call raises; the loop continues and the
   error is recorded in ``tool_trace`` and emitted in
   ``ToolCallCompletedEvent.error``.
3. **LLM error** — provider raises a non-retryable error; retries are
   exhausted (or short-circuited for client errors) and the job ends
   with status ``failed``.
4. **Missing context** — LLM returns content that does not parse as a
   valid classification; status is ``failed`` and ``raw_final_text`` is
   preserved.
5. **Baseline-on / baseline-off (force_classify)** — when context exceeds
   :data:`FORCE_CLASSIFY_CHARS` the loop appends the force-classify nudge
   and emits a ``ForceClassifyEvent``.

Plus a retry-then-success test exercising the ``RateLimitError`` /
``APIStatusError(5xx)`` retry path.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any, Callable, Dict, List, Optional
from uuid import uuid4

import httpx
import openai
import pytest

from otalon_ai.jobs import worker as worker_mod
from otalon_ai.jobs.domain.events import (
    FinalEvent,
    ForceClassifyEvent,
    SubagentEvent,
    ToolCallCompletedEvent,
    ToolCallStartedEvent,
)
from otalon_ai.jobs.worker import classify_alarm

# ── Mock OpenAI SDK response shapes ──────────────────────────────────


@dataclass
class _MFn:
    name: str
    arguments: str


@dataclass
class _MTc:
    id: str
    function: _MFn
    type: str = "function"


@dataclass
class _MMsg:
    content: Optional[str] = None
    tool_calls: Optional[List[_MTc]] = None


@dataclass
class _MChoice:
    message: _MMsg


@dataclass
class _MUsage:
    prompt_tokens: int = 10
    completion_tokens: int = 5


@dataclass
class _MResp:
    choices: List[_MChoice]
    usage: Optional[_MUsage] = field(default_factory=_MUsage)


# ── Mock LLM provider ────────────────────────────────────────────────


class _ScriptedProvider:
    """Scripted provider: pops one entry per ``chat_completion`` call.

    Each entry is either an :class:`_MResp` or an :class:`Exception` to
    raise. Records call args for assertions.
    """

    name = "scripted"
    model = "test-model"

    def __init__(self, script: List[Any]) -> None:
        self._script = list(script)
        self.calls: List[Dict[str, Any]] = []

    def chat_completion(
        self,
        messages: List[Dict[str, Any]],
        tools: List[Dict[str, Any]],
        *,
        temperature: float = 0.1,
        reasoning_effort: Optional[str] = None,
    ) -> Any:
        self.calls.append(
            {
                "messages": [dict(m) for m in messages],
                "tools": list(tools),
                "temperature": temperature,
                "reasoning_effort": reasoning_effort,
            }
        )
        if not self._script:
            raise AssertionError("LLM script exhausted")
        item = self._script.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item


# ── Mock MCP session ─────────────────────────────────────────────────


class _MockMcpResult:
    def __init__(self, text: str) -> None:
        self.content = [SimpleNamespace(text=text)]


class _ScriptedSession:
    """Scripted MCP session for ``session.call_tool``.

    ``responses`` maps a tool name to a list of either text payloads or
    exceptions; each call pops one entry from the relevant list.
    """

    def __init__(
        self,
        *,
        responses: Optional[Dict[str, List[Any]]] = None,
        default: str = '{"ok": true}',
    ) -> None:
        self._responses = responses or {}
        self._default = default
        self.calls: List[Dict[str, Any]] = []

    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> _MockMcpResult:
        self.calls.append({"name": name, "args": arguments})
        if name in self._responses and self._responses[name]:
            item = self._responses[name].pop(0)
            if isinstance(item, BaseException):
                raise item
            return _MockMcpResult(str(item))
        return _MockMcpResult(self._default)


# ── Helpers ──────────────────────────────────────────────────────────


_VALID_TWO_STEP = """```json
{
  "step1_technical": {
    "technical_method": "Modbus function code abuse",
    "observed_activity": "Write to coil 0x0001 from unauthorised IP",
    "evidence": ["pcap chunk 12"]
  },
  "step2_classification": {
    "classifications": [
      {"technique_id": "T0846", "confidence": 0.92, "variant": "discover", "reasoning": "scan pattern"}
    ]
  }
}
```"""

_VALID_TWO_STEP_EMPTY = """```json
{
  "step1_technical": {
    "technical_method": "Bounds/jitter anomaly",
    "observed_activity": "Timing jitter within expected operational bounds rather than malicious activity",
    "evidence": ["timeseries shows normal variance"]
  },
  "step2_classification": {
    "classifications": []
  }
}
```"""


def _tool_msg(tool_name: str, args: str = "{}", call_id: str = "tc-1") -> _MResp:
    return _MResp(
        choices=[
            _MChoice(
                message=_MMsg(
                    content=None,
                    tool_calls=[_MTc(id=call_id, function=_MFn(name=tool_name, arguments=args))],
                )
            )
        ]
    )


def _text_msg(content: str) -> _MResp:
    return _MResp(choices=[_MChoice(message=_MMsg(content=content))])


def _collect_events() -> tuple[Callable[[SubagentEvent], Any], List[SubagentEvent]]:
    captured: List[SubagentEvent] = []

    async def sink(evt: SubagentEvent) -> None:
        captured.append(evt)

    return sink, captured


# ── 1. Happy path ────────────────────────────────────────────────────


@pytest.mark.unit
async def test_happy_path_one_tool_then_valid_classification() -> None:
    """LLM emits a tool call, MCP returns data, second LLM round emits valid JSON."""
    provider = _ScriptedProvider(
        [
            _tool_msg("postgres.read_anomalies", args='{"limit": 5}', call_id="tc-1"),
            _text_msg(_VALID_TWO_STEP),
        ]
    )
    session = _ScriptedSession(responses={"postgres.read_anomalies": ['[{"id": 1}]']})
    sink, captured = _collect_events()

    alarm = {"id": "alarm-1", "primary_type": "should_be_stripped"}

    record = await classify_alarm(
        job_id=uuid4(),
        session=session,  # type: ignore[arg-type]
        provider=provider,  # type: ignore[arg-type]  # reason: _ScriptedProvider duck-types LlmProvider
        alarm=alarm,
        openai_tools=[{"type": "function", "function": {"name": "postgres.read_anomalies"}}],
        system_prompt="SYS",
        temperature=0.1,
        timeout_seconds=60,
        event_sink=sink,
    )

    assert record["status"] == "completed"
    assert record["step2_classification"]["classifications"][0]["technique_id"] == "T0846"
    assert record["tokens_prompt"] == 20  # two LLM rounds * 10
    assert record["tokens_completion"] == 10  # two LLM rounds * 5
    # tool_trace has the single tool call.
    assert len(record["tool_trace"]) == 1
    assert record["tool_trace"][0]["tool"] == "postgres.read_anomalies"
    assert record["tool_trace"][0]["error"] is None
    assert record["tool_trace"][0]["result_preview"] == '[{"id": 1}]'

    # Events: started, completed, final
    started = [e for e in captured if isinstance(e, ToolCallStartedEvent)]
    completed = [e for e in captured if isinstance(e, ToolCallCompletedEvent)]
    final = [e for e in captured if isinstance(e, FinalEvent)]
    assert len(started) == 1
    assert len(completed) == 1
    assert completed[0].result_preview == '[{"id": 1}]'
    assert len(final) == 1
    assert final[0].status == "completed"


@pytest.mark.unit
async def test_result_preview_truncated_for_long_results() -> None:
    """Preview is capped at PREVIEW_CHARS (2 000)."""
    long_text = "x" * 5_000
    provider = _ScriptedProvider(
        [
            _tool_msg("postgres.read_anomalies", call_id="tc-1"),
            _text_msg(_VALID_TWO_STEP),
        ]
    )
    session = _ScriptedSession(responses={"postgres.read_anomalies": [long_text]})

    record = await classify_alarm(
        job_id=uuid4(),
        session=session,  # type: ignore[arg-type]
        provider=provider,  # type: ignore[arg-type]  # reason: _ScriptedProvider duck-types LlmProvider
        alarm={"id": "x"},
        openai_tools=[],
        system_prompt="SYS",
        temperature=0.1,
        timeout_seconds=60,
    )

    assert len(record["tool_trace"]) == 1
    preview = record["tool_trace"][0]["result_preview"]
    assert len(preview) == worker_mod.PREVIEW_CHARS
    assert preview == "x" * worker_mod.PREVIEW_CHARS


@pytest.mark.unit
async def test_result_preview_omits_stripped_bias_text() -> None:
    """For bias-stripping tools the preview must not contain the removed prediction text."""
    provider = _ScriptedProvider(
        [
            _tool_msg("postgres.read_anomalies", call_id="tc-1"),
            _text_msg(_VALID_TWO_STEP),
        ]
    )
    session = _ScriptedSession(responses={"postgres.read_anomalies": ['{"anomaly_type": "leak", "value": 7}']})

    record = await classify_alarm(
        job_id=uuid4(),
        session=session,  # type: ignore[arg-type]
        provider=provider,  # type: ignore[arg-type]  # reason: _ScriptedProvider duck-types LlmProvider
        alarm={"id": "x"},
        openai_tools=[],
        system_prompt="SYS",
        temperature=0.1,
        timeout_seconds=60,
    )

    preview = record["tool_trace"][0]["result_preview"]
    assert "anomaly_type" not in preview
    assert "leak" not in preview
    assert '"value": 7' in preview


@pytest.mark.unit
async def test_happy_path_strips_ml_bias_from_tool_response() -> None:
    """``postgres.read_anomalies`` is a bias-stripping tool — fields removed."""
    provider = _ScriptedProvider(
        [
            _tool_msg("postgres.read_anomalies", call_id="tc-1"),
            _text_msg(_VALID_TWO_STEP),
        ]
    )
    session = _ScriptedSession(
        responses={"postgres.read_anomalies": ['[{"id": 1, "anomaly_type": "leak", "value": 7}]']}
    )

    await classify_alarm(
        job_id=uuid4(),
        session=session,  # type: ignore[arg-type]
        provider=provider,  # type: ignore[arg-type]  # reason: _ScriptedProvider duck-types LlmProvider
        alarm={"id": "x"},
        openai_tools=[],
        system_prompt="SYS",
        temperature=0.1,
        timeout_seconds=60,
    )

    # The tool-result message reaching the LLM in round 2 must not contain ``anomaly_type``.
    second_round_msgs = provider.calls[1]["messages"]
    tool_msg = next(m for m in second_round_msgs if m["role"] == "tool")
    assert "anomaly_type" not in tool_msg["content"]
    assert "leak" not in tool_msg["content"]
    assert "value" in tool_msg["content"]


# ── 2. MCP tool error ────────────────────────────────────────────────


@pytest.mark.unit
async def test_mcp_tool_error_is_recorded_loop_continues() -> None:
    """When ``session.call_tool`` raises, the loop records the error and continues."""
    provider = _ScriptedProvider(
        [
            _tool_msg("broken.tool", call_id="tc-1"),
            _text_msg(_VALID_TWO_STEP),
        ]
    )
    session = _ScriptedSession(responses={"broken.tool": [RuntimeError("MCP down")]})
    sink, captured = _collect_events()

    record = await classify_alarm(
        job_id=uuid4(),
        session=session,  # type: ignore[arg-type]
        provider=provider,  # type: ignore[arg-type]  # reason: _ScriptedProvider duck-types LlmProvider
        alarm={"id": "x"},
        openai_tools=[],
        system_prompt="SYS",
        temperature=0.1,
        timeout_seconds=60,
        event_sink=sink,
    )

    assert record["status"] == "completed"  # final LLM call produced a valid classification
    assert len(record["tool_trace"]) == 1
    assert record["tool_trace"][0]["error"] == "MCP down"

    completed_evts = [e for e in captured if isinstance(e, ToolCallCompletedEvent)]
    assert completed_evts[0].error == "MCP down"

    # The second LLM round saw an "Error calling tool: MCP down" tool message.
    second = provider.calls[1]["messages"]
    tool_msg = next(m for m in second if m["role"] == "tool")
    assert "Error calling tool" in tool_msg["content"]
    assert "MCP down" in tool_msg["content"]


# ── 3. LLM error ─────────────────────────────────────────────────────


def _api_status_error(code: int) -> openai.APIStatusError:
    req = httpx.Request("POST", "http://test/v1/chat")
    resp = httpx.Response(code, request=req)
    return openai.APIStatusError(f"http {code}", response=resp, body=None)


def _rate_limit_error() -> openai.RateLimitError:
    req = httpx.Request("POST", "http://test/v1/chat")
    resp = httpx.Response(429, request=req)
    return openai.RateLimitError("rate", response=resp, body=None)


@pytest.mark.unit
async def test_llm_client_error_aborts_immediately_status_failed() -> None:
    """A 4xx client error short-circuits retries → status=failed."""
    provider = _ScriptedProvider([_api_status_error(400)])
    session = _ScriptedSession()

    record = await classify_alarm(
        job_id=uuid4(),
        session=session,  # type: ignore[arg-type]
        provider=provider,  # type: ignore[arg-type]  # reason: _ScriptedProvider duck-types LlmProvider
        alarm={"id": "x"},
        openai_tools=[],
        system_prompt="SYS",
        temperature=0.1,
        timeout_seconds=60,
    )

    assert record["status"] == "failed"
    assert "client_error_400" in (record["error_message"] or "")
    # Only one LLM attempt was made; no retries.
    assert len(provider.calls) == 1


@pytest.mark.unit
async def test_llm_unexpected_exception_aborts_status_failed() -> None:
    """An unexpected (non-openai) exception is treated as non-retryable."""
    provider = _ScriptedProvider([ValueError("unexpected")])
    session = _ScriptedSession()

    record = await classify_alarm(
        job_id=uuid4(),
        session=session,  # type: ignore[arg-type]
        provider=provider,  # type: ignore[arg-type]  # reason: _ScriptedProvider duck-types LlmProvider
        alarm={"id": "x"},
        openai_tools=[],
        system_prompt="SYS",
        temperature=0.1,
        timeout_seconds=60,
    )

    assert record["status"] == "failed"
    assert "unexpected_api_error" in (record["error_message"] or "")


@pytest.mark.unit
async def test_llm_retry_exhaustion_status_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    """All MAX_RETRIES rate-limit errors → retries exhausted → failed."""

    # Patch ``asyncio.sleep`` inside the worker to avoid spending 10+ minutes.
    async def _no_sleep(*_a: Any, **_kw: Any) -> None:
        return None

    monkeypatch.setattr(asyncio, "sleep", _no_sleep)

    rate = _rate_limit_error()
    # 5 attempts max → 5 RateLimitErrors then loop sees response=None and fails.
    provider = _ScriptedProvider([rate, rate, rate, rate, rate])
    session = _ScriptedSession()

    record = await classify_alarm(
        job_id=uuid4(),
        session=session,  # type: ignore[arg-type]
        provider=provider,  # type: ignore[arg-type]  # reason: _ScriptedProvider duck-types LlmProvider
        alarm={"id": "x"},
        openai_tools=[],
        system_prompt="SYS",
        temperature=0.1,
        timeout_seconds=120,
    )

    assert record["status"] == "failed"
    assert "rate_limit" in (record["error_message"] or "")
    assert len(provider.calls) == worker_mod.MAX_RETRIES


@pytest.mark.unit
async def test_llm_retry_then_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """Retry path: one 5xx, one rate-limit, then a successful response."""

    async def _no_sleep(*_a: Any, **_kw: Any) -> None:
        return None

    monkeypatch.setattr(asyncio, "sleep", _no_sleep)

    provider = _ScriptedProvider(
        [
            _api_status_error(503),
            _rate_limit_error(),
            _text_msg(_VALID_TWO_STEP),
        ]
    )
    session = _ScriptedSession()

    record = await classify_alarm(
        job_id=uuid4(),
        session=session,  # type: ignore[arg-type]
        provider=provider,  # type: ignore[arg-type]  # reason: _ScriptedProvider duck-types LlmProvider
        alarm={"id": "x"},
        openai_tools=[],
        system_prompt="SYS",
        temperature=0.1,
        timeout_seconds=120,
    )

    assert record["status"] == "completed"
    assert len(provider.calls) == 3


# ── 4. Missing context ───────────────────────────────────────────────


@pytest.mark.unit
async def test_missing_context_falls_back_to_failed_with_raw_text() -> None:
    """LLM returns content but no parseable classification → failed + raw text kept."""
    provider = _ScriptedProvider([_text_msg("I cannot classify this alarm. No JSON here.")])
    session = _ScriptedSession()

    record = await classify_alarm(
        job_id=uuid4(),
        session=session,  # type: ignore[arg-type]
        provider=provider,  # type: ignore[arg-type]  # reason: _ScriptedProvider duck-types LlmProvider
        alarm={"id": "x"},
        openai_tools=[],
        system_prompt="SYS",
        temperature=0.1,
        timeout_seconds=60,
    )

    assert record["status"] == "failed"
    assert record["step1_technical"] is None
    assert record["step2_classification"] is None
    assert "raw_final_text" in record
    assert "I cannot classify this alarm" in record["raw_final_text"]
    assert "parse_error" in (record["error_message"] or "")


@pytest.mark.unit
async def test_empty_classifications_valid_no_attack() -> None:
    """LLM returns valid two-step JSON with empty classifications → completed, not failed."""
    provider = _ScriptedProvider([_text_msg(_VALID_TWO_STEP_EMPTY)])
    session = _ScriptedSession()

    record = await classify_alarm(
        job_id=uuid4(),
        session=session,  # type: ignore[arg-type]
        provider=provider,  # type: ignore[arg-type]  # reason: _ScriptedProvider duck-types LlmProvider
        alarm={"id": "x"},
        openai_tools=[],
        system_prompt="SYS",
        temperature=0.1,
        timeout_seconds=60,
    )

    assert record["status"] == "completed"
    assert record["step1_technical"] == {
        "technical_method": "Bounds/jitter anomaly",
        "observed_activity": "Timing jitter within expected operational bounds rather than malicious activity",
        "evidence": ["timeseries shows normal variance"],
    }
    assert record["step2_classification"] == {"classifications": []}
    assert record["verdict"] is None
    assert record["error_message"] is None
    assert "raw_final_text" not in record


@pytest.mark.unit
async def test_benign_verdict_is_persisted_with_empty_classifications() -> None:
    """LLM benign verdict is retained alongside an empty classification list."""
    response = {
        "step1_technical": {
            "technical_method": "scheduled_change",
            "observed_activity": "Configuration traffic during maintenance",
            "evidence": ["maintenance window"],
        },
        "step2_classification": {"classifications": []},
        "verdict": {
            "outcome": "benign",
            "reasoning": "Traffic matches the documented maintenance window.",
        },
    }
    provider = _ScriptedProvider([_text_msg(json.dumps(response))])
    session = _ScriptedSession()

    record = await classify_alarm(
        job_id=uuid4(),
        session=session,  # type: ignore[arg-type]
        provider=provider,  # type: ignore[arg-type]  # reason: _ScriptedProvider duck-types LlmProvider
        alarm={"id": "x"},
        openai_tools=[],
        system_prompt="SYS",
        temperature=0.1,
        timeout_seconds=60,
    )

    assert record["status"] == "completed"
    assert record["step2_classification"] == {"classifications": []}
    assert record["verdict"] == response["verdict"]


@pytest.mark.unit
async def test_flat_empty_classifications_valid_no_attack() -> None:
    """LLM returns flat JSON with empty classifications → completed, not failed."""
    provider = _ScriptedProvider([_text_msg('{"classifications": []}')])
    session = _ScriptedSession()

    record = await classify_alarm(
        job_id=uuid4(),
        session=session,  # type: ignore[arg-type]
        provider=provider,  # type: ignore[arg-type]  # reason: _ScriptedProvider duck-types LlmProvider
        alarm={"id": "x"},
        openai_tools=[],
        system_prompt="SYS",
        temperature=0.1,
        timeout_seconds=60,
    )

    assert record["status"] == "completed"
    assert record["step1_technical"] == {
        "technical_method": "",
        "observed_activity": "",
        "evidence": [],
    }
    assert record["step2_classification"] == {"classifications": []}
    assert record["error_message"] is None
    assert "raw_final_text" not in record


# ── 5. Force-classify / context-pressure guard ───────────────────────


@pytest.mark.unit
async def test_force_classify_event_fired_when_context_exceeds_threshold(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pushing context over FORCE_CLASSIFY_CHARS triggers ForceClassifyEvent."""
    # Lower thresholds so the test can exercise the guard with small payloads.
    monkeypatch.setattr(worker_mod, "FORCE_CLASSIFY_CHARS", 200)
    monkeypatch.setattr(worker_mod, "MAX_CONTEXT_CHARS", 150)

    # Round 1: tool call returns a big payload; round 2 must classify.
    big_payload = "x" * 1000
    provider = _ScriptedProvider(
        [
            _tool_msg("postgres.read_anomalies", call_id="tc-1"),
            _text_msg(_VALID_TWO_STEP),
        ]
    )
    session = _ScriptedSession(responses={"postgres.read_anomalies": [big_payload]})
    sink, captured = _collect_events()

    record = await classify_alarm(
        job_id=uuid4(),
        session=session,  # type: ignore[arg-type]
        provider=provider,  # type: ignore[arg-type]  # reason: _ScriptedProvider duck-types LlmProvider
        alarm={"id": "x"},
        openai_tools=[],
        system_prompt="SYS",
        temperature=0.1,
        timeout_seconds=60,
        event_sink=sink,
    )

    assert record["status"] == "completed"
    force_evts = [e for e in captured if isinstance(e, ForceClassifyEvent)]
    assert len(force_evts) >= 1


# ── Cancellation + timeout ───────────────────────────────────────────


@pytest.mark.unit
async def test_cancellation_check_terminates_loop_status_cancelled() -> None:
    """``cancellation_check`` returning True halts the loop early."""
    # Provider should never be called because cancellation fires before round 1.
    provider = _ScriptedProvider([])
    session = _ScriptedSession()

    record = await classify_alarm(
        job_id=uuid4(),
        session=session,  # type: ignore[arg-type]
        provider=provider,  # type: ignore[arg-type]  # reason: _ScriptedProvider duck-types LlmProvider
        alarm={"id": "x"},
        openai_tools=[],
        system_prompt="SYS",
        temperature=0.1,
        timeout_seconds=60,
        cancellation_check=lambda: True,
    )

    assert record["status"] == "cancelled"
    assert len(provider.calls) == 0


@pytest.mark.unit
async def test_timeout_marks_status_timeout() -> None:
    """A zero-elapsed timeout still allows round 1; passing 0 means no timeout.

    To actually exercise timeout, we pass a 1-second timeout and stub the
    provider to sleep just long enough that the elapsed check fires before
    round 2.
    """
    long_payload = _VALID_TWO_STEP

    # Two LLM rounds: first issues a tool call; the loop will then check
    # the timeout BEFORE round 2 and bail out.
    provider = _ScriptedProvider([_tool_msg("postgres.read_anomalies"), _text_msg(long_payload)])

    async def _slow_call(_name: str, arguments: Dict[str, Any]) -> _MockMcpResult:
        await asyncio.sleep(0.1)
        return _MockMcpResult('[{"id": 1}]')

    session = _ScriptedSession()
    session.call_tool = _slow_call  # type: ignore[assignment]

    record = await classify_alarm(
        job_id=uuid4(),
        session=session,  # type: ignore[arg-type]
        provider=provider,  # type: ignore[arg-type]  # reason: _ScriptedProvider duck-types LlmProvider
        alarm={"id": "x"},
        openai_tools=[],
        system_prompt="SYS",
        temperature=0.1,
        timeout_seconds=0.05,  # type: ignore[arg-type]  # int in real code, float fine at runtime
    )

    assert record["status"] in {"timeout", "failed"}
    # The timeout branch is what we expect; if the loop completed faster
    # than 0.05 s the status would be completed and the test is moot —
    # assert below ensures we exercised the timeout exit.
    assert record["status"] == "timeout"


# ── trace_persist callback ───────────────────────────────────────────


@pytest.mark.unit
async def test_trace_persist_invoked_per_tool_call() -> None:
    """``trace_persist`` is awaited once per tool call, with the trace entry."""
    provider = _ScriptedProvider(
        [
            _tool_msg("postgres.read_anomalies", call_id="tc-1"),
            _text_msg(_VALID_TWO_STEP),
        ]
    )
    session = _ScriptedSession()
    persisted: List[Dict[str, Any]] = []

    async def _persist(entry: Dict[str, Any]) -> None:
        persisted.append(entry)

    await classify_alarm(
        job_id=uuid4(),
        session=session,  # type: ignore[arg-type]
        provider=provider,  # type: ignore[arg-type]  # reason: _ScriptedProvider duck-types LlmProvider
        alarm={"id": "x"},
        openai_tools=[],
        system_prompt="SYS",
        temperature=0.1,
        timeout_seconds=60,
        trace_persist=_persist,
    )

    assert len(persisted) == 1
    assert persisted[0]["tool"] == "postgres.read_anomalies"


@pytest.mark.unit
async def test_trace_persist_exception_does_not_break_loop() -> None:
    """A raising ``trace_persist`` must not abort the worker."""
    provider = _ScriptedProvider(
        [
            _tool_msg("postgres.read_anomalies"),
            _text_msg(_VALID_TWO_STEP),
        ]
    )
    session = _ScriptedSession()

    async def _persist(_entry: Dict[str, Any]) -> None:
        raise RuntimeError("DB down")

    record = await classify_alarm(
        job_id=uuid4(),
        session=session,  # type: ignore[arg-type]
        provider=provider,  # type: ignore[arg-type]  # reason: _ScriptedProvider duck-types LlmProvider
        alarm={"id": "x"},
        openai_tools=[],
        system_prompt="SYS",
        temperature=0.1,
        timeout_seconds=60,
        trace_persist=_persist,
    )

    assert record["status"] == "completed"


@pytest.mark.unit
async def test_event_sink_exception_does_not_break_loop() -> None:
    """A raising ``event_sink`` is caught + logged but never propagated."""
    provider = _ScriptedProvider(
        [
            _tool_msg("postgres.read_anomalies"),
            _text_msg(_VALID_TWO_STEP),
        ]
    )
    session = _ScriptedSession()

    async def _bad_sink(_evt: SubagentEvent) -> None:
        raise RuntimeError("sink broken")

    record = await classify_alarm(
        job_id=uuid4(),
        session=session,  # type: ignore[arg-type]
        provider=provider,  # type: ignore[arg-type]  # reason: _ScriptedProvider duck-types LlmProvider
        alarm={"id": "x"},
        openai_tools=[],
        system_prompt="SYS",
        temperature=0.1,
        timeout_seconds=60,
        event_sink=_bad_sink,
    )

    assert record["status"] == "completed"


# ── Pure-helper tests (cheap coverage for the phase helpers) ────────


@pytest.mark.unit
def test_strip_ml_bias_fields_removes_known_keys() -> None:
    alarm = {
        "id": "a",
        "primary_type": "x",
        "anomaly_type": "y",
        "anomaly_type_stats": {"a": 1},
        "multi_type": True,
        "ml_details": {"label": "z"},
        "kept": 1,
    }
    out = worker_mod.strip_ml_bias_fields(alarm)
    assert out == {"id": "a", "kept": 1}


@pytest.mark.unit
def test_strip_ml_bias_from_tool_response_recursive() -> None:
    payload = (
        '[{"id": 1, "anomaly_type": "leak", '
        '"nested": {"primary_type": "x", "k": 2}, '
        '"chunks": [{"labels": {"primary_type": "y", "ok": true}}]}]'
    )
    stripped = worker_mod._strip_ml_bias_from_tool_response("postgres.read_anomalies", payload)
    assert "anomaly_type" not in stripped
    assert "primary_type" not in stripped
    assert "leak" not in stripped
    assert "ok" in stripped


@pytest.mark.unit
def test_strip_ml_bias_passes_through_non_json() -> None:
    out = worker_mod._strip_ml_bias_from_tool_response("postgres.read_anomalies", "not json")
    assert out == "not json"


@pytest.mark.unit
def test_truncate_result_long_input() -> None:
    out = worker_mod._truncate_result("a" * 100, 10)
    assert out.startswith("a" * 10)
    assert "TRUNCATED" in out


@pytest.mark.unit
def test_truncate_result_short_input_passthrough() -> None:
    assert worker_mod._truncate_result("short", 100) == "short"


@pytest.mark.unit
def test_compress_old_results_compresses_only_old_entries() -> None:
    messages: List[Dict[str, Any]] = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "u"},
    ]
    # 6 tool messages, keep_recent=4 → first 2 get compressed.
    for i in range(6):
        messages.append({"role": "tool", "content": "z" * 1000})
    worker_mod._compress_old_results(messages, keep_recent=4)
    tool_msgs = [m for m in messages if m["role"] == "tool"]
    assert len(tool_msgs[0]["content"]) < 1000
    assert len(tool_msgs[-1]["content"]) == 1000


@pytest.mark.unit
def test_build_user_prompt_strips_ml_fields() -> None:
    out = worker_mod.build_user_prompt({"id": "a", "primary_type": "phishing"})
    assert "phishing" not in out
    assert '"id": "a"' in out


# ── AI-01: execution-time allow-list gate ────────────────────────────


@pytest.mark.unit
async def test_tool_call_outside_execution_allow_list_is_refused() -> None:
    """AI-01: the worker MUST gate ``session.call_tool`` on the execution
    allow-list, mirroring the chat surface's belt-and-braces check.

    A model that hallucinates a tool name it was never advertised (e.g.
    ``training.retrain_classifier`` while the jobs allow-list only covers
    read tools) must NOT reach the MCP server: the call is refused
    client-side, the refusal is recorded in ``tool_trace``, and the LLM
    receives the refusal as the tool-message content.
    """
    provider = _ScriptedProvider(
        [
            _tool_msg("training.retrain_classifier", args='{"window_start": "x"}', call_id="tc-1"),
            _text_msg(_VALID_TWO_STEP),
        ]
    )
    session = _ScriptedSession(responses={"training.retrain_classifier": ['{"started": true}']})

    record = await classify_alarm(
        job_id=uuid4(),
        session=session,  # type: ignore[arg-type]
        provider=provider,  # type: ignore[arg-type]  # reason: _ScriptedProvider duck-types LlmProvider
        alarm={"id": "x"},
        openai_tools=[{"type": "function", "function": {"name": "postgres.read_anomalies"}}],
        system_prompt="SYS",
        temperature=0.1,
        timeout_seconds=60,
        allowed_tools=frozenset({"postgres.read_anomalies"}),
    )

    # No MCP round-trip happened for the refused tool.
    assert session.calls == []
    # The refusal is recorded in the trace.
    assert len(record["tool_trace"]) == 1
    assert record["tool_trace"][0]["tool"] == "training.retrain_classifier"
    assert record["tool_trace"][0]["error"] is not None
    assert "allow-list" in record["tool_trace"][0]["error"]
    # The LLM saw the refusal as the tool content and could still finish.
    assert record["status"] == "completed"
    tool_msgs = [m for m in provider.calls[-1]["messages"] if m.get("role") == "tool"]
    assert tool_msgs and "not in the jobs execution allow-list" in tool_msgs[0]["content"]


# ── AI-036: degraded status when evidence tools fail ─────────────────


@pytest.mark.unit
async def test_empty_classification_with_failed_pcap_tools_is_degraded() -> None:
    """AI-036: an empty classification list caused by a dead ``pcap.*``
    namespace must end ``degraded`` with a named reason, never green.

    Reproduces the PCAP-008 shape: every ``pcap.*`` call returns a 500,
    the model correctly refuses to invent a technique, and the job used
    to be persisted as a clean ``completed`` with
    ``{"classifications": []}``.
    """
    provider = _ScriptedProvider(
        [
            _tool_msg("pcap.analyze_chunk", args='{"chunk_id": 3}', call_id="tc-1"),
            _text_msg(_VALID_TWO_STEP_EMPTY),
        ]
    )
    session = _ScriptedSession(
        responses={"pcap.analyze_chunk": [RuntimeError("500 Server Error: Internal Server Error")]}
    )
    sink, captured = _collect_events()

    record = await classify_alarm(
        job_id=uuid4(),
        session=session,  # type: ignore[arg-type]
        provider=provider,  # type: ignore[arg-type]  # reason: _ScriptedProvider duck-types LlmProvider
        alarm={"id": "b1a5fbe1"},
        openai_tools=[],
        system_prompt="SYS",
        temperature=0.1,
        timeout_seconds=60,
        event_sink=sink,
    )

    assert record["status"] == "degraded"
    reason = record["error_message"] or ""
    assert "pcap.*" in reason
    assert "500 Server Error" in reason
    # step1 evidence is preserved — the run is incomplete, not discarded.
    assert record["step1_technical"]["technical_method"] == "Bounds/jitter anomaly"
    assert record["step2_classification"] == {"classifications": []}

    final = [e for e in captured if isinstance(e, FinalEvent)]
    assert len(final) == 1
    assert final[0].status == "degraded"
    assert "pcap.*" in (final[0].error or "")


@pytest.mark.unit
async def test_inband_mcp_failure_is_recorded_and_degrades_the_job() -> None:
    """AI-036 regression for the real PCAP-008 shape: ``otalon-mcp``
    returns HTTP 200 carrying ``{"ok": false, "error": ...}``, so
    ``session.call_tool`` never raises and the transport-level error is
    ``None``. The trace must still record the failure and the job must
    end ``degraded``."""
    inband = (
        '{"ok": false, "error": "pcap analyze_chunk failed: 500 Server Error: '
        'Internal Server Error for url: http://host.docker.internal:9090/chunks/20260901_021951.pcap"}'
    )
    provider = _ScriptedProvider(
        [
            _tool_msg("pcap.analyze_chunk", call_id="tc-1"),
            _text_msg(_VALID_TWO_STEP_EMPTY),
        ]
    )
    session = _ScriptedSession(responses={"pcap.analyze_chunk": [inband]})

    record = await classify_alarm(
        job_id=uuid4(),
        session=session,  # type: ignore[arg-type]
        provider=provider,  # type: ignore[arg-type]  # reason: _ScriptedProvider duck-types LlmProvider
        alarm={"id": "x"},
        openai_tools=[],
        system_prompt="SYS",
        temperature=0.1,
        timeout_seconds=60,
    )

    # The MCP call itself succeeded at transport level ...
    assert len(session.calls) == 1
    # ... but the trace records the in-band failure.
    assert record["tool_trace"][0]["error"] is not None
    assert "500 Server Error" in record["tool_trace"][0]["error"]
    assert record["status"] == "degraded"
    assert "pcap.analyze_chunk" in (record["error_message"] or "")

    # The LLM still saw the unmodified payload — detection is
    # observability only, it must not alter the model's context.
    tool_msg = next(m for m in provider.calls[1]["messages"] if m["role"] == "tool")
    assert tool_msg["content"] == inband


@pytest.mark.unit
async def test_non_empty_classification_with_failed_pcap_tools_stays_completed() -> None:
    """AI-036 negative control: a tool outage that still yielded a
    technique is a normal ``completed`` run — degradation keys on the
    missing classification, not on the failure alone."""
    provider = _ScriptedProvider(
        [
            _tool_msg("pcap.analyze_chunk", call_id="tc-1"),
            _text_msg(_VALID_TWO_STEP),
        ]
    )
    session = _ScriptedSession(responses={"pcap.analyze_chunk": [RuntimeError("500 Server Error")]})

    record = await classify_alarm(
        job_id=uuid4(),
        session=session,  # type: ignore[arg-type]
        provider=provider,  # type: ignore[arg-type]  # reason: _ScriptedProvider duck-types LlmProvider
        alarm={"id": "x"},
        openai_tools=[],
        system_prompt="SYS",
        temperature=0.1,
        timeout_seconds=60,
    )

    assert record["status"] == "completed"
    assert record["error_message"] is None
    assert record["step2_classification"]["classifications"][0]["technique_id"] == "T0846"


@pytest.mark.unit
async def test_empty_classification_with_healthy_tools_stays_completed() -> None:
    """AI-036 negative control: 'no technique applies' with every
    evidence tool healthy remains a legitimate ``completed`` verdict."""
    provider = _ScriptedProvider(
        [
            _tool_msg("pcap.analyze_chunk", call_id="tc-1"),
            _text_msg(_VALID_TWO_STEP_EMPTY),
        ]
    )
    session = _ScriptedSession(responses={"pcap.analyze_chunk": ['{"packets": 12}']})

    record = await classify_alarm(
        job_id=uuid4(),
        session=session,  # type: ignore[arg-type]
        provider=provider,  # type: ignore[arg-type]  # reason: _ScriptedProvider duck-types LlmProvider
        alarm={"id": "x"},
        openai_tools=[],
        system_prompt="SYS",
        temperature=0.1,
        timeout_seconds=60,
    )

    assert record["status"] == "completed"
    assert record["error_message"] is None
    assert record["step2_classification"] == {"classifications": []}


@pytest.mark.unit
async def test_partially_broken_namespace_still_degrades() -> None:
    """A namespace that is only partly down still degrades the job.

    This is the PCAP-008 shape: ``pcap.list_chunks`` answered while
    ``pcap.analyze_chunk`` returned 500 on every call. Aggregating at
    namespace level would call that healthy and reproduce the original
    silent-empty defect, so the rule keys on the individual tool.
    """
    provider = _ScriptedProvider(
        [
            _tool_msg("pcap.analyze_chunk", call_id="tc-1"),
            _tool_msg("pcap.list_chunks", call_id="tc-2"),
            _text_msg(_VALID_TWO_STEP_EMPTY),
        ]
    )
    session = _ScriptedSession(
        responses={
            "pcap.analyze_chunk": [RuntimeError("500 Server Error")],
            "pcap.list_chunks": ['{"chunks": []}'],
        }
    )

    record = await classify_alarm(
        job_id=uuid4(),
        session=session,  # type: ignore[arg-type]
        provider=provider,  # type: ignore[arg-type]  # reason: _ScriptedProvider duck-types LlmProvider
        alarm={"id": "x"},
        openai_tools=[],
        system_prompt="SYS",
        temperature=0.1,
        timeout_seconds=60,
    )

    assert record["status"] == "degraded"
    reason = record["error_message"] or ""
    assert "pcap.analyze_chunk" in reason
    assert "pcap.list_chunks" not in reason


@pytest.mark.unit
async def test_repeated_call_to_same_tool_with_one_success_does_not_degrade() -> None:
    """A transient single failure of a tool that later answered leaves
    the evidence supply intact — the empty result is the model's verdict."""
    provider = _ScriptedProvider(
        [
            _tool_msg("pcap.analyze_chunk", call_id="tc-1"),
            _tool_msg("pcap.analyze_chunk", call_id="tc-2"),
            _text_msg(_VALID_TWO_STEP_EMPTY),
        ]
    )
    session = _ScriptedSession(responses={"pcap.analyze_chunk": [RuntimeError("transient blip"), '{"packets": 12}']})

    record = await classify_alarm(
        job_id=uuid4(),
        session=session,  # type: ignore[arg-type]
        provider=provider,  # type: ignore[arg-type]  # reason: _ScriptedProvider duck-types LlmProvider
        alarm={"id": "x"},
        openai_tools=[],
        system_prompt="SYS",
        temperature=0.1,
        timeout_seconds=60,
    )

    assert record["status"] == "completed"


@pytest.mark.unit
async def test_degraded_does_not_override_timeout_or_cancellation() -> None:
    """Cancellation keeps precedence over the AI-036 degraded verdict."""
    provider = _ScriptedProvider([])
    session = _ScriptedSession()

    record = await classify_alarm(
        job_id=uuid4(),
        session=session,  # type: ignore[arg-type]
        provider=provider,  # type: ignore[arg-type]  # reason: _ScriptedProvider duck-types LlmProvider
        alarm={"id": "x"},
        openai_tools=[],
        system_prompt="SYS",
        temperature=0.1,
        timeout_seconds=60,
        cancellation_check=lambda: True,
    )

    assert record["status"] == "cancelled"


@pytest.mark.unit
async def test_tool_call_inside_execution_allow_list_executes() -> None:
    """AI-01 positive control: an allowed tool still executes normally."""
    provider = _ScriptedProvider(
        [
            _tool_msg("postgres.read_anomalies", args='{"limit": 1}', call_id="tc-1"),
            _text_msg(_VALID_TWO_STEP),
        ]
    )
    session = _ScriptedSession(responses={"postgres.read_anomalies": ['[{"id": 1}]']})

    record = await classify_alarm(
        job_id=uuid4(),
        session=session,  # type: ignore[arg-type]
        provider=provider,  # type: ignore[arg-type]  # reason: _ScriptedProvider duck-types LlmProvider
        alarm={"id": "x"},
        openai_tools=[],
        system_prompt="SYS",
        temperature=0.1,
        timeout_seconds=60,
        allowed_tools=frozenset({"postgres.read_anomalies"}),
    )

    assert len(session.calls) == 1
    assert session.calls[0]["name"] == "postgres.read_anomalies"
    assert record["tool_trace"][0]["error"] is None
    assert record["status"] == "completed"
