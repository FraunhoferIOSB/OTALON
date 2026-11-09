"""Unit tests for the forensic prompt variant (AI-017).

The forensic variant injects the monitored device inventory and the
triggering anomalies into the user prompt at runtime via orchestrator-
issued MCP tool calls. This bypasses the ``allowed_tools`` execution
gate because the calls are orchestrator-injected, not LLM-requested —
the agent itself never sees ``list_devices`` in its tool list.

Coverage areas:

1. **ML-bias sanitisation** — every injected block (alarm JSON, device
   table, anomalies JSON) must be free of the supervised-ML prediction
   fields (``primary_type``, ``anomaly_type_stats``, ``multi_type``,
   ``anomaly_type``, ``ml_details``).
2. **Device-injection block** — markdown table with the 5 expected
   columns; graceful degradation when the MCP call fails.
3. **Anomalies block** — filtered by ``series_ids``, deduplicated by
   ``id``, scoped to the alarm's module and time window.
4. **Prompt assembly** — the forensic user prompt contains all three
   blocks plus the "do not re-fetch" instruction.
5. **Regression** — ``expert`` / ``open`` variants stay byte-identical
   to :func:`_initial_messages` / :func:`build_user_prompt` so the
   paper-reproducible contract is preserved.
6. **``classify_alarm`` end-to-end** — the forensic variant injects
   context before the first LLM round.
"""

from __future__ import annotations

import json
from datetime import datetime
from types import SimpleNamespace
from typing import Any, Dict, List, Optional
from uuid import uuid4

import pytest

from otalon_ai.jobs import worker as worker_mod
from otalon_ai.jobs.worker import (
    _assemble_initial_messages,
    _build_forensic_user_prompt,
    _call_mcp_tool_json,
    _fetch_anomalies_block,
    _fetch_devices_block,
    _initial_messages,
    _to_iso,
)
from otalon_ai.prompts.loader import PromptLoader

# ── Mock MCP session (shared shape with test_classify_alarm) ─────────


class _MockMcpResult:
    def __init__(self, text: str) -> None:
        self.content = [SimpleNamespace(text=text)]


class _ScriptedSession:
    """Scripted MCP session for ``session.call_tool``.

    ``responses`` maps a tool name to a list of text payloads or
    exceptions; each call pops one entry.
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


# ── 1. _to_iso ───────────────────────────────────────────────────────


@pytest.mark.unit
def test_to_iso_converts_datetime() -> None:
    """A ``datetime`` argument is converted to an ISO 8601 string."""
    dt = datetime(2026, 9, 1, 12, 0, 0)
    assert _to_iso(dt) == "2026-09-01T12:00:00"


@pytest.mark.unit
def test_to_iso_passes_through_strings() -> None:
    """Non-datetime values are stringified."""
    assert _to_iso("2026-09-01T00:00:00") == "2026-09-01T00:00:00"
    assert _to_iso(42) == "42"


# ── 2. _call_mcp_tool_json ────────────────────────────────────────────


@pytest.mark.unit
async def test_call_mcp_tool_json_returns_parsed_dict() -> None:
    """A valid JSON dict response is returned as a Python dict."""
    session = _ScriptedSession(responses={"postgres.read_anomalies": ['{"ok": true, "records": []}']})
    result = await _call_mcp_tool_json(
        session,  # type: ignore[arg-type]
        "postgres.read_anomalies",
        {"module": "netcap"},
    )
    assert result == {"ok": True, "records": []}


@pytest.mark.unit
async def test_call_mcp_tool_json_strips_ml_bias_fields() -> None:
    """``read_anomalies`` responses have ML-bias fields removed before parsing."""
    payload = '{"ok": true, "records": [{"id": 1, "anomaly_type": "leak", "value": 7}]}'
    session = _ScriptedSession(responses={"postgres.read_anomalies": [payload]})
    result = await _call_mcp_tool_json(
        session,  # type: ignore[arg-type]
        "postgres.read_anomalies",
        {"module": "netcap"},
    )
    assert result is not None
    record = result["records"][0]
    assert "anomaly_type" not in record
    assert "leak" not in str(record)
    assert record["id"] == 1
    assert record["value"] == 7


@pytest.mark.unit
async def test_call_mcp_tool_json_returns_none_on_exception() -> None:
    """When the MCP call raises, ``None`` is returned (graceful degradation)."""
    session = _ScriptedSession(responses={"postgres.list_devices": [RuntimeError("MCP down")]})
    result = await _call_mcp_tool_json(
        session,  # type: ignore[arg-type]
        "postgres.list_devices",
        {"limit": 200},
    )
    assert result is None


@pytest.mark.unit
async def test_call_mcp_tool_json_returns_none_on_non_dict() -> None:
    """A JSON list (not a dict) returns ``None`` — we expect a dict wrapper."""
    session = _ScriptedSession(responses={"postgres.list_devices": ['[{"id": 1}]']})
    result = await _call_mcp_tool_json(
        session,  # type: ignore[arg-type]
        "postgres.list_devices",
        {"limit": 200},
    )
    assert result is None


# ── 3. _fetch_devices_block ─────────────────────────────────────────


@pytest.mark.unit
async def test_fetch_devices_block_formats_markdown_table() -> None:
    """Devices are rendered as a 5-column markdown table."""
    devices_json = json.dumps(
        {
            "ok": True,
            "records": [
                {
                    "id": 1,
                    "vendor": "Siemens",
                    "device_type": "PLC",
                    "device_role": "controller",
                    "primary_mac": "aa:bb:cc:dd:ee:01",
                },
                {
                    "id": 2,
                    "vendor": "Schneider",
                    "device_type": "RTU",
                    "device_role": "field_device",
                    "primary_mac": "aa:bb:cc:dd:ee:02",
                },
            ],
        }
    )
    session = _ScriptedSession(responses={"postgres.list_devices": [devices_json]})
    block = await _fetch_devices_block(session)  # type: ignore[arg-type]

    assert block.startswith("## Monitored Devices")
    # Header row with 5 columns.
    assert "| id | vendor | device_type | device_role | primary_mac |" in block
    # Both devices present.
    assert "Siemens" in block
    assert "Schneider" in block
    assert "aa:bb:cc:dd:ee:01" in block
    assert "aa:bb:cc:dd:ee:02" in block


@pytest.mark.unit
async def test_fetch_devices_block_graceful_on_failure() -> None:
    """When ``list_devices`` fails, the block notes unavailability."""
    session = _ScriptedSession(responses={"postgres.list_devices": [RuntimeError("MCP down")]})
    block = await _fetch_devices_block(session)  # type: ignore[arg-type]
    assert "## Monitored Devices" in block
    assert "unavailable" in block


@pytest.mark.unit
async def test_fetch_devices_block_empty_inventory() -> None:
    """An empty device list yields a 'no devices' note."""
    session = _ScriptedSession(responses={"postgres.list_devices": ['{"ok": true, "records": []}']})
    block = await _fetch_devices_block(session)  # type: ignore[arg-type]
    assert "No devices" in block


# ── 4. _fetch_anomalies_block ───────────────────────────────────────


@pytest.mark.unit
async def test_fetch_anomalies_block_filters_by_series_ids() -> None:
    """Only anomalies whose ``series_id`` is in the alarm's ``series_ids`` survive."""
    anomalies_json = json.dumps(
        {
            "ok": True,
            "records": [
                {"id": 1, "series_id": "s1", "value": 10},
                {"id": 2, "series_id": "s2", "value": 20},
                {"id": 3, "series_id": "s1", "value": 30},
            ],
        }
    )
    session = _ScriptedSession(responses={"postgres.read_anomalies": [anomalies_json]})
    alarm = {
        "module": "netcap",
        "start_timestamp": "2026-09-01T00:00:00",
        "end_timestamp": "2026-09-01T01:00:00",
        "series_ids": json.dumps(["s1"]),
    }
    block = await _fetch_anomalies_block(session, alarm)  # type: ignore[arg-type]

    assert "s1" in block
    assert "s2" not in block
    # Two records for s1 remain.
    parsed = json.loads(block.split("```json\n")[1].split("```")[0])
    assert len(parsed) == 2
    assert all(r["series_id"] == "s1" for r in parsed)


@pytest.mark.unit
async def test_fetch_anomalies_block_keeps_all_when_series_ids_empty() -> None:
    """An empty ``series_ids`` set keeps all records (no filtering)."""
    anomalies_json = json.dumps(
        {
            "ok": True,
            "records": [
                {"id": 1, "series_id": "s1"},
                {"id": 2, "series_id": "s2"},
            ],
        }
    )
    session = _ScriptedSession(responses={"postgres.read_anomalies": [anomalies_json]})
    alarm = {
        "module": "netcap",
        "start_timestamp": "2026-09-01T00:00:00",
        "end_timestamp": "2026-09-01T01:00:00",
        "series_ids": [],
    }
    block = await _fetch_anomalies_block(session, alarm)  # type: ignore[arg-type]
    parsed = json.loads(block.split("```json\n")[1].split("```")[0])
    assert len(parsed) == 2


@pytest.mark.unit
async def test_fetch_anomalies_block_deduplicates_by_id() -> None:
    """Duplicate anomaly IDs are removed."""
    anomalies_json = json.dumps(
        {
            "ok": True,
            "records": [
                {"id": 1, "series_id": "s1", "value": 10},
                {"id": 1, "series_id": "s1", "value": 10},
                {"id": 2, "series_id": "s1", "value": 20},
            ],
        }
    )
    session = _ScriptedSession(responses={"postgres.read_anomalies": [anomalies_json]})
    alarm = {
        "module": "netcap",
        "start_timestamp": "2026-09-01T00:00:00",
        "end_timestamp": "2026-09-01T01:00:00",
        "series_ids": ["s1"],
    }
    block = await _fetch_anomalies_block(session, alarm)  # type: ignore[arg-type]
    parsed = json.loads(block.split("```json\n")[1].split("```")[0])
    assert len(parsed) == 2
    ids = [r["id"] for r in parsed]
    assert ids == [1, 2]


@pytest.mark.unit
async def test_fetch_anomalies_block_strips_ml_bias_fields() -> None:
    """``anomaly_type`` and ``ml_details`` are stripped from anomalies."""
    anomalies_json = json.dumps(
        {
            "ok": True,
            "records": [
                {
                    "id": 1,
                    "series_id": "s1",
                    "anomaly_type": "leak",
                    "ml_details": {"label": "attack"},
                    "value": 10,
                },
            ],
        }
    )
    session = _ScriptedSession(responses={"postgres.read_anomalies": [anomalies_json]})
    alarm = {
        "module": "netcap",
        "start_timestamp": "2026-09-01T00:00:00",
        "end_timestamp": "2026-09-01T01:00:00",
        "series_ids": ["s1"],
    }
    block = await _fetch_anomalies_block(session, alarm)  # type: ignore[arg-type]
    assert "anomaly_type" not in block
    assert "ml_details" not in block
    assert "leak" not in block
    assert "value" in block


@pytest.mark.unit
async def test_fetch_anomalies_block_uses_alarm_module_and_time_window() -> None:
    """The ``read_anomalies`` call is scoped to the alarm's module and time."""
    anomalies_json = '{"ok": true, "records": []}'
    session = _ScriptedSession(responses={"postgres.read_anomalies": [anomalies_json]})
    alarm = {
        "module": "conn",
        "start_timestamp": datetime(2026, 9, 1, 10, 0, 0),
        "end_timestamp": datetime(2026, 9, 1, 11, 0, 0),
        "series_ids": [],
    }
    await _fetch_anomalies_block(session, alarm)  # type: ignore[arg-type]
    call = session.calls[0]
    assert call["name"] == "postgres.read_anomalies"
    assert call["args"]["module"] == "conn"
    assert call["args"]["start"] == "2026-09-01T10:00:00"
    assert call["args"]["stop"] == "2026-09-01T11:00:00"
    assert call["args"]["limit"] == 500


@pytest.mark.unit
async def test_fetch_anomalies_block_graceful_on_failure() -> None:
    """When ``read_anomalies`` fails, the block notes unavailability."""
    session = _ScriptedSession(responses={"postgres.read_anomalies": [RuntimeError("MCP down")]})
    alarm = {
        "module": "netcap",
        "start_timestamp": "2026-09-01T00:00:00",
        "end_timestamp": "2026-09-01T01:00:00",
        "series_ids": [],
    }
    block = await _fetch_anomalies_block(session, alarm)  # type: ignore[arg-type]
    assert "## Triggering Anomalies" in block
    assert "unavailable" in block


@pytest.mark.unit
async def test_fetch_anomalies_block_parses_series_ids_json_string() -> None:
    """``series_ids`` may arrive as a JSON string from PostgreSQL."""
    anomalies_json = json.dumps(
        {
            "ok": True,
            "records": [
                {"id": 1, "series_id": "s1", "value": 10},
                {"id": 2, "series_id": "s2", "value": 20},
            ],
        }
    )
    session = _ScriptedSession(responses={"postgres.read_anomalies": [anomalies_json]})
    alarm = {
        "module": "netcap",
        "start_timestamp": "2026-09-01T00:00:00",
        "end_timestamp": "2026-09-01T01:00:00",
        "series_ids": json.dumps(["s2"]),
    }
    block = await _fetch_anomalies_block(session, alarm)  # type: ignore[arg-type]
    parsed = json.loads(block.split("```json\n")[1].split("```")[0])
    assert len(parsed) == 1
    assert parsed[0]["series_id"] == "s2"


# ── 5. _build_forensic_user_prompt ──────────────────────────────────


@pytest.mark.unit
async def test_build_forensic_user_prompt_contains_all_blocks() -> None:
    """The prompt contains the alarm block, devices block, anomalies block, and instruction."""
    devices_json = json.dumps(
        {
            "ok": True,
            "records": [
                {
                    "id": 1,
                    "vendor": "Siemens",
                    "device_type": "PLC",
                    "device_role": "controller",
                    "primary_mac": "aa:bb:cc:dd:ee:01",
                },
            ],
        }
    )
    anomalies_json = json.dumps({"ok": True, "records": [{"id": 1, "series_id": "s1", "value": 10}]})
    session = _ScriptedSession(
        responses={
            "postgres.list_devices": [devices_json],
            "postgres.read_anomalies": [anomalies_json],
        }
    )
    alarm = {
        "id": "alarm-1",
        "module": "netcap",
        "start_timestamp": "2026-09-01T00:00:00",
        "end_timestamp": "2026-09-01T01:00:00",
        "series_ids": ["s1"],
    }
    prompt = await _build_forensic_user_prompt(session, alarm)  # type: ignore[arg-type]

    assert "## Alarm data" in prompt
    assert "supervised-ML prediction withheld" in prompt
    assert "## Monitored Devices" in prompt
    assert "## Triggering Anomalies" in prompt
    assert "do NOT re-fetch" in prompt
    assert "Provide your classification" in prompt


@pytest.mark.unit
async def test_build_forensic_user_prompt_strips_ml_bias_from_alarm() -> None:
    """The alarm JSON block must not contain ML-bias fields."""
    devices_json = '{"ok": true, "records": []}'
    anomalies_json = '{"ok": true, "records": []}'
    session = _ScriptedSession(
        responses={
            "postgres.list_devices": [devices_json],
            "postgres.read_anomalies": [anomalies_json],
        }
    )
    alarm = {
        "id": "alarm-1",
        "module": "netcap",
        "start_timestamp": "2026-09-01T00:00:00",
        "end_timestamp": "2026-09-01T01:00:00",
        "series_ids": [],
        "primary_type": "phishing",
        "anomaly_type_stats": {"a": 1},
        "multi_type": True,
    }
    prompt = await _build_forensic_user_prompt(session, alarm)  # type: ignore[arg-type]

    # The alarm block is the first json code fence.
    alarm_block = prompt.split("```json\n")[1].split("```")[0]
    parsed = json.loads(alarm_block)
    assert "primary_type" not in parsed
    assert "anomaly_type_stats" not in parsed
    assert "multi_type" not in parsed
    assert parsed["id"] == "alarm-1"


@pytest.mark.unit
async def test_build_forensic_user_prompt_no_ml_bias_fields_anywhere() -> None:
    """No ML-bias field name survives anywhere in the full forensic prompt."""
    devices_json = json.dumps(
        {
            "ok": True,
            "records": [
                {
                    "id": 1,
                    "vendor": "Siemens",
                    "device_type": "PLC",
                    "device_role": "controller",
                    "primary_mac": "aa:bb:cc:dd:ee:01",
                },
            ],
        }
    )
    anomalies_json = json.dumps(
        {
            "ok": True,
            "records": [
                {
                    "id": 1,
                    "series_id": "s1",
                    "anomaly_type": "leak",
                    "ml_details": {"label": "attack"},
                    "value": 10,
                },
            ],
        }
    )
    session = _ScriptedSession(
        responses={
            "postgres.list_devices": [devices_json],
            "postgres.read_anomalies": [anomalies_json],
        }
    )
    alarm = {
        "id": "alarm-1",
        "module": "netcap",
        "start_timestamp": "2026-09-01T00:00:00",
        "end_timestamp": "2026-09-01T01:00:00",
        "series_ids": ["s1"],
        "primary_type": "phishing",
        "anomaly_type_stats": {"leak": 3},
        "multi_type": True,
    }
    prompt = await _build_forensic_user_prompt(session, alarm)  # type: ignore[arg-type]

    for bias_field in ("primary_type", "anomaly_type_stats", "multi_type", "anomaly_type", "ml_details"):
        assert bias_field not in prompt, f"ML-bias field '{bias_field}' leaked into forensic prompt"


# ── 6. _assemble_initial_messages ───────────────────────────────────


@pytest.mark.unit
async def test_assemble_forensic_injects_context() -> None:
    """The forensic path calls MCP tools and injects context."""
    devices_json = json.dumps(
        {
            "ok": True,
            "records": [
                {
                    "id": 1,
                    "vendor": "Siemens",
                    "device_type": "PLC",
                    "device_role": "controller",
                    "primary_mac": "aa:bb:cc:dd:ee:01",
                }
            ],
        }
    )
    anomalies_json = json.dumps({"ok": True, "records": [{"id": 1, "series_id": "s1", "value": 10}]})
    session = _ScriptedSession(
        responses={
            "postgres.list_devices": [devices_json],
            "postgres.read_anomalies": [anomalies_json],
        }
    )
    messages = await _assemble_initial_messages(
        system_prompt="SYS",
        alarm={
            "id": "a",
            "module": "netcap",
            "start_timestamp": "2026-09-01T00:00:00",
            "end_timestamp": "2026-09-01T01:00:00",
            "series_ids": [],
        },
        prompt_variant="forensic",
        session=session,  # type: ignore[arg-type]
    )
    assert len(messages) == 2
    assert messages[0] == {"role": "system", "content": "SYS"}
    assert "## Monitored Devices" in messages[1]["content"]
    assert "## Triggering Anomalies" in messages[1]["content"]
    # Two orchestrator-injected MCP calls were made.
    assert len(session.calls) == 2


@pytest.mark.unit
async def test_assemble_expident_byte_identical_to_initial_messages() -> None:
    """The expert path MUST produce byte-identical output to the legacy _initial_messages."""
    alarm = {"id": "a", "module": "netcap", "primary_type": "phishing"}
    session = _ScriptedSession()  # no calls expected

    legacy = _initial_messages("SYS", alarm)
    assembled = await _assemble_initial_messages(
        system_prompt="SYS",
        alarm=alarm,
        prompt_variant="expert",
        session=session,  # type: ignore[arg-type]
    )
    assert assembled == legacy
    # No MCP calls were made for the expert variant.
    assert session.calls == []


@pytest.mark.unit
async def test_assemble_open_byte_identical_to_initial_messages() -> None:
    """The open path MUST also stay byte-identical to the legacy helper."""
    alarm = {"id": "a", "module": "netcap", "primary_type": "phishing"}
    session = _ScriptedSession()

    legacy = _initial_messages("SYS", alarm)
    assembled = await _assemble_initial_messages(
        system_prompt="SYS",
        alarm=alarm,
        prompt_variant="open",
        session=session,  # type: ignore[arg-type]
    )
    assert assembled == legacy
    assert session.calls == []


# ── 7. classify_alarm end-to-end with forensic variant ──────────────


# Reuse the scripted provider shape from test_classify_alarm.
from dataclasses import dataclass, field  # noqa: E402


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


class _ScriptedProvider:
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
        self.calls.append({"messages": [dict(m) for m in messages]})
        if not self._script:
            raise AssertionError("LLM script exhausted")
        item = self._script.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item


def _text_msg(content: str) -> _MResp:
    return _MResp(choices=[_MChoice(message=_MMsg(content=content))])


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


@pytest.mark.unit
async def test_classify_alarm_forensic_injects_before_first_round() -> None:
    """The forensic variant issues MCP calls before the first LLM round."""
    devices_json = json.dumps(
        {
            "ok": True,
            "records": [
                {
                    "id": 1,
                    "vendor": "Siemens",
                    "device_type": "PLC",
                    "device_role": "controller",
                    "primary_mac": "aa:bb:cc:dd:ee:01",
                }
            ],
        }
    )
    anomalies_json = json.dumps({"ok": True, "records": [{"id": 1, "series_id": "s1", "value": 10}]})
    provider = _ScriptedProvider([_text_msg(_VALID_TWO_STEP)])
    session = _ScriptedSession(
        responses={
            "postgres.list_devices": [devices_json],
            "postgres.read_anomalies": [anomalies_json],
        }
    )
    alarm = {
        "id": "alarm-1",
        "module": "netcap",
        "start_timestamp": "2026-09-01T00:00:00",
        "end_timestamp": "2026-09-01T01:00:00",
        "series_ids": ["s1"],
        "primary_type": "phishing",
    }

    record = await worker_mod.classify_alarm(
        job_id=uuid4(),
        session=session,  # type: ignore[arg-type]
        provider=provider,  # type: ignore[arg-type]
        alarm=alarm,
        openai_tools=[],
        system_prompt="SYS",
        temperature=0.1,
        timeout_seconds=60,
        prompt_variant="forensic",
    )

    assert record["status"] == "completed"
    # Two orchestrator-injected calls happened before the LLM round.
    assert len(session.calls) == 2
    assert session.calls[0]["name"] == "postgres.list_devices"
    assert session.calls[1]["name"] == "postgres.read_anomalies"
    # The first LLM message (user) contains the injected blocks.
    user_msg = provider.calls[0]["messages"][1]
    assert "## Monitored Devices" in user_msg["content"]
    assert "## Triggering Anomalies" in user_msg["content"]
    # ML-bias fields did not leak.
    assert "primary_type" not in user_msg["content"]
    assert "phishing" not in user_msg["content"]


@pytest.mark.unit
async def test_classify_alarm_forensic_degrades_gracefully_on_injection_failure() -> None:
    """If both injection calls fail, the job still runs with unavailable blocks."""
    provider = _ScriptedProvider([_text_msg(_VALID_TWO_STEP)])
    session = _ScriptedSession(
        responses={
            "postgres.list_devices": [RuntimeError("MCP down")],
            "postgres.read_anomalies": [RuntimeError("MCP down")],
        }
    )
    alarm = {
        "id": "alarm-1",
        "module": "netcap",
        "start_timestamp": "2026-09-01T00:00:00",
        "end_timestamp": "2026-09-01T01:00:00",
        "series_ids": [],
    }

    record = await worker_mod.classify_alarm(
        job_id=uuid4(),
        session=session,  # type: ignore[arg-type]
        provider=provider,  # type: ignore[arg-type]
        alarm=alarm,
        openai_tools=[],
        system_prompt="SYS",
        temperature=0.1,
        timeout_seconds=60,
        prompt_variant="forensic",
    )

    assert record["status"] == "completed"
    user_msg = provider.calls[0]["messages"][1]
    assert "unavailable" in user_msg["content"]


# ── 8. PromptLoader includes forensic variant ───────────────────────


@pytest.mark.unit
def test_prompt_loader_loads_forensic_variant() -> None:
    """``PromptLoader`` loads all three variants including forensic."""
    from pathlib import Path

    prompts_dir = Path(worker_mod.__file__).resolve().parent / "prompts_data"
    loader = PromptLoader(prompts_dir)
    forensic = loader.get("forensic")
    assert isinstance(forensic, str)
    assert len(forensic) > 0
    # The forensic prompt references the FP-first verdict space.
    assert "false_positive" in forensic or "false-positive" in forensic.lower() or "FP" in forensic
    # Hash is a 16-char hex prefix.
    h = loader.get_hash("forensic")
    assert len(h) == 16
    assert all(c in "0123456789abcdef" for c in h)


@pytest.mark.unit
def test_prompt_loader_forensic_distinct_from_expert() -> None:
    """The forensic prompt hash differs from the expert prompt hash."""
    from pathlib import Path

    prompts_dir = Path(worker_mod.__file__).resolve().parent / "prompts_data"
    loader = PromptLoader(prompts_dir)
    assert loader.get_hash("forensic") != loader.get_hash("expert")
    assert loader.get_hash("forensic") != loader.get_hash("open")


@pytest.mark.unit
def test_prompt_variant_literal_includes_forensic() -> None:
    """The ``PromptVariant`` Literal type includes 'forensic'."""
    from typing import get_args

    from otalon_ai.prompts.loader import PromptVariant

    variants = get_args(PromptVariant)
    assert "forensic" in variants
    assert "open" in variants
    assert "expert" in variants
