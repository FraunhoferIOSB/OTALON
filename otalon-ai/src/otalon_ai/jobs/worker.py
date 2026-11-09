"""Subagent worker loop ported from the paper experiment.

This module is a faithful port of
``llm-classification/software/experiment/single-model-dev/run_experiment.py::classify_alarm``
into the live agent service. The constants, retry logic, context guards,
and JSON parsing match the paper's reference implementation exactly so the
89% S2-Eff. observed in the paper transfers to the live system.

Key differences from the paper:
- ``session.call_tool`` runs against the live ``otalon-mcp`` over
  streamable-http instead of stdio.
- An optional async ``event_sink`` callback lets the SSE endpoint stream
  per-round progress to clients in real time.
- Classification text + traces are persisted incrementally to PostgreSQL
  (``subagent_jobs.tool_trace``) so a UI/SSE follower can replay history.
"""

from __future__ import annotations

import asyncio
import json
import random
import time
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Dict, List, Optional, Sequence
from uuid import UUID

import openai
from loguru import logger
from mcp import ClientSession

from otalon_ai.jobs.domain.events import (
    FinalEvent,
    ForceClassifyEvent,
    ProgressEvent,
    SubagentEvent,
    ToolCallCompletedEvent,
    ToolCallStartedEvent,
)
from otalon_ai.jobs.evidence import assess_evidence_health, degradation_reason, detect_inband_error
from otalon_ai.jobs.parsing import extract_two_step
from otalon_ai.llm.base import LlmProvider
from otalon_ai.prompts.loader import PromptVariant

# ── Context-management constants (must match paper) ───────────────────
MAX_CONTEXT_CHARS = 400_000
MAX_SINGLE_RESULT_CHARS = 30_000
PREVIEW_CHARS = 2_000
COMPRESS_RESULT_CHARS = 500
FORCE_CLASSIFY_CHARS = 480_000

# ── Retry constants ───────────────────────────────────────────────────
MAX_RETRIES = 5
BACKOFF_BASE = 10
BACKOFF_MAX = 120


EventSink = Callable[[SubagentEvent], Awaitable[None]]
TracePersist = Callable[[Dict[str, Any]], Awaitable[None]]
AllowedTools = Optional[frozenset[str]]


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _truncate_result(text: str, max_chars: int) -> str:
    """Truncate a single tool result if it exceeds ``max_chars``."""
    if len(text) <= max_chars:
        return text
    return (
        text[:max_chars] + f"\n\n... [TRUNCATED — original {len(text):,} chars, "
        f"showing first {max_chars:,} for context management]"
    )


def _estimate_context_chars(messages: Sequence[dict[str, Any]]) -> int:
    """Rough character count over all message contents."""
    return sum(len(str(m.get("content") or "")) for m in messages)


def _compress_old_results(messages: List[dict[str, Any]], keep_recent: int = 4) -> None:
    """Compress tool-role messages older than ``keep_recent`` to 500 chars."""
    tool_indices = [i for i, m in enumerate(messages) if m.get("role") == "tool"]
    if len(tool_indices) <= keep_recent:
        return
    to_compress = tool_indices[:-keep_recent]
    for idx in to_compress:
        content = messages[idx].get("content") or ""
        if len(content) > COMPRESS_RESULT_CHARS:
            messages[idx]["content"] = content[:COMPRESS_RESULT_CHARS] + "\n... [compressed for context management]"


# Fields that leak the supervised-ML prediction into the subagent's
# context and must therefore be stripped from any payload the LLM
# sees. The set covers both alarm-level fields (``primary_type``,
# ``anomaly_type_stats``, ``multi_type``) and the per-datapoint
# ``anomaly_type`` written by Cyberclas-ICS-Next on every anomaly
# row. The latter shows up nested inside ``postgres.read_anomalies``
# and inside the ``labels`` map attached to PCAP chunks.
_BIASING_ML_FIELDS = frozenset(
    {
        "primary_type",  # ML-predicted attack-method label (alarm row + chunk labels)
        "anomaly_type",  # ML-predicted label on each anomaly datapoint
        "anomaly_type_stats",  # per-class confidence scores (alarm row)
        "multi_type",  # multi-label flag (derived from ML)
        "ml_details",  # nested {label, type_counts, confidence_*} blob on each anomaly row
    }
)


def strip_ml_bias_fields(alarm: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of ``alarm`` with supervised-ML fields removed.

    Used everywhere an alarm record is forwarded to the LLM so the
    classifier output never reaches the subagent's prompt or any tool
    response it inspects. The full record is still available for the
    UI and the operator — only the in-LLM view is sanitised.
    """
    return {k: v for k, v in alarm.items() if k not in _BIASING_ML_FIELDS}


# MCP tools whose responses leak supervised-ML predictions to the
# subagent. The text response of these tools is parsed as JSON and
# all keys in :data:`_BIASING_ML_FIELDS` are removed recursively
# (i.e. also from nested ``labels`` maps in PCAP chunks). When the
# payload is not parseable as JSON we pass it through unchanged and
# log a warning — the worker loop must keep running even when an
# unexpected shape arrives.
#
# Coverage rationale:
# - ``postgres.read_alarm_details``    → top-level alarm row
# - ``postgres.read_anomalies``        → per-datapoint anomaly_type
# - ``postgres.read_recent_alarms``    → list of alarm rows
# - ``pcap.get_chunks_by_alarm_id``    → labels.primary_type per chunk
# - ``pcap.list_anomaly_chunks``       → labels.primary_type per chunk
# - ``pcap.list_chunks``               → labels.primary_type when anomaly
# - ``pcap.get_chunk_meta``            → labels.primary_type
_BIAS_STRIPPING_TOOLS = frozenset(
    {
        "postgres.read_alarm_details",
        "postgres.read_anomalies",
        "postgres.read_recent_alarms",
        "pcap.get_chunks_by_alarm_id",
        "pcap.list_anomaly_chunks",
        "pcap.list_chunks",
        "pcap.get_chunk_meta",
    }
)


def _strip_ml_bias_from_tool_response(tool_name: str, response_text: str) -> str:
    """Recursively remove biasing ML fields from a tool's JSON response.

    The MCP tool returns a JSON string. The caller has already
    verified that ``tool_name`` is in :data:`_BIAS_STRIPPING_TOOLS`.
    We walk the parsed structure (dicts and lists are descended into,
    primitive values are passed through) and remove every key listed
    in :data:`_BIASING_ML_FIELDS`. This catches both top-level alarm
    fields and labels nested inside arbitrary container shapes.

    Non-JSON or unparseable payloads pass through untouched.
    """

    def _walk(node: Any) -> Any:
        if isinstance(node, dict):
            return {k: _walk(v) for k, v in node.items() if k not in _BIASING_ML_FIELDS}
        if isinstance(node, list):
            return [_walk(item) for item in node]
        return node

    try:
        parsed = json.loads(response_text)
    except json.JSONDecodeError:
        logger.warning(
            "bias-strip: {} returned non-JSON payload, passing through",
            tool_name,
        )
        return response_text
    return json.dumps(_walk(parsed), ensure_ascii=False)


def build_user_prompt(alarm: dict[str, Any]) -> str:
    """Build the verbatim user prompt around the alarm record.

    The alarm dict is sanitised so the supervised-ML prediction
    (``primary_type``, ``anomaly_type_stats``, ``multi_type``) never
    reaches the LLM. The subagent must derive its classification from
    the time series, PCAP and MITRE evidence alone.
    """
    safe_alarm = strip_ml_bias_fields(alarm)
    alarm_json = json.dumps(safe_alarm, ensure_ascii=False, indent=2, default=str)
    return (
        f"Investigate and classify the following ICS network alarm.\n\n"
        f"**Alarm data (supervised-ML prediction withheld):**\n"
        f"```json\n{alarm_json}\n```\n\n"
        f"Use the available tools to analyze this alarm, then provide "
        f"your classification in the required JSON format."
    )


# ── Forensic variant: runtime-injected context (AI-017) ──────────────


def _to_iso(value: Any) -> str:
    """Convert a datetime or other value to an ISO 8601 string.

    Alarm timestamps come back from PostgreSQL as Python ``datetime``
    objects; MCP tool arguments expect ISO 8601 strings.
    """
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


async def _call_mcp_tool_json(
    session: ClientSession,
    tool_name: str,
    arguments: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """Call an MCP tool, strip ML-bias fields, and return parsed JSON.

    Returns ``None`` and logs a warning when the call fails or the
    response is not a JSON dict. Used by the forensic variant to inject
    device inventory and triggering anomalies into the user prompt at
    runtime. These calls bypass the ``allowed_tools`` execution gate
    because they are orchestrator-injected, not LLM-requested — the
    agent itself never sees ``list_devices`` in its tool list.
    """
    try:
        result = await session.call_tool(tool_name, arguments=arguments)
        parts: List[str] = []
        if result.content:
            for block in result.content:
                if hasattr(block, "text"):
                    parts.append(block.text)
                else:
                    parts.append(str(block))
        text = "\n".join(parts)
        stripped = _strip_ml_bias_from_tool_response(tool_name, text)
        parsed = json.loads(stripped)
        if not isinstance(parsed, dict):
            logger.warning("forensic injection: {} returned non-dict JSON", tool_name)
            return None
        return parsed
    except Exception as exc:
        logger.warning("forensic injection: {} failed: {}", tool_name, exc)
        return None


async def _fetch_devices_block(session: ClientSession) -> str:
    """Fetch the monitored device inventory and format it as a markdown table.

    Graceful degradation: if the MCP call fails, the block is noted as
    unavailable so the agent can still proceed with the alarm and
    anomalies.
    """
    data = await _call_mcp_tool_json(session, "postgres.list_devices", {"limit": 200})
    if data is None or not data.get("ok"):
        return "## Monitored Devices\n\n*(Device inventory unavailable — tool call failed)*"
    records = data.get("records") or []
    if not records:
        return "## Monitored Devices\n\n*(No devices in inventory)*"
    lines = [
        "| id | vendor | device_type | device_role | primary_mac |",
        "|---|---|---|---|---|",
    ]
    for dev in records:
        lines.append(
            f"| {dev.get('id', '')} | {dev.get('vendor', '')} | "
            f"{dev.get('device_type', '')} | {dev.get('device_role', '')} | "
            f"{dev.get('primary_mac', '')} |"
        )
    return "## Monitored Devices\n\n" + "\n".join(lines)


async def _fetch_anomalies_block(session: ClientSession, alarm: dict[str, Any]) -> str:
    """Fetch triggering anomalies for the alarm, filtered and deduplicated.

    Issues one ``postgres.read_anomalies`` call scoped to the alarm's
    module and time window, then client-side filters to records whose
    ``series_id`` is in the alarm's ``series_ids`` set (when non-empty)
    and deduplicates by ``id``. ML-bias fields are stripped by
    :func:`_call_mcp_tool_json`.
    """
    module = alarm.get("module", "netcap")
    start = _to_iso(alarm.get("start_timestamp"))
    stop = _to_iso(alarm.get("end_timestamp"))

    raw_series_ids = alarm.get("series_ids")
    series_ids: set[str] = set()
    if isinstance(raw_series_ids, str):
        try:
            raw_series_ids = json.loads(raw_series_ids)
        except json.JSONDecodeError:
            raw_series_ids = []
    if isinstance(raw_series_ids, list):
        series_ids = {str(s) for s in raw_series_ids}

    data = await _call_mcp_tool_json(
        session,
        "postgres.read_anomalies",
        {"module": module, "start": start, "stop": stop, "limit": 500},
    )
    if data is None or not data.get("ok"):
        return "## Triggering Anomalies\n\n*(Anomalies unavailable — tool call failed)*"
    records = data.get("records") or []
    if series_ids:
        records = [r for r in records if str(r.get("series_id", "")) in series_ids]
    seen_ids: set[Any] = set()
    deduped: List[Dict[str, Any]] = []
    for rec in records:
        rid = rec.get("id")
        if rid is not None:
            if rid in seen_ids:
                continue
            seen_ids.add(rid)
        deduped.append(rec)
    anomalies_json = json.dumps(deduped, ensure_ascii=False, indent=2, default=str)
    return "## Triggering Anomalies (supervised-ML prediction withheld)\n\n" f"```json\n{anomalies_json}\n```"


async def _build_forensic_user_prompt(
    session: ClientSession,
    alarm: dict[str, Any],
) -> str:
    """Build the forensic user prompt with runtime-injected context.

    Three blocks are injected: sanitized alarm data, the monitored device
    inventory, and the triggering anomalies. All blocks are sanitised
    via :func:`strip_ml_bias_fields` / :func:`_call_mcp_tool_json` so the
    supervised-ML prediction never reaches the LLM.
    """
    safe_alarm = strip_ml_bias_fields(alarm)
    alarm_json = json.dumps(safe_alarm, ensure_ascii=False, indent=2, default=str)
    devices_block = await _fetch_devices_block(session)
    anomalies_block = await _fetch_anomalies_block(session, alarm)
    return (
        "Investigate and classify the following ICS network alarm.\n\n"
        "## Alarm data (supervised-ML prediction withheld)\n"
        f"```json\n{alarm_json}\n```\n\n"
        f"{devices_block}\n\n"
        f"{anomalies_block}\n\n"
        "The alarm details, triggering anomalies, and device inventory above "
        "have already been gathered for you — do NOT re-fetch them via tools. "
        "Begin your investigation with traffic and baseline analysis "
        "(InfluxDB, PCAP).\n\n"
        "Provide your classification in the required JSON format."
    )


async def _emit(sink: Optional[EventSink], event: SubagentEvent) -> None:
    if sink is None:
        return
    try:
        await sink(event)
    except Exception as exc:
        logger.warning("event_sink raised: {}", exc)


def _initial_messages(system_prompt: str, alarm: dict[str, Any]) -> List[Dict[str, Any]]:
    """Build the initial chat history (system + user prompt).

    Phase 1/5 — context-load + prompt-build. Pure (no I/O). The alarm is
    sanitised inside :func:`build_user_prompt` so the supervised-ML
    prediction never leaks into the LLM context.
    """
    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": build_user_prompt(alarm)},
    ]


async def _assemble_initial_messages(
    *,
    system_prompt: str,
    alarm: dict[str, Any],
    prompt_variant: PromptVariant,
    session: ClientSession,
) -> List[Dict[str, Any]]:
    """Build the initial chat history, branching on the prompt variant.

    The ``forensic`` variant injects the device inventory and triggering
    anomalies into the user prompt via MCP tool calls at runtime (Phase 1
    context-load with I/O). The ``expert`` and ``open`` variants keep the
    byte-identical pure path through :func:`_initial_messages` /
    :func:`build_user_prompt` so the paper-reproducible contract is
    preserved.
    """
    if prompt_variant == "forensic":
        user_prompt = await _build_forensic_user_prompt(session, alarm)
    else:
        user_prompt = build_user_prompt(alarm)
    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]


async def _call_llm_with_retry(
    *,
    provider: LlmProvider,
    messages: List[Dict[str, Any]],
    openai_tools: List[dict[str, Any]],
    temperature: float,
    reasoning_effort: Optional[str],
    log_tag: str,
    round_no: int,
) -> tuple[Optional[Any], Optional[str]]:
    """Phase 3/5 — single LLM round-trip with rate-limit / 5xx backoff.

    Side-effects: outbound HTTPS call to the LLM provider (via
    ``provider.chat_completion`` on a worker thread); ``asyncio.sleep``
    between retries. Returns ``(response, last_error)``. ``response`` is
    ``None`` iff retries were exhausted or a non-retryable error fired —
    the caller maps that to ``api_failed``.
    """
    response = None
    last_error: Optional[str] = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            logger.info("{} round {} LLM call (attempt {})", log_tag, round_no, attempt)
            t_llm = time.monotonic()
            response = await asyncio.to_thread(
                provider.chat_completion,
                messages,
                openai_tools,
                temperature=temperature,
                reasoning_effort=reasoning_effort,
            )
            assert response is not None  # provider returns the SDK response or raises
            logger.info(
                "{} round {} LLM done in {:.1f}s (tools_called={})",
                log_tag,
                round_no,
                time.monotonic() - t_llm,
                len(response.choices[0].message.tool_calls or []),
            )
            return response, last_error
        except openai.RateLimitError as exc:
            wait = min(BACKOFF_BASE * (2 ** (attempt - 1)), BACKOFF_MAX)
            wait += random.uniform(0, wait * 0.25)
            last_error = f"rate_limit: {exc}"
            logger.warning("{} rate-limited (attempt {}/{}), waiting {:.1f}s", log_tag, attempt, MAX_RETRIES, wait)
            await asyncio.sleep(wait)
        except openai.APIStatusError as exc:
            if exc.status_code >= 500:
                wait = min(BACKOFF_BASE * (2 ** (attempt - 1)), BACKOFF_MAX)
                wait += random.uniform(0, wait * 0.25)
                last_error = f"server_error_{exc.status_code}: {exc}"
                logger.warning(
                    "{} server error {} (attempt {}/{}), waiting {:.1f}s",
                    log_tag,
                    exc.status_code,
                    attempt,
                    MAX_RETRIES,
                    wait,
                )
                await asyncio.sleep(wait)
            else:
                last_error = f"client_error_{exc.status_code}: {exc}"
                logger.error("{} client API error {}: {}", log_tag, exc.status_code, exc)
                return None, last_error
        except Exception as exc:
            last_error = f"unexpected_api_error: {exc}"
            logger.error("{} unexpected OpenAI API error: {}", log_tag, exc)
            return None, last_error
    return response, last_error


async def _execute_tool_calls(
    *,
    session: ClientSession,
    assistant_msg: Any,
    messages: List[Dict[str, Any]],
    tool_trace: List[Dict[str, Any]],
    trace_persist: Optional[TracePersist],
    event_sink: Optional[EventSink],
    job_str: str,
    round_no: int,
    log_tag: str,
    tool_name_map: Optional[Dict[str, str]] = None,
    allowed_tools: AllowedTools = None,
) -> None:
    """Phase 3.5 — execute every tool call requested by the assistant.

    Side-effects: MCP tool invocations via ``session.call_tool``; appends
    ``tool``-role messages to ``messages`` and entries to ``tool_trace``;
    optional ``trace_persist`` (DB write) per entry; emits
    ``ToolCallStarted`` / ``ToolCallCompleted`` events on ``event_sink``.
    Per-result text is truncated to :data:`MAX_SINGLE_RESULT_CHARS` and
    ML-bias fields are stripped from responses listed in
    :data:`_BIAS_STRIPPING_TOOLS`.

    ``tool_name_map`` is the sanitized→raw lookup table built in
    :class:`WorkerPool` (see :func:`src.mcp.schema.build_name_mapping`).
    The LLM emits the sanitized tool name; the real MCP tool name (which
    may contain dots) is needed for the ``session.call_tool`` round-trip.
    ``None`` keeps the legacy identity behaviour for callers (tests) that
    do not exercise sanitization.

    ``allowed_tools`` is the execution-time allow-list gate (AI-01),
    mirroring the chat surface's belt-and-braces check in
    :meth:`McpRegistry.call_tool`. When not ``None``, a ``mcp_name``
    outside the set is refused BEFORE any MCP round-trip: no
    ``session.call_tool`` fires, the refusal is recorded as the tool
    error, and the LLM receives it as the tool-message content.
    """
    for tc in assistant_msg.tool_calls:
        # Name emitted by the LLM, sanitized by construction (matches
        # ``^[a-zA-Z0-9_-]+$``). Used in events / traces / the assistant
        # echo so the wire log stays consistent.
        sanitized_name = tc.function.name
        # Real MCP tool name used for the server round-trip.
        mcp_name = tool_name_map.get(sanitized_name, sanitized_name) if tool_name_map else sanitized_name
        # The human-facing identity of the tool for traces is the sanitized
        # name (matches what the LLM sees) — we surface both in logs.
        tool_name = sanitized_name
        try:
            tool_args = json.loads(tc.function.arguments or "{}")
        except json.JSONDecodeError:
            tool_args = {}

        args_summary = json.dumps(tool_args, ensure_ascii=False)[:150]
        logger.debug(
            "{} [TOOL r{}] {} (mcp={})({})",
            log_tag,
            round_no,
            tool_name,
            mcp_name,
            args_summary,
        )
        await _emit(
            event_sink,
            ToolCallStartedEvent(
                job_id=job_str,
                round=round_no,
                tool=mcp_name,
                args_summary=args_summary,
            ),
        )

        t_tool = time.monotonic()
        tool_error: Optional[str] = None
        # AI-01: execution-time allow-list gate. Advertisement-time
        # filtering alone (WorkerPool) cannot stop a model that emits a
        # tool name it was never shown; mirror the chat surface's
        # belt-and-braces check and refuse BEFORE any MCP round-trip.
        if allowed_tools is not None and mcp_name not in allowed_tools:
            refusal = f"tool {mcp_name!r} is not in the jobs execution allow-list"
            logger.warning("{} [TOOL r{}] refused: {}", log_tag, round_no, refusal)
            result_text = f"Error calling tool: {refusal}"
            tool_error = refusal
        else:
            try:
                result = await session.call_tool(mcp_name, arguments=tool_args)
                parts: List[str] = []
                if result.content:
                    for block in result.content:
                        if hasattr(block, "text"):
                            parts.append(block.text)
                        else:
                            parts.append(str(block))
                result_text = "\n".join(parts)
                # Strip the supervised-ML prediction from tool responses
                # that surface raw alarm rows. This keeps the
                # PostgreSQL-side data intact (the UI and the n8n chat
                # agent still see the full record) but ensures the
                # subagent's "second opinion" stays independent. The bias
                # list keys on the raw MCP tool name (dotted), not the
                # sanitized name the LLM sees.
                if mcp_name in _BIAS_STRIPPING_TOOLS:
                    result_text = _strip_ml_bias_from_tool_response(mcp_name, result_text)
                # AI-036: otalon-mcp reports a backend outage in-band —
                # HTTP 200 carrying ``{"ok": false, "error": ...}``. The
                # transport succeeded, so without this the trace records
                # a success and a whole-namespace outage stays invisible.
                # The payload reaching the LLM is left untouched; only
                # the trace/event/DB view learns the truth.
                inband = detect_inband_error(result_text)
                if inband is not None:
                    tool_error = inband
                    logger.warning("{} [TOOL r{}] {} reported in-band failure: {}", log_tag, round_no, mcp_name, inband)
            except Exception as exc:
                result_text = f"Error calling tool: {exc}"
                tool_error = str(exc)
                logger.error("{} {}", log_tag, result_text)

        duration_ms = int((time.monotonic() - t_tool) * 1000)
        original_length = len(result_text)

        result_preview = result_text[:PREVIEW_CHARS]

        entry = {
            "round": round_no,
            # Trace persists the dotted MCP tool name so existing UI /
            # downstream consumers keep their format. Events for live SSE
            # also use the dotted name so the human sees the familiar
            # ``postgres.read_alarms`` rather than its sanitized form.
            "tool": mcp_name,
            "args": tool_args,
            "result_chars": original_length,
            "result_preview": result_preview,
            "duration_ms": duration_ms,
            "error": tool_error,
            "ts": _now_utc().isoformat(),
        }
        tool_trace.append(entry)
        if trace_persist:
            try:
                await trace_persist(entry)
            except Exception as exc:
                logger.warning("trace_persist raised: {}", exc)
        await _emit(
            event_sink,
            ToolCallCompletedEvent(
                job_id=job_str,
                round=round_no,
                tool=mcp_name,
                args=tool_args,
                result_chars=original_length,
                result_preview=result_preview,
                duration_ms=duration_ms,
                error=tool_error,
            ),
        )

        # Guard 1: per-result truncation
        if original_length > MAX_SINGLE_RESULT_CHARS:
            logger.warning(
                "{} [CTX] truncating {} {:,}->{:,} chars",
                log_tag,
                mcp_name,
                original_length,
                MAX_SINGLE_RESULT_CHARS,
            )
            result_text = _truncate_result(result_text, MAX_SINGLE_RESULT_CHARS)

        messages.append(
            {
                "role": "tool",
                "tool_call_id": tc.id,
                "content": result_text,
            }
        )


def _resolve_status(
    *,
    parsed: Optional[Dict[str, Any]],
    tool_trace: Sequence[Dict[str, Any]],
    cancelled: bool,
    timed_out: bool,
    api_failed: bool,
) -> tuple[str, Optional[str]]:
    """Resolve the terminal job status and its degradation reason (AI-036).

    Precedence: operator cancellation, wall-clock timeout and LLM API
    failure keep their existing terminal states. Only a job that ran to
    a parseable classification is inspected further: an empty
    ``classifications`` list while an evidence tool namespace was
    entirely unavailable resolves to ``degraded`` with a named reason
    instead of a silent green ``completed``.

    Returns:
        ``(status, degradation_reason)`` where the reason is ``None``
        for every status other than ``degraded``.
    """
    if cancelled:
        return "cancelled", None
    if timed_out:
        return "timeout", None
    if api_failed:
        return "failed", None
    if parsed is None:
        return "failed", None
    health = assess_evidence_health(tool_trace)
    reason = degradation_reason(health, parsed.get("classifications", []))
    if reason is not None:
        return "degraded", reason
    return "completed", None


async def _finalize_record(
    *,
    final_text: str,
    tool_trace: List[Dict[str, Any]],
    total_prompt_tokens: int,
    total_completion_tokens: int,
    t_start: float,
    cancelled: bool,
    timed_out: bool,
    api_failed: bool,
    last_error: Optional[str],
    event_sink: Optional[EventSink],
    job_str: str,
) -> Dict[str, Any]:
    """Phases 4 + 5 — parse the LLM output, resolve status, build the record, emit ``FinalEvent``.

    Side-effects: emits the terminal ``FinalEvent`` on ``event_sink``. DB
    persistence of the returned record is the caller's responsibility
    (``WorkerPool`` writes via the jobs repository); this function is
    otherwise pure CPU work on top of in-memory state.

    AI-036: when the classification came back empty because an evidence
    tool family was down, the status is ``degraded`` and
    ``error_message`` carries the named reason, so a tool outage can
    never present itself as a clean result.
    """
    duration = round(time.monotonic() - t_start, 2)
    parsed = extract_two_step(final_text)

    status, degraded_reason = _resolve_status(
        parsed=parsed,
        tool_trace=tool_trace,
        cancelled=cancelled,
        timed_out=timed_out,
        api_failed=api_failed,
    )
    if status == "degraded":
        logger.warning("job {} degraded: {}", job_str, degraded_reason)

    record: Dict[str, Any] = {
        "status": status,
        "duration_seconds": duration,
        "tool_trace": tool_trace,
        "tokens_prompt": total_prompt_tokens,
        "tokens_completion": total_completion_tokens,
        "error_message": (degraded_reason if status == "degraded" else (last_error if status == "failed" else None)),
    }

    # Surface jobs token usage on the Prometheus /metrics endpoint
    # (see otalon_ai/metrics.py). 0 is tolerated (no-op).
    from otalon_ai.metrics import record_jobs_tokens

    record_jobs_tokens(total_prompt_tokens, total_completion_tokens)

    if parsed:
        record["step1_technical"] = {
            "technical_method": parsed.get("technical_method", ""),
            "observed_activity": parsed.get("observed_activity", ""),
            "evidence": parsed.get("evidence", []),
        }
        record["step2_classification"] = {
            "classifications": parsed.get("classifications", []),
        }
        record["verdict"] = parsed.get("verdict")
    else:
        record["step1_technical"] = None
        record["step2_classification"] = None
        record["verdict"] = None
        if status == "failed":
            record["error_message"] = last_error or f"parse_error; final_text_tail={final_text[-200:]}"
            record["raw_final_text"] = final_text

    await _emit(
        event_sink,
        FinalEvent(
            job_id=job_str,
            status=status,  # type: ignore[arg-type]  # reason: status is locally built as str but always one of the FinalEvent Literal values
            step1_technical=record.get("step1_technical"),
            step2_classification=record.get("step2_classification"),
            verdict=record.get("verdict"),
            duration_seconds=duration,
            tokens_prompt=total_prompt_tokens,
            tokens_completion=total_completion_tokens,
            error=record.get("error_message"),
        ),
    )

    return record


async def _maybe_force_classify(
    *,
    messages: List[Dict[str, Any]],
    event_sink: Optional[EventSink],
    job_str: str,
    round_no: int,
    log_tag: str,
) -> None:
    """Phase 2 guard — force the LLM to classify when context is critically full.

    Side-effects: mutates ``messages`` (compress old tool results + append
    a user-role "classify NOW" nudge) when current size exceeds
    :data:`FORCE_CLASSIFY_CHARS`; emits a ``ForceClassifyEvent`` on
    ``event_sink``. No-op below the threshold.
    """
    ctx_size = _estimate_context_chars(messages)
    if ctx_size <= FORCE_CLASSIFY_CHARS:
        return
    _compress_old_results(messages, keep_recent=2)
    after_size = _estimate_context_chars(messages)
    logger.warning(
        "{} [CTX] FORCE CLASSIFY {:,}->{:,} chars (round {})",
        log_tag,
        ctx_size,
        after_size,
        round_no,
    )
    await _emit(
        event_sink,
        ForceClassifyEvent(
            job_id=job_str,
            context_chars_before=ctx_size,
            context_chars_after=after_size,
        ),
    )
    messages.append(
        {
            "role": "user",
            "content": (
                "IMPORTANT: You are running low on context space. "
                "Based on all the evidence you have gathered so far, "
                "provide your final classification NOW in the "
                "required JSON format. Do not call any more tools."
            ),
        }
    )


def _append_assistant_message(messages: List[Dict[str, Any]], assistant_msg: Any) -> None:
    """Append an assistant turn to ``messages`` in the OpenAI wire shape.

    Pure (mutates ``messages`` only). Preserves ``tool_calls`` when the
    assistant requested tool execution and normalises ``content`` to an
    empty string when both content and tool_calls are absent.
    """
    raw_content = assistant_msg.content
    msg_dict: Dict[str, Any] = {"role": "assistant"}
    if assistant_msg.tool_calls:
        msg_dict["content"] = raw_content  # may be None
        msg_dict["tool_calls"] = [
            {
                "id": tc.id,
                "type": "function",
                "function": {
                    "name": tc.function.name,
                    "arguments": tc.function.arguments,
                },
            }
            for tc in assistant_msg.tool_calls
        ]
    else:
        msg_dict["content"] = raw_content or ""
    messages.append(msg_dict)


async def _post_round_context_management(
    *,
    messages: List[Dict[str, Any]],
    event_sink: Optional[EventSink],
    job_str: str,
    round_no: int,
    log_tag: str,
) -> None:
    """Phase 2 guard — compress old tool results past the soft cap and emit progress.

    Side-effects: may mutate ``messages`` (compress old tool entries when
    over :data:`MAX_CONTEXT_CHARS`); emits a ``ProgressEvent`` either on
    compression or every 5 rounds as a heartbeat. No-op for rounds where
    neither condition fires.
    """
    ctx_size = _estimate_context_chars(messages)
    if ctx_size > MAX_CONTEXT_CHARS:
        _compress_old_results(messages, keep_recent=4)
        after_size = _estimate_context_chars(messages)
        logger.info(
            "{} [CTX] compressed old results {:,}->{:,} chars (round {})",
            log_tag,
            ctx_size,
            after_size,
            round_no,
        )
        await _emit(
            event_sink,
            ProgressEvent(
                job_id=job_str,
                round=round_no,
                context_chars=after_size,
            ),
        )
    elif round_no % 5 == 0:
        await _emit(
            event_sink,
            ProgressEvent(
                job_id=job_str,
                round=round_no,
                context_chars=ctx_size,
            ),
        )


async def classify_alarm(
    *,
    job_id: UUID,
    session: ClientSession,
    provider: LlmProvider,
    alarm: dict[str, Any],
    openai_tools: List[dict[str, Any]],
    system_prompt: str,
    temperature: float,
    timeout_seconds: int,
    event_sink: Optional[EventSink] = None,
    trace_persist: Optional[TracePersist] = None,
    cancellation_check: Optional[Callable[[], bool]] = None,
    reasoning_effort: Optional[str] = None,
    tool_name_map: Optional[Dict[str, str]] = None,
    allowed_tools: AllowedTools = None,
    prompt_variant: PromptVariant = "expert",
    log_tag: str = "[W]",
) -> Dict[str, Any]:
    """Run the iterative LLM tool-loop on a single alarm.

    Orchestrates five phases as private helpers in this module:

    1. :func:`_assemble_initial_messages` — context-load + prompt-build.
       For the ``forensic`` variant this performs MCP tool calls to inject
       the device inventory and triggering anomalies; for ``expert`` /
       ``open`` it stays pure via :func:`_initial_messages`.
    2. Main loop guards — cancellation, timeout, force-classify (in this function).
    3. :func:`_call_llm_with_retry` — LLM round-trip with retry/backoff.
    4. :func:`_execute_tool_calls` — MCP tool execution per assistant turn.
    5. :func:`_finalize_record` — parse output, resolve status, emit ``FinalEvent``.

    Returns a record with the keys consumed by the persistence layer:
    ``status`` (one of completed/failed/timeout/cancelled),
    ``step1_technical``, ``step2_classification``, ``tool_trace``,
    ``tokens_prompt`` / ``tokens_completion``, ``duration_seconds``,
    ``error_message``, ``raw_final_text`` (only on parse failure). DB
    persistence of the record is the caller's responsibility.

    ``allowed_tools`` (AI-01) is forwarded verbatim to
    :func:`_execute_tool_calls`: when set, every LLM-requested tool whose
    raw MCP name is not in the set is refused client-side before any
    ``session.call_tool`` round-trip.
    """
    job_str = str(job_id)
    alarm_id = str(alarm.get("id", ""))
    t_start = time.monotonic()

    messages: List[Dict[str, Any]] = await _assemble_initial_messages(
        system_prompt=system_prompt,
        alarm=alarm,
        prompt_variant=prompt_variant,
        session=session,
    )
    tool_trace: List[Dict[str, Any]] = []
    total_prompt_tokens = 0
    total_completion_tokens = 0
    final_text = ""
    timed_out = False
    cancelled = False
    api_failed = False
    last_error: Optional[str] = None

    max_rounds = 999  # bounded by timeout, see paper

    for round_idx in range(max_rounds):
        round_no = round_idx + 1
        logger.info(
            "{} round {} start: ctx={:,} chars, msgs={}",
            log_tag,
            round_no,
            _estimate_context_chars(messages),
            len(messages),
        )
        # ── Cancellation + timeout ─────────────────────────────────
        if cancellation_check and cancellation_check():
            cancelled = True
            logger.warning("{} cancelled by operator after round {}", log_tag, round_idx)
            break
        if timeout_seconds > 0 and (time.monotonic() - t_start) >= timeout_seconds:
            timed_out = True
            logger.warning("{} timeout reached ({}s) after {} rounds", log_tag, timeout_seconds, round_idx)
            for msg in reversed(messages):
                if msg.get("role") == "assistant" and msg.get("content"):
                    final_text = msg["content"]
                    break
            break

        # ── Guard 3: force-classify if context critically full ────
        await _maybe_force_classify(
            messages=messages,
            event_sink=event_sink,
            job_str=job_str,
            round_no=round_no,
            log_tag=log_tag,
        )

        # ── LLM call with retry/backoff ───────────────────────────
        response, retry_error = await _call_llm_with_retry(
            provider=provider,
            messages=messages,
            openai_tools=openai_tools,
            temperature=temperature,
            reasoning_effort=reasoning_effort,
            log_tag=log_tag,
            round_no=round_no,
        )
        if retry_error is not None:
            last_error = retry_error
        if response is None:
            logger.error("{} retries exhausted for alarm {}", log_tag, alarm_id)
            api_failed = True
            break

        if response.usage:
            total_prompt_tokens += response.usage.prompt_tokens or 0
            total_completion_tokens += response.usage.completion_tokens or 0

        assistant_msg = response.choices[0].message
        _append_assistant_message(messages, assistant_msg)

        # No tool calls → final response
        if not assistant_msg.tool_calls:
            final_text = assistant_msg.content or ""
            break

        # ── Execute tool calls ────────────────────────────────────
        await _execute_tool_calls(
            session=session,
            assistant_msg=assistant_msg,
            messages=messages,
            tool_trace=tool_trace,
            trace_persist=trace_persist,
            event_sink=event_sink,
            job_str=job_str,
            round_no=round_no,
            log_tag=log_tag,
            tool_name_map=tool_name_map,
            allowed_tools=allowed_tools,
        )

        # Guard 2: compress old results if total context exceeds soft limit
        await _post_round_context_management(
            messages=messages,
            event_sink=event_sink,
            job_str=job_str,
            round_no=round_no,
            log_tag=log_tag,
        )

    return await _finalize_record(
        final_text=final_text,
        tool_trace=tool_trace,
        total_prompt_tokens=total_prompt_tokens,
        total_completion_tokens=total_completion_tokens,
        t_start=t_start,
        cancelled=cancelled,
        timed_out=timed_out,
        api_failed=api_failed,
        last_error=last_error,
        event_sink=event_sink,
        job_str=job_str,
    )
