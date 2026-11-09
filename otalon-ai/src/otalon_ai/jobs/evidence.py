"""Evidence-health assessment for subagent classification jobs (AI-036).

The subagent derives its MITRE classification from MCP evidence tools
(``pcap.*``, ``postgres.*``, ``influx.*``, ``mitre.*``). When those tools
fail — the PCAP-008 incident had ``pcap.analyze_chunk`` /
``pcap.protocol_stats`` / ``pcap.conversations`` return HTTP 500 on every
call — a well-behaved model refuses to invent a technique and returns
``{"classifications": []}``. That refusal is correct; silently persisting
it as a green ``completed`` job is not: an operator cannot distinguish
"no attack found" from "the classifier was blind".

Two properties of the live system drive the design here:

**In-band failures.** ``otalon-mcp`` does not propagate a backend outage
as an exception. Every tool catches it and returns HTTP 200 carrying
``{"ok": false, "error": "..."}``. The worker's transport-level
``tool_error`` is therefore ``None`` for exactly the failure mode this
module exists to catch, so :func:`detect_inband_error` inspects the
payload as well.

**Per-tool, not per-namespace, granularity.** In the incident the
``pcap`` namespace was only partly broken: ``pcap.list_chunks`` and
``pcap.read_chunk_text`` answered while the three tshark-backed analysis
tools failed. A namespace-level rule would have called that healthy.
A tool counts as broken when it was called at least once and *every*
call failed.

All functions here are pure — they read the in-memory trace and return
value objects. Status resolution stays in
:func:`otalon_ai.jobs.worker._resolve_status`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Sequence

#: MCP tool namespaces whose results constitute classification evidence.
#: The namespace is the dotted prefix of the raw MCP tool name
#: (``pcap.analyze_chunk`` -> ``pcap``). A name without a dot is treated
#: as its own namespace so allow-list refusals of hallucinated tool names
#: are still accounted for.
EVIDENCE_NAMESPACES = frozenset({"pcap", "postgres", "influx", "mitre"})

#: Characters of a tool payload scanned for an in-band failure marker.
#: The ``ok`` key is emitted first by every ``otalon-mcp`` tool, so a
#: short prefix is enough and keeps the check cheap on 30 000-char
#: tshark dumps.
INBAND_SCAN_CHARS = 4_000


def tool_namespace(tool_name: str) -> str:
    """Return the namespace prefix of an MCP tool name.

    Args:
        tool_name: Raw (dotted) MCP tool name, e.g. ``pcap.analyze_chunk``.

    Returns:
        The part before the first dot, or the whole name when undotted.
    """
    return tool_name.split(".", 1)[0]


def is_evidence_tool(tool_name: str) -> bool:
    """Return whether a tool's result counts as classification evidence."""
    return tool_namespace(tool_name) in EVIDENCE_NAMESPACES


def detect_inband_error(result_text: str) -> Optional[str]:
    """Return the error message of an in-band MCP failure, or ``None``.

    ``otalon-mcp`` signals a backend outage inside a successful HTTP
    response: ``{"ok": false, "error": "pcap analyze_chunk failed: 500
    Server Error ..."}``. Both keys are required before we call it a
    failure, so a tool that legitimately reports ``ok: false`` without an
    error string (or a payload that merely contains the word) is not
    misread.

    Args:
        result_text: The tool's raw response text.

    Returns:
        The reported error string, or ``None`` when the payload is not a
        recognisable in-band failure.
    """
    prefix = result_text[:INBAND_SCAN_CHARS]
    if '"ok"' not in prefix or '"error"' not in prefix:
        return None
    try:
        parsed = json.loads(result_text)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(parsed, dict) or parsed.get("ok") is not False:
        return None
    error = parsed.get("error")
    return str(error) if error else None


@dataclass(frozen=True)
class EvidenceHealth:
    """Per-tool outcome counts over a job's tool trace.

    Attributes:
        succeeded: Successful call count per evidence tool.
        failed: Failed call count per evidence tool.
        sample_errors: One representative error string per broken tool,
            used to name the reason in the job record.
    """

    succeeded: Mapping[str, int] = field(default_factory=dict)
    failed: Mapping[str, int] = field(default_factory=dict)
    sample_errors: Mapping[str, str] = field(default_factory=dict)

    @property
    def broken_tools(self) -> tuple[str, ...]:
        """Evidence tools with at least one failure and no successful call."""
        return tuple(sorted(name for name, n in self.failed.items() if n > 0 and self.succeeded.get(name, 0) == 0))

    @property
    def broken_namespaces(self) -> tuple[str, ...]:
        """Distinct namespaces containing at least one broken tool."""
        return tuple(sorted({tool_namespace(name) for name in self.broken_tools}))

    @property
    def any_failure(self) -> bool:
        """``True`` when at least one evidence call failed."""
        return any(n > 0 for n in self.failed.values())


def entry_error(entry: Dict[str, Any]) -> Optional[str]:
    """Return a trace entry's failure reason, transport-level or in-band.

    Args:
        entry: One worker trace entry (``tool`` / ``error`` /
            ``result_preview``).

    Returns:
        The error string, or ``None`` when the call succeeded.
    """
    transport = entry.get("error")
    if transport:
        return str(transport)
    return detect_inband_error(str(entry.get("result_preview") or ""))


def assess_evidence_health(tool_trace: Sequence[Dict[str, Any]]) -> EvidenceHealth:
    """Aggregate per-tool success/failure counts from a tool trace.

    Only tools in :data:`EVIDENCE_NAMESPACES` are counted; calls to
    anything else (or to a tool whose entry carries no name) are ignored
    so an unrelated helper tool cannot degrade a job.

    Args:
        tool_trace: The worker's trace entries.

    Returns:
        The aggregated :class:`EvidenceHealth`.
    """
    succeeded: Dict[str, int] = {}
    failed: Dict[str, int] = {}
    sample_errors: Dict[str, str] = {}
    for entry in tool_trace:
        name = str(entry.get("tool") or "")
        if not is_evidence_tool(name):
            continue
        error = entry_error(entry)
        if error:
            failed[name] = failed.get(name, 0) + 1
            sample_errors.setdefault(name, error)
        else:
            succeeded[name] = succeeded.get(name, 0) + 1
    return EvidenceHealth(succeeded=succeeded, failed=failed, sample_errors=sample_errors)


def _format_reason(health: EvidenceHealth, broken: tuple[str, ...]) -> str:
    """Render the operator-facing degradation reason string."""
    parts = [
        f"{name} ({health.failed.get(name, 0)}x, first: {health.sample_errors.get(name, 'unknown error')})"
        for name in broken
    ]
    namespaces = ", ".join(f"{ns}.*" for ns in health.broken_namespaces)
    return (
        f"degraded: no MITRE technique assigned while evidence tools were unavailable ({namespaces}). "
        f"Failed tools: {'; '.join(parts)}. "
        "The classification is incomplete, not a clean result."
    )


def degradation_reason(
    health: EvidenceHealth,
    classifications: Sequence[Any],
) -> Optional[str]:
    """Return the named degradation reason, or ``None`` when the job is sound.

    A job degrades when it produced no classification at all *and* at
    least one evidence tool was completely unavailable. A job that
    returns an empty classification list with all evidence tools healthy
    is a legitimate "no attack technique applies" verdict and stays
    ``completed``.

    Args:
        health: Aggregated evidence outcome from
            :func:`assess_evidence_health`.
        classifications: The parsed ``step2_classification`` list.

    Returns:
        A human-readable reason string, or ``None``.
    """
    if classifications:
        return None
    broken = health.broken_tools
    if not broken:
        return None
    return _format_reason(health, broken)
