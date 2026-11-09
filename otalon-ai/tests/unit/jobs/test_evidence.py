"""Unit tests for :mod:`otalon_ai.jobs.evidence` (AI-036).

Pure-function coverage of the evidence-health assessment that decides
whether an empty ``step2_classification`` is a legitimate verdict or the
silent consequence of a tool outage.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import pytest

from otalon_ai.jobs.evidence import (
    EVIDENCE_NAMESPACES,
    assess_evidence_health,
    degradation_reason,
    detect_inband_error,
    entry_error,
    is_evidence_tool,
    tool_namespace,
)

#: Verbatim shape of the PCAP-008 in-band failure, as persisted in the
#: ``tool_trace`` of job ``646a22ec-58b5-4ead-bef5-c49e993779e0``.
_PCAP008_PAYLOAD = (
    '{\n  "ok": false,\n  "error": "pcap analyze_chunk failed: 500 Server Error: '
    'Internal Server Error for url: http://host.docker.internal:9090/chunks/20260901_021951.pcap"\n}'
)


def _entry(tool: str, error: Optional[str] = None, preview: str = '{"ok": true}') -> Dict[str, Any]:
    return {"round": 1, "tool": tool, "args": {}, "error": error, "result_preview": preview}


@pytest.mark.unit
def test_tool_namespace_splits_on_first_dot() -> None:
    assert tool_namespace("pcap.analyze_chunk") == "pcap"
    assert tool_namespace("postgres.read_anomalies") == "postgres"
    assert tool_namespace("undotted") == "undotted"


@pytest.mark.unit
def test_evidence_namespaces_cover_the_job_allow_list_families() -> None:
    assert EVIDENCE_NAMESPACES == {"pcap", "postgres", "influx", "mitre"}


@pytest.mark.unit
def test_is_evidence_tool() -> None:
    assert is_evidence_tool("pcap.analyze_chunk") is True
    assert is_evidence_tool("training.retrain_classifier") is False


# ── In-band failure detection (the actual PCAP-008 shape) ────────────


@pytest.mark.unit
def test_detect_inband_error_on_real_pcap008_payload() -> None:
    """otalon-mcp returns HTTP 200 with ``{"ok": false, "error": ...}``;
    the transport-level error is ``None`` for exactly this case."""
    error = detect_inband_error(_PCAP008_PAYLOAD)
    assert error is not None
    assert "500 Server Error" in error


@pytest.mark.unit
def test_detect_inband_error_none_on_success_payload() -> None:
    assert detect_inband_error('{"ok": true, "chunks": [], "count": 0}') is None


@pytest.mark.unit
def test_detect_inband_error_none_on_non_json() -> None:
    assert detect_inband_error("not json at all") is None


@pytest.mark.unit
def test_detect_inband_error_none_on_ok_false_without_error() -> None:
    assert detect_inband_error('{"ok": false}') is None


@pytest.mark.unit
def test_detect_inband_error_none_on_json_list() -> None:
    assert detect_inband_error('[{"ok": false, "error": "x"}]') is None


@pytest.mark.unit
def test_detect_inband_error_ignores_marker_beyond_scan_window() -> None:
    """A payload whose ``ok``/``error`` keys sit past the scan prefix is
    treated as healthy — the cheap prefix check gates the JSON parse."""
    payload = '{"data": "' + "x" * 5_000 + '", "ok": false, "error": "late"}'
    assert detect_inband_error(payload) is None


@pytest.mark.unit
def test_entry_error_prefers_transport_error() -> None:
    assert entry_error(_entry("pcap.analyze_chunk", "MCP down")) == "MCP down"


@pytest.mark.unit
def test_entry_error_falls_back_to_inband() -> None:
    entry = _entry("pcap.analyze_chunk", None, preview=_PCAP008_PAYLOAD)
    error = entry_error(entry)
    assert error is not None
    assert "500 Server Error" in error


# ── Per-tool aggregation ─────────────────────────────────────────────


@pytest.mark.unit
def test_assess_counts_success_and_failure_per_tool() -> None:
    trace: List[Dict[str, Any]] = [
        _entry("pcap.analyze_chunk", "500 Server Error"),
        _entry("pcap.protocol_stats", "500 Server Error"),
        _entry("postgres.read_anomalies"),
    ]
    health = assess_evidence_health(trace)
    assert health.failed["pcap.analyze_chunk"] == 1
    assert health.succeeded["postgres.read_anomalies"] == 1
    assert health.broken_tools == ("pcap.analyze_chunk", "pcap.protocol_stats")
    assert health.broken_namespaces == ("pcap",)
    assert health.any_failure is True


@pytest.mark.unit
def test_partially_broken_namespace_still_reports_broken_tools() -> None:
    """The PCAP-008 shape: ``list_chunks`` answered while the three
    tshark-backed tools failed. A namespace-level rule would have called
    that healthy and missed the incident."""
    trace = [
        _entry("pcap.list_chunks"),
        _entry("pcap.read_chunk_text"),
        _entry("pcap.analyze_chunk", None, preview=_PCAP008_PAYLOAD),
        _entry("pcap.protocol_stats", None, preview=_PCAP008_PAYLOAD),
    ]
    health = assess_evidence_health(trace)
    assert health.broken_tools == ("pcap.analyze_chunk", "pcap.protocol_stats")
    assert health.broken_namespaces == ("pcap",)


@pytest.mark.unit
def test_tool_with_one_success_is_not_broken() -> None:
    trace = [
        _entry("pcap.analyze_chunk", "500 Server Error"),
        _entry("pcap.analyze_chunk"),
    ]
    health = assess_evidence_health(trace)
    assert health.broken_tools == ()
    assert health.any_failure is True


@pytest.mark.unit
def test_non_evidence_namespace_is_ignored() -> None:
    health = assess_evidence_health([_entry("training.retrain_classifier", "refused")])
    assert health.broken_tools == ()
    assert health.any_failure is False


@pytest.mark.unit
def test_empty_trace_is_healthy() -> None:
    health = assess_evidence_health([])
    assert health.broken_tools == ()
    assert health.any_failure is False


# ── Degradation rule ─────────────────────────────────────────────────


@pytest.mark.unit
def test_degradation_reason_names_the_broken_tool_and_error() -> None:
    health = assess_evidence_health([_entry("pcap.analyze_chunk", "500 Server Error")])
    reason = degradation_reason(health, [])
    assert reason is not None
    assert "pcap.*" in reason
    assert "500 Server Error" in reason
    assert "pcap.analyze_chunk" in reason


@pytest.mark.unit
def test_degradation_reason_on_reconstructed_pcap008_trace() -> None:
    """Full regression against the incident trace of job
    ``646a22ec-58b5-4ead-bef5-c49e993779e0``: 4 healthy pcap calls,
    6 in-band 500s, empty classification list."""
    trace = [
        _entry("postgres.read_alarm_details"),
        _entry("postgres.read_anomalies"),
        _entry("influx.list_time_series"),
        _entry("pcap.get_chunks_by_alarm_id"),
        _entry("pcap.list_chunks"),
        _entry("pcap.read_chunk_text"),
        _entry("pcap.analyze_chunk", None, preview=_PCAP008_PAYLOAD),
        _entry("pcap.analyze_chunk", None, preview=_PCAP008_PAYLOAD),
        _entry("pcap.protocol_stats", None, preview=_PCAP008_PAYLOAD),
        _entry("pcap.conversations", None, preview=_PCAP008_PAYLOAD),
    ]
    reason = degradation_reason(assess_evidence_health(trace), [])
    assert reason is not None
    assert "pcap.analyze_chunk" in reason
    assert "pcap.protocol_stats" in reason
    assert "pcap.conversations" in reason
    assert "pcap.list_chunks" not in reason


@pytest.mark.unit
def test_degradation_reason_none_when_classification_present() -> None:
    health = assess_evidence_health([_entry("pcap.analyze_chunk", "500 Server Error")])
    assert degradation_reason(health, [{"technique_id": "T0846"}]) is None


@pytest.mark.unit
def test_degradation_reason_none_when_tools_healthy() -> None:
    health = assess_evidence_health([_entry("pcap.analyze_chunk")])
    assert degradation_reason(health, []) is None


@pytest.mark.unit
def test_degradation_reason_lists_every_broken_namespace() -> None:
    trace = [
        _entry("pcap.analyze_chunk", "500 Server Error"),
        _entry("influx.read_single_time_series", "connection refused"),
    ]
    reason = degradation_reason(assess_evidence_health(trace), [])
    assert reason is not None
    assert "pcap.*" in reason
    assert "influx.*" in reason
