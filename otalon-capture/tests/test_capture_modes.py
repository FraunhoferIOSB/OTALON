"""Bounded A1 contracts, without constructing an acquisition lifecycle."""

from __future__ import annotations

import importlib
import json
import subprocess

import pytest


def _runtime():
    return importlib.import_module("capture_runtime")


@pytest.mark.parametrize("value", [None, "NONE", " NONE\t", "LIVE", " LIVE\n"])
def test_boot_intent_is_exact_and_absent_defaults_none(value, monkeypatch):
    if value is None:
        monkeypatch.delenv("CAPTURE_TYPE", raising=False)
    else:
        monkeypatch.setenv("CAPTURE_TYPE", value)
    runtime = _runtime()
    assert runtime.resolve_capture_intent() is runtime.CaptureIntent("NONE" if value is None else value.strip())


@pytest.mark.parametrize("value", ["", " \t", "none", "live", "AUTO", "unknown-secret-value"])
def test_invalid_boot_intent_names_key_and_domain_without_echoing_value(value, monkeypatch):
    monkeypatch.setenv("CAPTURE_TYPE", value)
    with pytest.raises(ValueError) as error:
        _runtime().resolve_capture_intent()
    assert str(error.value) == "CAPTURE_TYPE must be NONE or LIVE for service startup."


def test_retired_boot_pcap_explains_manual_import(monkeypatch):
    monkeypatch.setenv("CAPTURE_TYPE", " PCAP ")
    with pytest.raises(ValueError) as error:
        _runtime().resolve_capture_intent()
    assert str(error.value) == (
        "CAPTURE_TYPE=PCAP is retired for service startup; use CAPTURE_TYPE=NONE "
        "and import PCAP/PCAPNG through Operations / Data Sources."
    )


def test_internal_parser_enum_still_accepts_pcap_and_live():
    from otalon_capture.settings import CaptureConfig, CaptureType

    assert list(CaptureType) == [CaptureType.PCAP, CaptureType.LIVE]
    assert CaptureConfig(source="/import/a.pcap", type="PCAP", interval=1000).type is CaptureType.PCAP


def test_runtime_and_none_settings_have_no_acquisition_or_credential_side_effects(monkeypatch, tmp_path):
    """Tripwires are installed before loading the new helper/settings boundary."""
    from capture_settings_base import OperatorAuthSettings
    from otalon_capture.influxdb_writer import InfluxDBWriter
    from otalon_capture.netcap import Netcap
    from otalon_capture.pipeline import CapturePipeline
    from pcap_recorder.capture_stats import CaptureLossMonitor
    from pcap_recorder.recorder import TcpdumpRecorder
    from pcap_recorder.settings import PcapRecorderSettings

    def forbidden(*args, **kwargs):
        pytest.fail("A1 NONE settings initialized acquisition, writer, monitor, subprocess, or credentials")

    for target in (Netcap, CapturePipeline, TcpdumpRecorder, CaptureLossMonitor, InfluxDBWriter):
        monkeypatch.setattr(target, "__init__", forbidden)
    monkeypatch.setattr(OperatorAuthSettings, "from_env", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setenv("CAPTURE_TYPE", "NONE")
    monkeypatch.delenv("CAPTURE_SOURCE", raising=False)
    _runtime()
    config = tmp_path / "recorder.json"
    config.write_text(
        json.dumps(
            {
                "pcap": {
                    "interface": "$CAPTURE_SOURCE",
                    "chunk_duration_sec": 30,
                    "ringbuffer": {"directory": str(tmp_path / "buffer"), "max_total_size_mb": 1, "max_file_count": 1},
                    "archive": {"directory": str(tmp_path / "archive")},
                },
                "api": {"host": "127.0.0.1", "port": 9090},
                "log": {"level": "INFO", "file": "recorder.log"},
            }
        ),
        encoding="utf-8",
    )
    assert PcapRecorderSettings.from_json_for_intent(config).pcap.interface == ""
    assert not (tmp_path / "buffer").exists()
    assert not (tmp_path / "archive").exists()


def test_retry_budget_defines_only_the_approved_finite_episode():
    budget = _runtime().RetryBudget()
    assert budget.retry_limit == 5
    assert [budget.delay_before(attempt) for attempt in range(1, 6)] == [0, 2, 4, 8, 16]
    assert budget.readiness_timeout_seconds == 5
    assert budget.stable_reset_seconds == 60
    for attempt in (0, 6):
        with pytest.raises(ValueError):
            budget.delay_before(attempt)


def test_snapshot_domains_and_unknown_defaults_do_not_invent_runtime_truth():
    runtime = _runtime()
    assert [item.value for item in runtime.CaptureBackend] == ["native", "wsl"]
    assert [item.value for item in runtime.SourceState] == ["disabled", "waiting", "recording", "degraded", "blocked"]
    snapshot = runtime.CaptureSnapshot()
    assert snapshot.capture_type is None
    assert snapshot.backend is None
    assert snapshot.source_state is runtime.SourceState.DEGRADED
    assert snapshot.reason_code is None
    assert snapshot.retry_attempt is None
    assert snapshot.retry_limit is None
    assert snapshot.retry_in_seconds is None
    assert snapshot.retry_exhausted is None
    assert snapshot.observation_age_seconds is None


@pytest.mark.parametrize(
    "field,value",
    [
        ("retry_attempt", -1),
        ("retry_attempt", 6),
        ("retry_limit", 4),
        ("retry_in_seconds", -1),
        ("retry_in_seconds", 17),
        ("retry_in_seconds", float("nan")),
        ("observation_age_seconds", -1),
        ("observation_age_seconds", float("inf")),
        ("reason_code", "raw exception with a secret"),
    ],
)
def test_snapshot_rejects_out_of_contract_status_values(field, value):
    with pytest.raises(ValueError):
        _runtime().CaptureSnapshot(**{field: value})


def test_adapter_snapshot_requires_bounded_current_generation_pid_and_monotonic_freshness():
    runtime = _runtime()
    payload = {
        "state": "recording",
        "generation": "attempt-1",
        "child_pid": 123,
        "updated_monotonic": 10.0,
        "reason_code": None,
    }
    encoded = json.dumps(payload).encode()
    parse = runtime.AdapterSnapshot.from_bytes
    snapshot = parse(encoded, generation="attempt-1", child_pid=123, now=15.9)
    assert snapshot is not None
    assert snapshot.state is runtime.SourceState.RECORDING
    assert parse(encoded, generation="attempt-2", child_pid=123, now=11) is None
    assert parse(encoded, generation="attempt-1", child_pid=124, now=11) is None
    assert parse(encoded, generation="attempt-1", child_pid=123, now=16) is None
    assert parse(encoded, generation="attempt-1", child_pid=123, now=9) is None
    for invalid in (
        b"{",
        b"{}",
        b"x" * 4097,
        json.dumps({**payload, "reason_code": "secret exception"}).encode(),
        json.dumps({**payload, "updated_monotonic": float("nan")}).encode(),
        json.dumps({**payload, "extra_secret": "not allowed"}).encode(),
    ):
        assert parse(invalid, generation="attempt-1", child_pid=123, now=11) is None
