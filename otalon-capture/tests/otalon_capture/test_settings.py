"""Tests for settings loading and environment placeholder resolution."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict

import pytest
from pydantic import ValidationError

from otalon_capture.settings import CaptureConfig, CaptureType, Settings


def _write_temp_config(tmp_path: Path, payload: Dict) -> Path:
    path = tmp_path / "config.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_settings_resolve_environment_variables(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("INFLUX_TOKEN", "secret")
    monkeypatch.setenv("INFLUX_URL", "http://localhost")
    monkeypatch.setenv("CAPTURE_SOURCE", "/tmp/sample.pcap")
    monkeypatch.setenv("CAPTURE_TYPE", "PCAP")
    monkeypatch.setenv("NETCAP_LOG_FILE", "adapter.log")

    config_payload = {
        "influx": {
            "host": "$INFLUX_URL",
            "token": "$INFLUX_TOKEN",
            "database": "netcap",
            "measurement_name": "network_metrics",
            "tags": ["uci"],
            "fields": {"packet_count": "get_total_packet_count"},
        },
        "capture": {"source": "$CAPTURE_SOURCE", "type": "$CAPTURE_TYPE", "interval": 1000},
        "write_options": {
            "batch_size": 10,
            "flush_interval": 1000,
            "jitter_interval": 100,
            "precision": "ms",
        },
        "log": {"level": "INFO", "file": "$NETCAP_LOG_FILE"},
        "preprocess": {"aggregate_sparse_ports": True, "max_packet_count_single": 3, "emit_interval_ms": 1000},
    }

    config_path = _write_temp_config(tmp_path, config_payload)
    settings = Settings.from_json(config_path)

    assert settings.influx.token.get_secret_value() == "secret"
    assert settings.capture.type == CaptureType.PCAP
    assert settings.log.file == "adapter.log"


def test_settings_missing_environment_variable_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("INFLUX_URL", "http://localhost")
    monkeypatch.setenv("INFLUX_TOKEN", "secret")
    monkeypatch.delenv("NETCAP_LOG_FILE", raising=False)

    config_payload = {
        "influx": {
            "host": "$INFLUX_URL",
            "token": "$INFLUX_TOKEN",
            "database": "netcap",
            "measurement_name": "network_metrics",
            "tags": ["uci"],
            "fields": {"packet_count": "get_total_packet_count"},
        },
        "capture": {"source": "/tmp/sample.pcap", "type": "PCAP", "interval": 1000},
        "write_options": {
            "batch_size": 10,
            "flush_interval": 1000,
            "jitter_interval": 100,
            "precision": "ms",
        },
        "log": {"level": "INFO", "file": "$NETCAP_LOG_FILE"},
    }

    config_path = _write_temp_config(tmp_path, config_payload)
    with pytest.raises(RuntimeError):
        Settings.from_json(config_path)


def test_capture_config_validation() -> None:
    with pytest.raises(ValidationError):
        CaptureConfig(source="", type="INVALID", interval=100)


@pytest.mark.parametrize("source", [None, ""])
def test_for_import_file_preserves_resolver_policy_and_validates_once(source, monkeypatch, tmp_path):
    monkeypatch.setenv("CAPTURE_TYPE", "NONE")
    if source is None:
        monkeypatch.delenv("CAPTURE_SOURCE", raising=False)
    else:
        monkeypatch.setenv("CAPTURE_SOURCE", source)
    monkeypatch.setenv("A1_HOST", "http://localhost")
    monkeypatch.setenv("A1_TAGS", '["uci", "protocol"]')
    monkeypatch.setenv("A1_LOG_ROOT", "/tmp/synthetic")
    monkeypatch.setenv("A1_LOG_FILE", "$A1_LOG_ROOT/adapter.log")
    payload = {
        "influx": {
            "host": "$A1_HOST",
            "token": "test-token",
            "database": "netcap",
            "measurement_name": "network_metrics",
            "tags": "$A1_TAGS",
            "fields": {"packet_count": "get_total_packet_count"},
        },
        "capture": {"source": "$CAPTURE_SOURCE", "type": "$CAPTURE_TYPE", "interval": 1000},
        "write_options": {"batch_size": 10, "flush_interval": 1000, "jitter_interval": 100, "precision": "ms"},
        "log": {"level": "INFO", "file": "$A1_LOG_FILE"},
        "ignored": "$A1_UNUSED",
    }
    monkeypatch.delenv("A1_UNUSED", raising=False)
    calls = []
    validate = Settings.model_validate

    def counted_validate(data):
        calls.append(data)
        return validate(data)

    monkeypatch.setattr(Settings, "model_validate", counted_validate)
    settings = Settings.for_import_file(_write_temp_config(tmp_path, payload), Path("/import/contained.pcap"))
    assert len(calls) == 1
    assert calls[0]["capture"] == {"source": "/import/contained.pcap", "type": "PCAP", "interval": 1000}
    assert "ignored" not in calls[0]
    assert settings.influx.tags == ["uci", "protocol"]
    assert settings.log.file == "/tmp/synthetic/adapter.log"


@pytest.mark.parametrize(
    "section,field,value",
    [
        ("influx", "host", "not-a-url"),
        ("influx", "token", None),
        ("write_options", "batch_size", "not-an-integer"),
        ("write_options", "precision", None),
        ("preprocess", "emit_interval_ms", "not-an-integer"),
        ("mac_aggregation", "emit_interval_ms", "not-an-integer"),
        ("log", "file", None),
    ],
)
def test_for_import_file_rejects_invalid_required_worker_fields(section, field, value, monkeypatch, tmp_path):
    monkeypatch.setenv("CAPTURE_TYPE", "NONE")
    monkeypatch.delenv("CAPTURE_SOURCE", raising=False)
    payload = {
        "influx": {
            "host": "http://localhost",
            "token": "test-token",
            "database": "netcap",
            "measurement_name": "network_metrics",
            "tags": ["uci"],
            "fields": {"packet_count": "get_total_packet_count"},
        },
        "capture": {"source": "$CAPTURE_SOURCE", "type": "$CAPTURE_TYPE", "interval": 1000},
        "write_options": {"batch_size": 10, "flush_interval": 1000, "jitter_interval": 100, "precision": "ms"},
        "preprocess": {"emit_interval_ms": 1000},
        "mac_aggregation": {"emit_interval_ms": 1000},
        "log": {"level": "INFO", "file": "adapter.log"},
    }
    payload[section][field] = value
    with pytest.raises(ValidationError, match=field):
        Settings.for_import_file(_write_temp_config(tmp_path, payload), "/import/contained.pcap")
