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
