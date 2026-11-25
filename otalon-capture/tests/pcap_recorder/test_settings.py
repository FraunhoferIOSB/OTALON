"""Tests fuer PcapRecorderSettings."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from pcap_recorder.settings import (
    ApiConfig,
    ArchiveConfig,
    LogConfig,
    PcapConfig,
    PcapRecorderSettings,
    RingbufferConfig,
)


def _write_tmp_config(tmp_path: Path, payload: dict) -> Path:
    path = tmp_path / "config_pcap.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_from_json_resolves_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("CAPTURE_SOURCE", "eth0")
    monkeypatch.setenv("PCAP_BUFFER_DIR", "/tmp/buffer")
    monkeypatch.setenv("PCAP_ARCHIVE_DIR", "/tmp/archive")
    monkeypatch.setenv("PCAP_LOG_FILE", "pcap.log")

    payload = {
        "pcap": {
            "interface": "$CAPTURE_SOURCE",
            "bpf_filter": "",
            "chunk_duration_sec": 30,
            "ringbuffer": {
                "directory": "$PCAP_BUFFER_DIR",
                "max_total_size_mb": 100,
                "max_file_count": 5,
            },
            "archive": {"directory": "$PCAP_ARCHIVE_DIR"},
        },
        "api": {"host": "0.0.0.0", "port": 9090},
        "log": {"level": "INFO", "file": "$PCAP_LOG_FILE"},
    }

    config_path = _write_tmp_config(tmp_path, payload)
    settings = PcapRecorderSettings.from_json(config_path)

    assert settings.pcap.interface == "eth0"
    assert settings.pcap.ringbuffer.directory == "/tmp/buffer"
    assert settings.pcap.archive.directory == "/tmp/archive"
    assert settings.log.file == "pcap.log"


def test_missing_env_raises(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("CAPTURE_SOURCE", raising=False)

    payload = {
        "pcap": {
            "interface": "$CAPTURE_SOURCE",
            "bpf_filter": "",
            "chunk_duration_sec": 30,
            "ringbuffer": {
                "directory": "/tmp/buffer",
                "max_total_size_mb": 100,
                "max_file_count": 5,
            },
            "archive": {"directory": "/tmp/archive"},
        },
        "api": {"host": "0.0.0.0", "port": 9090},
        "log": {"level": "INFO", "file": "pcap.log"},
    }

    config_path = _write_tmp_config(tmp_path, payload)

    with pytest.raises(RuntimeError):
        PcapRecorderSettings.from_json(config_path)


def test_pcap_config_validation() -> None:
    with pytest.raises(ValidationError):
        PcapConfig(
            interface="",
            chunk_duration_sec=0,
            ringbuffer=RingbufferConfig(directory="/tmp", max_total_size_mb=1, max_file_count=1),
            archive=ArchiveConfig(directory="/tmp/archive"),
        )

    config = PcapConfig(
        interface="eth0",
        chunk_duration_sec=30,
        ringbuffer=RingbufferConfig(directory="/tmp", max_total_size_mb=1, max_file_count=1),
        archive=ArchiveConfig(directory="/tmp/archive"),
    )
    assert config.interface == "eth0"


def test_api_config_positive_port() -> None:
    config = ApiConfig(host="0.0.0.0", port=9090)
    assert config.port == 9090

    with pytest.raises(ValidationError):
        ApiConfig(host="0.0.0.0", port=0)


def test_log_config_fields() -> None:
    config = LogConfig(level="INFO", file="pcap.log")
    assert config.level == "INFO"
    assert config.file == "pcap.log"


def _mode_payload() -> dict:
    return {
        "pcap": {
            "interface": "$CAPTURE_SOURCE",
            "bpf_filter": "$UNUSED_FILTER",
            "chunk_duration_sec": "$UNUSED_ROLLING",
            "replay_file": "$UNUSED_REPLAY",
            "ringbuffer": {"directory": "$PCAP_BUFFER_DIR", "max_total_size_mb": 100, "max_file_count": 5},
            "archive": {"directory": "$PCAP_ARCHIVE_DIR"},
        },
        "api": {"host": "127.0.0.1", "port": 9090},
        "log": {"level": "INFO", "file": "$PCAP_LOG_FILE"},
        "capture": {"type": "$CAPTURE_TYPE", "source": "$CAPTURE_SOURCE"},
        "influx": {"host": "$UNUSED_INFLUX_URL"},
    }


@pytest.mark.parametrize("source", [None, ""])
def test_none_loader_resolves_only_used_fields(source, monkeypatch, tmp_path):
    monkeypatch.setenv("CAPTURE_TYPE", "NONE")
    if source is None:
        monkeypatch.delenv("CAPTURE_SOURCE", raising=False)
    else:
        monkeypatch.setenv("CAPTURE_SOURCE", source)
    for key in ("UNUSED_FILTER", "UNUSED_ROLLING", "UNUSED_REPLAY", "UNUSED_INFLUX_URL"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("PCAP_BUFFER_DIR", "/tmp/buffer")
    monkeypatch.setenv("PCAP_ARCHIVE_DIR", "/tmp/archive")
    monkeypatch.setenv("PCAP_LOG_FILE", "recorder.log")
    settings = PcapRecorderSettings.from_json_for_intent(_write_tmp_config(tmp_path, _mode_payload()))
    assert settings.pcap.interface == ""
    assert settings.pcap.ringbuffer.directory == "/tmp/buffer"
    assert settings.pcap.archive.directory == "/tmp/archive"
    assert settings.log.file == "recorder.log"


@pytest.mark.parametrize("missing", ["PCAP_BUFFER_DIR", "PCAP_ARCHIVE_DIR", "PCAP_LOG_FILE"])
def test_none_loader_keeps_used_placeholders_strict(missing, monkeypatch, tmp_path):
    monkeypatch.setenv("CAPTURE_TYPE", "NONE")
    for key in ("PCAP_BUFFER_DIR", "PCAP_ARCHIVE_DIR", "PCAP_LOG_FILE"):
        monkeypatch.setenv(key, "synthetic-path")
    monkeypatch.delenv(missing)
    with pytest.raises(RuntimeError, match=missing):
        PcapRecorderSettings.from_json_for_intent(_write_tmp_config(tmp_path, _mode_payload()))


@pytest.mark.parametrize("source", [None, "", "eth 0", "../eth0", "-i", "a" * 16])
def test_live_loader_requires_safe_source_without_probing_devices(source, monkeypatch, tmp_path):
    monkeypatch.setenv("CAPTURE_TYPE", "LIVE")
    if source is None:
        monkeypatch.delenv("CAPTURE_SOURCE", raising=False)
    else:
        monkeypatch.setenv("CAPTURE_SOURCE", source)
    payload = _mode_payload()
    payload["pcap"].update(bpf_filter="", chunk_duration_sec=30, replay_file=None)
    for key in ("PCAP_BUFFER_DIR", "PCAP_ARCHIVE_DIR", "PCAP_LOG_FILE"):
        monkeypatch.setenv(key, "synthetic-path")
    with pytest.raises((ValueError, RuntimeError), match="CAPTURE_SOURCE"):
        PcapRecorderSettings.from_json_for_intent(_write_tmp_config(tmp_path, payload))


def test_live_loader_accepts_syntactically_valid_absent_interface(monkeypatch, tmp_path):
    monkeypatch.setenv("CAPTURE_TYPE", "LIVE")
    monkeypatch.setenv("CAPTURE_SOURCE", "absent-test0")
    payload = _mode_payload()
    payload["pcap"].update(bpf_filter="", chunk_duration_sec=30, replay_file=None)
    for key in ("PCAP_BUFFER_DIR", "PCAP_ARCHIVE_DIR", "PCAP_LOG_FILE"):
        monkeypatch.setenv(key, "synthetic-path")
    assert (
        PcapRecorderSettings.from_json_for_intent(_write_tmp_config(tmp_path, payload)).pcap.interface == "absent-test0"
    )


def test_absent_intent_and_source_load_idle_recorder_settings(monkeypatch, tmp_path):
    monkeypatch.delenv("CAPTURE_TYPE", raising=False)
    monkeypatch.delenv("CAPTURE_SOURCE", raising=False)
    payload = _mode_payload()
    for key in ("PCAP_BUFFER_DIR", "PCAP_ARCHIVE_DIR", "PCAP_LOG_FILE"):
        monkeypatch.setenv(key, "synthetic-path")
    del payload["pcap"]["interface"]
    settings = PcapRecorderSettings.from_json_for_intent(_write_tmp_config(tmp_path, payload))
    assert settings.pcap.interface == ""


@pytest.mark.parametrize("section,field", [("api", "port"), ("log", "file"), ("pcap", "archive")])
def test_none_loader_still_validates_used_configuration(section, field, monkeypatch, tmp_path):
    monkeypatch.setenv("CAPTURE_TYPE", "NONE")
    payload = _mode_payload()
    for key in ("PCAP_BUFFER_DIR", "PCAP_ARCHIVE_DIR", "PCAP_LOG_FILE"):
        monkeypatch.setenv(key, "synthetic-path")
    payload[section][field] = None
    with pytest.raises(ValidationError, match=field):
        PcapRecorderSettings.from_json_for_intent(_write_tmp_config(tmp_path, payload))
