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
