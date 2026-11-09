"""SUITE-060: the shipped capture config must not default to DEBUG (GB log volume)."""

from __future__ import annotations

import json
from pathlib import Path

CONFIG_PATH = Path(__file__).resolve().parents[2] / "config" / "config_pcap.json"


def test_shipped_config_log_level_is_not_debug() -> None:
    payload = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    assert payload["log"]["level"] != "DEBUG", "shipped default must not be DEBUG (SUITE-060)"
    assert payload["log"]["level"] == "INFO"
