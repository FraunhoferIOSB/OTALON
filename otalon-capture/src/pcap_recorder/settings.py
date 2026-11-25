"""Pydantic-basierte Konfiguration fuer den PCAP-Recorder.

Placeholder resolution is shared across this subproject's three packages via
``capture_settings_base.CaptureBaseSettings`` (SUITE-038).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional, Self, Union

from otalon_common.config import MissingEnvVarPolicy, resolve_env_placeholders
from pydantic import BaseModel, ConfigDict, PositiveInt

from capture_runtime import CaptureIntent, resolve_capture_intent
from capture_settings_base import CaptureBaseSettings

JsonPath = Union[str, Path]


class RingbufferConfig(BaseModel):
    """Filesystem-bedingte Limits fuer den Ringpuffer."""

    directory: str
    max_total_size_mb: PositiveInt
    max_file_count: PositiveInt


class ArchiveConfig(BaseModel):
    """Konfiguration fuer archivierte PCAP-Chunks."""

    directory: str
    max_archive_gb: PositiveInt = 200
    max_age_days: PositiveInt = 90


class PcapConfig(BaseModel):
    """Quelle und tcpdump-Rollierung fuer den Recorder."""

    interface: str
    bpf_filter: str = ""
    chunk_duration_sec: PositiveInt
    ringbuffer: RingbufferConfig
    archive: ArchiveConfig
    replay_file: Optional[str] = None


class ApiConfig(BaseModel):
    """REST-API Endpunktdefinition."""

    host: str
    port: PositiveInt
    subprocess_timeout_s: PositiveInt = 30


class LogConfig(BaseModel):
    """Logging-Konfiguration fuer den Recorder."""

    level: str
    file: str


class PcapRecorderSettings(CaptureBaseSettings):
    """Gesamtkonfiguration des PCAP-Recorders."""

    # Declared explicitly: the shared base forbids extra keys, while this
    # model has always ignored them (SUITE-038).
    model_config = ConfigDict(extra="ignore")

    pcap: PcapConfig
    api: ApiConfig
    log: LogConfig

    @classmethod
    def from_json_for_intent(cls, path: JsonPath, intent: CaptureIntent | None = None) -> Self:
        """Load only recorder fields, removing unused acquisition fields in NONE.

        ``from_json`` keeps its established semantics. This boundary performs
        no interface-existence check or acquisition/credential initialization.
        """
        selected = resolve_capture_intent() if intent is None else CaptureIntent(intent)
        raw_data = json.loads(Path(path).read_text(encoding="utf-8"))
        raw_data = {name: value for name, value in raw_data.items() if name in cls.model_fields}
        pcap = raw_data.get("pcap")
        if selected is CaptureIntent.NONE and isinstance(pcap, dict):
            # Evidence paths/limits remain strict; rolling/filter/replay are not
            # used by idle REST and must not resolve acquisition prerequisites.
            raw_data["pcap"] = {
                **pcap,
                "interface": "",
                "bpf_filter": "",
                "chunk_duration_sec": 30,
                "replay_file": None,
            }
        resolved_data = resolve_env_placeholders(
            raw_data, policy=MissingEnvVarPolicy.RAISE, json_arrays=True, expand_nested=True
        )
        settings = cls.model_validate(resolved_data)
        if selected is CaptureIntent.LIVE and not re.fullmatch(
            r"[A-Za-z0-9_][A-Za-z0-9_.:-]{0,14}", settings.pcap.interface
        ):
            raise ValueError("CAPTURE_SOURCE must be a nonempty, syntactically safe native interface name.")
        return settings
