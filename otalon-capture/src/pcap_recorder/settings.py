"""Pydantic-basierte Konfiguration fuer den PCAP-Recorder.

Placeholder resolution is shared across this subproject's three packages via
``capture_settings_base.CaptureBaseSettings`` (SUITE-038).
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Union

from pydantic import BaseModel, ConfigDict, PositiveInt

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
