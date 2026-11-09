"""Configuration models and helpers for the Netcap-to-Influx adapter.

Placeholder resolution is shared across this subproject's three packages via
``capture_settings_base.CaptureBaseSettings`` (SUITE-038).
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Union

from pydantic import BaseModel, ConfigDict, HttpUrl, SecretStr

from capture_settings_base import CaptureBaseSettings

JsonPath = Union[str, Path]


class CaptureType(str, Enum):
    """Supported capture modes for Netcap++."""

    PCAP = "PCAP"
    LIVE = "LIVE"


class InfluxConfig(BaseModel):
    """Configuration required to connect to InfluxDB."""

    host: HttpUrl
    token: SecretStr
    database: str
    measurement_name: str
    tags: List[str]
    fields: Dict[str, str]


class CaptureConfig(BaseModel):
    """Configuration for Netcap++ data acquisition."""

    source: str
    type: CaptureType
    interval: int


class WriteOptionsConfig(BaseModel):
    """Write buffering configuration for the InfluxDB client."""

    batch_size: int
    flush_interval: int
    jitter_interval: int
    precision: str


class LogConfig(BaseModel):
    """Logging configuration for the adapter."""

    level: str
    file: str
    verbose: bool = False


class PreprocessConfig(BaseModel):
    """Configuration for preprocessing steps applied before writing."""

    aggregate_sparse_ports: bool = True
    max_packet_count_single: int = 3
    emit_interval_ms: int = 1000


class MacAggregationConfig(BaseModel):
    """Configuration for real-time MAC aggregation pipeline."""

    enabled: bool = False
    emit_interval_ms: int = 1000


class ProtoAggregationConfig(BaseModel):
    """Configuration for real-time protocol aggregation pipeline."""

    enabled: bool = False
    emit_interval_ms: int = 1000


class Settings(CaptureBaseSettings):
    """Aggregate configuration model for the adapter."""

    # Declared explicitly: the shared base forbids extra keys, while this
    # model has always ignored them — the adapter's config.json carries a
    # top-level ``pcap`` block it does not declare (SUITE-038).
    model_config = ConfigDict(extra="ignore")

    influx: InfluxConfig
    capture: CaptureConfig
    write_options: WriteOptionsConfig
    log: LogConfig
    preprocess: PreprocessConfig = PreprocessConfig()
    mac_aggregation: MacAggregationConfig = MacAggregationConfig()
    proto_aggregation: ProtoAggregationConfig = ProtoAggregationConfig()
    mac_influx: Optional[InfluxConfig] = None
    proto_influx: Optional[InfluxConfig] = None
    protocol_map: Dict[int, str] = {}
