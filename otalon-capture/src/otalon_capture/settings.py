"""Configuration models and helpers for the Netcap-to-Influx adapter.

Placeholder resolution is shared across this subproject's three packages via
``capture_settings_base.CaptureBaseSettings`` (SUITE-038).
"""

from __future__ import annotations

import json
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Self, Union

from otalon_common.config import MissingEnvVarPolicy, resolve_env_placeholders
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

    @classmethod
    def for_import_file(cls, path: JsonPath, file_path: JsonPath) -> Self:
        """Override the contained input/internal PCAP mode before strict resolution.

        The runner owns path containment. Only declared adapter fields are
        resolved, preserving extra-ignore without requiring recorder variables.
        """
        raw_data = json.loads(Path(path).read_text(encoding="utf-8"))
        raw_data = {name: value for name, value in raw_data.items() if name in cls.model_fields}
        capture = raw_data.get("capture", {})
        if isinstance(capture, dict):
            raw_data["capture"] = {**capture, "source": str(file_path), "type": CaptureType.PCAP.value}
        resolved_data = resolve_env_placeholders(
            raw_data, policy=MissingEnvVarPolicy.RAISE, json_arrays=True, expand_nested=True
        )
        return cls.model_validate(resolved_data)
