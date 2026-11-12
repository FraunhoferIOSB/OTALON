"""Select only receiver metric sections before strict environment resolution."""

from otalon_capture.settings import (
    InfluxConfig,
    MacAggregationConfig,
    PreprocessConfig,
    ProtoAggregationConfig,
    WriteOptionsConfig,
)
from pydantic import BaseModel, ConfigDict, Field


class ReliablePipelineSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    interval_ms: int = Field(ge=1, le=3600000)
    influx: InfluxConfig
    mac_influx: InfluxConfig | None = None
    proto_influx: InfluxConfig | None = None
    write_options: WriteOptionsConfig
    preprocess: PreprocessConfig = PreprocessConfig()
    mac_aggregation: MacAggregationConfig = MacAggregationConfig()
    proto_aggregation: ProtoAggregationConfig = ProtoAggregationConfig()
    protocol_map: dict[int, str] = {}
