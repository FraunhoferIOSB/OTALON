"""Pydantic schemas for the PCAP proxy endpoints.

Mirrors the ``ChunkResponse`` contract exposed by the upstream PCAP
recorder at ``GET /chunks`` (port 9090). Fields are kept loose
(``str | None`` for timestamps) because the recorder may serialise
timestamps either as ISO-8601 with or without timezone offset depending
on its own settings; the proxy forwards them verbatim.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class PcapChunkSummary(BaseModel):
    """Metadata for a single PCAP chunk file held by the recorder.

    Mirrors the upstream ``ChunkResponse`` model. The proxy does not
    re-render packets; clients use ``download_url`` to fetch the raw
    PCAP via the recorder's ``GET /chunks/{chunk_id}`` endpoint.
    """

    chunk_id: str = Field(..., description="Chunk filename, e.g. '20260213_090000.pcap'.")
    start_ts: str | None = Field(default=None, description="Chunk start timestamp (ISO 8601).")
    end_ts: str | None = Field(default=None, description="Chunk end timestamp (ISO 8601).")
    size_bytes: int = Field(default=0, description="PCAP file size on disk in bytes.")
    is_anomaly: bool = Field(default=False, description="Whether the chunk was flagged as an anomaly.")
    labels: dict[str, Any] = Field(default_factory=dict, description="Free-form labels attached on flagging.")
    download_url: str = Field(
        ...,
        description=(
            "Relative URL on this API that streams the raw PCAP chunk "
            "(reserved for a future ``GET /api/v1/pcap/chunk/{chunk_id}`` "
            "endpoint). The current MVP exposes the metadata only; the "
            "frontend can compose its own ZIP from these IDs or call the "
            "recorder directly inside the trusted network."
        ),
    )


class PcapByAlarmResponse(BaseModel):
    """Response envelope for ``GET /api/v1/pcap/by-alarm/{alarm_id}``.

    Returns the time window taken from the alarm group plus all PCAP
    chunks the recorder holds that overlap that window. The recorder is
    the source of truth for which chunks still exist on disk; chunks
    older than the ringbuffer retention may be absent.
    """

    alarm_id: str = Field(..., description="Alarm group UUID this PCAP set belongs to.")
    start_ts: str = Field(
        ...,
        description="Alarm start timestamp (UTC ISO 8601) used to query the recorder.",
    )
    end_ts: str = Field(
        ...,
        description="Alarm end timestamp (UTC ISO 8601) used to query the recorder.",
    )
    chunk_count: int = Field(..., description="Number of chunks the recorder returned.")
    total_size_bytes: int = Field(..., description="Sum of ``size_bytes`` across returned chunks.")
    chunks: list[PcapChunkSummary] = Field(default_factory=list, description="Chunk metadata list.")
