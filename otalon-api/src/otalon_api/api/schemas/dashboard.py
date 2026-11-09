"""Pydantic v2 request/response schemas for dashboard API endpoints.

Covers:
- GD-09: Dashboard KPIs (signal color + aggregated counts)
- B-20: Network throughput sparkline
- F-13: Top connections sparkline data
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class WidgetLayoutItem(BaseModel):
    """Single grid-layout item for the dashboard.

    Attributes:
        i: Widget identifier (must match an entry in the frontend registry).
        x: Horizontal position in 8-column grid.
        y: Vertical position in grid rows.
        w: Width in columns.
        h: Height in rows.
    """

    i: str = Field(..., max_length=64)
    x: int = Field(..., ge=0, le=7)
    y: int = Field(..., ge=0, le=1000)
    w: int = Field(..., ge=1, le=8)
    h: int = Field(..., ge=1, le=8)


class DashboardLayoutPayload(BaseModel):
    """Persistent dashboard layout document (UI-018).

    Matches the frontend ``PersistedPayload`` so the store can round-trip
    the document without translation.

    Attributes:
        version: Schema version, currently fixed at 2.
        layout: Grid geometry for every known widget.
        hidden: Identifiers of widgets currently hidden from view.
    """

    version: Literal[2]
    layout: list[WidgetLayoutItem] = Field(..., max_length=64)
    hidden: list[str] = Field(..., max_length=64)


class TourStatePayload(BaseModel):
    """Global per-account tour-completion flag (UI-200).

    Attributes:
        completed: Whether the onboarding tour is completed account-wide.
    """

    completed: bool


class TopConnectionItem(BaseModel):
    """Single entry in the top connections ranking.

    Attributes:
        uci: Unique communication identifier.
        packet_count: Total packets for this connection in the time window.
        byte_count: Total bytes for this connection in the time window.
        is_anomaly: Whether this UCI appears in an active unconfirmed alarm group.
        sparkline: Approximately 12 data points of total_volume per 5-minute
            bucket over the last hour, suitable for rendering a mini sparkline.
    """

    uci: str
    packet_count: int
    byte_count: int
    is_anomaly: bool = False
    sparkline: list[int] = []


class DashboardKpisData(BaseModel):
    """Dashboard KPI data object (GD-09).

    Attributes:
        signal_color: Traffic-light indicator (``"success"``, ``"warning"``, ``"danger"``).
        anomaly_count: Total number of anomaly alarm groups.
        classified_count: Number of classified (non-active) alarm groups.
        device_count: Number of known devices from CyberScan-ICS.
        protocol_count: Number of distinct protocols observed in the window.
        connection_count: Number of monitored connections (UCI count).
        top_connections: Ranked list of the busiest connections.
    """

    signal_color: Literal["success", "warning", "danger"]
    anomaly_count: int
    classified_count: int
    device_count: int
    protocol_count: int
    connection_count: int
    top_connections: list[TopConnectionItem] = []


class DashboardKpisResponse(BaseModel):
    """Response envelope for dashboard KPIs (GD-09)."""

    data: list[DashboardKpisData]
    row_count: int
    parameters: dict[str, Any]


class ThroughputDataPoint(BaseModel):
    """Single data point in the throughput time series (B-20)."""

    timestamp: str
    total_bytes: int
    total_packets: int


class TopAssetItem(BaseModel):
    """Single entry in the top assets (MAC) ranking.

    Attributes:
        id: MAC address.
        packet_count: Total packets for this MAC in the time window.
        byte_count: Total bytes for this MAC in the time window.
        is_anomaly: Whether this MAC appears in an active unconfirmed
            alarm group for module ``mac_traffic``.
        sparkline: Approximately 12 data points of total bytes per
            bucket over the window, suitable for a mini sparkline.
    """

    id: str
    packet_count: int
    byte_count: int
    is_anomaly: bool = False
    sparkline: list[int] = []


class TopProtocolItem(BaseModel):
    """Single entry in the top protocols ranking.

    Attributes:
        id: Protocol stack identifier (plaintext).
        protocol: Human-readable protocol label (same as *id*).
        packet_count: Total packets for this protocol in the time window.
        byte_count: Total bytes for this protocol in the time window.
        is_anomaly: Whether this protocol appears in an active unconfirmed
            alarm group for module ``proto_traffic``.
        sparkline: Approximately 12 data points of total bytes per
            bucket over the window, suitable for a mini sparkline.
    """

    id: str
    protocol: str
    packet_count: int
    byte_count: int
    is_anomaly: bool = False
    sparkline: list[int] = []


class TopAssetsResponse(BaseModel):
    """Response envelope for top assets endpoint."""

    data: list[TopAssetItem]
    row_count: int
    parameters: dict[str, Any]


class TopProtocolsResponse(BaseModel):
    """Response envelope for top protocols endpoint."""

    data: list[TopProtocolItem]
    row_count: int
    parameters: dict[str, Any]


class VulnerabilitySummaryData(BaseModel):
    """Dashboard vulnerability summary data."""

    affected_device_count: int
    total_cve_count: int
    severity_breakdown: dict[str, int]
    top_cves: list[dict[str, Any]]


class VulnerabilitySummaryResponse(BaseModel):
    """Response envelope for the dashboard vulnerability summary endpoint."""

    data: VulnerabilitySummaryData
    parameters: dict[str, Any]


class ThroughputResponse(BaseModel):
    """Response for the network throughput sparkline endpoint (B-20)."""

    data: list[ThroughputDataPoint]
    bucket_seconds: int
    parameters: dict[str, Any]
