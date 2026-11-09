"""Topology domain schemas.

Defines internal Pydantic data models for network topology nodes, edges,
graph structures, and device inventory items.  Field names and types are
derived from GD-10 (topology graph) and GD-13 (devices table).
"""

from __future__ import annotations

from typing import Any, Union

from pydantic import BaseModel, Field


class NodeMeta(BaseModel):
    """Metadata for a resolved topology node backed by a ``devices`` row."""

    name: str = ""
    alias: str = ""
    device_type_name: str = ""
    device_role: str = ""
    mac: str = ""
    ip4: list[str] = Field(default_factory=list)


class UnresolvedNodeMeta(BaseModel):
    """Metadata for an unresolved topology node (not in ``devices``)."""

    mac: str = ""
    ip: str = ""


class TopologyNode(BaseModel):
    """Single node in the topology graph.

    Resolved nodes use :class:`NodeMeta`, unresolved ones
    :class:`UnresolvedNodeMeta`.
    """

    id: str
    label: str
    type: str = "Other"
    is_anomaly: bool = False
    meta: Union[NodeMeta, UnresolvedNodeMeta] = Field(default_factory=UnresolvedNodeMeta)


class EdgeMeta(BaseModel):
    """Metadata attached to a topology edge."""

    ucis: list[str] = Field(default_factory=list)
    protocols: list[str] = Field(default_factory=list)
    src_ports: list[str] = Field(default_factory=list)
    dst_ports: list[str] = Field(default_factory=list)
    wildcard: str = ""


class TopologyEdge(BaseModel):
    """Single directed edge between two topology nodes."""

    id: str
    source: str
    target: str
    label: str = ""
    is_anomaly: bool = False
    meta: EdgeMeta = Field(default_factory=EdgeMeta)


class TopologyGraphMeta(BaseModel):
    """Summary metadata for a topology graph response."""

    node_count: int
    edge_count: int
    truncated: bool = False


class TopologyGraph(BaseModel):
    """Full topology graph with nodes, edges, and metadata."""

    nodes: list[TopologyNode]
    edges: list[TopologyEdge]
    meta: TopologyGraphMeta


class SubnetProtocolsResponse(BaseModel):
    """Passive protocol signal for a subnet."""

    subnet: str
    protocols: list[str] = Field(default_factory=list)
    seen: bool = False


class NetworkInterfaceItem(BaseModel):
    """Single network interface attached to a device."""

    id: int
    mac_address: str | None = None
    ipv4_address: str | None = None
    ipv6_address: str | None = None
    subnet: str | None = None
    open_ports_summary: Any = None
    last_scan_at: str | None = None
    notes: str | None = None
    source: str | None = None


class DeviceItem(BaseModel):
    """Single device row from the ``devices`` PostgreSQL table (GD-13).

    Nullable string fields default to ``None`` to mirror the DB schema.
    The ``interfaces`` field carries the joined ``network_interfaces`` rows
    so that frontend tables can show MAC/IP addresses without an extra round trip.
    """

    id: int
    # P8 Welle A (F-04/F-10): the device's discovered network name
    # (PROFINET station-name / SNMP ``sysName``), distinct from
    # ``device_type``. Sourced from the otalon-scan ``devices.hostname``
    # column; the UI (Welle B) renders it as its own column / detail field.
    hostname: str | None = None
    vendor: str | None = None
    device_family: str | None = None
    device_type: str | None = None
    description: str | None = None
    article_number: str | None = None
    device_role: str | None = None
    firmware_version: str | None = None
    # SCAN-018 SNMP asset master-data (otalon-scan ``devices`` columns).
    product_name: str | None = None
    hw_version: str | None = None
    sw_version: str | None = None
    serial_number: str | None = None
    vulnerabilities: Any = None
    update_available: bool = False
    last_scan_at: str | None = None
    notes: str | None = None
    created_at: str | None = None
    updated_at: str | None = None
    interfaces: list[NetworkInterfaceItem] = Field(default_factory=list)


class DevicesResponse(BaseModel):
    """Paginated device list response."""

    devices: list[DeviceItem]
    total: int


class DeviceTypeOverrideRequest(BaseModel):
    """Request body for updating a device's type classification override."""

    device_type: str = Field(
        ...,
        min_length=1,
        description="New device type classification (e.g. PLC, IPC, IO, HMI, Other)",
    )


class DeviceTypeOverrideResponse(BaseModel):
    """Response after successfully updating a device type override."""

    device_id: int
    device_type: str
    previous_type: str | None = None
    message: str = "Device type override applied"


class DeviceTypeOverrideItem(BaseModel):
    """Single item in a bulk device-type override request.

    Attributes:
        device_id: Primary key of the device in the ``devices`` table.
        device_type: Target device-type classification.
    """

    device_id: int = Field(..., description="Device primary key")
    device_type: str = Field(
        ...,
        min_length=1,
        description="New device type classification (e.g. PLC, IPC, IO, HMI, Other)",
    )


class BulkDeviceTypeOverrideRequest(BaseModel):
    """Request body for the bulk device-type override endpoint.

    The list must contain at least one item. Duplicate ``device_id``
    entries are rejected so callers cannot accidentally race two
    target values for the same device within a single request — the
    last-write-wins semantics that would otherwise apply make the
    intended outcome ambiguous.
    """

    items: list[DeviceTypeOverrideItem] = Field(
        ...,
        min_length=1,
        description="Non-empty list of (device_id, device_type) overrides.",
    )


class BulkDeviceTypeOverrideResponse(BaseModel):
    """Response after a successful bulk device-type override request.

    Attributes:
        applied: Per-item override responses, in the same order as the
            request.
        count: Number of overrides applied (equals ``len(applied)``).
    """

    applied: list[DeviceTypeOverrideResponse]
    count: int


def node_to_response_dict(node: TopologyNode) -> dict[str, Any]:
    """Serialize a :class:`TopologyNode` to a GD-10 compatible dict.

    Uses ``isAnomaly`` (camelCase) for backward compatibility with the
    existing golden-data format.

    Args:
        node: The topology node to serialize.

    Returns:
        Dictionary matching the GD-10 JSON structure.
    """
    return {
        "id": node.id,
        "label": node.label,
        "type": node.type,
        "isAnomaly": node.is_anomaly,
        "meta": node.meta.model_dump(),
    }


def edge_to_response_dict(edge: TopologyEdge) -> dict[str, Any]:
    """Serialize a :class:`TopologyEdge` to a GD-10 compatible dict.

    Args:
        edge: The topology edge to serialize.

    Returns:
        Dictionary matching the GD-10 JSON structure.
    """
    return {
        "id": edge.id,
        "source": edge.source,
        "target": edge.target,
        "label": edge.label,
        "isAnomaly": edge.is_anomaly,
        "meta": edge.meta.model_dump(),
    }
