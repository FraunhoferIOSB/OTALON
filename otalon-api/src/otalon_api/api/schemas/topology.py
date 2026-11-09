"""Topology API response schemas.

Re-exports domain models for use in API router type annotations and
response-model declarations.  The domain schemas already match the
GD-10 / GD-13 golden-data structures, so no API-specific wrappers
are required at this time.
"""

from __future__ import annotations

from otalon_api.domain.topology.schemas import (
    BulkDeviceTypeOverrideRequest,
    BulkDeviceTypeOverrideResponse,
    DeviceItem,
    DevicesResponse,
    DeviceTypeOverrideItem,
    DeviceTypeOverrideRequest,
    DeviceTypeOverrideResponse,
    EdgeMeta,
    NetworkInterfaceItem,
    NodeMeta,
    SubnetProtocolsResponse,
    TopologyEdge,
    TopologyGraph,
    TopologyGraphMeta,
    TopologyNode,
    UnresolvedNodeMeta,
)

__all__ = [
    "BulkDeviceTypeOverrideRequest",
    "BulkDeviceTypeOverrideResponse",
    "DeviceItem",
    "DevicesResponse",
    "DeviceTypeOverrideItem",
    "DeviceTypeOverrideRequest",
    "DeviceTypeOverrideResponse",
    "EdgeMeta",
    "NetworkInterfaceItem",
    "NodeMeta",
    "SubnetProtocolsResponse",
    "TopologyEdge",
    "TopologyGraph",
    "TopologyGraphMeta",
    "TopologyNode",
    "UnresolvedNodeMeta",
]
