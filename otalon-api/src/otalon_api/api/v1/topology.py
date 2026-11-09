"""Topology router.

Provides REST endpoints for querying the network topology graph,
the device inventory, and managing device type overrides.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from loguru import logger

from otalon_api.api.schemas.common import PaginationParams
from otalon_api.api.schemas.topology import (
    BulkDeviceTypeOverrideRequest,
    BulkDeviceTypeOverrideResponse,
    DeviceItem,
    DevicesResponse,
    DeviceTypeOverrideRequest,
    DeviceTypeOverrideResponse,
    SubnetProtocolsResponse,
)
from otalon_api.dependencies import get_postgres_repo, get_topology_service, require_api_key
from otalon_api.domain.topology.classification import VALID_DEVICE_TYPES
from otalon_api.repositories.postgres_repo import PostgresRepository
from otalon_api.services.topology_service import TopologyService  # noqa: F401  (used in handlers)

router = APIRouter(prefix="/api/v1/topology", tags=["topology"])


@router.get("/graph")
async def get_topology_graph(
    start: datetime,
    stop: datetime,
    node_limit: int = 100,
    include_anomalies: bool = True,
    service: TopologyService = Depends(get_topology_service),
) -> dict[str, Any]:
    """Build and return the network topology graph for a time range.

    The response contains ``nodes``, ``edges``, and ``meta`` keys
    matching the GD-10 golden-data format.

    Args:
        start: Range start timestamp.
        stop: Range end timestamp.
        node_limit: Maximum number of nodes to include in the graph.
        include_anomalies: Whether to flag anomalous nodes and edges.
        service: Injected topology service.

    Returns:
        A topology graph dict with nodes, edges, and metadata.
    """
    if start >= stop:
        raise HTTPException(status_code=400, detail="start must be before stop")

    try:
        result = await service.get_topology(
            start=start,
            stop=stop,
            node_limit=node_limit,
            include_anomalies=include_anomalies,
        )
    except ValueError as exc:
        logger.warning("get_topology_graph not found: {}", exc)
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.error("get_topology_graph failed: {}", exc)
        raise HTTPException(status_code=500, detail="Failed to build topology graph") from exc

    return result


@router.get("/devices", response_model=DevicesResponse)
async def get_devices(
    pagination: PaginationParams = Depends(),
    service: TopologyService = Depends(get_topology_service),
) -> DevicesResponse:
    """Return a paginated list of devices from the inventory.

    Args:
        pagination: Shared ``limit``/``offset`` query parameters
            (:class:`otalon_api.api.schemas.common.PaginationParams`).
        service: Injected topology service.

    Returns:
        A DevicesResponse with the device list and total count.
    """
    try:
        result = await service.get_devices(limit=pagination.limit, offset=pagination.offset)
    except Exception as exc:
        logger.error("get_devices failed: {}", exc)
        raise HTTPException(status_code=500, detail="Failed to query devices") from exc

    return DevicesResponse(**result)


@router.get("/subnet-protocols", response_model=SubnetProtocolsResponse)
async def get_subnet_protocols(
    subnet: str,
    service: TopologyService = Depends(get_topology_service),
) -> SubnetProtocolsResponse:
    """Return passive protocol tokens ever observed within *subnet*.

    The signal is binary (ever-seen; no time window in v1).  An edge
    counts when either its source or destination IP address falls inside
    the given CIDR.

    Args:
        subnet: IPv4 or IPv6 CIDR (e.g. ``"192.168.0.0/24"``).
        service: Injected topology service.

    Returns:
        A :class:`SubnetProtocolsResponse` with the protocol list and
        ``seen`` flag.

    Raises:
        HTTPException: 422 when *subnet* is not a valid CIDR.
        HTTPException: 500 on unexpected query failures.
    """
    try:
        ipaddress.ip_network(subnet, strict=False)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid CIDR: {subnet}") from exc

    try:
        result = await service.get_subnet_protocols(subnet=subnet)
    except Exception as exc:
        logger.error("get_subnet_protocols failed: {}", exc)
        raise HTTPException(status_code=500, detail="Failed to query subnet protocols") from exc

    return SubnetProtocolsResponse(**result)


@router.get("/devices/{device_id}", response_model=DeviceItem)
def get_device_by_id(
    device_id: int,
    postgres_repo: PostgresRepository = Depends(get_postgres_repo),
) -> DeviceItem:
    """Retrieve a single device by its primary key.

    Joins the device row with all of its network interfaces in a single
    response so the frontend detail panel can render IPs/MACs immediately.
    FastAPI runs this synchronous endpoint in a thread pool so the
    blocking psycopg2 call does not stall the event loop.

    Args:
        device_id: The device ID.
        postgres_repo: Injected PostgreSQL repository.

    Returns:
        A DeviceItem with the device data and joined interface list.

    Raises:
        HTTPException: 404 if the device is not found.
    """
    try:
        row = postgres_repo.query_device_by_id(device_id)
        interfaces_by_id = postgres_repo.query_network_interfaces_for_devices([device_id]) if row else {}
    except Exception as exc:
        logger.error("get_device_by_id failed for id={}: {}", device_id, exc)
        raise HTTPException(status_code=500, detail="Failed to query device") from exc

    if row is None:
        raise HTTPException(status_code=404, detail=f"Device {device_id} not found")

    payload = TopologyService._format_device_row(row, interfaces_by_id)
    return DeviceItem(**payload)


@router.put(
    "/devices/{device_id}/type",
    response_model=DeviceTypeOverrideResponse,
    dependencies=[Depends(require_api_key)],
)
async def update_device_type(
    device_id: int,
    body: DeviceTypeOverrideRequest,
    service: TopologyService = Depends(get_topology_service),
) -> DeviceTypeOverrideResponse:
    """Set or update the device type classification override for a device.

    Requires a valid API key via the ``X-API-Key`` header.

    Args:
        device_id: Primary key of the device in the ``devices`` table.
        body: Request body containing the new device type.
        service: Injected topology service.

    Returns:
        A DeviceTypeOverrideResponse confirming the update.

    Raises:
        HTTPException: 404 if the device does not exist.
        HTTPException: 422 if the device type is invalid.
    """
    device_type = body.device_type.strip()
    if device_type not in VALID_DEVICE_TYPES:
        raise HTTPException(
            status_code=422,
            detail=(f"Invalid device_type '{device_type}'. " f"Must be one of: {sorted(VALID_DEVICE_TYPES)}"),
        )

    try:
        result = await service.update_device_type(device_id=device_id, device_type=device_type)
    except ValueError as exc:
        logger.warning("update_device_type not found: {}", exc)
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.error("update_device_type failed for id={}: {}", device_id, exc)
        raise HTTPException(status_code=500, detail="Failed to update device type") from exc

    return result


@router.put(
    "/devices/types",
    response_model=BulkDeviceTypeOverrideResponse,
    dependencies=[Depends(require_api_key)],
)
async def bulk_update_device_types(
    body: BulkDeviceTypeOverrideRequest,
    service: TopologyService = Depends(get_topology_service),
) -> BulkDeviceTypeOverrideResponse:
    """Atomically set device-type overrides for multiple devices.

    Bulk variant of :func:`update_device_type`. PUT is used because the
    operation is idempotent — issuing the same request twice yields the
    same end state. The request is all-or-nothing: every ``device_id``
    must exist and every ``device_type`` must be valid before any
    override is written; the first validation failure short-circuits
    the request with 4xx and no state mutation.

    Validation rules mirror the single-device endpoint and the existing
    bulk-delete pattern in ``scans.py``:

    * The ``items`` list must contain 1..N entries (an empty list is
      rejected with 422 by the schema-level ``min_length=1``).
    * Duplicate ``device_id`` entries within the same request are
      rejected with 422 to avoid ambiguous last-write-wins semantics.
    * Any invalid ``device_type`` (not in :data:`VALID_DEVICE_TYPES`)
      rejects the whole request with 422.
    * Any unknown ``device_id`` rejects the whole request with 404.

    Requires a valid API key via the ``X-API-Key`` header.

    Args:
        body: Bulk request body with the override list.
        service: Injected topology service.

    Returns:
        A :class:`BulkDeviceTypeOverrideResponse` with one entry per
        applied override, in input order, and a ``count`` for clients
        that want to assert all items were applied.

    Raises:
        HTTPException: 422 on duplicate IDs or invalid device-type.
        HTTPException: 404 if any device does not exist.
        HTTPException: 500 on unexpected persistence failures.
    """
    seen: set[int] = set()
    duplicates: list[int] = []
    for item in body.items:
        if item.device_id in seen:
            duplicates.append(item.device_id)
        seen.add(item.device_id)
    if duplicates:
        raise HTTPException(
            status_code=422,
            detail=(
                "Duplicate device_id entries are not allowed in a single " f"bulk request: {sorted(set(duplicates))}"
            ),
        )

    invalid = [item.device_type for item in body.items if item.device_type.strip() not in VALID_DEVICE_TYPES]
    if invalid:
        raise HTTPException(
            status_code=422,
            detail=(
                f"Invalid device_type value(s): {sorted(set(invalid))}. "
                f"Must be one of: {sorted(VALID_DEVICE_TYPES)}"
            ),
        )

    items = [(item.device_id, item.device_type.strip()) for item in body.items]

    try:
        applied = await service.bulk_update_device_types(items)
    except ValueError as exc:
        logger.warning("bulk_update_device_types not found: {}", exc)
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.error("bulk_update_device_types failed: {}", exc)
        raise HTTPException(status_code=500, detail="Failed to apply bulk device type overrides") from exc

    return BulkDeviceTypeOverrideResponse(applied=applied, count=len(applied))
