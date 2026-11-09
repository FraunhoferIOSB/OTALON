"""Device router (SCAN-033 extraction).

Owns the device surface: bulk delete, single delete, operator identity
patch, per-device scan listing and per-device service observations.

The repository is *injected* as ``Optional`` and narrowed with
:func:`require_repo` in the handler body rather than by a raising
``Depends``. FastAPI resolves dependencies before it validates the request
body, so a raising dependency would turn the bulk endpoints' 422 into a
500. See :mod:`otalon_scan.api.dependencies`.

Logging note (SCAN-034): stdlib ``logging`` call sites moved verbatim.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Response
from loguru import logger

from ...core.auth import verify_api_key
from ...repositories.postgres_repo import ScannerPostgresRepo
from ..dependencies import get_optional_repo, require_repo
from ..schemas.devices import (
    BulkDeleteDevicesRequest,
    BulkDeleteDevicesResponse,
    DeviceIdentityPatchRequest,
    DeviceItem,
    DeviceObservationsResponse,
    DeviceScansResponse,
)
from ..serializers import device_row_to_item, observation_row_to_item, scan_row_to_item

__all__ = ["router"]

router = APIRouter()


@router.delete(
    "/devices",
    response_model=BulkDeleteDevicesResponse,
    status_code=200,
    dependencies=[Depends(verify_api_key("operator"))],
)
async def delete_devices_bulk(
    payload: BulkDeleteDevicesRequest,
    repo: Optional[ScannerPostgresRepo] = Depends(get_optional_repo),
) -> BulkDeleteDevicesResponse:
    """Hard-delete a batch of devices atomically in a single transaction.

    Bulk counterpart to ``DELETE /devices/{device_id}``. The
    repository helper :meth:`ScannerPostgresRepo.delete_devices`
    cascades the same FK chain explicitly so the underlying
    ``SET NULL`` defaults do not orphan child rows.

    The endpoint returns HTTP 200 (not 204) because the response body
    carries the per-id outcome so the caller can surface a
    ``"X deleted, Y not found"`` notice without an extra round-trip.

    Returns:
        :class:`BulkDeleteDevicesResponse` with the two id arrays.

    Raises:
        HTTPException: 500 when the repository is not initialised
            (e.g. lifespan startup did not complete).
    """
    repository = require_repo(repo)
    result = await repository.delete_devices(payload.ids)
    logger.bind(
        requested=len(payload.ids),
        deleted=len(result["deleted"]),
        not_found=len(result["not_found"]),
    ).info("devices bulk deleted")
    return BulkDeleteDevicesResponse(
        deleted=result["deleted"], not_found=result["not_found"]
    )


@router.delete(
    "/devices/{device_id}",
    status_code=204,
    dependencies=[Depends(verify_api_key("operator"))],
)
async def delete_device(
    device_id: int,
    repo: Optional[ScannerPostgresRepo] = Depends(get_optional_repo),
) -> Response:
    """Hard-delete a device and all of its descendants.

    Removes the ``devices`` row, every linked ``network_interfaces``
    row, and every ``service_observations`` / ``vulnerability_observations``
    row referencing them — atomically, in one transaction. The
    operation is irreversible (no archival / soft-delete column); see
    :meth:`ScannerPostgresRepo.delete_device` for the cascade order
    and the rationale.

    Returns:
        HTTP 204 with no body on success.

    Raises:
        HTTPException: 404 when no ``devices`` row matches ``device_id``.
        HTTPException: 500 when the repository is not initialised
            (e.g. lifespan startup did not complete).
    """
    repository = require_repo(repo)
    deleted = await repository.delete_device(device_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Device not found")
    logger.bind(device_id=device_id).info("device deleted")
    return Response(status_code=204)


@router.patch(
    "/devices/{device_id}",
    response_model=DeviceItem,
    dependencies=[Depends(verify_api_key("operator"))],
)
async def patch_device_identity(
    device_id: int,
    payload: DeviceIdentityPatchRequest,
    repo: Optional[ScannerPostgresRepo] = Depends(get_optional_repo),
) -> DeviceItem:
    """Manually override identity fields of a device (SCAN-023).

    Operator-key auth (``operator`` scope), mirroring
    ``DELETE /devices/{device_id}``. Writes the supplied identity fields
    AND locks them in ``manual_identity_fields`` so a subsequent scan
    keeps the manual value instead of overwriting it
    (:meth:`ScannerPostgresRepo.set_manual_identity`). Returns the updated
    device so the UI can re-render the per-field "manual" marker and
    re-evaluate the lookup-eligibility indicator.

    Only fields explicitly present in the request body are written; a
    field set to ``null`` clears its value but still locks it.

    Returns:
        :class:`DeviceItem` with the updated identity fields and lock set.

    Raises:
        HTTPException: 404 when no ``devices`` row matches ``device_id``.
        HTTPException: 422 when the body validates but the repository
            rejects the field set (defensive — schema already filters).
        HTTPException: 500 when the repository is not initialised.
    """
    repository = require_repo(repo)
    fields = payload.model_dump(exclude_unset=True)
    try:
        row = await repository.set_manual_identity(device_id, fields)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if row is None:
        raise HTTPException(status_code=404, detail="Device not found")
    logger.bind(device_id=device_id, locked_fields=sorted(fields)).info(
        "device identity manually set"
    )
    return device_row_to_item(row)


@router.get(
    "/devices/{device_id}/scans",
    response_model=DeviceScansResponse,
    dependencies=[Depends(verify_api_key("viewer"))],
)
async def list_device_scans(
    device_id: int,
    repo: Optional[ScannerPostgresRepo] = Depends(get_optional_repo),
) -> DeviceScansResponse:
    """List scans that produced observations for a device (B-E1).

    Returns HTTP 200 with ``{"scans": [...]}`` — an empty list when the
    device exists but no scan has touched it. Raises a fachliche 404 when
    the device itself does not exist (distinct from a FastAPI route-miss).
    """
    repository = require_repo(repo)
    if not await repository.device_exists(device_id):
        raise HTTPException(status_code=404, detail=f"device {device_id} not found")
    rows = await repository.list_device_scans(device_id)
    return DeviceScansResponse(scans=[scan_row_to_item(r) for r in rows])


@router.get(
    "/devices/{device_id}/observations",
    response_model=DeviceObservationsResponse,
    dependencies=[Depends(verify_api_key("viewer"))],
)
async def list_device_observations(
    device_id: int,
    repo: Optional[ScannerPostgresRepo] = Depends(get_optional_repo),
) -> DeviceObservationsResponse:
    """List service observations for a device's interfaces (B-E1).

    Returns HTTP 200 with ``{"observations": [...]}`` — an empty list when
    the device exists but has no observations. Raises a fachliche 404 when
    the device itself does not exist (distinct from a FastAPI route-miss).
    """
    repository = require_repo(repo)
    if not await repository.device_exists(device_id):
        raise HTTPException(status_code=404, detail=f"device {device_id} not found")
    rows = await repository.list_device_observations(device_id)
    return DeviceObservationsResponse(
        observations=[observation_row_to_item(r) for r in rows]
    )
