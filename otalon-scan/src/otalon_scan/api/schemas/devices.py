"""Pydantic wire models for the device endpoints (SCAN-033 extraction).

Moved verbatim out of :mod:`otalon_scan.api.server`; shapes unchanged.
"""

from __future__ import annotations

from typing import List, Literal, Optional

from pydantic import BaseModel, Field, model_validator

from .scans import ScanItem

__all__ = [
    "BulkDeleteDevicesRequest",
    "BulkDeleteDevicesResponse",
    "DeviceIdentityPatchRequest",
    "DeviceItem",
    "DeviceObservationsResponse",
    "DeviceScansResponse",
    "ServiceObservationItem",
]


class DeviceScansResponse(BaseModel):
    """Envelope for ``GET /devices/{device_id}/scans`` (B-E1).

    Lists every scan that produced an observation for the device. Wrapped
    in a ``scans`` key to mirror :class:`ScansListResponse`.
    """

    scans: List[ScanItem]


class ServiceObservationItem(BaseModel):
    """Single service-observation row for ``GET /devices/{id}/observations``.

    Flat projection of :class:`~otalon_scan.repositories.models.ServiceObservation`
    with ISO-8601 timestamps so the wire shape is JSON-portable.
    """

    id: int
    scan_id: str
    interface_id: Optional[int] = None
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    port: Optional[int] = None
    transport: Optional[str] = None
    protocol: Optional[str] = None
    service_name: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    cpe: Optional[str] = None
    extra_info: Optional[str] = None
    first_seen_at: Optional[str] = None
    last_seen_at: Optional[str] = None


class DeviceObservationsResponse(BaseModel):
    """Envelope for ``GET /devices/{device_id}/observations`` (B-E1)."""

    observations: List[ServiceObservationItem]


class DeviceIdentityPatchRequest(BaseModel):
    """Operator manual-override body for ``PATCH /devices/{id}`` (SCAN-023).

    Every field is optional; only the supplied ones are written AND
    locked against scan-overwrite (mirrors
    :class:`VulnerabilityPatchRequest`). ``extra="forbid"`` rejects any
    non-identity key with HTTP 422 so a typo cannot silently no-op. At
    least one field must be present (enforced by the validator).
    """

    model_config = {"extra": "forbid"}

    vendor: Optional[str] = None
    device_family: Optional[str] = None
    device_type: Optional[
        Literal[
            "Application Server",
            "Control Server",
            "Data Gateway",
            "Data Historian",
            "DCS Controller",
            "Field I/O",
            "Firewall",
            "HMI",
            "IED",
            "Jump Host",
            "PAC",
            "PLC",
            "RTU",
            "Routers",
            "Safety Controller",
            "Switch",
            "VPN Server",
            "Workstation",
            "Other",
        ]
    ] = None
    article_number: Optional[str] = None
    firmware_version: Optional[str] = None
    product_name: Optional[str] = None
    hw_version: Optional[str] = None
    sw_version: Optional[str] = None

    @model_validator(mode="after")
    def _at_least_one_field(self) -> "DeviceIdentityPatchRequest":
        """Reject an empty patch body (no identity field supplied)."""
        if not self.model_fields_set:
            raise ValueError("at least one identity field must be supplied")
        return self


class DeviceItem(BaseModel):
    """Device identity projection returned by ``PATCH /devices/{id}``.

    Flat wire shape of a :class:`~otalon_scan.repositories.models.Device` carrying
    the eight lockable identity fields, the ``manual_identity_fields``
    lock set (so the UI can render a per-field "manual" marker and
    re-evaluate the lookup-eligibility indicator), and ISO-8601
    timestamps.
    """

    id: int
    primary_mac: Optional[str] = None
    # P8 Welle A (F-04/F-10): discovered network name, distinct from
    # ``device_type``. Read-only projection — not operator-lockable, so it
    # is intentionally absent from ``DeviceIdentityPatchRequest``.
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    device_family: Optional[str] = None
    device_type: Optional[str] = None
    article_number: Optional[str] = None
    firmware_version: Optional[str] = None
    product_name: Optional[str] = None
    hw_version: Optional[str] = None
    sw_version: Optional[str] = None
    manual_identity_fields: List[str] = Field(default_factory=list)
    last_scan_at: Optional[str] = None


class BulkDeleteDevicesRequest(BaseModel):
    """Request body for ``DELETE /devices`` (bulk reaper).

    The ``ids`` list MUST contain between 1 and 500 positive integer
    device primary-keys. Empty lists are rejected with HTTP 422 — that
    is a client bug, not a no-op; the single-delete endpoint exists for
    the one-id case. The 500-id ceiling caps the blast radius of a
    runaway operator action.
    """

    ids: List[int] = Field(
        ...,
        min_length=1,
        max_length=500,
        description="List of devices.id primary keys to hard-delete.",
    )

    @model_validator(mode="after")
    def _positive_ids(self) -> "BulkDeleteDevicesRequest":
        """Reject non-positive device primary keys."""
        for i in self.ids:
            if i <= 0:
                raise ValueError("device ids must be positive integers")
        return self


class BulkDeleteDevicesResponse(BaseModel):
    """Response body for ``DELETE /devices`` (bulk reaper).

    Reports which ids were actually removed (``deleted``) and which did
    not match any ``devices`` row (``not_found``). Per-id 404s are
    intentionally absent — the bulk endpoint succeeds as long as the
    transaction commits, even if some ids did not exist.
    """

    deleted: List[int] = Field(default_factory=list, description="Ids that existed and were removed.")
    not_found: List[int] = Field(default_factory=list, description="Ids that did not match any devices row.")
