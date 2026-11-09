"""Pure identity-cutoff selector for the CVE lookup (Welle A / D4).

The hard cutoff (design.md § D4): a device is only ever queued for a CVE
lookup when it has a COMPLETE identity — a non-empty ``vendor`` AND
``product`` AND ``version``. This trades a missed vulnerability for the
absence of false-positive noise, per the operator's security guard-rail
(CONCEPT §1). For every non-eligible device the selector emits the list
of missing identity fields so the operator can see exactly what to
back-fill ("Identität unvollständig" surface, Fork 3).

This module is intentionally pure and DB-free: it operates on
:class:`DeviceIdentity` value objects so it is trivially unit-testable
against the two spec scenarios. The repository layer
(:meth:`otalon_scan.repositories.postgres_repo.ScannerPostgresRepo.lookup_eligible_devices`)
reads ``devices`` rows, maps them to :class:`DeviceIdentity`, and applies
:func:`select_eligible`.
"""

from __future__ import annotations

from typing import Iterable, Optional

from pydantic import BaseModel, ConfigDict

# Canonical missing-field labels — mirror the ``devices`` column names so
# the UI can key tooltips/badges off them directly (Fork 3 / Task 1.3).
FIELD_VENDOR = "vendor"
FIELD_PRODUCT = "product_name"
FIELD_VERSION = "firmware_version"


def _is_blank(value: Optional[str]) -> bool:
    """Return ``True`` when ``value`` is ``None`` or whitespace-only."""
    return value is None or not value.strip()


class DeviceIdentity(BaseModel):
    """The identity-relevant view of a ``devices`` row.

    Only the three cutoff fields plus the device id are carried; the
    selector never needs the rest of the row. ``product`` maps onto the
    ``devices.product_name`` column and ``version`` onto
    ``devices.firmware_version`` (the D4 "version" axis).
    """

    model_config = ConfigDict(frozen=True)

    device_id: int
    vendor: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None


class EligibilityResult(BaseModel):
    """Outcome of the identity cutoff for a single device.

    Attributes:
        device_id: The ``devices.id`` evaluated.
        eligible: ``True`` only when vendor AND product AND version are
            all non-empty.
        missing_fields: Ordered list of the cutoff fields that are empty
            (``vendor`` / ``product_name`` / ``firmware_version``).
            Empty when ``eligible`` is ``True``.
    """

    model_config = ConfigDict(frozen=True)

    device_id: int
    eligible: bool
    missing_fields: list[str]


def evaluate_eligibility(identity: DeviceIdentity) -> EligibilityResult:
    """Apply the D4 identity cutoff to a single device identity.

    Args:
        identity: The device's identity view.

    Returns:
        An :class:`EligibilityResult`; ``eligible`` is ``True`` only when
        none of the three cutoff fields is blank, otherwise
        ``missing_fields`` names every blank field in
        vendor → product → version order.
    """
    missing: list[str] = []
    if _is_blank(identity.vendor):
        missing.append(FIELD_VENDOR)
    if _is_blank(identity.product):
        missing.append(FIELD_PRODUCT)
    if _is_blank(identity.version):
        missing.append(FIELD_VERSION)
    return EligibilityResult(
        device_id=identity.device_id,
        eligible=not missing,
        missing_fields=missing,
    )


def select_eligible(identities: Iterable[DeviceIdentity]) -> list[EligibilityResult]:
    """Partition a batch of identities by the D4 cutoff.

    Args:
        identities: Device identity views to evaluate.

    Returns:
        One :class:`EligibilityResult` per input identity, preserving
        input order. No partial-identity device is ever marked eligible.
    """
    return [evaluate_eligibility(identity) for identity in identities]
