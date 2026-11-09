"""Unit tests for the CVE-lookup identity cutoff (Welle A / Task 1.3).

Pins the two spec scenarios from
``openspec/changes/cve-lookup/specs/scan--device-identity-enrichment/spec.md``:

- Complete-identity asset (vendor AND product AND version) is eligible.
- Missing-firmware asset is NOT eligible and its missing-field list
  contains ``firmware_version``.

The selector is pure (no DB), so these exercise the cutoff logic
directly on :class:`DeviceIdentity` value objects.
"""

from __future__ import annotations

import pytest

from otalon_scan.cve_lookup import (
    DeviceIdentity,
    evaluate_eligibility,
    select_eligible,
)
from otalon_scan.cve_lookup.eligibility import (
    FIELD_PRODUCT,
    FIELD_VENDOR,
    FIELD_VERSION,
)


def test_complete_identity_is_eligible() -> None:
    """Scenario 1: vendor+product+version present → eligible, no gaps."""
    identity = DeviceIdentity(
        device_id=1,
        vendor="Siemens",
        product="SCALANCE XC216",
        version="V4.3",
    )
    result = evaluate_eligibility(identity)
    assert result.eligible is True
    assert result.missing_fields == []


def test_missing_firmware_is_ineligible_with_field() -> None:
    """Scenario 2: empty firmware → NOT eligible, gap names firmware."""
    identity = DeviceIdentity(
        device_id=2,
        vendor="Siemens",
        product="SCALANCE XC216",
        version=None,
    )
    result = evaluate_eligibility(identity)
    assert result.eligible is False
    assert FIELD_VERSION in result.missing_fields
    assert result.missing_fields == [FIELD_VERSION]


@pytest.mark.parametrize("blank", ["", "   ", None])
def test_blank_values_count_as_missing(blank: str | None) -> None:
    """Whitespace-only / empty / None all count as a missing field."""
    result = evaluate_eligibility(DeviceIdentity(device_id=3, vendor=blank, product=blank, version=blank))
    assert result.eligible is False
    assert result.missing_fields == [FIELD_VENDOR, FIELD_PRODUCT, FIELD_VERSION]


def test_missing_fields_are_ordered_vendor_product_version() -> None:
    """The gap list SHALL be in vendor → product → version order."""
    result = evaluate_eligibility(DeviceIdentity(device_id=4, product="X"))
    assert result.missing_fields == [FIELD_VENDOR, FIELD_VERSION]


def test_select_eligible_partitions_batch_in_order() -> None:
    """The batch selector SHALL emit one result per input, in order."""
    identities = [
        DeviceIdentity(device_id=10, vendor="Siemens", product="S7-1500", version="V2.9"),
        DeviceIdentity(device_id=11, vendor="Siemens", product="S7-1500"),
        DeviceIdentity(device_id=12),
    ]
    results = select_eligible(identities)
    assert [r.device_id for r in results] == [10, 11, 12]
    assert [r.eligible for r in results] == [True, False, False]
    assert results[1].missing_fields == [FIELD_VERSION]
    assert results[2].missing_fields == [FIELD_VENDOR, FIELD_PRODUCT, FIELD_VERSION]
