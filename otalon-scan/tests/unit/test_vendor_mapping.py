"""Unit tests for the manufacturer mapping table (Welle A / Task 1.2).

The PROFINET-DCP ``device_vendor_value`` and the SNMP vendor strings are
resolved to canonical manufacturer names via
:mod:`otalon_scan.modules.vendor_mapping`. These tests pin the data-driven rule
table against the descriptor strings observed verbatim on the live
testbed (``devices`` rows 46531/46532/46520/46524) plus the explicitly
required Siemens / Phoenix / Hirschmann vendors, and assert the
NULL-skipping contract (empty input → ``None``) the persistence layer
relies on.
"""

from __future__ import annotations

import pytest

from otalon_scan.modules.vendor_mapping import (
    VENDOR_RULES,
    map_dcp_descriptor,
    normalise_vendor,
)


@pytest.mark.parametrize(
    ("descriptor", "expected_vendor"),
    [
        ("S7-1500", "Siemens"),
        ("SIMATIC NET", "Siemens"),
        ("SCALANCE XC208", "Siemens"),
        ("AXC F 2152", "PHOENIX CONTACT Electronics GmbH"),
        ("AXL F BK PN", "PHOENIX CONTACT Electronics GmbH"),
        ("BK Device", "Beckhoff Automation GmbH"),
        ("BK9103", "Beckhoff Automation GmbH"),
        ("Hirschmann RSP20", "Hirschmann"),
    ],
)
def test_map_dcp_descriptor_resolves_known_vendors(descriptor: str, expected_vendor: str) -> None:
    """A known testbed descriptor SHALL resolve to its canonical vendor.

    The descriptor itself is preserved as ``product_name`` so the D4
    cutoff (vendor AND product AND version) can fill two fields from one
    DCP block.
    """
    vendor, product_name = map_dcp_descriptor(descriptor)
    assert vendor == expected_vendor
    assert product_name == descriptor


def test_map_dcp_descriptor_unknown_keeps_product_without_vendor() -> None:
    """An unmapped descriptor SHALL surface as product_name, vendor None.

    Returning ``vendor=None`` lets the NULL-skipping upsert keep any
    previously stored vendor instead of clobbering it, and never invents
    a manufacturer.
    """
    vendor, product_name = map_dcp_descriptor("Totally Unknown Widget 9000")
    assert vendor is None
    assert product_name == "Totally Unknown Widget 9000"


@pytest.mark.parametrize("empty", ["", "   ", None])
def test_map_dcp_descriptor_empty_is_null(empty: str | None) -> None:
    """Empty / whitespace / None descriptors SHALL yield ``(None, None)``."""
    assert map_dcp_descriptor(empty) == (None, None)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Siemens", "Siemens"),
        ("siemens ag", "Siemens"),
        ("PHOENIX CONTACT Electronics GmbH", "PHOENIX CONTACT Electronics GmbH"),
        ("Hirschmann Automation", "Hirschmann"),
    ],
)
def test_normalise_vendor_canonicalises(raw: str, expected: str) -> None:
    """A raw vendor string SHALL be normalised to its canonical spelling."""
    assert normalise_vendor(raw) == expected


def test_normalise_vendor_passthrough_unknown() -> None:
    """An unknown but non-empty vendor SHALL be returned trimmed, unchanged."""
    assert normalise_vendor("  ACME Robotics  ") == "ACME Robotics"


@pytest.mark.parametrize("empty", ["", "   ", None])
def test_normalise_vendor_empty_is_none(empty: str | None) -> None:
    """Empty / whitespace / None vendors SHALL yield ``None``."""
    assert normalise_vendor(empty) is None


def test_vendor_rules_are_data_driven_and_extensible() -> None:
    """The rule table SHALL expose the three required core vendors.

    Pins that Siemens / Phoenix / Hirschmann are present so a future
    refactor cannot silently drop a required manufacturer.
    """
    canonical = {rule.vendor for rule in VENDOR_RULES}
    assert "Siemens" in canonical
    assert "PHOENIX CONTACT Electronics GmbH" in canonical
    assert "Hirschmann" in canonical
