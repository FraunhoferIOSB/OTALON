"""Manufacturer mapping for active-scan device descriptors (Welle A / D4).

PROFINET-DCP surfaces a manufacturer-specific descriptor string in the
``DCPManufacturerSpecificBlock`` (``device_vendor_value``). That value is
NOT a clean vendor name — it carries a product/type designation such as
``"S7-1500"``, ``"AXC F 2152"`` or ``"BK Device"`` (observed verbatim on
the live testbed, ``devices`` rows 46531/46532/46520). Writing it
unmapped into ``devices.vendor`` leaves the CVE-lookup identity cutoff
(D4: vendor AND product AND version) without a usable ``vendor`` and with
the product descriptor stranded in the wrong column.

This module resolves a descriptor into a canonical ``(vendor,
product_name)`` pair so the scan→``devices`` write populates the cutoff
fields correctly. The rule table is data-driven (an ordered list of
``(pattern, vendor)`` rules) and additive: new testbed vendors are
appended without touching call sites. Only manufacturers with a
documentable signal are mapped — unknown descriptors are returned as a
``product_name`` with ``vendor=None`` so the NULL-skipping upsert never
clobbers a better value and the descriptor is still visible.

The same table backs the SNMP path's manufacturer normalisation; the
SNMP walker additionally derives vendors from ``sysDescr`` regexes (see
:func:`otalon_scan.modules.snmp_scan.walker.parse_sysDescr`) and those vendor
strings are normalised here to a single canonical spelling.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional, Pattern

__all__ = ["VENDOR_RULES", "VendorRule", "map_dcp_descriptor", "normalise_vendor"]


@dataclass(frozen=True)
class VendorRule:
    """A single data-driven manufacturer-resolution rule.

    Attributes:
        pattern: Case-insensitive regex matched against the raw scan
            descriptor (PROFINET-DCP ``device_vendor_value`` or an SNMP
            vendor string).
        vendor: Canonical manufacturer name written to
            ``devices.vendor`` when the pattern matches.
    """

    pattern: Pattern[str]
    vendor: str


def _rule(regex: str, vendor: str) -> VendorRule:
    """Compile ``regex`` (case-insensitive) into a :class:`VendorRule`."""
    return VendorRule(pattern=re.compile(regex, re.IGNORECASE), vendor=vendor)


# Ordered, data-driven rule table. Earlier rules win. Every entry maps a
# descriptor signal that is documentable from the live testbed inventory
# or the vendor's own product naming — nothing is invented. Extend by
# appending a new ``_rule(...)`` line.
VENDOR_RULES: tuple[VendorRule, ...] = (
    # Siemens SIMATIC / SCALANCE / S7 controllers and switches.
    _rule(r"\b(s7-?\d{3,4}|simatic|scalance|siemens)\b", "Siemens"),
    # Phoenix Contact AXC / AXL controllers.
    _rule(r"\b(axc|axl|phoenix\s*contact)\b", "PHOENIX CONTACT Electronics GmbH"),
    # Hirschmann (Belden) industrial switches.
    _rule(r"\b(hirschmann|rsp\d|rs\d{2}|eagle|greyhound)\b", "Hirschmann"),
    # Beckhoff Bus Coupler (BK / BKxxxx) terminals.
    _rule(r"\b(bk\d{3,4}|bk\s*device|beckhoff)\b", "Beckhoff Automation GmbH"),
)


def normalise_vendor(vendor: Optional[str]) -> Optional[str]:
    """Normalise a raw vendor string to the canonical spelling.

    Runs the raw vendor through :data:`VENDOR_RULES`; on a match the
    canonical manufacturer name is returned. A non-empty value with no
    matching rule is returned trimmed and unchanged (the scanner already
    produced a clean vendor). Empty / ``None`` input yields ``None`` so
    the persistence layer's COALESCE merge skips it.

    Args:
        vendor: Raw vendor string from a scan, or ``None``.

    Returns:
        The canonical vendor name, the trimmed original, or ``None``.
    """
    cleaned = (vendor or "").strip()
    if not cleaned:
        return None
    for rule in VENDOR_RULES:
        if rule.pattern.search(cleaned):
            return rule.vendor
    return cleaned


def map_dcp_descriptor(descriptor: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """Resolve a PROFINET-DCP descriptor into ``(vendor, product_name)``.

    The PROFINET-DCP ``device_vendor_value`` is a product/type
    descriptor (e.g. ``"S7-1500"``). This maps it to a canonical
    manufacturer via :data:`VENDOR_RULES` and carries the descriptor
    itself as the ``product_name`` so the D4 identity cutoff
    (vendor AND product AND version) can populate two of its three
    fields from a single DCP block.

    Args:
        descriptor: Raw ``device_vendor_value`` from the DCP block, or
            ``None``.

    Returns:
        A ``(vendor, product_name)`` tuple. ``vendor`` is the mapped
        manufacturer or ``None`` when no rule matches; ``product_name``
        is the trimmed descriptor or ``None`` when the input is empty.
    """
    cleaned = (descriptor or "").strip()
    if not cleaned:
        return None, None
    for rule in VENDOR_RULES:
        if rule.pattern.search(cleaned):
            return rule.vendor, cleaned
    return None, cleaned
