"""Unit tests for the SNMP Walker -> ``DeviceFinding`` mapping (SCAN-018).

The SNMP walker collects asset master-data on a
:class:`otalon_scan.modules.snmp_scan.model.Device` (``product_name`` /
``hw_version`` / ``sw_version`` / ``serial_number`` / ``order_number``).
Before SCAN-018 those fields were dropped when the module built its
:class:`otalon_scan.core.models.DeviceFinding`; only ``firmware_version`` and
``article_number`` survived.

These tests pin the enriched mapping: a fully-populated walker
``Device`` SHALL surface every asset field on the emitted finding, and a
sparse device SHALL leave the corresponding fields ``None`` (so the
persistence layer's NULL-skipping merge applies).

The tests stub the SNMP walk so no UDP traffic is required — they only
exercise the deterministic ``Device.export_yourself`` ->
``DeviceFinding`` translation inside ``SnmpsubmanagerModule.scan``.
"""

from __future__ import annotations

from typing import List
from unittest.mock import patch

import pytest

from otalon_scan.core.models import DeviceFinding, ScanConfig, ScanProgress
from otalon_scan.modules.snmp_scan.model import Device
from otalon_scan.modules.snmp_scan.start import SnmpsubmanagerModule


def _populate_full(device: Device) -> None:
    """Set every asset field on the walker ``Device`` like a SCALANCE walk."""
    device.set_vendor("Siemens")
    device.set_sys_name("scalance-xc200")
    device.set_product_name("SCALANCE XC216")
    device.set_product_type("SIMATIC NET")
    device.set_order_number("6GK5216-0BA00-2AB2")
    device.set_hw_version("4")
    device.set_sw_version("V4.3")
    device.set_serial_number("SVPL1234567")


async def _collect_findings(target_ip: str, populate: object) -> List[DeviceFinding]:
    """Run the SNMP module with the walk stubbed by ``populate``."""
    config = ScanConfig(
        module_name=SnmpsubmanagerModule.name,
        target_ip=target_ip,
        parameters={"communities": [[f"{target_ip}/32", "public", 0]]},
    )

    async def _fake_walker(a_device: Device, *args: object, **kwargs: object) -> None:
        populate(a_device)  # type: ignore[operator]

    findings: List[DeviceFinding] = []
    with patch("otalon_scan.modules.snmp_scan.start.walker", side_effect=_fake_walker):
        module = SnmpsubmanagerModule()
        async for event in module.scan(config):
            if isinstance(event, ScanProgress) and event.finding is not None:
                findings.append(event.finding)
    return findings


@pytest.mark.asyncio
async def test_full_device_maps_all_asset_fields() -> None:
    """A fully-populated walk SHALL surface every SCAN-018 asset field."""
    findings = await _collect_findings("192.168.0.233", _populate_full)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.product_name == "SCALANCE XC216"
    assert finding.hw_version == "4"
    assert finding.sw_version == "V4.3"
    assert finding.serial_number == "SVPL1234567"
    # firmware_version is retained (D3) and still mirrors sw_version.
    assert finding.firmware_version == "V4.3"
    # order_number maps onto article_number (unchanged legacy behaviour).
    assert finding.article_number == "6GK5216-0BA00-2AB2"
    # P8 Welle A (F-10): the SNMP ``sysName`` is the device HOSTNAME and
    # SHALL land in ``hostname`` — NOT ``device_type``. ``device_type``
    # stays None because no genuine device type was discovered.
    assert finding.hostname == "scalance-xc200"
    assert finding.device_type is None


@pytest.mark.asyncio
async def test_sparse_device_leaves_new_fields_none() -> None:
    """A walk that sets no asset fields SHALL leave them ``None``.

    NULL on the finding lets the persistence layer's COALESCE merge keep
    any previously-stored value instead of clobbering it.
    """

    def _populate_none(_device: Device) -> None:
        return None

    findings = await _collect_findings("192.168.0.233", _populate_none)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.product_name is None
    assert finding.hw_version is None
    assert finding.sw_version is None
    assert finding.serial_number is None


@pytest.mark.asyncio
async def test_partial_device_maps_only_present_fields() -> None:
    """Only the asset fields the walk actually set SHALL be carried."""

    def _populate_partial(device: Device) -> None:
        device.set_hw_version("2")
        device.set_serial_number("ABC987")

    findings = await _collect_findings("192.168.0.233", _populate_partial)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.hw_version == "2"
    assert finding.serial_number == "ABC987"
    assert finding.product_name is None
    assert finding.sw_version is None
