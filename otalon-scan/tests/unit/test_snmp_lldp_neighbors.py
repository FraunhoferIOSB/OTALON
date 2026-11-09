"""Unit tests for SCAN-022 SNMP LLDP-neighbor discovery + correlation.

The walker now reads four extra SNMP tables from a managed switch and joins
them into neighbor records with real MAC addresses:

    lldpRemTable[localPort] -> {SysName, mgmtIP, SysDesc, PortId}
      JOIN via BridgePort<->ifIndex with
    dot1dTpFdbTable[bridgePort] -> MAC

These tests use recorded fixture data shaped exactly like the live SCALANCE
XC208G output (192.168.0.233) captured with native ``snmpwalk -v2c``. They
assert the join produces the right MAC+IP+name per neighbor, that
``export_yourself`` returns the switch + N neighbors, that each neighbor
finding carries a canonical MAC (so it takes the ``primary_mac`` upsert
path), and that SysDesc parsing extracts vendor/product/firmware.
"""

from __future__ import annotations

from typing import Dict, List
from unittest.mock import patch

import pytest

from otalon_scan.core.models import DeviceFinding, ScanConfig, ScanProgress
from otalon_scan.modules.snmp_scan.model import Device, Neighbor
from otalon_scan.modules.snmp_scan.start import SnmpsubmanagerModule
from otalon_scan.modules.snmp_scan.walker import _strip_base, correlate_neighbors, parse_sysDescr
from otalon_scan.utils.mac import canonicalise

# ---------------------------------------------------------------------------
# Recorded fixtures (live SCALANCE XC208G @192.168.0.233, community public).
# Values are the pysnmp ``prettyPrint`` forms: STRING -> bare text,
# INTEGER -> decimal text, Hex-STRING -> space-separated octets.
# ---------------------------------------------------------------------------

LLDP_REM: Dict[str, str] = {
    # col 5 = lldpRemSysName
    ".1.0.8802.1.1.2.1.4.1.1.5.2239.1.1": "bk9103-2",
    ".1.0.8802.1.1.2.1.4.1.1.5.2245.7.2": "plcxb1.profinet-schnittstellexb15ee1",
    ".1.0.8802.1.1.2.1.4.1.1.5.2246.5.3": "bk9103",
    ".1.0.8802.1.1.2.1.4.1.1.5.5154.2.4": "axc-f-2152-2",
    ".1.0.8802.1.1.2.1.4.1.1.5.5614.6.5": "axc-f-2152-1",
    # col 7 = lldpRemPortId
    ".1.0.8802.1.1.2.1.4.1.1.7.2239.1.1": "port-001",
    ".1.0.8802.1.1.2.1.4.1.1.7.2245.7.2": "port-002",
    ".1.0.8802.1.1.2.1.4.1.1.7.2246.5.3": "port-002",
    ".1.0.8802.1.1.2.1.4.1.1.7.5154.2.4": "port-001",
    ".1.0.8802.1.1.2.1.4.1.1.7.5614.6.5": "port-001",
    # col 10 = lldpRemSysDesc
    ".1.0.8802.1.1.2.1.4.1.1.10.2239.1.1": "Beckhoff bk9103 - HW: V2.00, SW: V14.00",
    ".1.0.8802.1.1.2.1.4.1.1.10.2245.7.2": (
        "Siemens, SIMATIC S7, CPU 1516-3 PN/DP, 6ES7 516-3AP03-0AB0, "
        "HW: Version 4, FW: Version V4.0.4, S C-S3A143PV2024"
    ),
    ".1.0.8802.1.1.2.1.4.1.1.10.2246.5.3": "Beckhoff bk9103 - HW: V2.00, SW: V10.00",
    ".1.0.8802.1.1.2.1.4.1.1.10.5154.2.4": "",
    ".1.0.8802.1.1.2.1.4.1.1.10.5614.6.5": "",
}

LLDP_MAN: Dict[str, str] = {
    ".1.0.8802.1.1.2.1.4.2.1.3.2239.1.1.1.4.192.168.0.4": "2",
    ".1.0.8802.1.1.2.1.4.2.1.3.2245.7.2.1.4.192.168.0.1": "2",
    ".1.0.8802.1.1.2.1.4.2.1.3.2246.5.3.1.4.192.168.0.2": "2",
    ".1.0.8802.1.1.2.1.4.2.1.3.5154.2.4.1.4.192.168.0.10": "2",
    ".1.0.8802.1.1.2.1.4.2.1.3.5614.6.5.1.4.192.168.0.41": "2",
}

FDB: Dict[str, str] = {
    # col .2 = dot1dTpFdbPort (bridge port). Index is the dotted MAC.
    ".1.3.6.1.2.1.17.4.3.1.2.0.1.5.43.174.162": "5",  # 00:01:05:2b:ae:a2
    ".1.3.6.1.2.1.17.4.3.1.2.0.1.5.147.80.155": "1",  # 00:01:05:93:50:9b
    ".1.3.6.1.2.1.17.4.3.1.2.48.184.81.49.6.132": "7",  # 30:b8:51:31:06:84
    ".1.3.6.1.2.1.17.4.3.1.2.128.57.229.0.171.210": "3",  # 80:39:e5:00:ab:d2
    ".1.3.6.1.2.1.17.4.3.1.2.168.116.29.2.153.141": "6",  # a8:74:1d:02:99:8d
    ".1.3.6.1.2.1.17.4.3.1.2.168.116.29.24.198.150": "2",  # a8:74:1d:18:c6:96
}

BASE_PORT: Dict[str, str] = {f".1.3.6.1.2.1.17.1.4.1.2.{p}": str(p) for p in range(1, 9)}


def _neighbors_by_port() -> Dict[int, Neighbor]:
    neighbors = correlate_neighbors(LLDP_REM, LLDP_MAN, FDB, BASE_PORT)
    return {n.local_port: n for n in neighbors}


def test_join_resolves_mac_ip_name_per_neighbor() -> None:
    """The four-table join SHALL yield the right MAC+IP+name per neighbor."""
    by_port = _neighbors_by_port()

    s7 = by_port[7]
    assert s7.mac_addr == "30:b8:51:31:06:84"
    assert s7.ip_addr == "192.168.0.1"
    assert s7.sys_name == "plcxb1.profinet-schnittstellexb15ee1"

    bk_p1 = by_port[1]
    assert bk_p1.mac_addr == "00:01:05:93:50:9b"
    assert bk_p1.ip_addr == "192.168.0.4"

    bk_p5 = by_port[5]
    assert bk_p5.mac_addr == "00:01:05:2b:ae:a2"
    assert bk_p5.ip_addr == "192.168.0.2"

    axc_p2 = by_port[2]
    assert axc_p2.mac_addr == "a8:74:1d:18:c6:96"
    assert axc_p2.ip_addr == "192.168.0.10"

    axc_p6 = by_port[6]
    assert axc_p6.mac_addr == "a8:74:1d:02:99:8d"
    assert axc_p6.ip_addr == "192.168.0.41"


def test_export_returns_switch_plus_neighbors() -> None:
    """``export_yourself`` SHALL return the switch finding + one per neighbor."""
    device = Device("192.168.0.233")
    device.set_vendor("Siemens")
    device.set_product_name("SCALANCE XC208G")
    for neighbor in correlate_neighbors(LLDP_REM, LLDP_MAN, FDB, BASE_PORT):
        device.add_neighbor(neighbor)

    findings = device.export_yourself()
    assert len(findings) == 6  # switch + 5 neighbors
    # The first record is the switch (no neighbor MAC, has the switch IP).
    assert findings[0]["ip_address"] == "192.168.0.233"
    neighbor_macs = {f.get("mac_address") for f in findings[1:]}
    assert "30:b8:51:31:06:84" in neighbor_macs
    assert "00:01:05:93:50:9b" in neighbor_macs


def test_each_neighbor_carries_canonical_mac() -> None:
    """Every neighbor finding SHALL carry a canonicalisable MAC (upsert path)."""
    for neighbor in correlate_neighbors(LLDP_REM, LLDP_MAN, FDB, BASE_PORT):
        rec = neighbor.export_yourself()
        mac = rec.get("mac_address")
        assert mac is not None
        # Takes the ``primary_mac`` ON-CONFLICT path in save_findings_batch.
        assert canonicalise(mac) == mac


def test_sysdescr_parses_s7_and_bk9103() -> None:
    """SysDesc parsing SHALL extract vendor/product/fw for S7 and BK9103."""
    by_port = _neighbors_by_port()

    s7 = by_port[7]
    assert s7.vendor == "Siemens"
    assert s7.product_name == "CPU 1516-3 PN/DP"
    assert s7.order_number == "6ES7 516-3AP03-0AB0"
    assert s7.hw_version == "Version 4"
    assert s7.sw_version == "Version V4.0.4"

    bk = by_port[1]
    assert bk.vendor == "Beckhoff"
    assert bk.product_name == "bk9103"
    assert bk.hw_version == "V2.00"
    assert bk.sw_version == "V14.00"


def test_skip_neighbor_without_mac_and_ip() -> None:
    """A row with neither MAC nor IP SHALL NOT produce a neighbor."""
    rem = {".1.0.8802.1.1.2.1.4.1.1.5.9999.99.9": "ghost"}
    neighbors = correlate_neighbors(rem, {}, {}, {})
    assert neighbors == []


def test_ip_only_neighbor_is_kept() -> None:
    """A neighbor with an IP but no learned MAC SHALL still be emitted."""
    rem = {".1.0.8802.1.1.2.1.4.1.1.5.2245.7.2": "lonely"}
    man = {".1.0.8802.1.1.2.1.4.2.1.3.2245.7.2.1.4.10.0.0.9": "2"}
    neighbors = correlate_neighbors(rem, man, {}, {})
    assert len(neighbors) == 1
    assert neighbors[0].mac_addr is None
    assert neighbors[0].ip_addr == "10.0.0.9"


def test_strip_base_handles_pysnmp_textual_prefixes() -> None:
    """pysnmp ``prettyPrint`` resolves OID prefixes to MIB names.

    The live walk returns e.g. ``SNMPv2-SMI::iso.0.8802...`` and
    ``SNMPv2-SMI::mib-2.17.4.3.1.2...`` rather than the pure-numeric form
    captured by ``snmpwalk -On``. ``_strip_base`` MUST normalise both.
    """
    # iso. -> 1.
    assert _strip_base("SNMPv2-SMI::iso.0.8802.1.1.2.1.4.1.1.5.2245.7.2", "1.0.8802.1.1.2.1.4.1.1") == "5.2245.7.2"
    # mib-2. -> 1.3.6.1.2.1.
    assert _strip_base("SNMPv2-SMI::mib-2.17.4.3.1.2.48.184.81.49.6.132", "1.3.6.1.2.1.17.4.3.1.2") == (
        "48.184.81.49.6.132"
    )
    # Pure-numeric (snmpwalk -On / unit fixtures) still works.
    assert _strip_base(".1.3.6.1.2.1.17.1.4.1.2.7", "1.3.6.1.2.1.17.1.4.1.2") == "7"


def test_correlate_with_pysnmp_prefixed_keys() -> None:
    """The join MUST succeed when keys carry pysnmp textual prefixes."""
    rem = {
        "SNMPv2-SMI::iso.0.8802.1.1.2.1.4.1.1.5.2245.7.2": "plcxb1",
        "SNMPv2-SMI::iso.0.8802.1.1.2.1.4.1.1.10.2245.7.2": (
            "Siemens, SIMATIC S7, CPU 1516-3 PN/DP, 6ES7 516-3AP03-0AB0, " "HW: Version 4, FW: Version V4.0.4, S C-X"
        ),
    }
    man = {"SNMPv2-SMI::iso.0.8802.1.1.2.1.4.2.1.3.2245.7.2.1.4.192.168.0.1": "2"}
    fdb = {"SNMPv2-SMI::mib-2.17.4.3.1.2.48.184.81.49.6.132": "7"}
    base = {"SNMPv2-SMI::mib-2.17.1.4.1.2.7": "7"}
    neighbors = correlate_neighbors(rem, man, fdb, base)
    assert len(neighbors) == 1
    assert neighbors[0].mac_addr == "30:b8:51:31:06:84"
    assert neighbors[0].ip_addr == "192.168.0.1"
    assert neighbors[0].vendor == "Siemens"


def test_sysdescr_short_siemens_form_still_parses() -> None:
    """The legacy short Siemens SysDescr form SHALL keep working."""
    device = Device("10.0.0.1")
    parse_sysDescr("Siemens, foo, HW: V1, FW: V2", device)
    assert device.vendor == "Siemens"
    assert device.hw_version == "V1"
    assert device.sw_version == "V2"


# ---------------------------------------------------------------------------
# End-to-end through the module: stub the walker to attach neighbors and
# assert the emitted DeviceFindings.
# ---------------------------------------------------------------------------


async def _collect_findings_with_neighbors() -> List[DeviceFinding]:
    config = ScanConfig(
        module_name=SnmpsubmanagerModule.name,
        target_ip="192.168.0.233",
        parameters={"communities": [["192.168.0.233/32", "public", 0]]},
    )

    async def _fake_walker(a_device: Device, *args: object, **kwargs: object) -> None:
        a_device.set_vendor("Siemens")
        a_device.set_product_name("SCALANCE XC208G")
        for neighbor in correlate_neighbors(LLDP_REM, LLDP_MAN, FDB, BASE_PORT):
            a_device.add_neighbor(neighbor)

    findings: List[DeviceFinding] = []
    with patch("otalon_scan.modules.snmp_scan.start.walker", side_effect=_fake_walker):
        module = SnmpsubmanagerModule()
        async for event in module.scan(config):
            if isinstance(event, ScanProgress) and event.finding is not None:
                findings.append(event.finding)
    return findings


@pytest.mark.asyncio
async def test_module_emits_switch_plus_neighbor_findings() -> None:
    """The module SHALL emit one DeviceFinding for the switch + each neighbor."""
    findings = await _collect_findings_with_neighbors()
    assert len(findings) == 6

    by_mac = {f.mac: f for f in findings if f.mac}
    s7 = by_mac["30:b8:51:31:06:84"]
    assert s7.ipv4 == "192.168.0.1"
    assert s7.vendor is not None and "siemens" in s7.vendor.lower()
    assert s7.product_name == "CPU 1516-3 PN/DP"
    assert s7.firmware_version == "Version V4.0.4"

    assert "00:01:05:93:50:9b" in by_mac
    assert "a8:74:1d:02:99:8d" in by_mac or "a8:74:1d:18:c6:96" in by_mac
