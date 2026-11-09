"""SCAN-029 — tests for the pn_discovery transport wiring.

Complements ``test_pn_dcp_codec.py`` (pure wire format) with the layer
that glues the codec to the scan module:

- ``otalon_scan.modules.pn_discovery.raw_socket`` helpers that read host state
  (interface MAC, interface IPv4, default route) via procfs / psutil.
- ``PnDiscoveryModule._fetch_devices``, driven against a stubbed capture
  so the full sniff→decode→dedupe→filter path runs without ``NET_RAW``.
- The scapy-free invariant: nothing under ``otalon_scan.modules.pn_discovery``
  may pull scapy back in.

No test here opens a socket or requires a PROFINET segment.
"""

from __future__ import annotations

import json
import socket
import struct
import subprocess
import sys
from pathlib import Path
from typing import Any, List

import pytest

from otalon_scan.core.protocols import ScanModuleError
from otalon_scan.modules.pn_discovery import raw_socket
from otalon_scan.modules.pn_discovery.dcp import ETHERTYPE_PROFINET, FRAME_ID_IDENTIFY_RESPONSE, encode_mac
from otalon_scan.modules.pn_discovery.start import PnDiscoveryModule

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
#: otalon-scan package root (``src/``); the import probe runs with this as
#: CWD so ``import otalon_scan.modules...`` resolves in the child interpreter.
_PACKAGE_ROOT = _PROJECT_ROOT / "src"

LOCAL_MAC = "00:11:22:33:44:55"


def _response_frame(source_mac: str, name: str, ip: str = "192.168.0.10") -> bytes:
    """Assemble a minimal DCP Identify response advertising a name and an IP."""
    octets = bytes(int(part) for part in ip.split("."))
    ip_block = struct.pack("!BBH", 0x01, 0x02, 14) + struct.pack("!H", 1) + octets + bytes([255, 255, 255, 0]) + octets
    name_bytes = name.encode()
    name_block = struct.pack("!BBH", 0x02, 0x02, 2 + len(name_bytes)) + struct.pack("!H", 0) + name_bytes
    if len(name_bytes) % 2:
        name_block += b"\x00"
    blocks = ip_block + name_block

    ethernet = encode_mac(LOCAL_MAC) + encode_mac(source_mac) + struct.pack("!H", ETHERTYPE_PROFINET)
    pdu = (
        struct.pack("!H", FRAME_ID_IDENTIFY_RESPONSE)
        + struct.pack("!BB", 0x05, 0x01)
        + struct.pack("!I", 1)
        + struct.pack("!H", 0)
        + struct.pack("!H", len(blocks))
        + blocks
    )
    frame = ethernet + pdu
    return frame + b"\x00" * max(0, 60 - len(frame))


def _module(monkeypatch: pytest.MonkeyPatch, frames: List[bytes], interface: str = "eth-test") -> PnDiscoveryModule:
    """Return a module whose capture call replays ``frames`` verbatim."""
    module = PnDiscoveryModule()
    module._interface = interface
    module._local_mac = LOCAL_MAC
    monkeypatch.setattr(
        "otalon_scan.modules.pn_discovery.start.capture_dcp_responses",
        lambda interface, request_frame, listen_seconds: list(frames),
    )
    return module


# ---------------------------------------------------------------------------
# raw_socket host-state helpers
# ---------------------------------------------------------------------------


def test_read_interface_mac_returns_none_for_unknown_interface() -> None:
    """A non-existent interface SHALL yield ``None``, not raise."""
    assert raw_socket.read_interface_mac("definitely-not-an-iface") is None


def test_read_interface_mac_rejects_oversized_name() -> None:
    """An interface name at/over ``IFNAMSIZ`` SHALL be refused up front."""
    assert raw_socket.read_interface_mac("x" * 32) is None
    assert raw_socket.read_interface_mac("") is None


def test_read_interface_mac_reads_loopback() -> None:
    """The loopback interface SHALL report its all-zero MAC as ``None``."""
    assert raw_socket.read_interface_mac("lo") is None


def test_read_interface_ipv4_returns_cidr_for_loopback() -> None:
    """A configured IPv4 SHALL come back as ``address/netmask``."""
    cidr = raw_socket.read_interface_ipv4("lo")

    assert cidr is not None
    assert cidr.startswith("127.")
    assert "/" in cidr


def test_read_interface_ipv4_returns_none_for_unknown_interface() -> None:
    """An interface psutil does not know SHALL yield ``None``."""
    assert raw_socket.read_interface_ipv4("definitely-not-an-iface") is None


def test_read_interface_ipv4_skips_non_inet_families(monkeypatch: pytest.MonkeyPatch) -> None:
    """Only ``AF_INET`` entries SHALL be considered."""

    class _Addr:
        def __init__(self, family: Any, address: str, netmask: Any) -> None:
            self.family = family
            self.address = address
            self.netmask = netmask

    monkeypatch.setattr(
        "psutil.net_if_addrs",
        lambda: {
            "fake0": [
                _Addr(socket.AF_PACKET, "aa:bb:cc:dd:ee:ff", None),
                _Addr(socket.AF_INET, "10.1.2.3", "255.255.255.0"),
            ]
        },
    )
    assert raw_socket.read_interface_ipv4("fake0") == "10.1.2.3/255.255.255.0"


def test_default_interface_matches_procfs_default_route(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The device of the ``00000000`` destination row SHALL be returned."""
    route = tmp_path / "route"
    route.write_text(
        "Iface\tDestination\tGateway\tFlags\n" "eth9\t0000A8C0\t00000000\t0001\n" "eth7\t00000000\t0102A8C0\t0003\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(raw_socket, "_PROC_NET_ROUTE", route)

    assert raw_socket.default_interface() == "eth7"


def test_default_interface_returns_none_without_default_route(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A routing table without a default route SHALL yield ``None``."""
    route = tmp_path / "route"
    route.write_text("Iface\tDestination\tGateway\n" "eth9\t0000A8C0\t00000000\n", encoding="utf-8")
    monkeypatch.setattr(raw_socket, "_PROC_NET_ROUTE", route)

    assert raw_socket.default_interface() is None


def test_default_interface_returns_none_when_procfs_unreadable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """An unreadable ``/proc/net/route`` SHALL be logged and degrade to ``None``."""
    monkeypatch.setattr(raw_socket, "_PROC_NET_ROUTE", tmp_path / "missing")

    assert raw_socket.default_interface() is None


# ---------------------------------------------------------------------------
# Module-level fetch path
# ---------------------------------------------------------------------------


def test_fetch_devices_decodes_captured_frames(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every distinct responder SHALL become one legacy-shaped dict."""
    module = _module(
        monkeypatch,
        [
            _response_frame("aa:bb:cc:dd:ee:01", "plc-01", "192.168.0.10"),
            _response_frame("aa:bb:cc:dd:ee:02", "io-2", "192.168.0.11"),
        ],
    )
    devices = module._fetch_devices(sniff_time=1, filter_net=False)

    assert [d["mac_address"] for d in devices] == ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"]
    assert [d["name_of_station"] for d in devices] == ["plc-01", "io-2"]
    assert set(devices[0]) == {
        "mac_address",
        "device_vendor_value",
        "name_of_station",
        "device_role_details",
        "ip_address",
        "subnet_mask",
        "standard_gateway",
    }


def test_fetch_devices_drops_own_looped_back_frame(monkeypatch: pytest.MonkeyPatch) -> None:
    """A frame whose source is this host SHALL never surface as a device."""
    module = _module(
        monkeypatch,
        [_response_frame(LOCAL_MAC, "self"), _response_frame("aa:bb:cc:dd:ee:01", "plc-01")],
    )
    devices = module._fetch_devices(sniff_time=1, filter_net=False)

    assert [d["mac_address"] for d in devices] == ["aa:bb:cc:dd:ee:01"]


def test_fetch_devices_deduplicates_repeated_responders(monkeypatch: pytest.MonkeyPatch) -> None:
    """A station answering twice SHALL be reported once."""
    frame = _response_frame("aa:bb:cc:dd:ee:01", "plc-01")
    module = _module(monkeypatch, [frame, frame, frame])

    assert len(module._fetch_devices(sniff_time=1, filter_net=False)) == 1


def test_fetch_devices_ignores_undecodable_frames(monkeypatch: pytest.MonkeyPatch) -> None:
    """Garbage on the socket SHALL be skipped without aborting the scan."""
    module = _module(monkeypatch, [b"\x00" * 8, b"\xff" * 70, _response_frame("aa:bb:cc:dd:ee:01", "plc-01")])

    assert len(module._fetch_devices(sniff_time=1, filter_net=False)) == 1


def test_fetch_devices_filter_net_keeps_only_local_subnet(monkeypatch: pytest.MonkeyPatch) -> None:
    """``filter_net`` SHALL drop responders outside the interface network."""
    module = _module(
        monkeypatch,
        [
            _response_frame("aa:bb:cc:dd:ee:01", "near", "192.168.0.10"),
            _response_frame("aa:bb:cc:dd:ee:02", "far", "10.9.9.9"),
        ],
    )
    monkeypatch.setattr(
        "otalon_scan.modules.pn_discovery.start.read_interface_ipv4",
        lambda _iface: "192.168.0.5/255.255.255.0",
    )
    devices = module._fetch_devices(sniff_time=1, filter_net=True)

    assert [d["name_of_station"] for d in devices] == ["near"]


def test_fetch_devices_filter_net_degrades_when_interface_has_no_ipv4(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without an interface IPv4, ``filter_net`` SHALL pass results through."""
    module = _module(monkeypatch, [_response_frame("aa:bb:cc:dd:ee:01", "plc-01")])
    monkeypatch.setattr("otalon_scan.modules.pn_discovery.start.read_interface_ipv4", lambda _iface: None)

    assert len(module._fetch_devices(sniff_time=1, filter_net=True)) == 1


def test_build_request_without_local_mac_raises_module_error() -> None:
    """A missing interface MAC SHALL fail loudly instead of scanning blind."""
    module = PnDiscoveryModule()
    module._interface = "eth-test"
    module._local_mac = None

    with pytest.raises(ScanModuleError):
        module._build_request()


# ---------------------------------------------------------------------------
# SCAN-029 invariant
# ---------------------------------------------------------------------------


def test_pn_discovery_import_graph_is_scapy_free() -> None:
    """Importing the module SHALL NOT pull scapy into ``sys.modules``."""
    probe = (
        "import json, sys\n"
        "import otalon_scan.modules.pn_discovery.start\n"
        "print(json.dumps(sorted(sys.modules)))\n"
    )
    completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-c", probe],
        cwd=str(_PACKAGE_ROOT),
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert completed.returncode == 0, f"pn_discovery import probe failed:\n{completed.stderr}"

    imported = {name.split(".")[0] for name in json.loads(completed.stdout)}
    assert "scapy" not in imported


def test_requirements_no_longer_pin_scapy() -> None:
    """``requirements.txt`` SHALL NOT list scapy (SCAN-029 acceptance)."""
    requirements = (_PROJECT_ROOT / "requirements.txt").read_text(encoding="utf-8")
    declared = [line.strip() for line in requirements.splitlines() if line.strip() and not line.strip().startswith("#")]

    assert not [line for line in declared if line.lower().startswith("scapy")]
