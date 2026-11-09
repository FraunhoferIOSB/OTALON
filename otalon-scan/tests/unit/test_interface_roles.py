"""Unit tests for :mod:`otalon_scan.core.interface_roles`.

Covers role classification (``active_scan``, ``mirror``, ``other``) with
fully mocked :mod:`psutil` data so the tests run on any host.
"""

from __future__ import annotations

# psutil does not expose AF_INET / AF_INET6 on all platforms; use the
# socket module constants (the same values appear in net_if_addrs).
import socket as _socket
from typing import Any, List, NamedTuple, Optional

import psutil
import pytest

from otalon_scan.core.interface_roles import (
    _mirror_interface_names,
    classify_interface_role,
    list_interfaces,
)


class _SnicAddr(NamedTuple):
    """Local stand-in for psutil's ``snicaddr`` namedtuple.

    psutil 7.2.2 removed the private ``psutil._common.snicaddr`` attribute, so
    the tests define their own equivalent rather than depend on a private
    internal. Mirrors the five public fields of ``psutil.net_if_addrs()`` rows.
    """

    family: int
    address: Optional[str]
    netmask: Optional[str]
    broadcast: Optional[str]
    ptp: Optional[str]


def _snicaddr(
    family: int,
    address: Optional[str] = None,
    netmask: Optional[str] = None,
) -> _SnicAddr:
    return _SnicAddr(family, address, netmask, None, None)


def _make_addrs(
    *,
    ipv4: Optional[str] = None,
    ipv4_netmask: Optional[str] = None,
    ipv6: Optional[str] = None,
    mac: Optional[str] = None,
) -> List[_SnicAddr]:
    addrs: List[_SnicAddr] = []
    if ipv4:
        addrs.append(_snicaddr(_socket.AF_INET, ipv4, ipv4_netmask))
    if ipv6:
        addrs.append(_snicaddr(_socket.AF_INET6, ipv6, "ffff:ffff:ffff:ffff::"))
    if mac:
        af_packet = getattr(_socket, "AF_PACKET", 17)
        addrs.append(_snicaddr(af_packet, mac, None))
    return addrs


class TestClassifyInterfaceRole:
    """Tests for :func:`classify_interface_role`."""

    def test_active_scan_up_with_ipv4(self) -> None:
        addrs = _make_addrs(ipv4="192.168.1.100", ipv4_netmask="255.255.255.0")
        assert classify_interface_role("eth0", addrs, is_up=True) == "active_scan"

    def test_active_scan_not_mirror_even_if_named_enp(self) -> None:
        addrs = _make_addrs(ipv4="192.168.1.100", ipv4_netmask="255.255.255.0")
        assert classify_interface_role("enp4s0", addrs, is_up=True) == "active_scan"

    def test_mirror_explicit_list(self) -> None:
        addrs = _make_addrs(ipv4="192.168.1.100", ipv4_netmask="255.255.255.0")
        assert classify_interface_role("enp5s0", addrs, is_up=True, mirror_names={"enp5s0"}) == "mirror"

    def test_mirror_explicit_list_overrides_link_local_ipv4(self) -> None:
        """A mirror-listed interface MUST NOT be classified as active_scan."""
        addrs = _make_addrs(ipv4="169.254.1.1", ipv4_netmask="255.255.255.0")
        assert classify_interface_role("enp5s0", addrs, is_up=True, mirror_names={"enp5s0"}) == "mirror"

    def test_other_undeclared_no_ipv4(self) -> None:
        addrs: List[_SnicAddr] = []
        assert classify_interface_role("eth1", addrs, is_up=True) == "other"

    def test_other_undeclared_ipv6_only(self) -> None:
        addrs = _make_addrs(ipv6="fe80::1")
        assert classify_interface_role("eth1", addrs, is_up=True) == "other"

    def test_other_undeclared_veth_no_ipv4(self) -> None:
        """Regression: an undeclared IP-less veth MUST NOT be labelled mirror."""
        addrs: List[_SnicAddr] = []
        assert classify_interface_role("veth0", addrs, is_up=False) == "other"

    def test_other_loopback_by_name(self) -> None:
        addrs = _make_addrs(ipv4="127.0.0.1", ipv4_netmask="255.0.0.0")
        assert classify_interface_role("lo", addrs, is_up=True) == "other"

    def test_other_loopback_by_name_lo0(self) -> None:
        assert classify_interface_role("lo0", [], is_up=True) == "other"

    def test_other_down_with_ipv4(self) -> None:
        addrs = _make_addrs(ipv4="192.168.1.100", ipv4_netmask="255.255.255.0")
        assert classify_interface_role("eth0", addrs, is_up=False) == "other"

    def test_mirror_never_active_scan(self) -> None:
        """Invariant: every explicitly listed mirror interface has role ``mirror``."""
        addrs = _make_addrs(ipv4="10.0.0.1", ipv4_netmask="255.255.255.0")
        for is_up in (True, False):
            assert classify_interface_role("mirror0", addrs, is_up=is_up, mirror_names={"mirror0"}) == "mirror"

    def test_mirror_from_capture_source_even_with_ipv4(self) -> None:
        """CAPTURE_SOURCE-named interface MUST be mirror even when it has IPv4."""
        addrs = _make_addrs(ipv4="192.168.1.50", ipv4_netmask="255.255.255.0")
        assert classify_interface_role("enp5s0", addrs, is_up=True, mirror_names={"enp5s0"}) == "mirror"


class TestMirrorInterfaceNames:
    """Tests for :func:`_mirror_interface_names`."""

    def test_capture_source_alone(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CAPTURE_SOURCE", "enp5s0")
        monkeypatch.delenv("OTALON_SCAN_MIRROR_INTERFACES", raising=False)
        assert _mirror_interface_names() == {"enp5s0"}

    def test_cyberscan_mirror_interfaces_alone(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("CAPTURE_SOURCE", raising=False)
        monkeypatch.setenv("OTALON_SCAN_MIRROR_INTERFACES", "eth1, eth2")
        assert _mirror_interface_names() == {"eth1", "eth2"}

    def test_union_of_both_sources(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CAPTURE_SOURCE", "enp5s0")
        monkeypatch.setenv("OTALON_SCAN_MIRROR_INTERFACES", "eth1,enp5s0")
        assert _mirror_interface_names() == {"enp5s0", "eth1"}

    def test_empty_envs_return_empty_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("CAPTURE_SOURCE", raising=False)
        monkeypatch.delenv("OTALON_SCAN_MIRROR_INTERFACES", raising=False)
        assert _mirror_interface_names() == set()


class TestListInterfaces:
    """Tests for :func:`list_interfaces`."""

    def test_list_interfaces_shape(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The returned list SHALL contain dicts with the expected keys."""

        def _fake_addrs() -> dict[str, List[_SnicAddr]]:
            return {
                "eth0": _make_addrs(
                    ipv4="192.168.1.100",
                    ipv4_netmask="255.255.255.0",
                    mac="aa:bb:cc:dd:ee:ff",
                ),
                "lo": _make_addrs(ipv4="127.0.0.1", ipv4_netmask="255.0.0.0"),
            }

        def _fake_stats() -> dict[str, Any]:
            class _Stat:
                isup = True

            return {"eth0": _Stat(), "lo": _Stat()}

        monkeypatch.setattr(psutil, "net_if_addrs", _fake_addrs)
        monkeypatch.setattr(psutil, "net_if_stats", _fake_stats)

        result = list_interfaces()
        assert len(result) == 2

        eth0 = next(i for i in result if i["name"] == "eth0")
        assert eth0["ipv4"] == "192.168.1.100"
        assert eth0["subnet"] == "192.168.1.100/24"
        assert eth0["is_up"] is True
        assert eth0["role"] == "active_scan"
        assert eth0["mac"] == "aa:bb:cc:dd:ee:ff"

        lo = next(i for i in result if i["name"] == "lo")
        assert lo["role"] == "other"

    def test_list_interfaces_mirror_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """``OTALON_SCAN_MIRROR_INTERFACES`` SHALL be honoured."""
        monkeypatch.setenv("OTALON_SCAN_MIRROR_INTERFACES", "eth1")

        def _fake_addrs() -> dict[str, List[_SnicAddr]]:
            return {
                "eth0": _make_addrs(ipv4="192.168.1.100", ipv4_netmask="255.255.255.0"),
                "eth1": _make_addrs(ipv4="192.168.1.101", ipv4_netmask="255.255.255.0"),
            }

        def _fake_stats() -> dict[str, Any]:
            class _Stat:
                isup = True

            return {"eth0": _Stat(), "eth1": _Stat()}

        monkeypatch.setattr(psutil, "net_if_addrs", _fake_addrs)
        monkeypatch.setattr(psutil, "net_if_stats", _fake_stats)

        result = list_interfaces()
        eth1 = next(i for i in result if i["name"] == "eth1")
        assert eth1["role"] == "mirror"

    def test_list_interfaces_scan_source_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """SCAN_SOURCE naming an active_scan interface marks it default."""
        monkeypatch.setenv("SCAN_SOURCE", "eth0")
        monkeypatch.delenv("CAPTURE_SOURCE", raising=False)
        monkeypatch.delenv("OTALON_SCAN_MIRROR_INTERFACES", raising=False)

        def _fake_addrs() -> dict[str, List[_SnicAddr]]:
            return {
                "eth0": _make_addrs(ipv4="192.168.1.100", ipv4_netmask="255.255.255.0"),
                "eth1": _make_addrs(ipv4="192.168.1.101", ipv4_netmask="255.255.255.0"),
            }

        def _fake_stats() -> dict[str, Any]:
            class _Stat:
                isup = True

            return {"eth0": _Stat(), "eth1": _Stat()}

        monkeypatch.setattr(psutil, "net_if_addrs", _fake_addrs)
        monkeypatch.setattr(psutil, "net_if_stats", _fake_stats)

        result = list_interfaces()
        eth0 = next(i for i in result if i["name"] == "eth0")
        eth1 = next(i for i in result if i["name"] == "eth1")
        assert eth0["is_default"] is True
        assert eth1["is_default"] is False

    def test_list_interfaces_scan_source_unset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """No interface is default when SCAN_SOURCE is unset."""
        monkeypatch.delenv("SCAN_SOURCE", raising=False)
        monkeypatch.delenv("CAPTURE_SOURCE", raising=False)
        monkeypatch.delenv("OTALON_SCAN_MIRROR_INTERFACES", raising=False)

        def _fake_addrs() -> dict[str, List[_SnicAddr]]:
            return {
                "eth0": _make_addrs(ipv4="192.168.1.100", ipv4_netmask="255.255.255.0"),
            }

        def _fake_stats() -> dict[str, Any]:
            class _Stat:
                isup = True

            return {"eth0": _Stat()}

        monkeypatch.setattr(psutil, "net_if_addrs", _fake_addrs)
        monkeypatch.setattr(psutil, "net_if_stats", _fake_stats)

        result = list_interfaces()
        assert not any(i["is_default"] for i in result)

    def test_list_interfaces_scan_source_mirror_not_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A declared mirror interface must NOT be marked default even if SCAN_SOURCE names it."""
        monkeypatch.setenv("SCAN_SOURCE", "eth1")
        monkeypatch.setenv("OTALON_SCAN_MIRROR_INTERFACES", "eth1")
        monkeypatch.delenv("CAPTURE_SOURCE", raising=False)

        def _fake_addrs() -> dict[str, List[_SnicAddr]]:
            return {
                "eth0": _make_addrs(ipv4="192.168.1.100", ipv4_netmask="255.255.255.0"),
                "eth1": _make_addrs(ipv4="192.168.1.101", ipv4_netmask="255.255.255.0"),
            }

        def _fake_stats() -> dict[str, Any]:
            class _Stat:
                isup = True

            return {"eth0": _Stat(), "eth1": _Stat()}

        monkeypatch.setattr(psutil, "net_if_addrs", _fake_addrs)
        monkeypatch.setattr(psutil, "net_if_stats", _fake_stats)

        result = list_interfaces()
        assert not any(i["is_default"] for i in result)

    def test_list_interfaces_scan_source_down_not_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A down interface named by SCAN_SOURCE must NOT be marked default."""
        monkeypatch.setenv("SCAN_SOURCE", "eth0")
        monkeypatch.delenv("CAPTURE_SOURCE", raising=False)
        monkeypatch.delenv("OTALON_SCAN_MIRROR_INTERFACES", raising=False)

        def _fake_addrs() -> dict[str, List[_SnicAddr]]:
            return {
                "eth0": _make_addrs(ipv4="192.168.1.100", ipv4_netmask="255.255.255.0"),
            }

        def _fake_stats() -> dict[str, Any]:
            class _Down:
                isup = False

            return {"eth0": _Down()}

        monkeypatch.setattr(psutil, "net_if_addrs", _fake_addrs)
        monkeypatch.setattr(psutil, "net_if_stats", _fake_stats)

        result = list_interfaces()
        assert not any(i["is_default"] for i in result)

    def test_list_interfaces_scan_source_nonexistent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """SCAN_SOURCE naming a non-existent interface results in no default."""
        monkeypatch.setenv("SCAN_SOURCE", "eth99")
        monkeypatch.delenv("CAPTURE_SOURCE", raising=False)
        monkeypatch.delenv("OTALON_SCAN_MIRROR_INTERFACES", raising=False)

        def _fake_addrs() -> dict[str, List[_SnicAddr]]:
            return {
                "eth0": _make_addrs(ipv4="192.168.1.100", ipv4_netmask="255.255.255.0"),
            }

        def _fake_stats() -> dict[str, Any]:
            class _Stat:
                isup = True

            return {"eth0": _Stat()}

        monkeypatch.setattr(psutil, "net_if_addrs", _fake_addrs)
        monkeypatch.setattr(psutil, "net_if_stats", _fake_stats)

        result = list_interfaces()
        assert not any(i["is_default"] for i in result)

    def test_list_interfaces_at_most_one_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Only the SCAN_SOURCE interface is default; other active_scan interfaces are not."""
        monkeypatch.setenv("SCAN_SOURCE", "eth0")
        monkeypatch.delenv("CAPTURE_SOURCE", raising=False)
        monkeypatch.delenv("OTALON_SCAN_MIRROR_INTERFACES", raising=False)

        def _fake_addrs() -> dict[str, List[_SnicAddr]]:
            return {
                "eth0": _make_addrs(ipv4="192.168.1.100", ipv4_netmask="255.255.255.0"),
                "eth1": _make_addrs(ipv4="192.168.1.101", ipv4_netmask="255.255.255.0"),
                "eth2": _make_addrs(ipv4="192.168.1.102", ipv4_netmask="255.255.255.0"),
            }

        def _fake_stats() -> dict[str, Any]:
            class _Stat:
                isup = True

            return {"eth0": _Stat(), "eth1": _Stat(), "eth2": _Stat()}

        monkeypatch.setattr(psutil, "net_if_addrs", _fake_addrs)
        monkeypatch.setattr(psutil, "net_if_stats", _fake_stats)

        result = list_interfaces()
        defaults = [i for i in result if i["is_default"]]
        assert len(defaults) == 1
        assert defaults[0]["name"] == "eth0"


class TestRouteOrdering:
    """FastAPI route-order sanity checks."""

    def test_interfaces_route_before_scan_id(self) -> None:
        """``/scans/interfaces`` MUST be registered before the catch-all
        ``/scans/{scan_id}`` so that ``interfaces`` is not matched as a scan id."""
        from otalon_scan.api.server import app

        paths = [r.path for r in app.routes if hasattr(r, "path")]
        interfaces_idx = paths.index("/scans/interfaces")
        scan_id_idx = paths.index("/scans/{scan_id}")
        assert interfaces_idx < scan_id_idx


class TestInterfaceItemSerialization:
    """Regression guard for SCAN-016.

    The ``GET /scans/interfaces`` route serialises through
    ``response_model=InterfacesResponse``. If ``InterfaceItem`` omits the
    ``is_default`` field, Pydantic silently drops it from the response,
    so the UI never learns which interface is the configured ``SCAN_SOURCE``.
    """

    def test_is_default_survives_response_model(self) -> None:
        """``is_default`` from ``list_interfaces`` must reach the serialised body."""
        from otalon_scan.api.schemas.interfaces import InterfaceItem, InterfacesResponse

        rows: List[dict[str, Any]] = [
            {
                "name": "enp4s0",
                "ipv4": "10.0.0.5",
                "subnet": "10.0.0.5/24",
                "is_up": True,
                "role": "active_scan",
                "mac": "aa:bb:cc:dd:ee:ff",
                "is_default": True,
            },
            {
                "name": "br-deadbeef",
                "ipv4": "172.17.0.1",
                "subnet": "172.17.0.1/16",
                "is_up": True,
                "role": "active_scan",
                "mac": None,
                "is_default": False,
            },
        ]
        response = InterfacesResponse(interfaces=[InterfaceItem(**row) for row in rows])
        dumped = response.model_dump()

        for item in dumped["interfaces"]:
            assert "is_default" in item

        defaults = [i["name"] for i in dumped["interfaces"] if i["is_default"]]
        assert defaults == ["enp4s0"]
