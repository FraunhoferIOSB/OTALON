"""Unit tests for :mod:`otalon_scan.core.module_config` and the per-module schemas.

Verifies:

- Every shipped module slug has a registered override schema.
- :func:`resolve_module_slug` normalises both ``"arp_scan"`` and
  ``"modules/arp_scan"`` to the leaf slug.
- Each schema rejects unknown keys (``extra="forbid"``) and accepts an
  empty override payload.
- Each schema delegates field validation to the Phase-1 validators in
  :mod:`otalon_scan.core.validators`.
"""

from __future__ import annotations

import pytest
from pydantic import BaseModel, ValidationError

from otalon_scan.core.module_config import (
    MODULE_SCHEMA_REGISTRY,
    resolve_module_slug,
    schema_for_module,
)
from otalon_scan.modules.arp_scan.schema import ArpScanOverrides
from otalon_scan.modules.opcua_discover.schema import OpcuaDiscoverOverrides
from otalon_scan.modules.pn_discovery.schema import PnDiscoveryOverrides
from otalon_scan.modules.port_scan.schema import PortScanOverrides
from otalon_scan.modules.snmp_scan.schema import SnmpScanOverrides

_KNOWN_SLUGS = {"arp_scan", "port_scan", "snmp_scan", "opcua_discover", "pn_discovery"}


# ---- Registry shape ----


def test_registry_covers_every_known_module() -> None:
    """Every leaf-slug module SHALL have a registered override schema."""
    assert set(MODULE_SCHEMA_REGISTRY.keys()) == _KNOWN_SLUGS


def test_registry_values_are_basemodel_subclasses() -> None:
    """Registry values SHALL be ``BaseModel`` subclasses (not instances)."""
    for slug, schema in MODULE_SCHEMA_REGISTRY.items():
        assert isinstance(schema, type), f"{slug} registry value is not a class"
        assert issubclass(schema, BaseModel), f"{slug} schema is not a BaseModel subclass"


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("arp_scan", "arp_scan"),
        ("modules/arp_scan", "arp_scan"),
        ("  modules/port_scan  ", "port_scan"),
        ("", ""),
        ("modules/unknown", "unknown"),
    ],
)
def test_resolve_module_slug(raw: str, expected: str) -> None:
    """``resolve_module_slug`` SHALL strip the ``modules/`` prefix."""
    assert resolve_module_slug(raw) == expected


def test_schema_for_module_lookups() -> None:
    """``schema_for_module`` SHALL return the registered class or ``None``."""
    assert schema_for_module("arp_scan") is ArpScanOverrides
    assert schema_for_module("modules/port_scan") is PortScanOverrides
    assert schema_for_module("does_not_exist") is None


# ---- Per-schema rejection of unknown keys ----


@pytest.mark.parametrize(
    "schema_cls",
    [
        ArpScanOverrides,
        PortScanOverrides,
        SnmpScanOverrides,
        OpcuaDiscoverOverrides,
        PnDiscoveryOverrides,
    ],
)
def test_schema_rejects_unknown_keys(schema_cls: type[BaseModel]) -> None:
    """Every per-module schema SHALL reject unknown keys."""
    with pytest.raises(ValidationError):
        schema_cls.model_validate({"definitely_not_a_real_field": "x"})


@pytest.mark.parametrize(
    "schema_cls",
    [
        ArpScanOverrides,
        PortScanOverrides,
        SnmpScanOverrides,
        OpcuaDiscoverOverrides,
        PnDiscoveryOverrides,
    ],
)
def test_schema_accepts_empty_payload(schema_cls: type[BaseModel]) -> None:
    """Every per-module schema SHALL accept an empty override payload."""
    instance = schema_cls.model_validate({})
    assert isinstance(instance, schema_cls)


# ---- Field-level delegation to Phase-1 validators ----


def test_arp_scan_target_subnet_normalises_cidr() -> None:
    """ArpScanOverrides SHALL normalise non-canonical CIDR input."""
    instance = ArpScanOverrides.model_validate({"target_subnet": "10.0.0.5/24"})
    assert instance.target_subnet == "10.0.0.0/24"


def test_arp_scan_target_subnet_rejects_garbage() -> None:
    """ArpScanOverrides SHALL reject malformed CIDR input via the validator."""
    with pytest.raises(ValidationError):
        ArpScanOverrides.model_validate({"target_subnet": "not-a-subnet"})


def test_port_scan_port_range_rejects_descending() -> None:
    """PortScanOverrides SHALL reject descending port ranges via the validator."""
    with pytest.raises(ValidationError):
        PortScanOverrides.model_validate({"port_range": "1024-22"})


def test_port_scan_port_range_rejects_out_of_range() -> None:
    """PortScanOverrides SHALL reject port tokens outside [1, 65535]."""
    with pytest.raises(ValidationError):
        PortScanOverrides.model_validate({"port_range": "0-100"})
    with pytest.raises(ValidationError):
        PortScanOverrides.model_validate({"port_range": "1-70000"})


def test_port_scan_timing_template_rejects_out_of_range() -> None:
    """PortScanOverrides SHALL reject timing templates outside '0'..'5'."""
    with pytest.raises(ValidationError):
        PortScanOverrides.model_validate({"timing_template": "6"})


def test_port_scan_target_ip_accepts_v4_and_v6() -> None:
    """PortScanOverrides SHALL accept canonical IPv4 and IPv6 addresses."""
    v4 = PortScanOverrides.model_validate({"target_ip": "192.168.1.1"})
    assert v4.target_ip == "192.168.1.1"
    v6 = PortScanOverrides.model_validate({"target_ip": "::1"})
    assert v6.target_ip == "::1"


def test_port_scan_target_ip_rejects_garbage() -> None:
    """PortScanOverrides SHALL reject malformed IP input via the validator."""
    with pytest.raises(ValidationError):
        PortScanOverrides.model_validate({"target_ip": "not.an.ip.addr"})


def test_opcua_discover_target_port_bounds() -> None:
    """OpcuaDiscoverOverrides SHALL bound target_port to [1, 65535]."""
    OpcuaDiscoverOverrides.model_validate({"target_port": 4840})
    with pytest.raises(ValidationError):
        OpcuaDiscoverOverrides.model_validate({"target_port": 0})
    with pytest.raises(ValidationError):
        OpcuaDiscoverOverrides.model_validate({"target_port": 70000})


def test_pn_discovery_only_accepts_network_interface() -> None:
    """PnDiscoveryOverrides SHALL forbid all fields except network_interface."""
    with pytest.raises(ValidationError):
        PnDiscoveryOverrides.model_validate({"target_ip": "127.0.0.1"})


# ---- SCAN-003/009/010/014: extended port_scan override fields ----


def test_port_scan_accepts_boolean_toggle_overrides() -> None:
    """PortScanOverrides SHALL accept the udp/version/detection booleans."""
    instance = PortScanOverrides.model_validate(
        {
            "udp_scan": True,
            "service_version_info": True,
            "detection_and_traceroute": False,
        }
    )
    assert instance.udp_scan is True
    assert instance.service_version_info is True
    assert instance.detection_and_traceroute is False


def test_port_scan_host_timeout_ms_bounds() -> None:
    """PortScanOverrides SHALL bound host_timeout_ms to [100, 3_600_000]."""
    assert PortScanOverrides.model_validate({"host_timeout_ms": 5000}).host_timeout_ms == 5000
    with pytest.raises(ValidationError):
        PortScanOverrides.model_validate({"host_timeout_ms": 99})
    with pytest.raises(ValidationError):
        PortScanOverrides.model_validate({"host_timeout_ms": 3_600_001})


def test_port_scan_hard_timeout_s_bounds() -> None:
    """PortScanOverrides SHALL bound hard_timeout_s to [1, 3_600]."""
    assert PortScanOverrides.model_validate({"hard_timeout_s": 120}).hard_timeout_s == 120
    with pytest.raises(ValidationError):
        PortScanOverrides.model_validate({"hard_timeout_s": 0})
    with pytest.raises(ValidationError):
        PortScanOverrides.model_validate({"hard_timeout_s": 3_601})


def test_port_scan_unknown_key_still_422s() -> None:
    """An unknown port_scan key SHALL still be rejected (extra='forbid')."""
    with pytest.raises(ValidationError):
        PortScanOverrides.model_validate({"service_version_infooo": True})


# ---- SCAN-003 (snmp half): extended snmp_scan override fields ----


def test_snmp_scan_accepts_communities_triples() -> None:
    """SnmpScanOverrides SHALL accept a list of valid community triples."""
    instance = SnmpScanOverrides.model_validate(
        {"communities": [["192.168.0.0/24", "public", 0], ["10.0.0.0/8", "private", 1]]}
    )
    assert instance.communities is not None
    assert len(instance.communities) == 2


def test_snmp_scan_communities_rejects_bad_cidr() -> None:
    """SnmpScanOverrides SHALL reject a community triple with a bad CIDR."""
    with pytest.raises(ValidationError):
        SnmpScanOverrides.model_validate({"communities": [["not-a-cidr", "public", 0]]})


def test_snmp_scan_communities_rejects_malformed_triple() -> None:
    """SnmpScanOverrides SHALL reject a community entry that is not a triple."""
    with pytest.raises(ValidationError):
        SnmpScanOverrides.model_validate({"communities": [["192.168.0.0/24", "public"]]})


def test_snmp_scan_operation_timeout_bounds() -> None:
    """SnmpScanOverrides SHALL bound operation_timeout to [1, 600]."""
    assert SnmpScanOverrides.model_validate({"operation_timeout": 30}).operation_timeout == 30
    with pytest.raises(ValidationError):
        SnmpScanOverrides.model_validate({"operation_timeout": 0})
    with pytest.raises(ValidationError):
        SnmpScanOverrides.model_validate({"operation_timeout": 601})


def test_snmp_scan_retry_attempts_bounds() -> None:
    """SnmpScanOverrides SHALL bound retry_attempts to [0, 10] (0 allowed)."""
    assert SnmpScanOverrides.model_validate({"retry_attempts": 0}).retry_attempts == 0
    assert SnmpScanOverrides.model_validate({"retry_attempts": 10}).retry_attempts == 10
    with pytest.raises(ValidationError):
        SnmpScanOverrides.model_validate({"retry_attempts": -1})
    with pytest.raises(ValidationError):
        SnmpScanOverrides.model_validate({"retry_attempts": 11})


def test_snmp_scan_unknown_key_still_422s() -> None:
    """An unknown snmp_scan key SHALL still be rejected (extra='forbid')."""
    with pytest.raises(ValidationError):
        SnmpScanOverrides.model_validate({"community": "public"})
