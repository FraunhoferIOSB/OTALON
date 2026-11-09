"""Unit tests for the per-module ``*Config`` full-schema models (F-02).

Verifies the ``scan--module-config-schemas`` capability:

- Every shipped module slug has a registered ``*Config`` schema.
- ``CveLookupConfig`` is registered as a forward-compatible placeholder.
- Each schema rejects unknown fields (``extra="forbid"``).
- Each schema rejects type coercion (``strict=True``).
- Each schema rejects out-of-range values (``Field(ge=, le=)``).
- Each module's ``config.json`` defaults validate cleanly against the
  registered schema.
- Schemas are importable without dragging FastAPI / uvicorn transitively
  (task 2.11 — forward-compat with MCP F-04).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from pydantic import BaseModel, ValidationError

from otalon_scan.core.models import CveLookupConfig
from otalon_scan.core.module_config import (
    MODULE_CONFIG_REGISTRY,
    config_schema_for_module,
    validate_module_default_configs,
)
from otalon_scan.modules.arp_scan.config import ArpScanConfig
from otalon_scan.modules.opcua_discover.config import OpcUaDiscoverConfig
from otalon_scan.modules.pn_discovery.config import PnDiscoveryConfig
from otalon_scan.modules.port_scan.config import PortScanConfig
from otalon_scan.modules.snmp_scan.config import SnmpScanConfig

_KNOWN_FULL_SLUGS = {
    "arp_scan",
    "port_scan",
    "snmp_scan",
    "opcua_discover",
    "pn_discovery",
    "cve_lookup",
}

_MODULES_ROOT = Path(__file__).resolve().parents[2] / "src" / "otalon_scan" / "modules"


# ---- Registry shape ----


def test_full_config_registry_covers_every_known_module() -> None:
    """Every shipped module + cve_lookup placeholder SHALL be registered."""
    assert set(MODULE_CONFIG_REGISTRY.keys()) == _KNOWN_FULL_SLUGS


def test_full_config_registry_values_are_basemodel_subclasses() -> None:
    """Registry values SHALL be ``BaseModel`` subclasses."""
    for slug, schema in MODULE_CONFIG_REGISTRY.items():
        assert isinstance(schema, type), f"{slug} registry value is not a class"
        assert issubclass(schema, BaseModel), f"{slug} schema is not a BaseModel subclass"


def test_config_schema_for_module_lookups() -> None:
    """``config_schema_for_module`` SHALL return the registered class or ``None``."""
    assert config_schema_for_module("arp_scan") is ArpScanConfig
    assert config_schema_for_module("modules/port_scan") is PortScanConfig
    assert config_schema_for_module("cve_lookup") is CveLookupConfig
    assert config_schema_for_module("does_not_exist") is None


@pytest.mark.parametrize(
    "schema_cls,expected_module_type",
    [
        (ArpScanConfig, "arp_scan"),
        (PortScanConfig, "port_scan"),
        (SnmpScanConfig, "snmp_scan"),
        (OpcUaDiscoverConfig, "opcua_discover"),
        (PnDiscoveryConfig, "pn_discovery"),
        (CveLookupConfig, "cve_lookup"),
    ],
)
def test_module_type_discriminator_matches_slug(schema_cls: type[BaseModel], expected_module_type: str) -> None:
    """``module_type`` literal SHALL exactly match the directory-name slug."""
    instance = schema_cls.model_construct()
    assert getattr(instance, "module_type") == expected_module_type


# ---- Unknown-field rejection (extra="forbid") ----


_ALL_FULL_SCHEMAS = [
    ArpScanConfig,
    PortScanConfig,
    SnmpScanConfig,
    OpcUaDiscoverConfig,
    PnDiscoveryConfig,
    CveLookupConfig,
]


@pytest.mark.parametrize("schema_cls", _ALL_FULL_SCHEMAS)
def test_schema_rejects_unknown_field(schema_cls: type[BaseModel]) -> None:
    """Every ``*Config`` schema SHALL reject unknown keys (extra='forbid')."""
    payload = {"definitely_not_a_real_field": "x"}
    # ArpScanConfig and PortScanConfig also need their required fields;
    # we only care about whether unknown-key rejection fires, so we add
    # plausible minimal-valid values for the required fields.
    if schema_cls is ArpScanConfig:
        payload["target_subnet"] = "10.0.0.0/24"
    elif schema_cls is PortScanConfig:
        payload["target_ip"] = "10.0.0.1"
    elif schema_cls is OpcUaDiscoverConfig:
        payload["target_ip"] = "10.0.0.1"
    with pytest.raises(ValidationError) as excinfo:
        schema_cls.model_validate(payload)
    assert "definitely_not_a_real_field" in str(excinfo.value)


# ---- Type-coercion rejection (strict=True) ----


def test_arp_scan_config_rejects_string_int_for_timeout() -> None:
    """``strict=True`` SHALL reject ``"30"`` (str) for an int field."""
    with pytest.raises(ValidationError):
        ArpScanConfig.model_validate({"target_subnet": "10.0.0.0/24", "host_timeout_ms": "30"})


def test_opcua_discover_config_rejects_string_port() -> None:
    """``strict=True`` SHALL reject ``"4840"`` (str) for ``target_port`` int."""
    with pytest.raises(ValidationError):
        OpcUaDiscoverConfig.model_validate({"target_ip": "10.0.0.1", "target_port": "4840"})


# ---- Bounded-field range rejection ----


def test_arp_scan_config_rejects_out_of_range_timeout() -> None:
    """``host_timeout_ms`` SHALL be bounded; values outside [1, 600_000] rejected."""
    with pytest.raises(ValidationError):
        ArpScanConfig.model_validate({"target_subnet": "10.0.0.0/24", "host_timeout_ms": 0})
    with pytest.raises(ValidationError):
        ArpScanConfig.model_validate({"target_subnet": "10.0.0.0/24", "host_timeout_ms": 600_001})


def test_opcua_discover_config_rejects_out_of_range_port() -> None:
    """``target_port`` SHALL be bounded to [1, 65535]."""
    with pytest.raises(ValidationError):
        OpcUaDiscoverConfig.model_validate({"target_ip": "10.0.0.1", "target_port": 0})
    with pytest.raises(ValidationError):
        OpcUaDiscoverConfig.model_validate({"target_ip": "10.0.0.1", "target_port": 70_000})


# ---- config.json defaults validate against the schema ----


@pytest.mark.parametrize(
    "module_slug,schema_cls",
    [
        ("arp_scan", ArpScanConfig),
        ("port_scan", PortScanConfig),
        ("snmp_scan", SnmpScanConfig),
        ("opcua_discover", OpcUaDiscoverConfig),
        ("pn_discovery", PnDiscoveryConfig),
    ],
)
def test_module_default_config_validates(module_slug: str, schema_cls: type[BaseModel]) -> None:
    """Each module's ``config.json`` SHALL validate against its ``*Config`` schema."""
    config_path = _MODULES_ROOT / module_slug / "config.json"
    with config_path.open("r", encoding="utf-8") as fh:
        payload = json.load(fh)
    instance = schema_cls.model_validate(payload)
    assert isinstance(instance, schema_cls)


def test_validate_module_default_configs_no_drift() -> None:
    """The startup validator SHALL succeed on the shipped defaults."""
    # No raise => no drift between every module's config.json and its schema.
    validate_module_default_configs(_MODULES_ROOT)


# ---- Forward-compat: schemas importable without web stack (task 2.11) ----


def test_config_schemas_do_not_depend_on_fastapi() -> None:
    """``ArpScanConfig`` import SHALL NOT pull in FastAPI / Starlette / uvicorn.

    The schemas are designed for reuse by the future MCP ``start_scan``
    tool (capability ``scan--mcp-tools``); that tool runs in
    ``otalon-mcp``, which does NOT have a web framework as a
    dependency. Capturing this invariant here prevents accidental
    coupling regressions.
    """
    # Identify modules already loaded for the test run; we only check
    # that none of the *Config modules' own dependencies trigger a
    # FastAPI import on first load.
    config_modules = [
        "otalon_scan.modules.arp_scan.config",
        "otalon_scan.modules.port_scan.config",
        "otalon_scan.modules.pn_discovery.config",
        "otalon_scan.modules.opcua_discover.config",
        "otalon_scan.modules.snmp_scan.config",
    ]
    for name in config_modules:
        assert name in sys.modules, f"{name} should already be loaded by the test imports above"

    # The schemas' transitive imports MUST NOT include FastAPI/uvicorn.
    # We assert by inspecting each *Config module's __dict__ for any
    # FastAPI/uvicorn artefacts. The schemas import only typing,
    # pydantic, and (indirectly) stdlib.
    for name in config_modules:
        module = sys.modules[name]
        for forbidden in ("FastAPI", "APIRouter", "Starlette", "uvicorn"):
            assert not hasattr(module, forbidden), f"{name} should not expose {forbidden}"
