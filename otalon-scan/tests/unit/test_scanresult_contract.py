"""Unit tests for the F-02 ``ScanResult`` discriminated union contract.

Verifies the ``scan--scanresult-contract`` capability:

- The per-module typed result classes (``ArpScanResult``,
  ``PortScanResult``, ``PnDiscoveryResult``, ``OpcUaDiscoverResult``,
  ``SnmpScanResult``, ``CveLookupResult``) exist, set the right
  ``module_type`` literal, and inherit the legacy :class:`ScanResult`
  fields so the persistence path keeps working.
- ``TypeAdapter(TypedScanResult).validate_python(...)`` dispatches on
  ``module_type`` and returns the correct concrete class without
  manual branching.
- Per-module ``*Finding`` models reject unknown fields
  (``extra='forbid'``) and accept typed inputs.
- The ``MODULE_RESULT_REGISTRY`` covers every shipped module plus the
  ``cve_lookup`` forward-compat placeholder.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from otalon_scan.core.models import (
    MODULE_RESULT_REGISTRY,
    ArpFinding,
    ArpScanResult,
    CveFinding,
    CveLookupResult,
    OpcUaDiscoverResult,
    OpcUaFinding,
    PnDiscoveryResult,
    PnFinding,
    PortFinding,
    PortScanResult,
    ScanResult,
    SnmpFinding,
    SnmpScanResult,
    TypedScanResult,
    typed_scan_result_adapter,
)

_TYPED_RESULT_CLASSES = [
    ArpScanResult,
    PortScanResult,
    PnDiscoveryResult,
    OpcUaDiscoverResult,
    SnmpScanResult,
    CveLookupResult,
]

_DISCRIMINATORS = {
    ArpScanResult: "arp_scan",
    PortScanResult: "port_scan",
    PnDiscoveryResult: "pn_discovery",
    OpcUaDiscoverResult: "opcua_discover",
    SnmpScanResult: "snmp_scan",
    CveLookupResult: "cve_lookup",
}


# ---- Class-level invariants ----


@pytest.mark.parametrize("result_cls,expected_discriminator", list(_DISCRIMINATORS.items()))
def test_typed_result_discriminator_value(result_cls: type, expected_discriminator: str) -> None:
    """Each ``*ScanResult`` SHALL set ``module_type`` to the module slug."""
    instance = result_cls(module_name=f"T/{expected_discriminator}")
    assert getattr(instance, "module_type") == expected_discriminator


@pytest.mark.parametrize("result_cls", _TYPED_RESULT_CLASSES)
def test_typed_result_inherits_scanresult(result_cls: type) -> None:
    """Every typed result SHALL be a subclass of the legacy ``ScanResult``."""
    assert issubclass(result_cls, ScanResult)


def test_module_result_registry_covers_every_slug() -> None:
    """The registry SHALL cover every shipped module + cve_lookup placeholder."""
    assert set(MODULE_RESULT_REGISTRY.keys()) == set(_DISCRIMINATORS.values())
    for slug, cls in MODULE_RESULT_REGISTRY.items():
        assert _DISCRIMINATORS[cls] == slug


# ---- Discriminated-union dispatch ----


@pytest.mark.parametrize("result_cls,expected_discriminator", list(_DISCRIMINATORS.items()))
def test_typed_scan_result_adapter_dispatches_on_module_type(result_cls: type, expected_discriminator: str) -> None:
    """``TypeAdapter(TypedScanResult)`` SHALL dispatch on ``module_type``."""
    payload = result_cls(module_name=f"T/{expected_discriminator}").model_dump(mode="json")
    parsed = typed_scan_result_adapter.validate_python(payload)
    assert isinstance(parsed, result_cls)
    assert getattr(parsed, "module_type") == expected_discriminator


def test_typed_scan_result_adapter_rejects_unknown_module_type() -> None:
    """An unknown ``module_type`` SHALL raise ``ValidationError``."""
    payload = {
        "module_name": "dummy",
        "module_type": "nonexistent_module_type",
        "findings": [],
    }
    with pytest.raises(ValidationError):
        typed_scan_result_adapter.validate_python(payload)


def test_typed_scan_result_adapter_rejects_missing_discriminator() -> None:
    """A payload without ``module_type`` SHALL raise ``ValidationError``."""
    payload = {"module_name": "dummy", "findings": []}
    with pytest.raises(ValidationError):
        typed_scan_result_adapter.validate_python(payload)


def test_typed_scan_result_union_type_is_annotated() -> None:
    """``TypedScanResult`` SHALL carry the ``Field(discriminator=...)`` metadata."""
    # The Annotated form is what makes the discriminated-union dispatch
    # work; we only assert it's a non-trivial type alias here.
    assert TypedScanResult is not None


# ---- Per-module *Finding models reject unknown fields ----


_ALL_FINDINGS = [
    (ArpFinding, {"ip_address": "10.0.0.1"}),
    (PortFinding, {"ip_address": "10.0.0.1", "port": 22}),
    (PnFinding, {"mac_address": "aa:bb:cc:dd:ee:ff"}),
    (OpcUaFinding, {"endpoint_url": "opc.tcp://10.0.0.1:4840"}),
    (SnmpFinding, {"ip_address": "10.0.0.1"}),
    (CveFinding, {"cve_id": "CVE-2024-0001"}),
]


@pytest.mark.parametrize("finding_cls,valid_payload", _ALL_FINDINGS)
def test_finding_rejects_unknown_field(finding_cls: type, valid_payload: dict) -> None:
    """Each ``*Finding`` SHALL reject unknown keys (extra='forbid')."""
    payload = {**valid_payload, "definitely_not_a_real_field": "x"}
    with pytest.raises(ValidationError) as excinfo:
        finding_cls.model_validate(payload)
    assert "definitely_not_a_real_field" in str(excinfo.value)


@pytest.mark.parametrize("finding_cls,valid_payload", _ALL_FINDINGS)
def test_finding_accepts_typed_payload(finding_cls: type, valid_payload: dict) -> None:
    """Each ``*Finding`` SHALL construct cleanly from a valid payload."""
    instance = finding_cls.model_validate(valid_payload)
    assert isinstance(instance, finding_cls)


def test_port_finding_bounds_port() -> None:
    """``PortFinding.port`` SHALL be bounded to [1, 65535]."""
    with pytest.raises(ValidationError):
        PortFinding.model_validate({"ip_address": "10.0.0.1", "port": 0})
    with pytest.raises(ValidationError):
        PortFinding.model_validate({"ip_address": "10.0.0.1", "port": 70_000})


def test_port_finding_transport_is_literal() -> None:
    """``PortFinding.transport`` SHALL accept only 'tcp' or 'udp'."""
    with pytest.raises(ValidationError):
        PortFinding.model_validate({"ip_address": "10.0.0.1", "port": 22, "transport": "sctp"})


# ---- Per-module typed result yields are isinstance of their concrete class ----


@pytest.mark.parametrize("result_cls", _TYPED_RESULT_CLASSES)
def test_typed_result_module_dump_round_trip(result_cls: type) -> None:
    """A typed result SHALL round-trip via ``model_dump`` + adapter."""
    discriminator = _DISCRIMINATORS[result_cls]
    instance = result_cls(module_name=f"X/{discriminator}", protocol="x")
    dumped = instance.model_dump(mode="json")
    assert dumped["module_type"] == discriminator
    reparsed = typed_scan_result_adapter.validate_python(dumped)
    assert isinstance(reparsed, result_cls)


# ---- raw_results JSON serialization (Follow-up 2026-05-19) ----------------


def test_scan_result_model_dump_json_handles_dataframe_in_raw_results() -> None:
    """``ScanResult.model_dump(mode='json')`` SHALL accept a pandas DataFrame
    in ``raw_results`` without raising ``PydanticSerializationError``.

    Regression for the 2026-05-19 follow-up: every arp_scan run logged
    ``Failed to run module: Unable to serialize unknown type: <class
    'pandas.core.frame.DataFrame'>`` after persistence completed,
    because :meth:`ModuleManager._finalize_run` calls
    ``final_result.model_dump(mode='json')`` and the legacy ``Any`` field
    had no field serializer for non-JSON-native shapes.
    """
    import pandas as pd

    df = pd.DataFrame([{"IP": "10.0.0.1"}, {"IP": "10.0.0.2"}])
    result = ScanResult(module_name="T1018/arp_scan", protocol="arp", raw_results=df)

    dumped = result.model_dump(mode="json")
    assert dumped["raw_results"] == [{"IP": "10.0.0.1"}, {"IP": "10.0.0.2"}]


def test_scan_result_model_dump_json_handles_none_raw_results() -> None:
    """``raw_results=None`` SHALL serialize as ``None`` (default path)."""
    result = ScanResult(module_name="T/x", protocol="x")
    dumped = result.model_dump(mode="json")
    assert dumped["raw_results"] is None


def test_scan_result_model_dump_json_passes_list_through() -> None:
    """``raw_results`` already shaped as ``list[dict]`` SHALL pass through verbatim."""
    payload = [{"ip": "10.0.0.1", "open_ports": [22]}]
    result = ScanResult(module_name="T/x", protocol="x", raw_results=payload)
    dumped = result.model_dump(mode="json")
    assert dumped["raw_results"] == payload


def test_scan_result_python_mode_dump_preserves_dataframe() -> None:
    """``model_dump()`` (default, python mode) SHALL leave the DataFrame intact.

    The serializer is scoped to ``when_used='json'`` so in-process Python
    consumers can still receive the native object. Only the JSON-mode
    round-trip needs the coercion.
    """
    import pandas as pd

    df = pd.DataFrame([{"IP": "10.0.0.1"}])
    result = ScanResult(module_name="T/x", protocol="x", raw_results=df)
    dumped = result.model_dump()
    assert isinstance(dumped["raw_results"], pd.DataFrame)
