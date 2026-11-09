"""Unit tests for the SCAN-037 mirror/SPAN guard on the scan trigger path.

ICS/OT safety invariant: an interface classified as ``mirror`` by
:func:`otalon_scan.core.interface_roles.classify_interface_role` is a passive
SPAN/TAP port. Actively transmitting on it (ARP sweep, nmap probe, PROFINET
DCP, SNMP walk) is a real operational fault, so ``POST /scans/start`` MUST
reject such an interface for every module unless the operator passes the
explicit top-level ``allow_mirror_interface`` flag.

The tests declare the mirror set through ``OTALON_SCAN_MIRROR_INTERFACES``
and point it at a real host interface, because the existence check in
:func:`otalon_scan.core.validators.validate_network_interface` runs first and
would otherwise mask the mirror verdict.
"""

from __future__ import annotations

from typing import Any, Dict

import psutil
import pytest
from pydantic import BaseModel, ValidationError

from otalon_scan.api.schemas.scans import StartScanRequest
from otalon_scan.core.module_config import MODULE_SCHEMA_REGISTRY
from otalon_scan.core.validators import (
    MIRROR_OVERRIDE_CONTEXT_KEY,
    validate_network_interface,
)

MIRROR_REJECT_MESSAGE = "is a mirror/SPAN port"

# Minimal valid companion overrides so each module schema validates for a
# reason other than a missing sibling field. All five schemas have every
# field optional, so only ``network_interface`` is required per case.
MODULE_SLUGS = ["arp_scan", "port_scan", "snmp_scan", "opcua_discover", "pn_discovery"]


def _host_interface() -> str:
    """Return one interface name that genuinely exists on the test host."""
    interfaces = list(psutil.net_if_addrs().keys())
    assert interfaces, "host has no network interfaces; cannot run this test"
    return str(interfaces[0])


@pytest.fixture()
def mirror_interface(monkeypatch: pytest.MonkeyPatch) -> str:
    """Declare a real host interface as a mirror port for the test duration."""
    iface = _host_interface()
    monkeypatch.delenv("CAPTURE_SOURCE", raising=False)
    monkeypatch.setenv("OTALON_SCAN_MIRROR_INTERFACES", iface)
    return iface


@pytest.fixture()
def plain_interface(monkeypatch: pytest.MonkeyPatch) -> str:
    """Return a real host interface with no mirror declaration in force."""
    monkeypatch.delenv("CAPTURE_SOURCE", raising=False)
    monkeypatch.delenv("OTALON_SCAN_MIRROR_INTERFACES", raising=False)
    return _host_interface()


class TestValidatorLevelGuard:
    """Tests for :func:`validate_network_interface` itself."""

    def test_rejects_mirror_interface_by_default(self, mirror_interface: str) -> None:
        """A mirror-declared interface SHALL be rejected without an override."""
        with pytest.raises(ValueError, match=MIRROR_REJECT_MESSAGE):
            validate_network_interface(mirror_interface)

    def test_accepts_mirror_interface_with_explicit_override(self, mirror_interface: str) -> None:
        """``allow_mirror=True`` SHALL accept the mirror interface unchanged."""
        assert validate_network_interface(mirror_interface, allow_mirror=True) == mirror_interface

    def test_accepts_non_mirror_interface(self, plain_interface: str) -> None:
        """An undeclared interface SHALL still pass, preserving prior behaviour."""
        assert validate_network_interface(plain_interface) == plain_interface

    def test_capture_source_alone_declares_a_mirror(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """``CAPTURE_SOURCE`` alone SHALL be enough to reject the interface."""
        iface = _host_interface()
        monkeypatch.delenv("OTALON_SCAN_MIRROR_INTERFACES", raising=False)
        monkeypatch.setenv("CAPTURE_SOURCE", iface)
        with pytest.raises(ValueError, match=MIRROR_REJECT_MESSAGE):
            validate_network_interface(iface)

    def test_unknown_interface_still_rejected_first(self, mirror_interface: str) -> None:
        """The existence check SHALL keep precedence over the mirror check."""
        with pytest.raises(ValueError, match="not present on host"):
            validate_network_interface("definitely_not_an_interface_zzz_42")

    def test_override_is_logged(self, mirror_interface: str, caplog: pytest.LogCaptureFixture) -> None:
        """The deliberate override SHALL emit a WARNING naming the interface."""
        from loguru import logger

        records: list[str] = []
        sink_id = logger.add(records.append, level="WARNING")
        try:
            validate_network_interface(mirror_interface, allow_mirror=True)
        finally:
            logger.remove(sink_id)
        assert any(mirror_interface in line and "mirror/SPAN" in line for line in records)


class TestModuleSchemaGuard:
    """The guard SHALL hold for every registered per-module override schema."""

    @pytest.mark.parametrize("slug", MODULE_SLUGS)
    def test_module_schema_rejects_mirror_interface(self, slug: str, mirror_interface: str) -> None:
        """Each module's ``*Overrides`` schema SHALL reject a mirror bind."""
        schema: type[BaseModel] = MODULE_SCHEMA_REGISTRY[slug]
        with pytest.raises(ValidationError, match=MIRROR_REJECT_MESSAGE):
            schema.model_validate({"network_interface": mirror_interface})

    @pytest.mark.parametrize("slug", MODULE_SLUGS)
    def test_module_schema_rejects_without_context(self, slug: str, mirror_interface: str) -> None:
        """A missing validation context SHALL default to reject, not allow."""
        schema: type[BaseModel] = MODULE_SCHEMA_REGISTRY[slug]
        with pytest.raises(ValidationError, match=MIRROR_REJECT_MESSAGE):
            schema.model_validate({"network_interface": mirror_interface}, context=None)

    @pytest.mark.parametrize("slug", MODULE_SLUGS)
    def test_module_schema_rejects_falsy_context_flag(self, slug: str, mirror_interface: str) -> None:
        """A non-``True`` context flag SHALL NOT unlock the mirror bind."""
        schema: type[BaseModel] = MODULE_SCHEMA_REGISTRY[slug]
        for flag in (False, "true", 1, None):
            with pytest.raises(ValidationError, match=MIRROR_REJECT_MESSAGE):
                schema.model_validate(
                    {"network_interface": mirror_interface},
                    context={MIRROR_OVERRIDE_CONTEXT_KEY: flag},
                )

    @pytest.mark.parametrize("slug", MODULE_SLUGS)
    def test_module_schema_accepts_with_context_override(self, slug: str, mirror_interface: str) -> None:
        """The explicit context flag SHALL unlock the mirror bind."""
        schema: type[BaseModel] = MODULE_SCHEMA_REGISTRY[slug]
        model = schema.model_validate(
            {"network_interface": mirror_interface},
            context={MIRROR_OVERRIDE_CONTEXT_KEY: True},
        )
        assert getattr(model, "network_interface") == mirror_interface

    @pytest.mark.parametrize("slug", MODULE_SLUGS)
    def test_module_schema_accepts_non_mirror_interface(self, slug: str, plain_interface: str) -> None:
        """Non-mirror interfaces SHALL keep validating as before."""
        schema: type[BaseModel] = MODULE_SCHEMA_REGISTRY[slug]
        model = schema.model_validate({"network_interface": plain_interface})
        assert getattr(model, "network_interface") == plain_interface


class TestTriggerPathGuard:
    """End-to-end guard on :class:`StartScanRequest` — the trigger path."""

    @pytest.mark.parametrize("slug", MODULE_SLUGS)
    def test_start_scan_request_rejects_mirror_interface(self, slug: str, mirror_interface: str) -> None:
        """``POST /scans/start`` payloads SHALL be rejected per module."""
        payload: Dict[str, Any] = {
            "module_name": f"modules/{slug}",
            "overrides": {"network_interface": mirror_interface},
        }
        with pytest.raises(ValidationError, match=MIRROR_REJECT_MESSAGE):
            StartScanRequest.model_validate(payload)

    @pytest.mark.parametrize("slug", MODULE_SLUGS)
    def test_start_scan_request_rejects_when_flag_false(self, slug: str, mirror_interface: str) -> None:
        """An explicit ``allow_mirror_interface=false`` SHALL still reject."""
        payload: Dict[str, Any] = {
            "module_name": f"modules/{slug}",
            "overrides": {"network_interface": mirror_interface},
            "allow_mirror_interface": False,
        }
        with pytest.raises(ValidationError, match=MIRROR_REJECT_MESSAGE):
            StartScanRequest.model_validate(payload)

    @pytest.mark.parametrize("slug", MODULE_SLUGS)
    def test_start_scan_request_allows_with_explicit_flag(self, slug: str, mirror_interface: str) -> None:
        """``allow_mirror_interface=true`` SHALL let the request through."""
        payload: Dict[str, Any] = {
            "module_name": f"modules/{slug}",
            "overrides": {"network_interface": mirror_interface},
            "allow_mirror_interface": True,
        }
        req = StartScanRequest.model_validate(payload)
        assert req.allow_mirror_interface is True
        assert req.overrides == {"network_interface": mirror_interface}

    def test_flag_defaults_to_false(self, plain_interface: str) -> None:
        """The override flag SHALL default to ``False`` (reject-by-default)."""
        req = StartScanRequest.model_validate({"module_name": "modules/arp_scan"})
        assert req.allow_mirror_interface is False

    def test_flag_is_not_a_module_override_key(self, mirror_interface: str) -> None:
        """The flag SHALL NOT be smuggleable through the ``overrides`` payload."""
        payload: Dict[str, Any] = {
            "module_name": "modules/arp_scan",
            "overrides": {
                "network_interface": mirror_interface,
                "allow_mirror_interface": True,
            },
        }
        with pytest.raises(ValidationError):
            StartScanRequest.model_validate(payload)

    def test_flag_not_forwarded_into_module_overrides(self, mirror_interface: str) -> None:
        """The flag SHALL NOT leak into the normalised override payload."""
        req = StartScanRequest.model_validate(
            {
                "module_name": "modules/arp_scan",
                "overrides": {"network_interface": mirror_interface},
                "allow_mirror_interface": True,
            }
        )
        assert req.overrides is not None
        assert "allow_mirror_interface" not in req.overrides

    def test_non_interface_overrides_unaffected(self, mirror_interface: str) -> None:
        """A payload without ``network_interface`` SHALL be unaffected."""
        req = StartScanRequest.model_validate(
            {
                "module_name": "modules/port_scan",
                "overrides": {"port_range": "22,80"},
            }
        )
        assert req.overrides == {"port_range": "22,80"}


class TestDisplayEndpointUnaffected:
    """The SCAN-037 guard SHALL NOT alter the interface-listing contract."""

    def test_list_interfaces_still_reports_mirror_role(self, mirror_interface: str) -> None:
        """``list_interfaces`` SHALL keep classifying, not rejecting."""
        from otalon_scan.core.interface_roles import list_interfaces

        entries = {item["name"]: item for item in list_interfaces()}
        assert mirror_interface in entries
        assert entries[mirror_interface]["role"] == "mirror"
