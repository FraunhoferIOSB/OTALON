"""Regression tests for the OPC UA discovery ``device_type`` mapping (G2-02).

Operator decision (P8 Findings-R2 / G2-02): ``device_type`` is a *purely
manual* operator field ("Controller" / "HMI" / "IPC"). Automatic scans —
``opcua_discover`` in particular — MUST NEVER populate it. A live device
had ``device_type = "eUAServer@192.168.0.41"`` (the OPC-UA *application
name*), which is nonsense as a device type.

These tests stub ``uadiscover`` so no network traffic is required. They
pin two invariants of :class:`OpcUaEnumModule.scan`:

* the emitted :class:`DeviceFinding` leaves ``device_type`` ``None``, and
* the OPC-UA application name is still discoverable in
  ``notes`` / ``description`` / ``extra`` (so no information is lost).
"""

from __future__ import annotations

from typing import Any, Dict, List
from unittest.mock import patch

import pytest

from otalon_scan.core.models import DeviceFinding, ScanConfig, ScanProgress
from otalon_scan.modules.opcua_discover.start import OpcUaEnumModule


async def _collect_findings(raw_results: Dict[str, Any]) -> List[DeviceFinding]:
    """Run the OPC UA module with ``uadiscover`` stubbed to ``raw_results``.

    The stub is installed directly into the namespace ``OpcUaEnumModule.scan``
    resolves its ``uadiscover`` global from (the coroutine's ``__globals__``).
    ``tests/unit/test_modules.py`` swaps a *fresh* copy of this module into
    ``sys.modules`` (via ``importlib.util.module_from_spec`` +
    ``sys.modules[...] = mod``) and never restores it, so a plain
    ``patch("otalon_scan.modules.opcua_discover.start.uadiscover")`` can stub a
    different module copy than the one this class actually reads — leaving
    the real network call live. Patching ``scan.__globals__`` is authoritative
    regardless of import history and guarantees no UDP traffic leaves the test.
    """
    config = ScanConfig(
        module_name=OpcUaEnumModule.name,
        target_ip="192.168.0.41",
        target_port=4840,
    )

    async def _fake_uadiscover(_ip: str, _port: int) -> Dict[str, Any]:
        return raw_results

    findings: List[DeviceFinding] = []
    with patch.dict(OpcUaEnumModule.scan.__globals__, {"uadiscover": _fake_uadiscover}):
        module = OpcUaEnumModule()
        async for event in module.scan(config):
            if isinstance(event, ScanProgress) and event.finding is not None:
                findings.append(event.finding)
    return findings


@pytest.mark.asyncio
async def test_opcua_finding_never_sets_device_type() -> None:
    """G2-02: the OPC-UA application name MUST NOT land in ``device_type``."""
    raw_results = {
        "servers": [],
        "endpoints": [
            {
                "Endpoint URL": "opc.tcp://192.168.0.41:4840",
                "Application Name": "eUAServer",
                "Application Type": "Server",
                "Application URI": "urn:192.168.0.41:eUAServer",
            }
        ],
    }

    findings = await _collect_findings(raw_results)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.ipv4 == "192.168.0.41"
    # The core invariant: auto-discovery leaves device_type empty.
    assert finding.device_type is None
    # The application name is not lost — it stays in notes/description/extra.
    assert "eUAServer" in (finding.notes or "")
    assert "eUAServer" in (finding.description or "")
    assert finding.extra is not None
    assert finding.extra["endpoint"]["Application Name"] == "eUAServer"


@pytest.mark.asyncio
async def test_opcua_finding_without_app_name_still_none_device_type() -> None:
    """An endpoint with no application name MUST also leave ``device_type`` None."""
    raw_results = {
        "servers": [],
        "endpoints": [
            {
                "Endpoint URL": "opc.tcp://192.168.0.41:4840",
            }
        ],
    }

    findings = await _collect_findings(raw_results)

    assert len(findings) == 1
    assert findings[0].device_type is None
