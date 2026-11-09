"""Unit tests for the Phase 2 ScanModule Protocol and module conformance.

These tests deliberately do NOT touch PostgreSQL — modules are pure
scanners after HC6, so a DB fixture is no longer required. The orchestrator
is now the sole DB writer; orchestrator-side persistence is tested
separately in ``tests/unit/test_orchestrator_persistence.py``.
"""

from __future__ import annotations

import asyncio
import importlib
import os
import shutil
import sys
from pathlib import Path
from typing import Any, List, Type

import pandas as pd
import pytest

from otalon_scan.core.models import DeviceFinding, ScanConfig, ScanProgress, ScanResult
from otalon_scan.core.protocols import ScanModule

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = PROJECT_ROOT / "src" / "otalon_scan"
MODULES_DIR = SRC_DIR / "modules"


def _load_module_class(module_rel: str) -> Type[Any]:
    """Import a ScanModule class from ``otalon_scan.modules.<name>.start``.

    Uses a plain ``importlib.import_module`` on the canonical dotted name
    rather than a fresh ``module_from_spec`` copy. A file-path spec load
    would install a *duplicate* module object in ``sys.modules`` whose
    classes close over the copy's globals; later tests that ``patch(...)``
    a global (e.g. ``uadiscover`` / ``walker``) on the ORIGINAL module then
    stub the wrong copy, so the real implementation runs and those tests
    fail only when ordered *after* this file. A normal import keeps a single
    canonical module object, so ``sys.modules[cls.__module__]`` (relied on by
    ``_patched_pn_module``) and any global patch always target the same
    namespace the class actually reads from.
    """
    leaf = module_rel.split("/")[-1]
    dotted_name = f"otalon_scan.modules.{leaf}.start"

    mod = importlib.import_module(dotted_name)

    # Find a class conforming to the ScanModule Protocol (D2 enforcement).
    for attr_name in dir(mod):
        if attr_name.startswith("_"):
            continue
        attr = getattr(mod, attr_name)
        if isinstance(attr, type) and hasattr(attr, "name") and hasattr(attr, "scan"):
            return attr
    raise RuntimeError(f"No ScanModule-conforming class found in {dotted_name}")


# ---- Protocol conformance ----


@pytest.mark.parametrize("module_rel", ["arp_scan", "port_scan", "pn_discovery", "snmp_scan", "opcua_discover"])
def test_module_class_conforms_to_protocol(module_rel: str) -> None:
    """Every shipped module SHALL be loadable and conform to the ScanModule Protocol."""
    cls = _load_module_class(module_rel)
    instance = cls()
    assert isinstance(instance, ScanModule), f"{cls.__name__} does not conform to ScanModule"
    assert isinstance(getattr(instance, "name"), str) and instance.name
    assert hasattr(instance, "scan") and callable(instance.scan)


@pytest.mark.parametrize("module_rel", ["arp_scan", "port_scan", "pn_discovery", "snmp_scan", "opcua_discover"])
def test_module_does_not_import_postgres_repo(module_rel: str) -> None:
    """No module under src/otalon_scan/modules/ SHALL import ScannerPostgresRepo (HC6 invariant)."""
    start_path = MODULES_DIR / module_rel / "start.py"
    text = start_path.read_text(encoding="utf-8")
    assert "ScannerPostgresRepo" not in text, f"{module_rel}/start.py still references ScannerPostgresRepo"
    assert (
        "repositories.postgres_repo" not in text
    ), f"{module_rel}/start.py still imports from repositories.postgres_repo"


# ---- Yield contract (no DB, no network) ----


async def _drain(gen: Any) -> tuple[List[ScanProgress], List[ScanResult]]:
    progress: List[ScanProgress] = []
    results: List[ScanResult] = []
    async for event in gen:
        if isinstance(event, ScanProgress):
            progress.append(event)
        elif isinstance(event, ScanResult):
            results.append(event)
        else:
            raise AssertionError(f"Unexpected event type: {type(event)!r}")
    return progress, results


def test_snmp_scan_yields_terminal_result_with_empty_target(tmp_path: Path) -> None:
    """snmp_scan with no matching community SHALL yield exactly one ScanResult, zero DB calls."""
    cls = _load_module_class("snmp_scan")
    instance = cls()
    cfg = ScanConfig(
        module_name=instance.name,
        target_ip="127.0.0.1",
        parameters={"target_ip": "127.0.0.1", "communities": []},
    )
    progress, results = asyncio.run(_drain(instance.scan(cfg)))
    assert len(results) == 1
    assert isinstance(results[0], ScanResult)
    assert results[0].protocol == "snmp"
    # findings list is allowed to be empty when no community matches
    assert isinstance(results[0].findings, list)


def test_snmp_scan_raises_on_missing_target() -> None:
    """snmp_scan SHALL raise ScanModuleError when ``target_ip`` is missing."""
    from otalon_scan.core.protocols import ScanModuleError

    cls = _load_module_class("snmp_scan")
    instance = cls()
    cfg = ScanConfig(module_name=instance.name, parameters={"communities": []})

    async def _run() -> None:
        async for _ in instance.scan(cfg):
            pass

    with pytest.raises(ScanModuleError, match="target_ip"):
        asyncio.run(_run())


# ---- Network-dependent smoke tests (opt-in) ----

_SKIP_NMAP = (shutil.which("nmap") is None) or (os.getenv("CS_RUN_NMAP_TESTS", "0") != "1")


@pytest.mark.skipif(_SKIP_NMAP, reason="nmap-based tests disabled; set CS_RUN_NMAP_TESTS=1 to enable")
def test_arp_scan_on_loopback() -> None:
    """arp_scan against loopback-safe subnet SHALL complete and yield a ScanResult."""
    cls = _load_module_class("arp_scan")
    instance = cls()
    cfg_path = MODULES_DIR / "arp_scan" / "config.json"
    from otalon_scan.core.config_utils import load_json

    raw_cfg = dict(load_json(str(cfg_path)) or {})
    raw_cfg.update(
        {
            "network_interface": "lo",
            "target_subnet": "127.0.0.1/32",
            "target_ip": "127.0.0.1",
            "port_range": "1-4",
            "service_version_info": False,
        }
    )
    cfg = ScanConfig(module_name=instance.name, target_subnet=raw_cfg.get("target_subnet"), parameters=raw_cfg)
    _progress, results = asyncio.run(_drain(instance.scan(cfg)))
    assert len(results) == 1
    res = results[0]
    assert res.protocol == "arp"
    assert isinstance(res.raw_results, pd.DataFrame)
    assert "IP" in list(res.raw_results.columns)


@pytest.mark.skipif(_SKIP_NMAP, reason="nmap-based tests disabled; set CS_RUN_NMAP_TESTS=1 to enable")
def test_port_scan_on_loopback_small_range() -> None:
    """port_scan against loopback SHALL yield a ScanResult with a list raw_results."""
    cls = _load_module_class("port_scan")
    instance = cls()
    cfg_path = MODULES_DIR / "port_scan" / "config.json"
    from otalon_scan.core.config_utils import load_json

    raw_cfg = dict(load_json(str(cfg_path)) or {})
    raw_cfg.update(
        {
            "network_interface": "lo",
            "target_subnet": "127.0.0.1/32",
            "target_ip": "127.0.0.1",
            "port_range": "1-4",
            "service_version_info": False,
        }
    )
    cfg = ScanConfig(
        module_name=instance.name,
        target_ip=raw_cfg.get("target_ip"),
        parameters=raw_cfg,
    )
    _progress, results = asyncio.run(_drain(instance.scan(cfg)))
    assert len(results) == 1
    res = results[0]
    assert isinstance(res.raw_results, list)


def test_opcua_discover_async_module_runs() -> None:
    """opcua_discover SHALL complete and yield a ScanResult with raw_results dict."""
    cls = _load_module_class("opcua_discover")
    instance = cls()
    cfg_path = MODULES_DIR / "opcua_discover" / "config.json"
    from otalon_scan.core.config_utils import load_json

    raw_cfg = load_json(str(cfg_path)) or {}
    cfg = ScanConfig(
        module_name=instance.name,
        target_ip=raw_cfg.get("target_ip"),
        target_port=raw_cfg.get("target_port"),
        parameters=raw_cfg,
    )
    _progress, results = asyncio.run(_drain(instance.scan(cfg)))
    assert len(results) == 1
    res = results[0]
    assert res.protocol == "opcua"
    assert isinstance(res.raw_results, dict)
    assert "servers" in res.raw_results and "endpoints" in res.raw_results


def test_opcua_discover_bounds_a_hanging_target(monkeypatch: pytest.MonkeyPatch) -> None:
    """SCAN-020 regression: opcua_discover SHALL bound a slow/half-open target.

    Root cause of the 24 stranded ``modules/opcua_discover`` scans: the
    module awaited ``uadiscover()`` with no wall-clock cap. Against an
    OPC UA server that accepts the TCP connection but never completes the
    handshake, the child process hung forever, ``_finalize_run`` never
    fired (its monitor blocks on ``process.join()``), and the ``Scan``
    row stayed ``status=RUNNING`` / ``finished_at=NULL``.

    Mutation guard: revert the ``asyncio.wait_for`` cap in
    ``OpcUaEnumModule.scan`` and this test hangs past its own timeout
    instead of yielding a terminal :class:`ScanResult` — RED before the
    fix, GREEN after. The scan MUST always emit exactly one terminal
    result so the orchestrator can finalise the run to a terminal status.
    """
    import otalon_scan.modules.opcua_discover.start as opcua_start

    async def _never_returns(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        await asyncio.sleep(3600)
        return {"servers": [], "endpoints": []}

    monkeypatch.setattr(opcua_start, "uadiscover", _never_returns)

    instance = opcua_start.OpcUaEnumModule()
    cfg = ScanConfig(
        module_name=instance.name,
        target_ip="192.0.2.1",
        target_port=4840,
        parameters={"target_ip": "192.0.2.1", "target_port": 4840, "discovery_timeout": 1},
    )

    async def _run_bounded() -> tuple[List[ScanProgress], List[ScanResult]]:
        return await asyncio.wait_for(_drain(instance.scan(cfg)), timeout=15)

    _progress, results = asyncio.run(_run_bounded())
    assert len(results) == 1, "opcua_discover must yield a terminal ScanResult even when discovery hangs"
    res = results[0]
    assert res.protocol == "opcua"
    assert res.finished_at is not None


# ---- DeviceFinding round-trip ----


def test_device_finding_round_trip() -> None:
    """DeviceFinding SHALL survive a JSON round trip (orchestrator IPC contract)."""
    finding = DeviceFinding(
        ipv4="10.0.0.5",
        mac="aa:bb:cc:dd:ee:ff",
        vendor="Siemens",
        device_type="S7-1500",
        open_ports_summary={"open": [{"port": 102, "proto": "tcp"}]},
        notes="lab-bench",
    )
    dumped = finding.model_dump(mode="json")
    parsed = DeviceFinding.model_validate(dumped)
    assert parsed == finding


# ---- pn_discovery single-station targeting (P8 Welle E / F-11) ----


def _run_pn_scan(module: Any, config: ScanConfig) -> List[Any]:
    """Drive a ``PnDiscoveryModule`` instance to completion, collect events."""

    async def _collect() -> List[Any]:
        events: List[Any] = []
        async for event in module.scan(config):
            events.append(event)
        return events

    return asyncio.run(_collect())


_PN_RESPONDERS: List[dict[str, Any]] = [
    {
        "mac_address": "AA:BB:CC:DD:EE:01",
        "device_vendor_value": "S7-1500",
        "name_of_station": "plc-1",
        "device_role_details": "Primary",
        "ip_address": "192.168.0.10",
        "subnet_mask": "255.255.255.0",
        "standard_gateway": "",
    },
    {
        "mac_address": "aa:bb:cc:dd:ee:02",
        "device_vendor_value": "ET200",
        "name_of_station": "io-2",
        "device_role_details": "Secondary",
        "ip_address": "192.168.0.11",
        "subnet_mask": "255.255.255.0",
        "standard_gateway": "",
    },
]


def _patched_pn_module(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Load the pn_discovery module and stub out all privileged L2 I/O.

    Returns a ``PnDiscoveryModule`` instance whose ``_fetch_devices``
    yields the synthetic responder matrix and whose interface-MAC lookup
    is stubbed (``read_interface_mac`` reads an ioctl that would return
    ``None`` for the synthetic interface names used in CI).
    """
    pn_cls = _load_module_class("pn_discovery")
    pn_mod = sys.modules[pn_cls.__module__]
    monkeypatch.setattr(pn_mod, "read_interface_mac", lambda _iface: "00:11:22:33:44:55")
    monkeypatch.setattr(pn_cls, "_fetch_devices", lambda self, sniff_time, filter_net: list(_PN_RESPONDERS))
    return pn_cls()


def test_pn_discovery_target_mac_filters_to_single_station(monkeypatch: pytest.MonkeyPatch) -> None:
    """A ``target_mac`` override SHALL surface only the matching responder.

    The match is separator/case-insensitive (the requested MAC is upper /
    dash-separated, the responder is canonical lowercase colon form).
    """
    module = _patched_pn_module(monkeypatch)
    config = ScanConfig(
        module_name="T0846/pn_discovery",
        target_mac="AA-BB-CC-DD-EE-02",
        parameters={"target_mac": "AA-BB-CC-DD-EE-02", "sniff_time": 1},
    )
    events = _run_pn_scan(module, config)

    results = [e for e in events if isinstance(e, ScanResult)]
    assert len(results) == 1
    findings = results[0].findings
    assert len(findings) == 1
    assert findings[0].mac == "aa:bb:cc:dd:ee:02"


def test_pn_discovery_without_target_mac_returns_all(monkeypatch: pytest.MonkeyPatch) -> None:
    """Absent ``target_mac`` (the "Scan all" path) SHALL keep every responder."""
    module = _patched_pn_module(monkeypatch)
    config = ScanConfig(module_name="T0846/pn_discovery", parameters={"sniff_time": 1})
    events = _run_pn_scan(module, config)

    results = [e for e in events if isinstance(e, ScanResult)]
    assert len(results) == 1
    assert len(results[0].findings) == 2
