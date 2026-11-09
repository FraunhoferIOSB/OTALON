"""Unit tests for the Phase 3 subprocess-hardening refactor.

These tests assert the **invariant** that ``arp_scan`` and ``port_scan``
invoke ``subprocess.run`` with:

- an **argv list** as the first positional argument (no string command),
- ``shell=False`` explicitly,
- ``capture_output=True``,
- an explicit ``timeout=<int>`` keyword.

They also cover the :class:`subprocess.TimeoutExpired` branch: the
module must terminate gracefully and yield a :class:`ScanResult` with a
typed ``abort_reason`` rather than re-raising or hanging.

Normative reference: ``scan--subprocess-execution`` spec, Phase 3 of the
``harden-otalon-scan-security`` OpenSpec change.
"""

from __future__ import annotations

import asyncio
import subprocess
from typing import Any, List, Tuple
from unittest.mock import MagicMock

import pandas as pd
import pytest

from otalon_scan.core.models import ScanConfig, ScanProgress, ScanResult
from otalon_scan.modules.arp_scan.start import NmapArpScanModule
from otalon_scan.modules.port_scan.start import PortScanModule

# ---------- helpers ----------


# Minimal valid nmap XML the arp_scan parser will accept (one host up).
_ARP_NMAP_XML = (
    '<?xml version="1.0"?><nmaprun>'
    '<host><status state="up"/>'
    '<address addr="10.0.0.5" addrtype="ipv4"/>'
    '<address addr="aa:bb:cc:dd:ee:ff" addrtype="mac"/>'
    "</host></nmaprun>"
)

# Minimal valid nmap XML for a port scan with one host, one open port.
_PORT_NMAP_XML = (
    '<?xml version="1.0"?><nmaprun>'
    '<host><status state="up"/>'
    '<address addr="127.0.0.1" addrtype="ipv4"/>'
    "<ports>"
    '<port protocol="tcp" portid="22"><state state="open"/></port>'
    "</ports></host></nmaprun>"
)


def _completed(stdout: str, returncode: int = 0) -> subprocess.CompletedProcess[str]:
    """Return a stub :class:`subprocess.CompletedProcess` suitable for mocks."""
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr="")


async def _drain(gen: Any) -> Tuple[List[ScanProgress], List[ScanResult]]:
    progress: List[ScanProgress] = []
    results: List[ScanResult] = []
    async for event in gen:
        if isinstance(event, ScanProgress):
            progress.append(event)
        elif isinstance(event, ScanResult):
            results.append(event)
    return progress, results


# ---------- arp_scan invariants ----------


def test_arp_scan_invokes_subprocess_with_argv_list_and_shell_false(mocker: Any) -> None:
    """``arp_scan`` SHALL invoke ``subprocess.run`` with an argv list, ``shell=False`` and a timeout."""
    mock_run = mocker.patch(
        "otalon_scan.modules.arp_scan.start.subprocess.run",
        return_value=_completed(_ARP_NMAP_XML),
    )

    module = NmapArpScanModule()
    cfg = ScanConfig(
        module_name=module.name,
        target_subnet="10.0.0.0/24",
        parameters={
            "target_subnet": "10.0.0.0/24",
            "host_timeout_ms": "500",
            "max_retries": "1",
            "min_parallelism": "1",
            "hard_timeout_s": "30",
        },
    )

    _progress, results = asyncio.run(_drain(module.scan(cfg)))

    assert mock_run.call_count == 1
    args, kwargs = mock_run.call_args

    # First positional argument is an argv LIST, not a string.
    assert isinstance(args[0], list), f"expected argv list, got {type(args[0]).__name__}"
    argv = args[0]
    assert argv[0] == "nmap"
    assert "-sn" in argv
    assert "-oX" in argv
    assert "10.0.0.0/24" in argv
    # No element contains shell metacharacters bundled inside.
    for token in argv:
        assert isinstance(token, str)
        assert ";" not in token and "&&" not in token and "|" not in token

    # Mandatory subprocess hardening kwargs.
    assert kwargs.get("shell") is False
    assert kwargs.get("capture_output") is True
    assert "timeout" in kwargs and isinstance(kwargs["timeout"], int) and kwargs["timeout"] > 0

    # Terminal result is still yielded with expected shape.
    assert len(results) == 1
    assert results[0].protocol == "arp"
    assert isinstance(results[0].raw_results, pd.DataFrame)


def test_arp_scan_argv_includes_interface_flag_when_provided(mocker: Any) -> None:
    """``arp_scan`` SHALL pass ``-e <iface>`` as separate argv tokens, not a single string."""
    mock_run = mocker.patch(
        "otalon_scan.modules.arp_scan.start.subprocess.run",
        return_value=_completed(_ARP_NMAP_XML),
    )

    module = NmapArpScanModule()
    cfg = ScanConfig(
        module_name=module.name,
        network_interface="lo",
        target_subnet="10.0.0.0/24",
        parameters={
            "network_interface": "lo",
            "target_subnet": "10.0.0.0/24",
        },
    )
    asyncio.run(_drain(module.scan(cfg)))

    argv = mock_run.call_args.args[0]
    assert "-e" in argv
    iface_idx = argv.index("-e")
    assert argv[iface_idx + 1] == "lo"
    # Subnet is the final positional element.
    assert argv[-1] == "10.0.0.0/24"


def test_arp_scan_argv_omits_interface_flag_when_null(mocker: Any) -> None:
    """The literal string ``"null"`` SHALL be treated as 'no interface' and ``-e`` omitted."""
    mock_run = mocker.patch(
        "otalon_scan.modules.arp_scan.start.subprocess.run",
        return_value=_completed(_ARP_NMAP_XML),
    )

    module = NmapArpScanModule()
    cfg = ScanConfig(
        module_name=module.name,
        target_subnet="10.0.0.0/24",
        parameters={
            "network_interface": "null",
            "target_subnet": "10.0.0.0/24",
        },
    )
    asyncio.run(_drain(module.scan(cfg)))

    argv = mock_run.call_args.args[0]
    assert "-e" not in argv


def test_arp_scan_handles_timeout_expired(mocker: Any) -> None:
    """``arp_scan`` SHALL catch ``TimeoutExpired``, log, and yield a typed empty result."""
    mocker.patch(
        "otalon_scan.modules.arp_scan.start.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd=["nmap"], timeout=1),
    )

    module = NmapArpScanModule()
    cfg = ScanConfig(
        module_name=module.name,
        target_subnet="10.0.0.0/24",
        parameters={"target_subnet": "10.0.0.0/24", "hard_timeout_s": "1"},
    )
    _progress, results = asyncio.run(_drain(module.scan(cfg)))

    assert len(results) == 1
    res = results[0]
    assert res.protocol == "arp"
    assert res.findings == []
    assert res.abort_reason is not None and "timeout" in res.abort_reason.lower()
    assert isinstance(res.raw_results, pd.DataFrame)
    assert list(res.raw_results.columns) == ["IP"]


def test_arp_scan_missing_target_subnet_raises() -> None:
    """``arp_scan`` SHALL raise :class:`ScanModuleError` when ``target_subnet`` is missing."""
    from otalon_scan.core.protocols import ScanModuleError

    module = NmapArpScanModule()
    cfg = ScanConfig(module_name=module.name, parameters={})

    async def _run() -> None:
        async for _ in module.scan(cfg):
            pass

    with pytest.raises(ScanModuleError, match="target_subnet"):
        asyncio.run(_run())


# ---------- port_scan invariants ----------


def test_port_scan_invokes_subprocess_with_argv_list_and_shell_false(mocker: Any) -> None:
    """``port_scan`` SHALL invoke ``subprocess.run`` with an argv list, ``shell=False`` and a timeout."""
    mock_run = mocker.patch(
        "otalon_scan.modules.port_scan.start.subprocess.run",
        return_value=_completed(_PORT_NMAP_XML),
    )

    module = PortScanModule()
    cfg = ScanConfig(
        module_name=module.name,
        target_ip="127.0.0.1",
        parameters={
            "target_ip": "127.0.0.1",
            "port_range": "22",
            "timing_template": "4",
            "udp_scan": "False",
            "detection_and_traceroute": "False",
            "service_version_info": "False",
            "host_timeout_ms": "1000",
            "max_retries": "1",
            "min_parallelism": "1",
            "hard_timeout_s": "30",
        },
    )

    _progress, results = asyncio.run(_drain(module.scan(cfg)))

    assert mock_run.call_count == 1
    args, kwargs = mock_run.call_args

    assert isinstance(args[0], list)
    argv = args[0]
    assert argv[0] == "nmap"
    assert "-p" in argv
    assert "22" in argv  # port range token (separate from -p)
    assert "-T4" in argv  # timing template bundled as a single nmap-style token
    assert "-oX" in argv
    assert argv[-1] == "127.0.0.1"

    assert kwargs.get("shell") is False
    assert kwargs.get("capture_output") is True
    assert kwargs.get("timeout") == 30

    assert len(results) == 1
    assert results[0].protocol == "ethernet:ipv4:tcp"


@pytest.mark.parametrize(
    ("udp_scan", "detection", "version_info", "expected", "forbidden"),
    [
        (False, True, True, {"-A", "-sV"}, {"-sU"}),
        (True, True, True, {"-sU"}, {"-A", "-sV"}),
        (False, False, False, set(), {"-A", "-sV", "-sU"}),
    ],
)
def test_port_scan_argv_conditional_flags(
    mocker: Any,
    udp_scan: bool,
    detection: bool,
    version_info: bool,
    expected: set[str],
    forbidden: set[str],
) -> None:
    """``port_scan`` SHALL add ``-sU``/``-A``/``-sV`` argv elements per the boolean overrides."""
    mock_run = mocker.patch(
        "otalon_scan.modules.port_scan.start.subprocess.run",
        return_value=_completed(_PORT_NMAP_XML),
    )

    module = PortScanModule()
    cfg = ScanConfig(
        module_name=module.name,
        target_ip="127.0.0.1",
        parameters={
            "target_ip": "127.0.0.1",
            "port_range": "22",
            "timing_template": "4",
            "udp_scan": "True" if udp_scan else "False",
            "detection_and_traceroute": "True" if detection else "False",
            "service_version_info": "True" if version_info else "False",
        },
    )
    asyncio.run(_drain(module.scan(cfg)))

    argv_set = set(mock_run.call_args.args[0])
    for token in expected:
        assert token in argv_set, f"expected {token!r} in argv {argv_set!r}"
    for token in forbidden:
        assert token not in argv_set, f"forbidden {token!r} in argv {argv_set!r}"


def test_port_scan_argv_omits_sv_when_version_info_unset(mocker: Any) -> None:
    """SCAN-010 regression: an unset ``service_version_info`` SHALL NOT add ``-sV``.

    The plain port scan must default to the fast, no-version-probe path.
    This is the explicit "no -sV" half of the SCAN-010 guard.
    """
    mock_run = mocker.patch(
        "otalon_scan.modules.port_scan.start.subprocess.run",
        return_value=_completed(_PORT_NMAP_XML),
    )

    module = PortScanModule()
    cfg = ScanConfig(
        module_name=module.name,
        target_ip="127.0.0.1",
        parameters={
            "target_ip": "127.0.0.1",
            "port_range": "22",
            "timing_template": "4",
        },
    )
    asyncio.run(_drain(module.scan(cfg)))

    argv = mock_run.call_args.args[0]
    assert "-sV" not in argv, f"unset service_version_info must not add -sV; argv={argv!r}"


def test_port_scan_argv_includes_sv_when_version_info_true(mocker: Any) -> None:
    """SCAN-010 regression: ``service_version_info=true`` SHALL add ``-sV``.

    This is the explicit "opt-in -sV" half of the SCAN-010 guard.
    """
    mock_run = mocker.patch(
        "otalon_scan.modules.port_scan.start.subprocess.run",
        return_value=_completed(_PORT_NMAP_XML),
    )

    module = PortScanModule()
    cfg = ScanConfig(
        module_name=module.name,
        target_ip="127.0.0.1",
        parameters={
            "target_ip": "127.0.0.1",
            "port_range": "22",
            "timing_template": "4",
            "service_version_info": "True",
        },
    )
    asyncio.run(_drain(module.scan(cfg)))

    argv = mock_run.call_args.args[0]
    assert "-sV" in argv, f"service_version_info=true must add -sV; argv={argv!r}"


def test_port_scan_argv_includes_interface_flag_when_provided(mocker: Any) -> None:
    """SCAN-009: a provided ``network_interface`` SHALL reach argv as ``-e <iface>``."""
    mock_run = mocker.patch(
        "otalon_scan.modules.port_scan.start.subprocess.run",
        return_value=_completed(_PORT_NMAP_XML),
    )

    module = PortScanModule()
    cfg = ScanConfig(
        module_name=module.name,
        target_ip="127.0.0.1",
        network_interface="lo",
        parameters={
            "target_ip": "127.0.0.1",
            "port_range": "22",
            "timing_template": "4",
            "network_interface": "lo",
        },
    )
    asyncio.run(_drain(module.scan(cfg)))

    argv = mock_run.call_args.args[0]
    assert "-e" in argv
    assert argv[argv.index("-e") + 1] == "lo"


def test_port_scan_argv_includes_su_when_udp_scan_true(mocker: Any) -> None:
    """SCAN-014: ``udp_scan=true`` SHALL add ``-sU`` to argv."""
    mock_run = mocker.patch(
        "otalon_scan.modules.port_scan.start.subprocess.run",
        return_value=_completed(_PORT_NMAP_XML),
    )

    module = PortScanModule()
    cfg = ScanConfig(
        module_name=module.name,
        target_ip="127.0.0.1",
        parameters={
            "target_ip": "127.0.0.1",
            "port_range": "22",
            "timing_template": "4",
            "udp_scan": "True",
        },
    )
    asyncio.run(_drain(module.scan(cfg)))

    argv = mock_run.call_args.args[0]
    assert "-sU" in argv


def test_port_scan_handles_timeout_expired(mocker: Any) -> None:
    """``port_scan`` SHALL catch ``TimeoutExpired``, log, and yield a typed empty result."""
    mocker.patch(
        "otalon_scan.modules.port_scan.start.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd=["nmap"], timeout=1),
    )

    module = PortScanModule()
    cfg = ScanConfig(
        module_name=module.name,
        target_ip="127.0.0.1",
        parameters={
            "target_ip": "127.0.0.1",
            "port_range": "22",
            "timing_template": "4",
            "hard_timeout_s": "1",
        },
    )
    _progress, results = asyncio.run(_drain(module.scan(cfg)))

    assert len(results) == 1
    res = results[0]
    assert res.protocol == "ethernet:ipv4:tcp"
    assert res.findings == []
    assert res.abort_reason is not None and "timeout" in res.abort_reason.lower()
    assert res.raw_results == []


def test_port_scan_missing_required_fields_raises() -> None:
    """``port_scan`` SHALL raise :class:`ScanModuleError` when required fields are missing."""
    from otalon_scan.core.protocols import ScanModuleError

    module = PortScanModule()
    cfg = ScanConfig(module_name=module.name, parameters={})

    async def _run() -> None:
        async for _ in module.scan(cfg):
            pass

    with pytest.raises(ScanModuleError):
        asyncio.run(_run())


# ---------- shape-equivalence smoke test (mocked nmap binary) ----------


def test_arp_scan_smoke_with_mocked_nmap_produces_same_shape(mocker: Any) -> None:
    """Mocked nmap output SHALL parse into a ScanResult with the legacy DataFrame shape."""
    mocker.patch(
        "otalon_scan.modules.arp_scan.start.subprocess.run",
        return_value=_completed(_ARP_NMAP_XML),
    )

    module = NmapArpScanModule()
    cfg = ScanConfig(
        module_name=module.name,
        target_subnet="10.0.0.0/24",
        parameters={"target_subnet": "10.0.0.0/24"},
    )
    progress, results = asyncio.run(_drain(module.scan(cfg)))

    assert len(results) == 1
    res = results[0]
    assert res.protocol == "arp"
    assert len(res.findings) == 1
    assert res.findings[0].ipv4 == "10.0.0.5"
    assert res.findings[0].mac == "aa:bb:cc:dd:ee:ff"
    assert isinstance(res.raw_results, pd.DataFrame)
    assert list(res.raw_results.columns) == ["IP"]
    assert res.raw_results["IP"].tolist() == ["10.0.0.5"]
    # At least one progress event was emitted before the terminal result.
    assert len(progress) == 1


def test_port_scan_smoke_with_mocked_nmap_produces_same_shape(mocker: Any) -> None:
    """Mocked nmap output SHALL parse into a ScanResult with the legacy list-of-dicts shape."""
    mocker.patch(
        "otalon_scan.modules.port_scan.start.subprocess.run",
        return_value=_completed(_PORT_NMAP_XML),
    )

    module = PortScanModule()
    cfg = ScanConfig(
        module_name=module.name,
        target_ip="127.0.0.1",
        parameters={
            "target_ip": "127.0.0.1",
            "port_range": "22",
            "timing_template": "4",
        },
    )
    progress, results = asyncio.run(_drain(module.scan(cfg)))

    assert len(results) == 1
    res = results[0]
    assert res.protocol == "ethernet:ipv4:tcp"
    assert isinstance(res.raw_results, list)
    assert len(res.raw_results) == 1
    assert res.raw_results[0].get("ip_address") == "127.0.0.1"
    # One progress event per parsed host.
    assert len(progress) == 1


# ---------- guard: no f-string command construction sneaks back in ----------


def test_arp_scan_source_has_no_shell_true() -> None:
    """The arp_scan module SHALL never invoke subprocess with ``shell=True``."""
    from pathlib import Path

    src = Path(__file__).resolve().parents[2] / "src" / "otalon_scan" / "modules" / "arp_scan" / "start.py"
    text = src.read_text(encoding="utf-8")
    assert "shell=True" not in text, "arp_scan/start.py reintroduced shell=True"


def test_port_scan_source_has_no_shell_true() -> None:
    """The port_scan module SHALL never invoke subprocess with ``shell=True``."""
    from pathlib import Path

    src = Path(__file__).resolve().parents[2] / "src" / "otalon_scan" / "modules" / "port_scan" / "start.py"
    text = src.read_text(encoding="utf-8")
    assert "shell=True" not in text, "port_scan/start.py reintroduced shell=True"


# silence unused-import warning for MagicMock (used implicitly via pytest-mock's mocker)
_ = MagicMock
