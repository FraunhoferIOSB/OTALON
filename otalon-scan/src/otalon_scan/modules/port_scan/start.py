"""Port scan module — pure scanner conforming to :class:`ScanModule`.

Runs ``nmap`` against ``target_ip`` for the configured port range and
yields a :class:`ScanProgress` event per host and a terminal
:class:`ScanResult` carrying both per-host findings and the raw
``parse_nmap_portscan_xml`` output (preserved for API compatibility).

Persistence is owned by the orchestrator (HC6); this module performs
zero database writes.

Security invariants (Phase 3 of ``harden-otalon-scan-security``):

- The ``nmap`` invocation is constructed as an argv list and passed to
  :func:`subprocess.run` with ``shell=False``. No f-string command
  construction reaches the shell.
- Caller-controlled override values (``target_ip``, ``port_range``,
  ``timing_template``) are validated at the API boundary by
  :class:`PortScanOverrides` (Phase 2). The module reads them via
  typed locals and never touches the raw request body. Re-validation
  inside the module is intentionally avoided because the same
  ``parameters`` dict also carries trusted ``config.json`` defaults
  that may not parse cleanly on every host.
- The subprocess call carries an explicit ``timeout`` keyword.
  :class:`subprocess.TimeoutExpired` is handled, the child is
  terminated by ``subprocess.run`` itself, a structured timeout event is
  logged, and a typed empty :class:`ScanResult` is yielded.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Dict, List, Optional, Union

from loguru import logger

from otalon_scan.core.models import DeviceFinding, PortScanResult, ScanConfig, ScanProgress, ScanResult
from otalon_scan.core.nmap_utils import format_nmap_result_str, parse_nmap_portscan_xml
from otalon_scan.core.protocols import ScanModuleError

# Default hard timeout for the nmap subprocess (seconds). Overridable via
# the ``hard_timeout_s`` parameter; we cap unbounded blocking either way.
_DEFAULT_NMAP_TIMEOUT_SEC: int = 60


def _build_nmap_argv(
    *,
    network_interface: Optional[str],
    target_ip: str,
    port_range: str,
    timing_template: str,
    host_timeout_ms: int,
    max_retries: int,
    min_parallelism: int,
    udp_scan: bool,
    detection_and_traceroute: bool,
    service_version_info: bool,
) -> List[str]:
    """Build the ``nmap`` argv list for a port scan.

    Every element is an explicit list entry — no whitespace splitting,
    no shell metacharacters, no f-string interpolation reaches the shell.

    :param network_interface: Optional interface name (``-e`` flag).
        Omitted when ``None`` or the literal ``"null"`` (case-insensitive).
    :param target_ip: Single IP address to scan (last positional argument).
    :param port_range: nmap-style port-range expression.
    :param timing_template: Single digit ``0``-``5`` for nmap ``-T``.
    :param host_timeout_ms: Per-host timeout in milliseconds.
    :param max_retries: nmap ``--max-retries`` value.
    :param min_parallelism: nmap ``--min-parallelism`` value.
    :param udp_scan: Enable ``-sU``.
    :param detection_and_traceroute: Enable ``-A`` (only when not UDP).
    :param service_version_info: Enable ``-sV`` (only when not UDP).
    :returns: argv list ready for :func:`subprocess.run`.
    """
    argv: List[str] = [
        "nmap",
        "-p",
        port_range,
        f"-T{timing_template}",
        "-oX",
        "-",
        "--host-timeout",
        f"{host_timeout_ms}ms",
        "--max-retries",
        str(max_retries),
        "--min-parallelism",
        str(min_parallelism),
    ]
    if udp_scan:
        argv.append("-sU")
    if detection_and_traceroute and not udp_scan:
        argv.append("-A")
    if service_version_info and not udp_scan:
        argv.append("-sV")
    if network_interface and network_interface.lower() != "null":
        argv.extend(["-e", network_interface])
    argv.append(target_ip)
    return argv


class PortScanModule:
    """TCP/UDP port-discovery scanner.

    Conforms to the :class:`~otalon_scan.core.protocols.ScanModule` Protocol.
    """

    name: str = "T0840/port_scan"

    async def scan(
        self,
        config: ScanConfig,
    ) -> AsyncIterator[Union[ScanProgress, ScanResult]]:
        """Run ``nmap`` against ``target_ip`` and yield progress / result events."""
        started_at = datetime.now(tz=timezone.utc)
        params = config.parameters or {}

        # All caller-controlled override values (``target_ip``,
        # ``port_range``, ``timing_template``) arrive already validated
        # by :class:`PortScanOverrides` at the API boundary (Phase 2);
        # for the CLI entry point they come from the trusted
        # ``config.json``. We read them via well-typed locals rather
        # than ad-hoc raw-dict access elsewhere in the function.
        target_ip_raw = config.target_ip or params.get("target_ip")
        port_range = params.get("port_range")
        timing_template = params.get("timing_template")
        network_interface = config.network_interface or params.get("network_interface")

        if not target_ip_raw:
            raise ScanModuleError("port_scan: target_ip is required")
        if not port_range:
            raise ScanModuleError("port_scan: port_range is required")
        if not timing_template:
            raise ScanModuleError("port_scan: timing_template is required")

        target_ip = str(target_ip_raw)

        udp_scan = str(params.get("udp_scan")).lower() == "true"
        detection_and_traceroute = str(params.get("detection_and_traceroute")).lower() == "true"
        # SCAN-010: service/version detection (``-sV``) is opt-in only.
        # A plain port scan runs without ``-sV`` (sub-second instead of
        # ~30 s) unless the caller explicitly sets ``service_version_info``
        # truthy. ``None`` (no override) keeps the fast default.
        service_version_info = str(params.get("service_version_info", False)).lower() == "true"

        # SCAN-010: without service/version detection the per-host probe is
        # cheap, so the no-``-sV`` path uses a much lower default host
        # timeout. The ``-sV`` path keeps the historic 60 s default because
        # version probes legitimately take longer. An explicit
        # ``host_timeout_ms`` override (validated upstream) wins either way.
        default_host_timeout_ms = "60000" if service_version_info else "5000"
        host_timeout_ms = int(str(params.get("host_timeout_ms", default_host_timeout_ms)))
        max_retries = int(str(params.get("max_retries", "1")))
        min_parallelism = int(str(params.get("min_parallelism", "1")))
        run_timeout_sec = int(str(params.get("hard_timeout_s", str(_DEFAULT_NMAP_TIMEOUT_SEC))))

        network_interface_arg: Optional[str] = str(network_interface) if network_interface is not None else None

        argv = _build_nmap_argv(
            network_interface=network_interface_arg,
            target_ip=target_ip,
            port_range=str(port_range),
            timing_template=str(timing_template),
            host_timeout_ms=host_timeout_ms,
            max_retries=max_retries,
            min_parallelism=min_parallelism,
            udp_scan=udp_scan,
            detection_and_traceroute=detection_and_traceroute,
            service_version_info=service_version_info,
        )

        logger.debug(
            "port_scan executing argv={argv} timeout={run_timeout_sec}s", argv=argv, run_timeout_sec=run_timeout_sec
        )

        portscan_results: List[Dict[str, Any]] = []
        result: Optional[subprocess.CompletedProcess[str]] = None
        try:
            result = await asyncio.to_thread(
                subprocess.run,
                argv,
                shell=False,
                capture_output=True,
                text=True,
                timeout=run_timeout_sec,
            )
        except asyncio.CancelledError:
            logger.warning("port_scan: cancellation received during nmap execution")
            raise
        except subprocess.TimeoutExpired as ex:
            logger.warning(
                "port_scan: nmap timed out — "
                "event=subprocess.timeout module={module} "
                "target_ip={target_ip!r} port_range={port_range!r} "
                "timeout_s={timeout_s} timeout_arg={timeout_arg}",
                module=self.name,
                target_ip=target_ip,
                port_range=port_range,
                timeout_s=run_timeout_sec,
                timeout_arg=getattr(ex, "timeout", None),
            )
            yield PortScanResult(
                module_name=self.name,
                protocol="ethernet:ipv4:udp" if udp_scan else "ethernet:ipv4:tcp",
                findings=[],
                raw_results=[],
                started_at=started_at,
                finished_at=datetime.now(tz=timezone.utc),
                abort_reason=f"subprocess_timeout:{run_timeout_sec}s",
            )
            return
        except (OSError, subprocess.SubprocessError) as ex:
            raise ScanModuleError(f"nmap subprocess failed: {ex}") from ex

        if result is not None and result.returncode == 0:
            portscan_results = list(parse_nmap_portscan_xml(result.stdout) or [])
        elif result is not None:
            logger.error(
                "port_scan: nmap failed: {format_nmap_result_str_result_stderr}",
                format_nmap_result_str_result_stderr=format_nmap_result_str(result.stderr),
            )

        findings: List[DeviceFinding] = []
        for host in portscan_results:
            host_ip = str(host.get("ip_address") or "") or None
            open_ports = list(host.get("open_ports") or [])
            summary_ports = [
                {"port": int(p.get("port")), "proto": str(p.get("protocol") or ("udp" if udp_scan else "tcp"))}
                for p in open_ports
                if p.get("port") is not None
            ]
            finding = DeviceFinding(
                ipv4=host_ip,
                open_ports_summary={"open": summary_ports} if summary_ports else None,
                extra={"open_ports": open_ports},
            )
            findings.append(finding)
            yield ScanProgress(
                module_name=self.name,
                message=f"host {host_ip} scanned ({len(open_ports)} open ports)",
                finding=finding,
            )

        yield PortScanResult(
            module_name=self.name,
            protocol="ethernet:ipv4:udp" if udp_scan else "ethernet:ipv4:tcp",
            findings=findings,
            raw_results=portscan_results,
            started_at=started_at,
            finished_at=datetime.now(tz=timezone.utc),
        )


# ---------------------------------------------------------------------------
# CLI entry point (`asyncio.run` permitted here per HC8 invariant)
# ---------------------------------------------------------------------------
if __name__ == "__main__":  # pragma: no cover
    from otalon_scan.core.config_utils import load_json

    cfg_path = os.path.join(os.path.dirname(__file__), "config.json")
    raw_cfg = load_json(cfg_path) or {}
    cfg = ScanConfig(module_name=PortScanModule.name, parameters=raw_cfg)

    async def _run() -> None:
        mod = PortScanModule()
        async for event in mod.scan(cfg):
            print(event)

    asyncio.run(_run())
