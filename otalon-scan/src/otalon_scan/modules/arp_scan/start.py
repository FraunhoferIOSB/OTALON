"""ARP scan module — pure scanner conforming to :class:`ScanModule`.

Discovers IPv4 hosts via ``nmap -sn`` against ``target_subnet`` and
enriches the result with MAC addresses from the system ARP table.
Persistence is owned by the orchestrator (HC6); this module performs
zero database writes.

Security invariants (Phase 3 of ``harden-otalon-scan-security``):

- The ``nmap`` invocation is constructed as an argv list and passed to
  :func:`subprocess.run` with ``shell=False``. No f-string command
  construction reaches the shell.
- Caller-controlled values (``network_interface``, ``target_subnet``)
  are validated at the API boundary by :class:`ArpScanOverrides`
  (Phase 2). The module reads them via typed locals and never touches
  the raw request body. Re-validation inside the module is intentionally
  avoided because the same ``parameters`` dict also carries trusted
  ``config.json`` defaults that may not parse cleanly on every host
  (e.g. a default interface name that does not exist in test envs).
- The subprocess call carries an explicit ``timeout`` keyword.
  :class:`subprocess.TimeoutExpired` is handled, the child is
  terminated by ``subprocess.run`` itself, a structured timeout event
  is logged, and a typed empty :class:`ScanResult` is yielded so the
  orchestrator does not hang.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import AsyncIterator, Dict, List, Optional, Tuple, Union

import pandas as pd
from loguru import logger

from otalon_scan.core.models import ArpScanResult, DeviceFinding, ScanConfig, ScanProgress, ScanResult
from otalon_scan.core.nmap_utils import format_nmap_result_str
from otalon_scan.core.protocols import ScanModuleError

# Default hard timeout for the nmap subprocess (seconds). The orchestrator
# may override via the ``hard_timeout_s`` parameter in ``config.json`` /
# overrides; we cap unbounded blocking either way.
_DEFAULT_NMAP_TIMEOUT_SEC: int = 120


def _extract_ip_mac_from_nmap_xml(xml_string: str) -> List[Tuple[str, Optional[str]]]:
    """Parse ``nmap -sn`` XML and return ``[(ip, mac)]`` pairs for hosts in state ``up``."""
    pairs: List[Tuple[str, Optional[str]]] = []
    try:
        root = ET.fromstring(xml_string)
        for host in root.findall("host"):
            status = host.find("status")
            if status is not None and status.get("state") != "up":
                continue
            ip: Optional[str] = None
            mac: Optional[str] = None
            for addr in host.findall("address"):
                t = addr.get("addrtype")
                if t == "ipv4":
                    ip = addr.get("addr")
                elif t == "mac":
                    mac = addr.get("addr")
            if ip:
                pairs.append((ip, mac))
    except ET.ParseError as ex:
        raise ScanModuleError(f"Failed to parse nmap XML output: {ex}") from ex
    return pairs


def _read_arp_table_map() -> Dict[str, str]:
    """Read the system ARP table and return ``ip -> mac`` (Linux ``/proc/net/arp``)."""
    mapping: Dict[str, str] = {}
    path = "/proc/net/arp"
    if not os.path.exists(path):
        return mapping
    try:
        with open(path, "r", encoding="utf-8") as f:
            next(f, None)
            for line in f:
                fields = line.split()
                if len(fields) >= 4:
                    ip = fields[0].strip()
                    mac = fields[3].strip()
                    if ip and mac and mac != "00:00:00:00:00:00":
                        mapping[ip] = mac
    except OSError as ex:
        logger.debug("Failed to read ARP table at {path}: {ex}", path=path, ex=ex)
    return mapping


def _build_nmap_argv(
    *,
    network_interface: Optional[str],
    target_subnet: str,
    host_timeout_ms: int,
    max_retries: int,
    min_parallelism: int,
) -> List[str]:
    """Build the ``nmap`` argv list for an ARP host-discovery sweep.

    All elements are explicit list entries — no whitespace splitting, no
    shell metacharacters, no f-string interpolation reaches the shell.

    :param network_interface: Optional interface name (``-e`` flag).
        If ``None`` or the literal string ``"null"`` (case-insensitive),
        the ``-e`` flag is omitted.
    :param target_subnet: CIDR subnet to scan (last positional argument).
    :param host_timeout_ms: Per-host timeout in milliseconds.
    :param max_retries: nmap ``--max-retries`` value.
    :param min_parallelism: nmap ``--min-parallelism`` value.
    :returns: argv list ready for :func:`subprocess.run`.
    """
    argv: List[str] = [
        "nmap",
        "-sn",
        "-oX",
        "-",
        "--host-timeout",
        f"{host_timeout_ms}ms",
        "--max-retries",
        str(max_retries),
        "--min-parallelism",
        str(min_parallelism),
    ]
    if network_interface and network_interface.lower() != "null":
        argv.extend(["-e", network_interface])
    argv.append(target_subnet)
    return argv


class NmapArpScanModule:
    """ARP host-discovery scanner.

    Conforms to the :class:`~otalon_scan.core.protocols.ScanModule` Protocol.
    """

    name: str = "T1018/arp_scan"

    async def scan(
        self,
        config: ScanConfig,
    ) -> AsyncIterator[Union[ScanProgress, ScanResult]]:
        """Run an ``nmap -sn`` host discovery and yield progress + result."""
        started_at = datetime.now(tz=timezone.utc)
        params = config.parameters or {}

        # Both ``target_subnet`` and ``network_interface`` arrive already
        # validated by :class:`ArpScanOverrides` (Phase 2) when they reach
        # us via the API; for the CLI entry point they come from the
        # trusted ``config.json``. We read them via well-typed locals
        # rather than ad-hoc raw-dict access elsewhere in the function.
        target_subnet_value = config.target_subnet or params.get("target_subnet")
        network_interface_value = config.network_interface or params.get("network_interface")

        target_subnet: Optional[str] = str(target_subnet_value) if target_subnet_value else None
        network_interface: Optional[str] = str(network_interface_value) if network_interface_value else None

        if not target_subnet:
            raise ScanModuleError("arp_scan: target_subnet is required")

        host_timeout_ms = int(str(params.get("host_timeout_ms", "1000")))
        max_retries = int(str(params.get("max_retries", "1")))
        min_parallelism = int(str(params.get("min_parallelism", "1")))
        run_timeout_sec = int(str(params.get("hard_timeout_s", str(_DEFAULT_NMAP_TIMEOUT_SEC))))

        argv = _build_nmap_argv(
            network_interface=network_interface,
            target_subnet=target_subnet,
            host_timeout_ms=host_timeout_ms,
            max_retries=max_retries,
            min_parallelism=min_parallelism,
        )

        logger.debug(
            "arp_scan executing argv={argv} timeout={run_timeout_sec}s", argv=argv, run_timeout_sec=run_timeout_sec
        )

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
            logger.warning("arp_scan: cancellation received during nmap execution")
            raise
        except subprocess.TimeoutExpired as ex:
            # asyncio.to_thread runs the call in a worker thread; subprocess.run
            # itself already kills the child on timeout, but we log a structured
            # event and surface a typed empty result so the orchestrator does
            # not hang on a partial yield.
            logger.warning(
                "arp_scan: nmap timed out — "
                "event=subprocess.timeout module={module} "
                "target_subnet={target_subnet!r} timeout_s={timeout_s} "
                "timeout_arg={timeout_arg}",
                module=self.name,
                target_subnet=target_subnet,
                timeout_s=run_timeout_sec,
                timeout_arg=getattr(ex, "timeout", None),
            )
            yield ArpScanResult(
                module_name=self.name,
                protocol="arp",
                findings=[],
                raw_results=pd.DataFrame([], columns=["IP"]),
                started_at=started_at,
                finished_at=datetime.now(tz=timezone.utc),
                abort_reason=f"subprocess_timeout:{run_timeout_sec}s",
            )
            return
        except (OSError, subprocess.SubprocessError) as ex:
            raise ScanModuleError(f"nmap subprocess failed: {ex}") from ex

        findings: List[DeviceFinding] = []
        ip_list: List[str] = []
        mac_list: List[str] = []
        ip_mac_map: Dict[str, Optional[str]] = {}

        if result.returncode != 0:
            logger.error(
                "arp_scan: nmap failed: {format_nmap_result_str_result_stderr}",
                format_nmap_result_str_result_stderr=format_nmap_result_str(result.stderr),
            )
        else:
            pairs = _extract_ip_mac_from_nmap_xml(result.stdout)
            arp_map = _read_arp_table_map() if any(mac is None for _, mac in pairs) else {}

            for ip, mac in pairs:
                resolved_mac = mac or arp_map.get(ip)
                ip_mac_map[ip] = resolved_mac
                ip_list.append(ip)
                if resolved_mac:
                    mac_list.append(resolved_mac)

                finding = DeviceFinding(
                    ipv4=ip,
                    mac=resolved_mac,
                    subnet=target_subnet,
                )
                findings.append(finding)
                yield ScanProgress(
                    module_name=self.name,
                    message=f"host {ip} up",
                    finding=finding,
                )

        # raw_results preserves the legacy DataFrame shape consumed by the API serializer
        raw_df = pd.DataFrame(ip_list, columns=["IP"])

        yield ArpScanResult(
            module_name=self.name,
            protocol="arp",
            findings=findings,
            raw_results=raw_df,
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
    cfg = ScanConfig(module_name=NmapArpScanModule.name, parameters=raw_cfg)

    async def _run() -> None:
        mod = NmapArpScanModule()
        async for event in mod.scan(cfg):
            print(event)

    asyncio.run(_run())
