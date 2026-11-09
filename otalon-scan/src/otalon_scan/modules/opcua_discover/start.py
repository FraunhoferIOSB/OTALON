"""OPC UA discovery module — pure scanner conforming to :class:`ScanModule`.

Discovers OPC UA servers / endpoints at ``target_ip:target_port`` via
``uadiscover``. Yields one :class:`ScanProgress` per discovered endpoint
and a terminal :class:`ScanResult` carrying the parsed findings plus the
raw ``uadiscover`` dict (for API serializer compatibility).

Persistence is owned by the orchestrator (HC6); this module performs
zero database writes.
"""

from __future__ import annotations

import asyncio
import os
import re
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple, Union

from loguru import logger

from otalon_scan.core.models import DeviceFinding, OpcUaDiscoverResult, ScanConfig, ScanProgress, ScanResult
from otalon_scan.core.protocols import ScanModuleError

from .uadiscover import uadiscover

_LOCALIZED_TEXT_RE = re.compile(r"""Text=(?:'([^']*)'|"([^"]*)")""")

# SCAN-020: hard wall-clock cap (seconds) on the whole discovery exchange.
# Without it a slow / half-open OPC UA server (TCP accepted but the
# handshake never completes) hangs the child process indefinitely; the
# orchestrator monitor blocks on ``process.join()``, ``_finalize_run``
# never fires, and the ``Scan`` row strands at ``status=RUNNING``. The
# value is overridable via the ``discovery_timeout`` parameter.
_DEFAULT_DISCOVERY_TIMEOUT_SEC: int = 10


def clean_localized_text(value: Optional[str]) -> Optional[str]:
    """Extract the inner text from an asyncua ``LocalizedText`` repr.

    ``asyncua``'s ``LocalizedText.to_string()`` (used by
    ``application_to_strings`` / ``endpoint_to_strings``) renders the
    object as e.g. ``LocalizedText(Locale=None, Text='PLC_1')``. This
    helper returns the inner ``PLC_1`` for such reprs. A plain string
    (``PLC_1``) that does not match the repr shape is returned unchanged,
    as is ``None``.
    """
    if value is None:
        return None
    match = _LOCALIZED_TEXT_RE.search(value)
    if match is None:
        return value
    return match.group(1) if match.group(1) is not None else match.group(2)


def _parse_endpoint_url(url: Optional[str]) -> Tuple[Optional[str], Optional[int]]:
    """Extract ``(host, port)`` from a URL like ``opc.tcp://192.168.0.1:4840``."""
    if not url:
        return None, None
    try:
        s = str(url).strip()
        if "://" in s:
            s = s.split("://", 1)[1]
        s = s.split("/", 1)[0]
        host_raw, _, port_s = s.partition(":")
        host: Optional[str] = host_raw.strip() or None
        port = int(port_s) if port_s and port_s.isdigit() else None
        return host, port
    except (ValueError, AttributeError):
        return None, None


def _extract_servers_and_endpoints(
    results: Any,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Normalize ``uadiscover()`` output to ``(servers, endpoints)``."""
    servers: List[Dict[str, Any]] = []
    endpoints: List[Dict[str, Any]] = []
    if isinstance(results, dict):
        srvs = results.get("servers") or []
        eps = results.get("endpoints") or []
        if isinstance(srvs, list):
            servers = [dict(x) for x in srvs if isinstance(x, dict)]
        if isinstance(eps, list):
            endpoints = [dict(x) for x in eps if isinstance(x, dict)]
    return servers, endpoints


class OpcUaEnumModule:
    """OPC UA server / endpoint enumerator.

    Conforms to the :class:`~otalon_scan.core.protocols.ScanModule` Protocol.
    """

    name: str = "T0846/opcua_discover"

    async def scan(
        self,
        config: ScanConfig,
    ) -> AsyncIterator[Union[ScanProgress, ScanResult]]:
        """Run OPC UA discovery and yield endpoints + a terminal result."""
        started_at = datetime.now(tz=timezone.utc)
        params = config.parameters or {}

        target_ip = config.target_ip if config.target_ip is not None else params.get("target_ip", "127.0.0.1")
        target_port = int(config.target_port or params.get("target_port", 4840))
        discovery_timeout = int(params.get("discovery_timeout", _DEFAULT_DISCOVERY_TIMEOUT_SEC))

        try:
            raw_results = await asyncio.wait_for(
                uadiscover(str(target_ip), target_port),
                timeout=discovery_timeout,
            )
        except asyncio.TimeoutError:
            # SCAN-020: a hung discovery MUST still terminate the run with a
            # terminal result so the orchestrator can finalise the scan to a
            # terminal status instead of stranding it at ``RUNNING``.
            logger.warning(
                "opcua_discover: discovery timed out after {timeout}s for {ip}:{port}",
                timeout=discovery_timeout,
                ip=target_ip,
                port=target_port,
            )
            yield OpcUaDiscoverResult(
                module_name=self.name,
                protocol="opcua",
                findings=[],
                raw_results={"servers": [], "endpoints": []},
                started_at=started_at,
                finished_at=datetime.now(tz=timezone.utc),
                abort_reason=f"discovery_timeout:{discovery_timeout}s",
            )
            return
        except asyncio.CancelledError:
            logger.warning("opcua_discover: cancellation received during discovery")
            raise
        except Exception as ex:
            raise ScanModuleError(f"OPC UA discovery failed: {ex}") from ex

        servers, endpoints = _extract_servers_and_endpoints(raw_results)

        app_map: Dict[str, Dict[str, Any]] = {}
        for s in servers:
            app_uri = str(s.get("Application URI") or "").strip()
            app_map[app_uri] = {
                "product_uri": str(s.get("Product URI") or "").strip() or None,
                "application_name": clean_localized_text(str(s.get("Application Name") or "").strip()) or None,
                "application_type": str(s.get("Application Type") or "").strip() or None,
                "discovery_url": str(s.get("Discovery URL") or "").strip() or None,
            }

        findings: List[DeviceFinding] = []
        for ep in endpoints:
            endpoint_url = str(ep.get("Endpoint URL") or ep.get("Discovery URL") or "").strip() or None
            ip_val, port = _parse_endpoint_url(endpoint_url)
            if not ip_val:
                app_uri = str(ep.get("Application URI") or "").strip()
                disc_url = app_map.get(app_uri, {}).get("discovery_url")
                ip_val, port = _parse_endpoint_url(disc_url) if disc_url else (None, None)
            if not ip_val:
                continue

            app_uri = str(ep.get("Application URI") or "").strip()
            product_uri = str(ep.get("Product URI") or "").strip() or app_map.get(app_uri, {}).get("product_uri")
            raw_app_name = clean_localized_text(str(ep.get("Application Name") or "").strip())
            application_name = raw_app_name or app_map.get(app_uri, {}).get("application_name")
            if "Application Name" in ep:
                ep["Application Name"] = clean_localized_text(ep.get("Application Name"))
            application_type = str(ep.get("Application Type") or "").strip() or app_map.get(app_uri, {}).get(
                "application_type"
            )

            notes_parts: List[str] = []
            if application_name:
                notes_parts.append(f"opcua_app_name={application_name}")
            if application_type:
                notes_parts.append(f"opcua_type={application_type}")
            if product_uri:
                notes_parts.append(f"product_uri={product_uri}")
            notes_meta = ";".join(notes_parts) if notes_parts else None

            port_num = port or 4840
            open_summary = {"open": [{"port": int(port_num), "proto": "tcp"}]} if port_num else None

            desc_parts = ["OPC UA application"]
            if application_name:
                desc_parts.append(application_name)
            if application_type:
                desc_parts.append(application_type)
            description = " ".join(desc_parts)

            # ``device_type`` is a purely manual operator field ("Controller",
            # "HMI", "IPC"); auto-discovery must NEVER populate it. The OPC-UA
            # application name lives in ``notes``/``description``/``extra`` only.
            finding = DeviceFinding(
                ipv4=ip_val,
                device_type=None,
                description=description,
                open_ports_summary=open_summary,
                notes=notes_meta,
                extra={"endpoint": ep},
            )
            findings.append(finding)
            yield ScanProgress(
                module_name=self.name,
                message=f"OPC UA endpoint {ip_val}:{port_num}",
                finding=finding,
            )

        yield OpcUaDiscoverResult(
            module_name=self.name,
            protocol="opcua",
            findings=findings,
            raw_results=raw_results,
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
    cfg = ScanConfig(module_name=OpcUaEnumModule.name, parameters=raw_cfg)

    async def _run() -> None:
        mod = OpcUaEnumModule()
        async for event in mod.scan(cfg):
            print(event)

    asyncio.run(_run())
