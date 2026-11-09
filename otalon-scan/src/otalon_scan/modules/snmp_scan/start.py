"""SNMP single-target scan module — pure scanner conforming to :class:`ScanModule`.

Walks SNMP OIDs against ``target_ip`` using the most specific community
entry from ``parameters.communities`` matching the target. Yields the
SNMP findings as a single terminal :class:`ScanResult`; no DB writes.

Persistence is owned by the orchestrator (HC6).
"""

from __future__ import annotations

import asyncio
import os
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple, Union

from loguru import logger

from otalon_scan.core.models import (
    DeviceFinding,
    ScanConfig,
    ScanProgress,
    ScanResult,
    SnmpScanResult,
)
from otalon_scan.core.protocols import ScanModuleError
from otalon_scan.modules.vendor_mapping import normalise_vendor

from .model import Device as SnmpDevice
from .walker import walker

# ---------------------------------------------------------------------------
# Credential redaction (HC14 / Phase 4 of harden-otalon-scan-security)
# ---------------------------------------------------------------------------
#
# SNMP community strings are sensitive credentials. By default every log
# emission site that would otherwise include the community value MUST
# substitute the literal ``***`` token. The only way to recover the
# cleartext value in logs is to set the environment variable
# ``CS_SNMP_LOG_COMMUNITY`` to the exact string ``"1"``. Any other value
# (unset, empty, ``"0"``, ``"true"`` …) preserves redaction.
#
# The single env-flag check lives inside :func:`_redact_community` so the
# behavior is consistent across call sites. The accompanying startup
# WARNING (emitted at most once when the override is active) lives in
# this package's ``__init__`` — see ``otalon-scan/src/otalon_scan/modules/snmp_scan/__init__.py``.

_REDACTED = "***"
_ENV_FLAG_NAME = "CS_SNMP_LOG_COMMUNITY"


def _redact_community(value: str) -> str:
    """Return the community string for logging.

    Returns the literal ``***`` token unless ``CS_SNMP_LOG_COMMUNITY=1``
    is set in the environment, in which case the original ``value`` is
    returned unchanged.

    Args:
        value: The cleartext community string.

    Returns:
        Either ``"***"`` (default) or ``value`` (when the override is active).
    """
    if os.environ.get(_ENV_FLAG_NAME) == "1":
        return value
    return _REDACTED


def _read_arp_table_map(path: Optional[str] = None) -> Dict[str, str]:
    """Read the system ARP table and return ``ip -> mac`` (Linux ``/proc/net/arp``)."""
    mapping: Dict[str, str] = {}
    table_path = path or "/proc/net/arp"
    if not os.path.exists(table_path):
        return mapping
    try:
        with open(table_path, "r", encoding="utf-8") as f:
            next(f, None)
            for line in f:
                fields = line.split()
                if len(fields) >= 4:
                    ip = fields[0].strip()
                    mac = fields[3].strip()
                    if ip and mac and mac != "00:00:00:00:00:00":
                        mapping[ip] = mac
    except OSError as ex:
        logger.debug(
            "snmp_scan: failed to read ARP table at {table_path}: {ex}",
            table_path=table_path,
            ex=ex,
        )
    return mapping


def _find_most_specific_for_ip(ipaddr: str, cidrs: List[str]) -> Optional[str]:
    """Return the most-specific CIDR from ``cidrs`` containing ``ipaddr`` (or None)."""
    try:
        ip_obj = ip_address(ipaddr)
    except ValueError:
        return None
    best: Optional[Tuple[int, str]] = None
    for cidr in cidrs:
        try:
            net = ip_network(cidr, strict=False)
        except ValueError:
            continue
        if ip_obj.version == net.version and ip_obj in net:
            spec = int(net.prefixlen)
            if best is None or spec > best[0]:
                best = (spec, cidr)
    return best[1] if best else None


def _normalize_findings(raw: Any) -> List[Dict[str, Any]]:
    """Normalize ``Device.export_yourself()`` output to ``list[dict]``."""
    out: List[Dict[str, Any]] = []
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                out.append(item)
    elif isinstance(raw, dict):
        items = raw.get("results", [])
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict):
                    out.append(item)
    return out


class SnmpsubmanagerModule:
    """SNMP single-target scanner.

    Conforms to the :class:`~otalon_scan.core.protocols.ScanModule` Protocol.
    """

    name: str = "T0888/snmp_scan"

    async def scan(
        self,
        config: ScanConfig,
    ) -> AsyncIterator[Union[ScanProgress, ScanResult]]:
        """Walk SNMP against ``target_ip`` using the best-matching community entry."""
        started_at = datetime.now(tz=timezone.utc)
        params = config.parameters or {}

        target_ip_raw = config.target_ip if config.target_ip is not None else params.get("target_ip")
        target_ip = str(target_ip_raw or "").strip()
        if not target_ip:
            raise ScanModuleError("snmp_scan: 'target_ip' is required in config")

        # ``operation_timeout`` / ``retry_attempts`` arrive already
        # bounds-validated by :class:`SnmpScanOverrides` at the API
        # boundary; on the CLI path they come from the trusted
        # ``config.json``. They tune the pysnmp UDP transport only.
        operation_timeout = float(str(params.get("operation_timeout", "1")))
        retry_attempts = int(str(params.get("retry_attempts", "5")))

        communities = list(params.get("communities") or [])
        snmp_table: Dict[str, List[Any]] = {}
        for entry in communities:
            try:
                cidr, community, mpmodel = entry
                snmp_table[str(cidr)] = [str(community), int(mpmodel)]
            except (TypeError, ValueError) as ex:
                # Do NOT log ``entry`` directly — it may contain the
                # community in position 1. Log only the structural shape
                # and the parsing exception.
                entry_len = len(entry) if hasattr(entry, "__len__") else "n/a"
                logger.warning(
                    "snmp_scan: skipping malformed community entry "
                    "(type={entry_type}, len={entry_len}, community={community}): {ex}",
                    entry_type=type(entry).__name__,
                    entry_len=entry_len,
                    community=_REDACTED,
                    ex=ex,
                )
                continue

        cidr_match = _find_most_specific_for_ip(target_ip, list(snmp_table.keys()))
        a_device = SnmpDevice(target_ip)
        mac_map = _read_arp_table_map()
        if target_ip in mac_map:
            a_device.set_mac_addr(mac_map[target_ip])

        if not cidr_match:
            logger.warning(
                "snmp_scan: no matching community for {target_ip}; skipping SNMP walk",
                target_ip=target_ip,
            )
        else:
            community, mpmodel = snmp_table[cidr_match]
            logger.info(
                "snmp_scan: walking {target_ip} with community '{community}' " "(mpmodel={mpmodel}, cidr={cidr_match})",
                target_ip=target_ip,
                community=_redact_community(community),
                mpmodel=mpmodel,
                cidr_match=cidr_match,
            )
            try:
                await walker(
                    a_device,
                    community,
                    mpmodel,
                    timeout=operation_timeout,
                    retries=retry_attempts,
                )
            except asyncio.CancelledError:
                logger.warning("snmp_scan: cancellation received during SNMP walk")
                raise
            except Exception as ex:
                logger.warning(
                    "snmp_scan: SNMP walk failed for {target_ip}: {ex}",
                    target_ip=target_ip,
                    ex=ex,
                )

        raw_results = a_device.export_yourself()
        records = _normalize_findings(raw_results)

        findings: List[DeviceFinding] = []
        for rec in records:
            ip_val = (str(rec.get("ip_address") or "")).strip() or None
            mac_val = (str(rec.get("mac_address") or "")).strip() or None

            # SCAN-022: a neighbor with neither a MAC nor an IP would take
            # the blind-INSERT path in ``save_findings_batch`` (no conflict
            # key -> duplicate rows on every scan). Skip it. The correlated
            # neighbors always carry at least one of the two; the switch
            # target itself carries its own IP.
            if not mac_val and not ip_val:
                logger.debug("snmp_scan: skipping MAC-less + IP-less record: {rec}", rec=rec)
                continue
            vendor = normalise_vendor(str(rec.get("manufacturer") or ""))
            device_name = (str(rec.get("device_name") or "")).strip() or None
            device_role = (str(rec.get("device_role") or "")).strip() or None
            description = (str(rec.get("description") or "")).strip() or None
            article_number = (str(rec.get("article_number") or "")).strip() or None
            sw_version = (str(rec.get("sw_version") or "")).strip() or None
            location = (str(rec.get("location") or "")).strip() or None

            # SCAN-018: carry the asset master-data the walker collects into
            # the finding so the persistence layer can UPSERT it onto
            # ``devices``. ``product_family`` maps onto ``device_family``
            # (operator decision D2); ``firmware_version`` stays alongside
            # the new ``sw_version`` (D3).
            product_family = (str(rec.get("product_family") or "")).strip() or None
            product_name = (str(rec.get("product_name") or "")).strip() or None
            hw_version = (str(rec.get("hw_version") or "")).strip() or None
            serial_number = (str(rec.get("serial_number") or "")).strip() or None

            # P8 Welle A (F-10): the SNMP ``sysName`` (carried here as
            # ``device_name``) is the device HOSTNAME, not a device type.
            # Store it in ``hostname`` and leave ``device_type`` unset —
            # the real type, when known, is carried by ``product_name`` /
            # ``device_family``. Do not guess a ``device_type``.
            finding = DeviceFinding(
                ipv4=ip_val,
                mac=mac_val,
                vendor=vendor,
                device_family=product_family,
                hostname=device_name,
                device_role=device_role,
                description=description,
                article_number=article_number,
                firmware_version=sw_version,
                product_name=product_name,
                hw_version=hw_version,
                sw_version=sw_version,
                serial_number=serial_number,
                notes=(f"location={location}" if location else None),
                extra={"raw": rec},
            )
            findings.append(finding)
            yield ScanProgress(
                module_name=self.name,
                message=f"SNMP record for {ip_val or target_ip}",
                finding=finding,
            )

        yield SnmpScanResult(
            module_name=self.name,
            protocol="snmp",
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
    cfg = ScanConfig(module_name=SnmpsubmanagerModule.name, parameters=raw_cfg)

    async def _run() -> None:
        mod = SnmpsubmanagerModule()
        async for event in mod.scan(cfg):
            print(event)

    asyncio.run(_run())
