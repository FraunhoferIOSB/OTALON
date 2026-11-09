"""ProfiNet DCP discovery module — pure scanner conforming to :class:`ScanModule`.

Sends a ProfiNet DCP Identify request and sniffs responses to discover
PROFINET devices on the local subnet. Yields one :class:`ScanProgress`
per discovered device and a terminal :class:`ScanResult` carrying both
the per-device findings and the legacy DataFrame shape (raw_results)
consumed by the API serializer.

Persistence is owned by the orchestrator (HC6); this module performs
zero database writes.

SCAN-029: the transport and the DCP wire format are implemented in-house
(:mod:`otalon_scan.modules.pn_discovery.dcp` for the codec,
:mod:`otalon_scan.modules.pn_discovery.raw_socket` for the Linux ``AF_PACKET``
I/O). The former ``scapy`` / ``scapy.contrib.pnio_dcp`` dependency is
gone; the observable output shape (Vendor / Station name / Role / IP /
Subnet mask / Gateway) is unchanged.
"""

from __future__ import annotations

import asyncio
import os
from datetime import datetime, timezone
from ipaddress import IPv4Address, IPv4Network
from typing import Any, AsyncIterator, Dict, List, Optional, Union

import pandas as pd
from loguru import logger

from otalon_scan.core.models import DeviceFinding, PnDiscoveryResult, ScanConfig, ScanProgress, ScanResult
from otalon_scan.core.protocols import ScanModuleError
from otalon_scan.modules.pn_discovery.dcp import DCP_DEVICE_ROLES, DCP_IDENTIFY_MULTICAST_MAC, build_identify_request
from otalon_scan.modules.pn_discovery.dcp import decode_station as decode_dcp_station
from otalon_scan.modules.pn_discovery.raw_socket import (
    capture_dcp_responses,
    default_interface,
    read_interface_ipv4,
    read_interface_mac,
)
from otalon_scan.modules.vendor_mapping import map_dcp_descriptor
from otalon_scan.utils.mac import InvalidMacError, canonicalise

DEFAULT_BROADCAST = DCP_IDENTIFY_MULTICAST_MAC
DEFAULT_SNIFF_TIME = 2
DEFAULT_FILTER_NET = False

__all__ = ["DCP_DEVICE_ROLES", "PnDiscoveryModule"]


class PnDiscoveryModule:
    """PROFINET DCP discovery scanner.

    Conforms to the :class:`~otalon_scan.core.protocols.ScanModule` Protocol.
    """

    name: str = "T0846/pn_discovery"

    def __init__(self) -> None:
        self._local_mac: Optional[str] = None
        self._interface: Optional[str] = None
        self._broadcast: str = DEFAULT_BROADCAST

    async def scan(
        self,
        config: ScanConfig,
    ) -> AsyncIterator[Union[ScanProgress, ScanResult]]:
        """Send a DCP Identify and yield findings as devices respond."""
        started_at = datetime.now(tz=timezone.utc)
        params = config.parameters or {}

        # Without an explicit interface the module falls back to whichever
        # interface carries the IPv4 default route (``/proc/net/route``),
        # which is the closest standard-library equivalent of the previous
        # ``scapy.conf.iface`` default.
        requested_interface = config.network_interface or params.get("network_interface")
        interface: str = str(requested_interface or default_interface() or "")
        broadcast: str = params.get("broadcast", DEFAULT_BROADCAST)
        sniff_time: int = int(params.get("sniff_time", DEFAULT_SNIFF_TIME))
        filter_net: bool = bool(params.get("filter_net", DEFAULT_FILTER_NET))

        # P8 Welle E (F-11): optional single-station targeting. PROFINET DCP
        # Identify is an inherently multicast discovery frame — there is no
        # reliable unicast Identify every station honours — so a requested
        # ``target_mac`` is applied as a RESULT FILTER: the multicast probe
        # is still sent, but only the responder whose source MAC matches is
        # surfaced. The value arrives already canonicalised (lowercase
        # colon-separated) from ``validate_target_mac`` at the API boundary;
        # we still normalise defensively for the trusted CLI/config path.
        target_mac_raw = config.target_mac or params.get("target_mac")
        target_mac: Optional[str] = self._normalise_target_mac(target_mac_raw)

        self._interface = interface
        self._broadcast = broadcast
        self._local_mac = read_interface_mac(interface) if interface else None
        if self._local_mac is None:
            logger.warning(
                "pn_discovery: no usable hardware address for interface {iface!r}",
                iface=interface,
            )

        logger.info(
            "pn_discovery: starting (iface={iface}, broadcast={broadcast}, "
            "sniff_time={sniff_time}s, filter_net={filter_net}, src_mac={src_mac})",
            iface=interface,
            broadcast=broadcast,
            sniff_time=sniff_time,
            filter_net=filter_net,
            src_mac=self._local_mac or "unknown",
        )

        try:
            devices = await asyncio.to_thread(self._fetch_devices, sniff_time, filter_net)
        except asyncio.CancelledError:
            logger.warning("pn_discovery: cancellation received during sniff")
            raise
        except Exception as ex:
            raise ScanModuleError(f"PROFINET DCP scan failed: {ex}") from ex

        if target_mac:
            total = len(devices)
            devices = [d for d in devices if self._normalise_target_mac(d.get("mac_address")) == target_mac]
            logger.info(
                "pn_discovery: target_mac filter applied — target={target_mac} " "matched={matched}/{total} responders",
                target_mac=target_mac,
                matched=len(devices),
                total=total,
            )

        findings: List[DeviceFinding] = []
        for dev in devices:
            mac_val = (dev.get("mac_address") or "").strip() or None
            ip_val = (dev.get("ip_address") or "").strip() or None
            mask_val = (dev.get("subnet_mask") or "").strip() or None
            gw_val = (dev.get("standard_gateway") or "").strip() or None

            cidr_val: Optional[str] = None
            if ip_val and mask_val:
                try:
                    cidr_val = str(IPv4Network(f"{ip_val}/{mask_val}", strict=False))
                except ValueError:
                    cidr_val = None

            # The DCP ``device_vendor_value`` is a product/type descriptor,
            # not a clean vendor name (Welle A / D4). Resolve it into a
            # canonical ``(vendor, product_name)`` so the scan→``devices``
            # write populates the identity-cutoff fields correctly instead
            # of stranding the product string in ``vendor``.
            vendor, product_name = map_dcp_descriptor(dev.get("device_vendor_value"))
            station_name = (dev.get("name_of_station") or "").strip() or None
            device_role = (dev.get("device_role_details") or "").strip() or None

            # P8 Welle A (F-04): the PROFINET ``name_of_station`` is the
            # device HOSTNAME, not a device type. Store it in ``hostname``
            # and leave ``device_type`` unset — the real type, when known,
            # is carried by ``product_name`` (mapped from the DCP
            # descriptor above). Do not guess a ``device_type``.
            finding = DeviceFinding(
                ipv4=ip_val,
                mac=mac_val,
                subnet=cidr_val,
                vendor=vendor,
                product_name=product_name,
                hostname=station_name,
                device_role=device_role,
                notes=(f"gateway={gw_val}" if gw_val else None),
                extra={"raw": dev},
            )
            findings.append(finding)
            yield ScanProgress(
                module_name=self.name,
                message=f"PROFINET device {mac_val or ip_val or 'unknown'}",
                finding=finding,
            )

        raw_df = (
            pd.DataFrame(devices)
            if devices
            else pd.DataFrame(
                [],
                columns=[
                    "mac_address",
                    "device_vendor_value",
                    "name_of_station",
                    "device_role_details",
                    "ip_address",
                    "subnet_mask",
                    "standard_gateway",
                ],
            )
        )

        yield PnDiscoveryResult(
            module_name=self.name,
            protocol="pn_dcp",
            findings=findings,
            raw_results=raw_df,
            started_at=started_at,
            finished_at=datetime.now(tz=timezone.utc),
        )

    # ---- internals ----

    @staticmethod
    def _normalise_target_mac(value: Optional[str]) -> Optional[str]:
        """Return the canonical form of ``value`` or ``None`` if absent/invalid.

        Used both for the requested ``target_mac`` filter value and for each
        responder's source MAC so the comparison is separator/case-agnostic.
        A malformed responder MAC simply fails to match (returns ``None``)
        rather than raising — the multicast sniff may surface unexpected
        frames and the filter must not abort the whole scan.
        """
        if not value:
            return None
        try:
            return canonicalise(value)
        except InvalidMacError:
            return None

    # ---- transport internals (sync, run in a worker thread) ----

    def _build_request(self) -> bytes:
        """Return the DCP Identify frame to transmit on this scan.

        Raises:
            ScanModuleError: If the local interface has no usable MAC. A
                DCP request must carry a real source address — responders
                answer by unicast to it, so an all-zero source would make
                the scan silently return nothing.
        """
        if not self._local_mac:
            raise ScanModuleError(
                f"pn_discovery: interface {self._interface!r} has no usable MAC address; "
                "cannot build a DCP Identify request"
            )
        return build_identify_request(source_mac=self._local_mac, destination_mac=self._broadcast)

    def _is_foreign_responder(self, station_mac: str) -> bool:
        """Return ``True`` unless ``station_mac`` is this host's own address.

        The raw socket sees the outgoing request looped back, so the
        sender must drop frames it sent itself.
        """
        if not self._local_mac:
            return True
        return station_mac.lower() != self._local_mac.lower()

    def _filter_to_local_net(self, devices: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Keep only responders whose IPv4 lies in the scan interface's network."""
        cidr = read_interface_ipv4(self._interface) if self._interface else None
        if not cidr:
            logger.warning(
                "pn_discovery: filter_net requested but interface {iface!r} has no IPv4 address",
                iface=self._interface,
            )
            return devices
        try:
            network = IPv4Network(cidr, strict=False)
        except ValueError as ex:
            logger.warning("pn_discovery: could not filter by subnet: {ex}", ex=ex)
            return devices

        kept: List[Dict[str, Any]] = []
        for device in devices:
            address = device.get("ip_address")
            if not address:
                continue
            try:
                if IPv4Address(address) in network:
                    kept.append(device)
            except ValueError:
                continue
        return kept

    def _fetch_devices(self, sniff_time: int, filter_net: bool) -> List[Dict[str, Any]]:
        """Send the DCP request and collect responses (runs in a worker thread)."""
        frames = capture_dcp_responses(
            interface=self._interface or "",
            request_frame=self._build_request(),
            listen_seconds=float(sniff_time),
        )

        devices: List[Dict[str, Any]] = []
        seen: set[str] = set()
        for frame in frames:
            station = decode_dcp_station(frame)
            if station is None:
                continue
            if not self._is_foreign_responder(station.mac_address):
                continue
            if station.mac_address in seen:
                continue
            seen.add(station.mac_address)
            devices.append(dict(station.as_dict()))

        if filter_net:
            devices = self._filter_to_local_net(devices)
        return devices


# ---------------------------------------------------------------------------
# CLI entry point (`asyncio.run` permitted here per HC8 invariant)
# ---------------------------------------------------------------------------
if __name__ == "__main__":  # pragma: no cover
    from otalon_scan.core.config_utils import load_json

    cfg_path = os.path.join(os.path.dirname(__file__), "config.json")
    raw_cfg = load_json(cfg_path) or {}
    cfg = ScanConfig(module_name=PnDiscoveryModule.name, parameters=raw_cfg)

    async def _run() -> None:
        mod = PnDiscoveryModule()
        async for event in mod.scan(cfg):
            print(event)

    asyncio.run(_run())
