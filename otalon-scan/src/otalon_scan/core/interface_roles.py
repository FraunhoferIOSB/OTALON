"""Host network-interface classification for scan discovery.

Provides pure functions that transform raw :mod:`psutil` interface data into
a UI-friendly shape with a ``role`` field suitable for scan orchestration.

Roles:

- ``active_scan`` — an up interface carrying an IPv4 address. Suitable as the
  default bind interface for active scan modules.
- ``mirror`` — a passive mirror/SPAN port. Determined by ``CAPTURE_SOURCE``
  (single interface name, the authoritative capture source used by
  otalon-capture / pcap_recorder) and optionally augmented by
    ``OTALON_SCAN_MIRROR_INTERFACES`` (comma-separated interface names).
  The two sources are combined in a union; either can declare a mirror.
  A declared mirror interface is **never** promoted to ``active_scan``, even
  when it carries a link-local address.
- ``other`` — loopback and anything else not usable for active scanning.

Default selection:

- ``SCAN_SOURCE`` (single interface name, stripped) declares the preferred
  default interface for active scans. When the named interface has role
  ``active_scan``, ``list_interfaces`` sets ``is_default: true`` for that
  entry and ``false`` for all others. If ``SCAN_SOURCE`` is unset, empty,
  or names a mirror/down/non-existent interface, no entry is marked default
  and callers fall back to the first ``active_scan`` interface.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from typing import Any, Dict, List, Optional

import psutil

__all__ = ["classify_interface_role", "list_interfaces"]


_AF_PACKET = getattr(socket, "AF_PACKET", 17)


def _mirror_interface_names() -> set[str]:
    """Return the set of interface names declared as mirror ports.

    Combines ``CAPTURE_SOURCE`` (single interface name, stripped) with
    ``OTALON_SCAN_MIRROR_INTERFACES`` (comma-separated, stripped).
    Either may be empty/unset.
    """
    names: set[str] = set()

    capture_source = os.environ.get("CAPTURE_SOURCE", "").strip()
    if capture_source:
        names.add(capture_source)

    raw = os.environ.get("OTALON_SCAN_MIRROR_INTERFACES", "")
    names.update(name.strip() for name in raw.split(",") if name.strip())

    return names


def _scan_source_name() -> Optional[str]:
    """Return the interface name declared as the preferred default scan source.

    Reads ``SCAN_SOURCE`` (single interface name, stripped).
    Empty or unset → ``None``.
    """
    name = os.environ.get("SCAN_SOURCE", "").strip()
    return name if name else None


def _is_loopback(name: str, addrs: List[psutil._common.snicaddr]) -> bool:
    """Heuristic loopback detection.

    Matches ``lo`` / ``lo0`` by name, or any interface whose IPv4 address
    is ``127.0.0.1``.
    """
    if name in ("lo", "lo0") or name.startswith("lo:"):
        return True
    for addr in addrs:
        if addr.family == socket.AF_INET and addr.address == "127.0.0.1":
            return True
    return False


def _extract_ipv4_info(
    addrs: List[psutil._common.snicaddr],
) -> tuple[Optional[str], Optional[str]]:
    """Return ``(ipv4_address, subnet_with_prefix)`` from interface addresses.

    ``subnet_with_prefix`` is the IPv4 address plus CIDR prefix (e.g.
    ``192.168.1.100/24``). If the netmask is missing or malformed, only
    the plain address is returned.
    """
    for addr in addrs:
        if addr.family == socket.AF_INET:
            ipv4 = addr.address
            netmask = addr.netmask
            if ipv4 and netmask:
                try:
                    iface = ipaddress.ip_interface(f"{ipv4}/{netmask}")
                    return ipv4, iface.with_prefixlen
                except (ValueError, TypeError):
                    return ipv4, None
            return ipv4, None
    return None, None


def _extract_mac(addrs: List[psutil._common.snicaddr]) -> Optional[str]:
    """Return the MAC address from the first AF_PACKET / AF_LINK entry."""
    for addr in addrs:
        if addr.family == _AF_PACKET:
            val = addr.address
            if isinstance(val, str):
                return val
    return None


def classify_interface_role(
    name: str,
    addrs: List[psutil._common.snicaddr],
    is_up: bool,
    mirror_names: Optional[set[str]] = None,
) -> str:
    """Classify a single interface into one of ``active_scan``, ``mirror``, ``other``.

    :param name: Interface name (e.g. ``"enp4s0"``).
    :param addrs: List of :class:`psutil._common.snicaddr` from
        :func:`psutil.net_if_addrs`.
    :param is_up: Link-up status from :func:`psutil.net_if_stats`.
    :param mirror_names: Optional pre-computed set of mirror interface names.
        When ``None``, the set is read from the environment.
    :returns: One of ``"active_scan"``, ``"mirror"``, ``"other"``.
    """
    if mirror_names is None:
        mirror_names = _mirror_interface_names()

    if name in mirror_names:
        return "mirror"

    if _is_loopback(name, addrs):
        return "other"

    ipv4, _ = _extract_ipv4_info(addrs)

    if is_up and ipv4:
        return "active_scan"

    return "other"


def list_interfaces() -> List[Dict[str, Any]]:
    """Return a list of host interfaces enriched with scan-oriented metadata.

    Each item is a dict with keys:

    - ``name`` — interface name.
    - ``ipv4`` — IPv4 address string or ``None``.
    - ``subnet`` — IPv4 address with CIDR prefix or ``None``.
    - ``is_up`` — boolean link status.
    - ``role`` — ``active_scan``, ``mirror``, or ``other``.
    - ``mac`` — MAC address string or ``None``.
    - ``is_default`` — ``True`` only for the interface matching ``SCAN_SOURCE``
      with role ``active_scan``.

    Data is sourced from :func:`psutil.net_if_addrs` and
    :func:`psutil.net_if_stats`.
    """
    addrs_map = psutil.net_if_addrs()
    stats_map = psutil.net_if_stats()
    mirror_names = _mirror_interface_names()
    scan_source = _scan_source_name()

    result: List[Dict[str, Any]] = []
    for name in sorted(addrs_map.keys()):
        addrs = addrs_map[name]
        stats = stats_map.get(name)
        is_up = bool(stats.isup) if stats is not None else False
        ipv4, subnet = _extract_ipv4_info(addrs)
        mac = _extract_mac(addrs)
        role = classify_interface_role(name, addrs, is_up, mirror_names)
        is_default = name == scan_source and role == "active_scan"
        result.append(
            {
                "name": name,
                "ipv4": ipv4,
                "subnet": subnet,
                "is_up": is_up,
                "role": role,
                "mac": mac,
                "is_default": is_default,
            }
        )
    return result
