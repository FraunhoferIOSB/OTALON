"""Linux ``AF_PACKET`` transport for PROFINET DCP discovery.

SCAN-029: this module replaces scapy's ``sendp``/``sniff``/``get_if_hwaddr``
with the standard-library primitives Linux already exposes:

- :data:`socket.AF_PACKET` + :data:`socket.SOCK_RAW` bound to a single
  interface and filtered to ``ETH_P_PROFINET`` (0x8892) at bind time, so
  the kernel never copies unrelated traffic into user space.
- ``SIOCGIFHWADDR`` via :func:`fcntl.ioctl` for the local interface MAC.

Everything here is blocking, privileged, and platform-specific. The pure
frame codec lives in :mod:`otalon_scan.modules.pn_discovery.dcp`, which is what
the unit tests exercise; this module is intentionally thin so the
untestable surface stays as small as possible.

Required capability: ``CAP_NET_RAW`` (the ``otalon-scan`` container
already requests ``NET_RAW``/``NET_ADMIN``; see ``docker-compose.yml``).
"""

from __future__ import annotations

import fcntl
import socket
import struct
import time
from pathlib import Path
from typing import List, Optional

import psutil
from loguru import logger

from otalon_scan.modules.pn_discovery.dcp import ETHERTYPE_PROFINET

__all__ = [
    "RawSocketError",
    "capture_dcp_responses",
    "default_interface",
    "read_interface_ipv4",
    "read_interface_mac",
]

#: Kernel routing table export used to find the default-route interface.
_PROC_NET_ROUTE: Path = Path("/proc/net/route")

#: ``SIOCGIFHWADDR`` — get hardware address (``linux/sockios.h``).
_SIOCGIFHWADDR: int = 0x8927

#: Maximum interface-name length including the NUL (``IFNAMSIZ``).
_IFNAMSIZ: int = 16

#: Upper bound for a single received frame (jumbo-safe).
_RECV_BUFFER_SIZE: int = 65535

#: Poll granularity while waiting for responses, in seconds.
_RECV_POLL_INTERVAL: float = 0.2


class RawSocketError(OSError):
    """Raised when the raw L2 socket cannot be created, bound, or used.

    Wraps the underlying :class:`OSError` (typically ``EPERM`` when the
    process lacks ``CAP_NET_RAW``, or ``ENODEV`` for an unknown interface)
    so the calling scan module can turn it into a typed module error.
    """


def read_interface_mac(interface: str) -> Optional[str]:
    """Return the MAC address of ``interface`` in canonical form.

    Uses the ``SIOCGIFHWADDR`` ioctl, which needs no elevated privileges.

    Args:
        interface: The interface name, e.g. ``"eth0"``.

    Returns:
        The canonical lowercase colon-separated MAC, or ``None`` if the
        interface does not exist, has no hardware address, or reports the
        all-zero placeholder address.
    """
    encoded = interface.encode("utf-8")
    if not encoded or len(encoded) >= _IFNAMSIZ:
        logger.warning("pn_discovery: interface name {interface!r} is not usable", interface=interface)
        return None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            response = fcntl.ioctl(
                probe.fileno(),
                _SIOCGIFHWADDR,
                struct.pack("256s", encoded[: _IFNAMSIZ - 1]),
            )
    except OSError as exc:
        logger.warning(
            "pn_discovery: SIOCGIFHWADDR failed for {interface}: {exc}",
            interface=interface,
            exc=exc,
        )
        return None
    raw = response[18:24]
    if raw == b"\x00" * 6:
        return None
    return ":".join(f"{octet:02x}" for octet in raw)


def read_interface_ipv4(interface: str) -> Optional[str]:
    """Return the first IPv4 address and netmask of ``interface`` as a CIDR string.

    Used by the optional ``filter_net`` behaviour to keep only responders
    that live in the scan interface's own IPv4 network.

    Args:
        interface: The interface name to inspect.

    Returns:
        A CIDR string such as ``"192.168.0.5/24"``, or ``None`` if the
        interface has no IPv4 address configured.
    """
    for address in psutil.net_if_addrs().get(interface, []):
        if address.family is socket.AF_INET and address.address:
            netmask = address.netmask or "255.255.255.0"
            return f"{address.address}/{netmask}"
    return None


def default_interface() -> Optional[str]:
    """Return the interface carrying the IPv4 default route, if any.

    Replaces scapy's ``conf.iface`` fallback. Reads ``/proc/net/route``
    and returns the device of the first entry whose destination is
    ``0.0.0.0``.

    Returns:
        The interface name, or ``None`` when no default route exists or
        the procfs entry cannot be read.
    """
    try:
        lines = _PROC_NET_ROUTE.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        logger.warning("pn_discovery: cannot read {path}: {exc}", path=_PROC_NET_ROUTE, exc=exc)
        return None
    for line in lines[1:]:
        columns = line.split()
        if len(columns) >= 2 and columns[1] == "00000000":
            return columns[0]
    return None


def capture_dcp_responses(interface: str, request_frame: bytes, listen_seconds: float) -> List[bytes]:
    """Send one DCP request and collect every PROFINET frame that follows.

    The socket is opened and bound BEFORE the request is transmitted so no
    fast responder can answer into a closed socket. Collection stops after
    ``listen_seconds`` of wall-clock time measured from the transmit.

    Args:
        interface: Interface to bind and transmit on.
        request_frame: The complete Ethernet frame to send once.
        listen_seconds: How long to keep collecting responses.

    Returns:
        Every frame received on the bound socket within the window, in
        arrival order. Filtering (own MAC, FrameID, ...) is the caller's
        job — this function performs no interpretation.

    Raises:
        RawSocketError: If the socket cannot be created, bound, or written
            to; most commonly a missing ``CAP_NET_RAW`` or an unknown
            interface name.
    """
    frames: List[bytes] = []
    try:
        raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETHERTYPE_PROFINET))
    except OSError as exc:
        raise RawSocketError(f"cannot open AF_PACKET socket on {interface}: {exc}") from exc

    try:
        try:
            raw_socket.bind((interface, ETHERTYPE_PROFINET))
            raw_socket.settimeout(_RECV_POLL_INTERVAL)
            raw_socket.send(request_frame)
        except OSError as exc:
            raise RawSocketError(f"cannot send DCP request on {interface}: {exc}") from exc

        deadline = time.monotonic() + max(listen_seconds, 0.0)
        while time.monotonic() < deadline:
            try:
                frames.append(raw_socket.recv(_RECV_BUFFER_SIZE))
            except TimeoutError:
                continue
            except OSError as exc:
                raise RawSocketError(f"receive failed on {interface}: {exc}") from exc
    finally:
        raw_socket.close()
    return frames
