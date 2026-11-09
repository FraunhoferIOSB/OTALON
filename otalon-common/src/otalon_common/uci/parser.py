"""UCI parsing with split limit for safe IPv6 and protocol stack handling."""

import ipaddress
from typing import NamedTuple

from otalon_common.uci.constants import UCI_FIELDS, UCI_SEGMENT_COUNT


class UciParts(NamedTuple):
    """Parsed UCI components as a named tuple with exactly 9 fields."""

    src_mac: str
    dst_mac: str
    vlan: str
    ip_proto: str
    src_ip: str
    dst_ip: str
    src_port: str
    dst_port: str
    protocols: str


def parse_uci(uci: str) -> UciParts:
    """Parse a UCI string into its component fields.

    Uses ``split("/", 8)`` to produce at most 9 segments, correctly handling
    IPv6 addresses and protocol stacks containing slashes (e.g., ``TCP/HTTP``).

    Args:
        uci: The UCI string to parse.

    Returns:
        A UciParts named tuple with all 9 fields populated (missing segments
        are padded with empty strings).
    """
    parts = uci.split("/", 8)
    padded = parts + [""] * (UCI_SEGMENT_COUNT - len(parts))
    return UciParts(*padded[:UCI_SEGMENT_COUNT])


def parse_uci_to_dict(uci: str) -> dict[str, str]:
    """Parse a UCI string into a dictionary mapping field names to values.

    Args:
        uci: The UCI string to parse.

    Returns:
        A dict with all 9 UCI field names as keys.
    """
    parts = parse_uci(uci)
    return dict(zip(UCI_FIELDS, parts))


def normalize_uci(uci: str) -> str:
    """Normalize a UCI string by canonicalizing IPv6 addresses.

    Args:
        uci: The UCI string to normalize.

    Returns:
        The UCI string with IPv6 addresses in compressed canonical form.
    """
    parts = parse_uci(uci)
    src_ip = _normalize_ip(parts.src_ip)
    dst_ip = _normalize_ip(parts.dst_ip)
    normalized = parts._replace(src_ip=src_ip, dst_ip=dst_ip)
    return "/".join(normalized)


def _normalize_ip(ip_str: str) -> str:
    """Normalize an IP address string to its canonical form.

    Args:
        ip_str: The IP address string (IPv4 or IPv6).

    Returns:
        The canonical string representation, or the original string if parsing fails.
    """
    if not ip_str:
        return ip_str
    try:
        return str(ipaddress.ip_address(ip_str))
    except ValueError:
        return ip_str
