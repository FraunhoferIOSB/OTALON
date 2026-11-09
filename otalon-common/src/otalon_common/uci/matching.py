"""UCI matching utilities: base-key extraction, wildcard detection, and pattern matching.

The sibling matcher (``matches_port_collapse_sibling``) mirrors the
canonical UI logic in ``otalon-ui/app/utils/uci.ts``
(``matchesPortCollapseSibling``) so the detector and the UI badge agree on
what counts as the same connection across wildcard or rotated ports.
"""

from otalon_common.uci.parser import parse_uci

_WILDCARD = "*"
_BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


def _is_unicast_mac(mac: str) -> bool:
    """Return whether a MAC address is a unicast address.

    A broadcast/multicast address (least-significant bit of the first octet
    set, which also covers ``ff:ff:ff:ff:ff:ff``) has no meaningful reverse
    direction and must not be treated as swappable when matching siblings.

    Args:
        mac: MAC address string (colon-separated hex octets).

    Returns:
        True when the MAC is a unicast address.
    """
    if not mac:
        return False
    if mac.lower() == _BROADCAST_MAC:
        return False
    first_octet_str = mac.split(":", 1)[0]
    try:
        first_octet = int(first_octet_str, 16)
    except ValueError:
        return False
    return (first_octet & 0x01) == 0


def base_key_without_ports(uci: str) -> str:
    """Extract the 7-field base key from a UCI (without port fields).

    The base key consists of: src_mac, dst_mac, vlan, ip_proto, src_ip, dst_ip, protocols.

    Args:
        uci: The UCI string.

    Returns:
        A slash-separated string of the 7 base-key fields.
    """
    parts = parse_uci(uci)
    return "/".join(
        [
            parts.src_mac,
            parts.dst_mac,
            parts.vlan,
            parts.ip_proto,
            parts.src_ip,
            parts.dst_ip,
            parts.protocols,
        ]
    )


def is_wildcard_uci(uci: str) -> bool:
    """Check whether a UCI string contains wildcards in port fields.

    Args:
        uci: The UCI string to check.

    Returns:
        True if either src_port or dst_port is ``"*"``.
    """
    parts = parse_uci(uci)
    return parts.src_port == "*" or parts.dst_port == "*"


def match_uci_pattern(uci: str, pattern: str) -> bool:
    """Check if a concrete UCI matches a wildcard pattern.

    A ``"*"`` in the pattern matches any value in the corresponding field.
    Non-wildcard fields must match exactly.

    Args:
        uci: The concrete UCI string.
        pattern: The UCI pattern (may contain ``"*"`` in port fields).

    Returns:
        True if the UCI matches the pattern.
    """
    uci_parts = parse_uci(uci)
    pattern_parts = parse_uci(pattern)

    for uci_field, pattern_field in zip(uci_parts, pattern_parts):
        if pattern_field == "*":
            continue
        if uci_field != pattern_field:
            return False
    return True


def matches_port_collapse_sibling(left: str, right: str) -> bool:
    """Return whether two UCIs identify the same connection or port-collapse sibling.

    Mirrors the canonical UI logic ``matchesPortCollapseSibling`` in
    ``otalon-ui/app/utils/uci.ts``. Two UCIs match when they are:

    * exactly equal, or
    * direct siblings: their port-stripped base keys (MACs, VLAN, IP
      protocol, IPs, protocol stack) are equal -- so wildcard ports
      (``*/*``), partial wildcards (``56247/*``) and rotated concrete port
      pairs all collapse onto the same trained series, or
    * reverse siblings: the connection is the same endpoints seen in the
      opposite direction, which is only meaningful between four unicast
      MACs. A broadcast/multicast target has no reverse direction, so it
      is never reverse-matched. Ports mirror across the swap but a wildcard
      port on either side collapses the port dimension there.

    Args:
        left: First UCI string.
        right: Second UCI string.

    Returns:
        True when the UCIs match directly, across a wildcard port, or as a
        direction-swapped unicast sibling.
    """
    if left == right:
        return True
    left_parts = parse_uci(left)
    right_parts = parse_uci(right)
    if base_key_without_ports(left) == base_key_without_ports(right):
        return True
    all_unicast = (
        _is_unicast_mac(left_parts.src_mac)
        and _is_unicast_mac(left_parts.dst_mac)
        and _is_unicast_mac(right_parts.src_mac)
        and _is_unicast_mac(right_parts.dst_mac)
    )
    if not all_unicast:
        return False
    macs_swapped = (
        left_parts.src_mac == right_parts.dst_mac
        or left_parts.dst_mac == right_parts.src_mac
    )
    ports_mirror = (
        left_parts.src_port == _WILDCARD
        or right_parts.dst_port == _WILDCARD
        or left_parts.src_port == right_parts.dst_port
    ) and (
        left_parts.dst_port == _WILDCARD
        or right_parts.src_port == _WILDCARD
        or left_parts.dst_port == right_parts.src_port
    )
    return bool(
        left_parts.vlan == right_parts.vlan
        and left_parts.ip_proto == right_parts.ip_proto
        and left_parts.src_ip == right_parts.dst_ip
        and left_parts.dst_ip == right_parts.src_ip
        and left_parts.protocols == right_parts.protocols
        and macs_swapped
        and ports_mirror
    )
