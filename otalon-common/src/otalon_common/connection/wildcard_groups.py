"""Wildcard group building for UCI grouping by base key."""

from otalon_common.connection.port_collapsing import port_wildcard
from otalon_common.uci.parser import parse_uci


def build_wildcard_groups(ucis: list[str]) -> dict[str, list[str]]:
    """Group UCIs by base key and create wildcard patterns.

    Single-member groups retain their concrete UCI as key.
    Multi-member groups use ``"*"`` for heterogeneous port fields.

    Args:
        ucis: List of UCI strings.

    Returns:
        A dict mapping wildcard pattern keys to sorted lists of concrete member UCIs.
    """
    base_key_groups: dict[str, list[str]] = {}

    for uci in ucis:
        parts = parse_uci(uci)
        base_key = "/".join(
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
        base_key_groups.setdefault(base_key, []).append(uci)

    result: dict[str, list[str]] = {}

    for members in base_key_groups.values():
        if len(members) == 1:
            result[members[0]] = members
            continue

        group_key = _build_group_key(members)
        result[group_key] = sorted(members)

    return result


def _build_group_key(members: list[str]) -> str:
    """Build a wildcard group key from a list of UCIs sharing the same base key.

    Args:
        members: List of UCI strings in the same base-key group.

    Returns:
        A UCI string with ``"*"`` for heterogeneous port fields.
    """
    parsed = [parse_uci(uci) for uci in members]
    first = parsed[0]

    src_ports = [p.src_port for p in parsed]
    dst_ports = [p.dst_port for p in parsed]

    return "/".join(
        [
            first.src_mac,
            first.dst_mac,
            first.vlan,
            first.ip_proto,
            first.src_ip,
            first.dst_ip,
            port_wildcard(src_ports),
            port_wildcard(dst_ports),
            first.protocols,
        ]
    )
