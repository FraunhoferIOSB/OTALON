"""UCI (Unique Communication Identifier) parsing and matching.

Thin re-export wrapper around ``otalon_common.uci``.  Local callers
import from this module so that a single compatibility layer (argument
order, return type) isolates them from the shared library API.

A UCI string has 9 slash-separated fields::

    src_mac/dst_mac/vlan/ip_proto/src_ip/dst_ip/src_port/dst_port/protocols
"""

from __future__ import annotations

from otalon_common.uci import is_wildcard_uci as is_wildcard_uci, normalize_uci as normalize_uci, parse_uci as parse_uci


def base_key_without_ports(uci: str) -> tuple[str, str, str, str, str, str, str]:
    """Extract the UCI base key excluding source and destination ports.

    Returns a 7-tuple of ``(src_mac, dst_mac, vlan, ip_proto, src_ip,
    dst_ip, protocols)`` — the fields that identify a connection group
    independent of port numbers.

    This wrapper preserves the tuple return type expected by API callers
    (used as dict grouping keys) while delegating parsing to
    ``otalon_common.uci``.

    Args:
        uci: The raw UCI string.

    Returns:
        A 7-tuple suitable as a dictionary grouping key.
    """
    p = parse_uci(uci)
    return (p.src_mac, p.dst_mac, p.vlan, p.ip_proto, p.src_ip, p.dst_ip, p.protocols)


def match_uci_pattern(pattern: str, uci: str) -> bool:
    """Check whether *uci* matches *pattern* with wildcard port support.

    This wrapper preserves the ``(pattern, uci)`` argument order used
    throughout the API while delegating to ``otalon_common.uci``
    which uses ``(uci, pattern)``.

    Args:
        pattern: The UCI pattern (may contain ``*`` in port fields).
        uci: The concrete UCI string to test.

    Returns:
        ``True`` if *uci* matches *pattern*.
    """
    from otalon_common.uci import match_uci_pattern as _match

    return _match(uci, pattern)
