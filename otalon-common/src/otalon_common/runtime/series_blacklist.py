"""Series-blacklist entry syntax validator (CLAS-071, decision D7).

One shared, stdlib-only validator defines the accepted entry forms of the
``detection.series_blacklist`` runtime key so otalon-api (pre-persist
rejection with a 422 naming the entry index) and otalon-clas
(defense-in-depth behind the API) accept exactly the same universe of
entries. It deliberately does NOT import the otalon-clas matcher: the
dependency direction stays clas -> common, and otalon-common keeps its
documented "no DB/web deps" contract (``tests/test_runtime_import_purity.py``
pins that).

Accepted entry forms (verified against the matcher in
``otalon-clas/.../detection/series_blacklist.py``):

1. **IP endpoint address** — IPv4 or IPv6, optionally with a ``/prefix``
   CIDR suffix (``ipaddress``-parsed: ``192.168.0.1``, ``8.8.8.8``,
   ``fe80::1/64``).
2. **MAC address** — 2-6 colon-separated octets where a whole trailing
   octet sequence may be ``*`` wildcards (``ff:ff:ff:ff:ff:ff``,
   ``33:33:00:00:00:01``, ``33:33:*``, ``01:00:5e:*``). A concrete-only
   MAC must carry all six octets; a concrete field is one or two hex
   digits. The wildcard head may be dropped only through trailing ``*``
   octets, so ``33:33:zz`` can never sneak through as a "tag".
3. **L3 token** — ``IPv4`` | ``IPv6`` | ``ARP``, case-insensitive (the
   matcher lowercases every token).
4. **Plain protocol tag** — a colon-separated tag with non-empty
   segments (``Ethernet:ARP``, ``Ethernet:IPv4:TCP:DNS``), optionally
   with one trailing ``*`` segment (``Ethernet:IPv4:*``).
5. **Compound UCI pattern** — 2-9 ``/``-separated fields, each field a
   non-empty value or ``*``, mirroring the matcher's ``split("/")``
   field-wise semantics (a shorter pattern addresses a prefix of the
   9-field UCI, ``series_blacklist.py:105-107``).

Everything else is rejected with :class:`ListEntryValidationError`
carrying the ``entry[N]: …`` message with N the 0-based index, exactly
matching the HTTP 422 detail contract of the API (design.md D10).
Structural failures (non-array JSON, non-string elements) raise plain
:class:`ValueError` WITHOUT an entry index, which the API maps to the
existing 400 structural semantics.
"""

from __future__ import annotations

import ipaddress
import json
import re

from otalon_common.runtime.registry import ListEntryValidationError

_L3_TOKENS: frozenset[str] = frozenset({"ipv4", "ipv6", "arp"})
_MAC_OCTET: re.Pattern[str] = re.compile(r"^[0-9a-f]{1,2}$")
_MAC_MIN_FIELDS: int = 2
_MAC_FULL_FIELDS: int = 6
_MIN_UCI_FIELDS: int = 2
_MAX_UCI_FIELDS: int = 9


def _is_l3_token(entry: str) -> bool:
    """Return whether *entry* is one of the case-insensitive L3 tokens."""
    return entry in _L3_TOKENS


def _is_ip_with_optional_cidr(entry: str) -> bool:
    """Return whether *entry* is an IPv4/IPv6 address, optionally with CIDR."""
    if "." not in entry and ":" not in entry:
        return False
    try:
        ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return False
    return True


def _is_mac(entry: str) -> bool:
    """Return whether *entry* is a MAC with optional trailing ``*`` octets.

    ``*`` octets are legal only as a trailing sequence after at least one
    concrete hex octet; without any wildcard all six octets are required.
    """
    fields = entry.split(":")
    if not _MAC_MIN_FIELDS <= len(fields) <= _MAC_FULL_FIELDS:
        return False
    if "*" in fields:
        first_star = fields.index("*")
        if first_star == 0:
            return False
        if any(field != "*" for field in fields[first_star:]):
            return False
        concrete = fields[:first_star]
    else:
        if len(fields) != _MAC_FULL_FIELDS:
            return False
        concrete = fields
    return all(_MAC_OCTET.fullmatch(field) for field in concrete)


def _is_plain_tag(entry: str) -> bool:
    """Return whether *entry* is a plain protocol tag with an optional ``*`` tail.

    A tag whose first segment looks like a MAC octet is MAC-shaped, not a
    tag, so malformed MACs cannot take the tag path.
    """
    fields = entry.split(":")
    if any(field == "" for field in fields):
        return False
    if "*" in fields:
        first_star = fields.index("*")
        if first_star == 0:
            return False
        if any(field != "*" for field in fields[first_star:]):
            return False
    if _MAC_OCTET.fullmatch(fields[0]):
        return False
    return True


def _is_uci_pattern(entry: str) -> bool:
    """Return whether *entry* is a 2-9 field ``/``-separated UCI pattern.

    A full UCI addresses 9 fields (``src_mac/dst_mac/vlan/ip_proto/
    src_ip/dst_ip/sport/dport/protocols``); a shorter pattern addresses
    a prefix of them (the matcher compares field-wise and leaves the
    un-addressed fields free). A pattern with MORE than 9 raw
    ``/``-separated segments is rejected as malformed — the one
    deliberate narrowing versus the matcher's ``split("/", 8)``, which
    tolerates slashy protocol stacks; per design D7's risk note a
    rejected odd entry (422, fixable) beats a persisted dead pattern.
    Empty segments are legal (real production UCIs carry ``//`` for an
    absent vlan/ip_proto).
    """
    return _MIN_UCI_FIELDS <= len(entry.split("/")) <= _MAX_UCI_FIELDS


def _entry_reason(entry: str) -> str:
    """Build the per-entry rejection reason for *entry*."""
    return (
        "expected an IPv4/IPv6 address (optional CIDR), a MAC with trailing "
        "'*' octet wildcards, an L3 token (IPv4/IPv6/ARP), a plain protocol "
        f"tag with an optional trailing '*', or a '/'-separated UCI pattern, got {entry!r}"
    )


def _validate_entry(entry: str, index: int) -> None:
    """Raise :class:`ListEntryValidationError` when *entry* matches no form.

    Args:
        entry: One stripped, lowercased blacklist entry.
        index: 0-based position of the entry inside its array, surfaced
            in the error message so the API can report it in a 422.

    Raises:
        ListEntryValidationError: When the entry matches none of the
            accepted forms.
    """
    acceptable = (
        _is_l3_token(entry)
        or _is_ip_with_optional_cidr(entry)
        or _is_mac(entry)
        or (":" in entry and _is_plain_tag(entry))
        or ("/" in entry and _is_uci_pattern(entry))
    )
    if not acceptable:
        raise ListEntryValidationError(f"entry[{index}]: {_entry_reason(entry)}")


def series_blacklist_syntax_validator(value: str) -> None:
    """Validate a series-blacklist runtime value: a JSON array of patterns.

    The input is the raw persisted-value text: a JSON array in which
    every element is a string. Each entry is stripped and lowercased
    before the syntax check (the otalon-clas matcher normalizes the
    same way). Structural failures — *value* not being a JSON array of
    strings — raise plain :class:`ValueError` without referencing an
    entry index; a syntactically invalid entry raises
    :class:`ListEntryValidationError` naming the offending 0-based
    index in the ``entry[N]: …`` message form that the API surfaces
    verbatim as the HTTP 422 detail.

    Args:
        value: Candidate value string; expected to be JSON text of an
            array of strings.

    Raises:
        ValueError: When *value* is not a JSON array of strings.
        ListEntryValidationError: On the first syntactically invalid
            entry, naming its 0-based index.
    """
    try:
        parsed = json.loads(value)
        if not isinstance(parsed, list):
            raise ValueError("top-level JSON value is not an array")
    except ValueError as exc:
        raise ValueError(
            f"expected a JSON array of strings, got {value[:64]!r}"
        ) from exc
    if any(not isinstance(element, str) for element in parsed):
        raise ValueError("expected a JSON array of strings; found a non-string element")
    for index, element in enumerate(parsed):
        assert isinstance(element, str)
        stripped = element.strip().lower()
        if not stripped:
            raise ListEntryValidationError(
                f"entry[{index}]: expected a non-empty string"
            )
        _validate_entry(stripped, index)
