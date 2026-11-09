"""Field-aware series-blacklist matching for otalon-clas modules.

Hosts a single :class:`SeriesBlacklist` policy object so bounds
training, bounds checking and the frequency/absence monitor share ONE
matching implementation instead of three drifted private copies.

Motivated by CLAS-039 (the blacklisting half of CLAS-061/F-007): the
``conn`` module identifies series by the 9-field compound UCI
(``src_mac/dst_mac/vlan/l3/src_ip/dst_ip/sport/dport/protocols``),
while the ``SERIES_BLACKLIST`` entries are single field values (one
MAC, one IP, an L3 name). Exact-equality or prefix matching against
the whole identifier can never hit, so the configured exclusions were
ignored by every detection consumer.

Semantics:

* Plain tag identities (``mac_traffic``, ``proto_traffic``) keep the
  legacy exact / trailing-``*`` prefix behaviour.
* Compound UCIs are matched field-aware:

  - a bare MAC token equals ``src_mac`` or ``dst_mac``;
  - a bare IP token equals ``src_ip`` or ``dst_ip``;
  - a wildcard value token without ``/`` (e.g. ``33:33:*``)
    prefix-matches the four endpoint fields with the same
    trailing-``*`` semantics as the plain-tag path (CLAS-071 D5);
  - an L3 token (``IPv4``/``IPv6``/``ARP``) equals the ``l3`` field;
  - a UCI-shaped pattern (contains ``/``) is compared field by field,
    ``*`` wildcards a field, trailing fields may be omitted.

  No substring matching anywhere: a naive ``in`` check would let the
  ``IPv6`` entry also swallow legitimate IPv6 unicast flows
  (``Ethernet:IPv6:UDP:DNS``), which CLAS-039 explicitly forbids.
"""

from __future__ import annotations

from otalon_common.uci import UCI_SEGMENT_COUNT, parse_uci

_LEGACY_L3_TOKENS: frozenset[str] = frozenset({"ipv4", "ipv6", "arp"})
_L3_FIELD_INDEX: int = 3
_ENDPOINT_FIELD_INDICES: tuple[int, ...] = (0, 1, 4, 5)
_PROTOCOLS_FIELD_INDEX: int = 8
_MAC_FIELD_INDICES: tuple[int, ...] = (0, 1)
_MULTICAST_MAC_PREFIXES: tuple[str, ...] = ("33:33:", "ff:ff:ff:ff:ff:ff", "01:00:5e:", "01:80:c2:")


def _has_multicast_endpoint(fields: list[str]) -> bool:
    """Return whether a flow's MAC endpoints include a multicast/broadcast address.

    Constrains the legacy L3 tokens (``IPv6`` etc.) to noise flows: an
    L3 entry excludes multicast/broadcast flows of that protocol, not
    every unicast flow of the IP family (CLAS-039 over-matching guard).

    Args:
        fields: Normalized UCI fields of the candidate series.

    Returns:
        ``True`` when either MAC field carries a multicast/broadcast
        address.
    """
    return any(any(fields[idx].startswith(prefix) for prefix in _MULTICAST_MAC_PREFIXES) for idx in _MAC_FIELD_INDICES)


def _prefix_matches(candidate: str, token: str) -> bool:
    """Return whether *candidate* matches a token that may end in ``*``.

    Encodes the one shared wildcard semantics of the plain-tag path so
    the compound-UCI endpoint prefix match (CLAS-071 D5) cannot drift
    from it: an exact token equals the candidate, a trailing-``*``
    token prefix-matches it, a token that is all ``*`` matches
    everything, and a ``*`` inside the token is literal (no substring
    matching anywhere, CLAS-039).

    Args:
        candidate: Normalized identity or UCI field value.
        token: Normalized configured token.

    Returns:
        ``True`` when the candidate equals the token or carries its
        trailing-``*`` prefix.
    """
    if candidate == token:
        return True
    if not token.endswith("*"):
        return False
    head = token[:-1]
    return not head or candidate.startswith(head)


def _norm(value: str) -> str:
    """Normalise a token for case-insensitive matching.

    Args:
        value: Raw token as configured or observed.

    Returns:
        Lowercased, whitespace-stripped token (never ``None``).
    """
    return value.strip().lower()


def _is_uci_shaped(pattern: str) -> bool:
    """Return whether a pattern addresses UCI fields rather than a value.

    Args:
        pattern: Normalized pattern.

    Returns:
        ``True`` when the pattern contains ``/`` (multi-field UCI
        pattern), ``False`` for single-value tokens.
    """
    return "/" in pattern


class SeriesBlacklist:
    """Immutable blacklist policy shared by all detection consumers.

    Args:
        patterns: Patterns as resolved from the module's ``blacklist``
            config (``SERIES_BLACKLIST`` for ``conn``). Accepts the
            single-string legacy form and lists (CLAS-038).
    """

    __slots__ = ("_uci_patterns", "_value_tokens")

    def __init__(self, patterns: str | list[str] | None) -> None:
        """Split configured patterns into value tokens and UCI patterns."""
        if isinstance(patterns, str):
            raw: list[str] = [patterns]
        else:
            raw = list(patterns or [])
        normalized = [_norm(item) for item in raw if _norm(item)]
        self._value_tokens: frozenset[str] = frozenset(item for item in normalized if not _is_uci_shaped(item))
        self._uci_patterns: tuple[tuple[str, ...], ...] = tuple(
            tuple(item.split("/")[:UCI_SEGMENT_COUNT]) for item in normalized if _is_uci_shaped(item)
        )

    @property
    def is_empty(self) -> bool:
        """Return ``True`` when no pattern is configured."""
        return not (self._value_tokens or self._uci_patterns)

    @property
    def patterns(self) -> frozenset[str]:
        """Return every normalized configured pattern.

        Exposes the resolved pattern set for introspection (tests,
        diagnostics). Not used on the detection hot path.
        """
        merged = set(self._value_tokens)
        merged.update("/".join(parts) for parts in self._uci_patterns)
        return frozenset(merged)

    def matches(self, series_id: str) -> bool:
        """Return whether a series identifier is blacklisted.

        Args:
            series_id: Series identity as the detectors see it — a
                plain tag (MAC, protocol) or a full compound UCI.

        Returns:
            ``True`` when the identity matches any configured pattern
            under legacy exact/prefix or field-aware UCI semantics.
        """
        candidate = _norm(series_id)
        if not candidate or self.is_empty:
            return False
        if not _is_uci_shaped(candidate):
            return self._matches_plain_tag(candidate)
        return self._matches_compound_uci(series_id)

    def _matches_plain_tag(self, candidate: str) -> bool:
        """Apply the legacy exact / trailing-star prefix semantics.

        Args:
            candidate: Normalized plain tag identity.

        Returns:
            ``True`` when any value token equals the candidate or is a
            trailing-``*`` prefix of it.
        """
        return any(_prefix_matches(candidate, token) for token in self._value_tokens)

    def _matches_compound_uci(self, series_id: str) -> bool:
        """Match a compound UCI field by field.

        Args:
            series_id: Raw compound UCI identifier (9 fields).

        Returns:
            ``True`` when a bare token equals one of the endpoint
            fields (MACs, IPs), when a wildcard token prefix-matches
            an endpoint field, when an L3 token matches the ``l3``
            field of a multicast/broadcast flow, or when a UCI-shaped
            pattern matches all its addressed fields.
        """
        fields = [_norm(part) for part in parse_uci(series_id)]
        for token in self._value_tokens:
            if token in _LEGACY_L3_TOKENS:
                if fields[_L3_FIELD_INDEX] == token and _has_multicast_endpoint(fields):
                    return True
                continue
            if "*" in token:
                if any(_prefix_matches(fields[idx], token) for idx in _ENDPOINT_FIELD_INDICES):
                    return True
                continue
            if any(fields[idx] == token for idx in _ENDPOINT_FIELD_INDICES):
                return True
        return self._matches_uci_pattern(fields)

    def _matches_uci_pattern(self, fields: list[str]) -> bool:
        """Compare every UCI-shaped pattern against the parsed fields.

        Args:
            fields: Normalized UCI fields of the candidate series.

        Returns:
            ``True`` when one pattern matches: wildcards skip a field,
            further fields of a longer pattern are required, patterns
            shorter than the UCI leave the remaining fields free.
        """
        for pattern_parts in self._uci_patterns:
            if len(pattern_parts) <= len(fields) and all(
                part == "*" or part == field for part, field in zip(pattern_parts, fields)
            ):
                return True
        return False
