"""MAC-address canonicalisation utility.

Introduced by F-03 (``refactor-otalon-scan-device-network-ownership-v1``).

The F-03 device-identity strategy (see design.md § D-DEVICE-KEY and the
``ck_devices_primary_mac_format`` CHECK constraint added in alembic
revision ``0002``) requires MAC addresses on ``devices.primary_mac`` and
on the ``upsert_device`` / ``upsert_network_interface`` helper inputs to
be in canonical lowercase colon-separated form, e.g.
``"aa:bb:cc:dd:ee:ff"``.

This module exposes :func:`canonicalise`, a pure helper that accepts any
of the commonly encountered input forms and returns the canonical form.
It is deliberately NOT invoked silently by the repository helpers — per
design.md § D-UPSERT-DEVICE the helper raises on malformed input rather
than masking module bugs. Callers SHOULD invoke :func:`canonicalise`
explicitly before calling the helper.
"""

from __future__ import annotations

import re

# Canonical MAC pattern matched by the DB CHECK constraint
# ``ck_devices_primary_mac_format``. The application-layer regex below
# is more permissive about INPUT (it accepts uppercase / dashes / dots /
# bare hex) and returns the canonical OUTPUT that the CHECK admits.
_CANONICAL_MAC_RE: re.Pattern[str] = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


class InvalidMacError(ValueError):
    """Raised by :func:`canonicalise` when the input does not parse as a MAC.

    Subclass of :class:`ValueError` for backwards compatibility with
    callers that catch the latter; the dedicated subclass lets callers
    that *do* care about MAC-specific failure distinguish from other
    ``ValueError``\\s raised by the repository helpers.

    Attributes:
        raw: The exact string that failed to parse.
    """

    def __init__(self, raw: str) -> None:
        """Initialise the typed parse-failure error.

        Args:
            raw: The original input string, included verbatim in the
                error message for operator debugging.
        """
        super().__init__(
            f"canonicalise: {raw!r} is not a recognisable MAC address (expected "
            f"6 hex octets separated by colons, dashes, or dots, optionally "
            f"with case differences)"
        )
        self.raw = raw


def canonicalise(mac: str) -> str:
    """Return ``mac`` in canonical lowercase colon-separated form.

    Accepts any of these input forms (case-insensitive):

    - ``"aa:bb:cc:dd:ee:ff"`` — already canonical (returned lowercased).
    - ``"AA:BB:CC:DD:EE:FF"`` — uppercase colon-separated.
    - ``"aa-bb-cc-dd-ee-ff"`` — dash-separated (Windows ``getmac`` style).
    - ``"aabb.ccdd.eeff"`` — Cisco-style three-dotted-quartets.
    - ``"aabbccddeeff"`` — bare 12-character hex string.

    Args:
        mac: Input MAC string; any of the supported forms.

    Returns:
        The canonical lowercase colon-separated form.

    Raises:
        InvalidMacError: If ``mac`` is empty, contains non-hex characters
            after separator stripping, has the wrong number of hex digits,
            or otherwise fails to parse. Inherits from :class:`ValueError`.

    Examples:
        >>> canonicalise("AA:BB:CC:DD:EE:FF")
        'aa:bb:cc:dd:ee:ff'
        >>> canonicalise("aa-bb-cc-dd-ee-ff")
        'aa:bb:cc:dd:ee:ff'
        >>> canonicalise("aabb.ccdd.eeff")
        'aa:bb:cc:dd:ee:ff'
        >>> canonicalise("aabbccddeeff")
        'aa:bb:cc:dd:ee:ff'
    """
    if not isinstance(mac, str):
        raise InvalidMacError(repr(mac))
    if not mac:
        raise InvalidMacError(mac)

    # Strip the three commonly-encountered separators and lowercase.
    bare = mac.replace(":", "").replace("-", "").replace(".", "").lower()

    if len(bare) != 12 or not all(c in "0123456789abcdef" for c in bare):
        raise InvalidMacError(mac)

    canonical = ":".join(bare[i : i + 2] for i in range(0, 12, 2))

    # Defensive: the resulting string MUST match the canonical regex; if it
    # doesn't, the code above has a bug. Keep the assert so a future
    # refactor cannot silently produce CHECK-rejecting output.
    assert _CANONICAL_MAC_RE.match(canonical), f"BUG: canonicalise produced {canonical!r}"
    return canonical
