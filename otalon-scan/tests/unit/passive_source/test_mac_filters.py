"""Unit tests for ``otalon_scan.passive_source.mac_filters``.

Covers the Multicast/Broadcast/Group-bit predicate
(:func:`is_multicast_or_broadcast`) and the Locally-Administered
predicate (:func:`is_locally_administered`).

Maps onto the following spec scenarios from
``openspec/changes/add-passive-asset-seeder/specs/``
``passive-asset-seeding/spec.md``:

- ``Broadcast MAC dropped``
- ``IPv4-multicast MAC dropped``
- ``LAA MAC dropped only when opt-in flag is true`` (predicate side)
- ``LAA MAC dropped when opt-in flag is true`` (predicate side)

(The "opt-in flag" arm of the LAA scenarios is exercised at the cycle
level by ``test_entrypoint.py``; here we only assert the predicate.)
"""

from __future__ import annotations

import pytest

from otalon_scan.passive_source.mac_filters import (
    is_locally_administered,
    is_multicast_or_broadcast,
)


class TestIsMulticastOrBroadcast:
    """Cover Group-bit logic for the four canonical MAC classes."""

    def test_broadcast_rejected(self) -> None:
        """SCENARIO: Broadcast MAC dropped."""
        assert is_multicast_or_broadcast("ff:ff:ff:ff:ff:ff") is True

    def test_ipv4_multicast_rejected(self) -> None:
        """SCENARIO: IPv4-multicast MAC dropped."""
        assert is_multicast_or_broadcast("01:00:5e:7f:00:01") is True

    def test_ipv6_multicast_rejected(self) -> None:
        """IPv6 multicast prefix ``33:33:*`` has Group bit set."""
        assert is_multicast_or_broadcast("33:33:00:00:00:01") is True

    def test_bridge_control_rejected(self) -> None:
        """STP / bridge-control prefix ``01:80:c2:*`` has Group bit set."""
        assert is_multicast_or_broadcast("01:80:c2:00:00:00") is True

    def test_ics_unicast_accepted(self) -> None:
        """SCENARIO sample: unicast MAC ``aa:bb:cc:dd:ee:ff`` accepted.

        ``0xaa = 0b10101010`` has the Group bit (LSB) clear.
        """
        assert is_multicast_or_broadcast("aa:bb:cc:dd:ee:ff") is False

    def test_global_burned_in_accepted(self) -> None:
        """A globally-unique burned-in MAC has the Group bit clear."""
        assert is_multicast_or_broadcast("00:1c:06:11:22:33") is False

    def test_malformed_raises(self) -> None:
        """Malformed MACs raise ``ValueError``; caller MUST handle."""
        with pytest.raises(ValueError):
            is_multicast_or_broadcast("not-a-mac")


class TestIsLocallyAdministered:
    """Cover LAA-bit logic for the four corners of bit 0 × bit 1."""

    def test_laa_set_returns_true(self) -> None:
        """SCENARIO sample: ``02:11:22:33:44:55`` has LAA bit set.

        ``0x02 = 0b00000010`` — the bit-1 LAA flag is on, bit-0 clear.
        """
        assert is_locally_administered("02:11:22:33:44:55") is True

    def test_global_burned_in_returns_false(self) -> None:
        """``00:1c:06:…`` is globally administered; LAA bit clear."""
        assert is_locally_administered("00:1c:06:11:22:33") is False

    def test_aa_prefix_is_laa(self) -> None:
        """``0xaa = 0b10101010`` has bit-1 set, so LAA is True."""
        assert is_locally_administered("aa:bb:cc:dd:ee:ff") is True

    def test_broadcast_is_also_laa(self) -> None:
        """``0xff = 0b11111111`` has both Group and LAA bits set.

        This documents the interaction: the seeder filters Group-bit
        MACs first, so a broadcast never reaches the LAA arm. The
        predicate itself must still report ``True`` here for parity
        with the IEEE 802 bit semantics.
        """
        assert is_locally_administered("ff:ff:ff:ff:ff:ff") is True
