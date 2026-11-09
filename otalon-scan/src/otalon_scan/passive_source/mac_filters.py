"""Pure MAC-address predicates for the passive seeder's filter stage.

Implements the ``Multicast and Broadcast MAC Filtering`` requirement
from ``openspec/changes/add-passive-asset-seeder/specs/``
``passive-asset-seeding/spec.md`` and design.md decision ``D-MAC-FILTER``.

Both predicates are pure functions of the first octet of the MAC
string — no I/O, no side effects, suitable for direct unit testing
without any fixture.

The seeder applies them BEFORE issuing any ``upsert_network_interface``
call so multicast/broadcast/control-plane MACs and (when opt-in)
locally-administered MACs never reach the inventory.
"""

from __future__ import annotations


def _first_octet(mac: str) -> int:
    """Return the integer value of the MAC's first octet.

    Accepts the canonical ``aa:bb:cc:dd:ee:ff`` form. Raises
    :class:`ValueError` on malformed input so misuse surfaces loudly
    rather than silently letting an unintended MAC through the filter.
    """
    try:
        return int(mac.split(":", 1)[0], 16)
    except (ValueError, IndexError) as exc:
        raise ValueError(f"malformed MAC address: {mac!r}") from exc


def is_multicast_or_broadcast(mac: str) -> bool:
    """Return ``True`` if the MAC's Group bit is set.

    The Group bit is the **least-significant** bit of the first octet
    (IEEE 802 §4.2.3); when set, the address denotes a group rather
    than an individual NIC. This single check subsumes:

    - the broadcast address ``ff:ff:ff:ff:ff:ff``,
    - the IPv4-multicast prefix ``01:00:5e:*``,
    - the IPv6-multicast prefix ``33:33:*``,
    - the bridge-control prefix ``01:80:c2:*``,
    - IGMP/MLD ranges,
    - any other 802.1 group address.

    Per requirement ``Multicast and Broadcast MAC Filtering``, the
    passive seeder MUST drop any MAC for which this predicate returns
    ``True`` before calling ``upsert_network_interface``.
    """
    return bool(_first_octet(mac) & 0b0000_0001)


def is_locally_administered(mac: str) -> bool:
    """Return ``True`` if the MAC's LAA bit is set.

    The LAA (locally-administered) bit is the **second-lowest** bit of
    the first octet (IEEE 802 §4.2.3); when set, the address was
    assigned locally rather than burned in by a manufacturer.
    Random-MAC Wi-Fi clients flip this bit. Per design decision
    ``D-MAC-FILTER`` and requirement ``Multicast and Broadcast MAC
    Filtering`` scenario ``LAA MAC dropped only when opt-in flag is
    true``, the passive seeder drops these MACs only when the
    operator opts in via ``PASSIVE_SEEDER_DROP_LAA=true``.
    """
    return bool(_first_octet(mac) & 0b0000_0010)
