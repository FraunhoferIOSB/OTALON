"""Unit tests for the ``otalon_scan.api.serializers`` row projections."""

from __future__ import annotations

import uuid
from ipaddress import IPv4Address

from otalon_scan.api.serializers import observation_row_to_item
from otalon_scan.repositories.models import ServiceObservation


def test_observation_row_to_item_serialises_ipv4_address() -> None:
    """An :class:`~ipaddress.IPv4Address` object SHALL be coerced to ``str``
    so that :class:`ServiceObservationItem` accepts it.
    """
    row = ServiceObservation(
        id=1,
        scan_id=uuid.uuid4(),
        ip_address=IPv4Address("192.168.0.41"),
        mac_address="aa:bb:cc:dd:ee:ff",
    )
    item = observation_row_to_item(row)
    assert item.ip_address == "192.168.0.41"
    assert item.mac_address == "aa:bb:cc:dd:ee:ff"


def test_observation_row_to_item_preserves_none_addresses() -> None:
    """``None`` values for optional address fields SHALL stay ``None``."""
    row = ServiceObservation(
        id=2,
        scan_id=uuid.uuid4(),
        ip_address=None,
        mac_address=None,
    )
    item = observation_row_to_item(row)
    assert item.ip_address is None
    assert item.mac_address is None
