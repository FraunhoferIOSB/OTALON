"""Direct provenance tests for passive-discovery interface source.

These tests prove the passive-seeder producer fact ``network_interfaces.source``
flows from the repository SELECT contract, through the real device-row
formatter, into the typed :class:`NetworkInterfaceItem` API contract. They
traverse the actual formatting seam rather than asserting a hand-built dict.
"""

from __future__ import annotations

from typing import Any

import pytest

from otalon_api.domain.topology.schemas import NetworkInterfaceItem
from otalon_api.services.topology_service import TopologyService


@pytest.mark.unit
def test_format_device_row_propagates_interface_source() -> None:
    """A repo interface row's ``source`` reaches the formatted API interface."""
    row: dict[str, Any] = {"id": 7, "hostname": "plc-1"}
    interfaces_by_id = {
        7: [
            {
                "id": 11,
                "mac_address": "aa:bb:cc:dd:ee:ff",
                "ipv4_address": "10.0.0.9",
                "source": "passive",
            }
        ]
    }
    device = TopologyService._format_device_row(row, interfaces_by_id)
    assert device["interfaces"][0]["source"] == "passive"


@pytest.mark.unit
def test_network_interface_item_carries_source_contract() -> None:
    """The typed API item preserves the provenance field end to end."""
    item = NetworkInterfaceItem.model_validate({"id": 11, "mac_address": "aa:bb:cc:dd:ee:ff", "source": "passive"})
    assert item.source == "passive"
    assert item.model_dump()["source"] == "passive"


@pytest.mark.unit
def test_missing_source_is_null_not_fabricated() -> None:
    """Absent provenance stays null rather than being invented."""
    row: dict[str, Any] = {"id": 7}
    interfaces_by_id = {7: [{"id": 11, "mac_address": "aa:bb:cc:dd:ee:ff"}]}
    device = TopologyService._format_device_row(row, interfaces_by_id)
    assert device["interfaces"][0]["source"] is None
