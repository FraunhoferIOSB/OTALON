"""Unit tests for connection aggregation (B-08 / B-16).

Tests cover UCI grouping, wildcard pattern generation, server-side
member resolution, and the extended list_ids service method.
"""

# mypy: disable-error-code="no-untyped-def"

from __future__ import annotations

from datetime import datetime
from unittest.mock import MagicMock

import pytest

from otalon_api.domain.topology.uci import base_key_without_ports, is_wildcard_uci, match_uci_pattern, parse_uci

UCI_TCP_A = "aa:bb:cc:dd:ee:01/aa:bb:cc:dd:ee:02/0//192.168.1.1//1234/80/Ethernet:IPv4:TCP"
UCI_TCP_B = "aa:bb:cc:dd:ee:01/aa:bb:cc:dd:ee:02/0//192.168.1.1//5678/80/Ethernet:IPv4:TCP"
UCI_TCP_C = "aa:bb:cc:dd:ee:01/aa:bb:cc:dd:ee:02/0//192.168.1.1//1234/443/Ethernet:IPv4:TCP"
UCI_L2 = "aa:bb:cc:dd:ee:01/aa:bb:cc:dd:ee:02/0//////Ethernet:VLAN:PROFINET_RT"
UCI_OTHER_HOST = "aa:bb:cc:dd:ee:03/aa:bb:cc:dd:ee:04/0//10.0.0.1//1234/80/Ethernet:IPv4:TCP"


@pytest.mark.unit
class TestBaseKeyWithoutPorts:
    """Tests for base_key_without_ports()."""

    def test_ip_tcp_uci_extracts_seven_fields(self) -> None:
        """Standard IP/TCP UCI returns correct 7-tuple without ports."""
        result = base_key_without_ports(UCI_TCP_A)
        assert result == (
            "aa:bb:cc:dd:ee:01",
            "aa:bb:cc:dd:ee:02",
            "0",
            "",
            "192.168.1.1",
            "",
            "Ethernet:IPv4:TCP",
        )

    def test_layer2_uci_without_ip(self) -> None:
        """Layer-2-only UCI (no IP/ports) returns correct 7-tuple."""
        result = base_key_without_ports(UCI_L2)
        assert result == (
            "aa:bb:cc:dd:ee:01",
            "aa:bb:cc:dd:ee:02",
            "0",
            "",
            "",
            "",
            "Ethernet:VLAN:PROFINET_RT",
        )

    def test_different_ports_yield_same_base_key(self) -> None:
        """UCIs differing only in ports share the same base key."""
        assert base_key_without_ports(UCI_TCP_A) == base_key_without_ports(UCI_TCP_B)

    def test_different_dst_ports_yield_same_base_key(self) -> None:
        """UCIs differing only in destination port share the same base key."""
        assert base_key_without_ports(UCI_TCP_A) == base_key_without_ports(UCI_TCP_C)

    def test_different_hosts_yield_different_base_key(self) -> None:
        """UCIs with different MACs/IPs have different base keys."""
        assert base_key_without_ports(UCI_TCP_A) != base_key_without_ports(UCI_OTHER_HOST)


@pytest.mark.unit
class TestIsWildcardUci:
    """Tests for is_wildcard_uci()."""

    def test_concrete_uci_is_not_wildcard(self) -> None:
        """A regular UCI without '*' is not a wildcard."""
        assert is_wildcard_uci(UCI_TCP_A) is False

    def test_wildcard_src_port(self) -> None:
        """A UCI with '*' as src_port is a wildcard."""
        wc = "aa:bb:cc:dd:ee:01/aa:bb:cc:dd:ee:02/0//192.168.1.1//*/80/Ethernet:IPv4:TCP"
        assert is_wildcard_uci(wc) is True

    def test_wildcard_dst_port(self) -> None:
        """A UCI with '*' as dst_port is a wildcard."""
        wc = "aa:bb:cc:dd:ee:01/aa:bb:cc:dd:ee:02/0//192.168.1.1//1234/*/Ethernet:IPv4:TCP"
        assert is_wildcard_uci(wc) is True

    def test_wildcard_both_ports(self) -> None:
        """A UCI with '*' in both ports is a wildcard."""
        wc = "aa:bb:cc:dd:ee:01/aa:bb:cc:dd:ee:02/0//192.168.1.1//*/*/Ethernet:IPv4:TCP"
        assert is_wildcard_uci(wc) is True


@pytest.mark.unit
class TestMatchUciPattern:
    """Tests for match_uci_pattern()."""

    def test_exact_match(self) -> None:
        """Concrete pattern matches identical UCI."""
        assert match_uci_pattern(UCI_TCP_A, UCI_TCP_A) is True

    def test_wildcard_src_matches(self) -> None:
        """Wildcard src_port matches any src_port."""
        pattern = "aa:bb:cc:dd:ee:01/aa:bb:cc:dd:ee:02/0//192.168.1.1//*/80/Ethernet:IPv4:TCP"
        assert match_uci_pattern(pattern, UCI_TCP_A) is True
        assert match_uci_pattern(pattern, UCI_TCP_B) is True

    def test_wildcard_dst_matches(self) -> None:
        """Wildcard dst_port matches any dst_port."""
        pattern = "aa:bb:cc:dd:ee:01/aa:bb:cc:dd:ee:02/0//192.168.1.1//1234/*/Ethernet:IPv4:TCP"
        assert match_uci_pattern(pattern, UCI_TCP_A) is True
        assert match_uci_pattern(pattern, UCI_TCP_C) is True

    def test_wildcard_does_not_match_different_host(self) -> None:
        """Wildcard in ports does not match UCIs with different base fields."""
        pattern = "aa:bb:cc:dd:ee:01/aa:bb:cc:dd:ee:02/0//192.168.1.1//*/80/Ethernet:IPv4:TCP"
        assert match_uci_pattern(pattern, UCI_OTHER_HOST) is False

    def test_concrete_mismatch_returns_false(self) -> None:
        """Different concrete UCIs do not match."""
        assert match_uci_pattern(UCI_TCP_A, UCI_TCP_B) is False


@pytest.mark.unit
class TestBuildWildcardGroups:
    """Tests for NetcapAggregationService.build_wildcard_groups()."""

    def test_multiple_src_ports_become_wildcard(self, aggregation_service) -> None:
        """UCIs with different source ports yield a wildcard in src_port."""
        ucis = [UCI_TCP_A, UCI_TCP_B]
        groups = aggregation_service.build_wildcard_groups(ucis)
        assert len(groups) == 1
        wildcard = list(groups.keys())[0]
        assert "*/80/" in wildcard
        assert is_wildcard_uci(wildcard)
        assert len(groups[wildcard][0]) == 2
        assert groups[wildcard][1] is False

    def test_multiple_dst_ports_become_wildcard(self, aggregation_service) -> None:
        """UCIs with different destination ports yield a wildcard in dst_port."""
        ucis = [UCI_TCP_A, UCI_TCP_C]
        groups = aggregation_service.build_wildcard_groups(ucis)
        assert len(groups) == 1
        wildcard = list(groups.keys())[0]
        assert "/1234/*/" in wildcard
        assert is_wildcard_uci(wildcard)

    def test_identical_ports_no_wildcard(self, aggregation_service) -> None:
        """UCIs with identical ports do NOT produce a wildcard."""
        ucis = [UCI_TCP_A]
        groups = aggregation_service.build_wildcard_groups(ucis)
        assert len(groups) == 1
        wildcard = list(groups.keys())[0]
        assert not is_wildcard_uci(wildcard)
        assert "/1234/80/" in wildcard

    def test_empty_list_returns_empty(self, aggregation_service) -> None:
        """Empty UCI list produces empty result."""
        groups = aggregation_service.build_wildcard_groups([])
        assert groups == {}

    def test_distinct_base_keys_not_grouped(self, aggregation_service) -> None:
        """UCIs with different base keys form separate groups."""
        ucis = [UCI_TCP_A, UCI_OTHER_HOST]
        groups = aggregation_service.build_wildcard_groups(ucis)
        assert len(groups) == 2

    def test_layer2_uci_without_ports(self, aggregation_service) -> None:
        """Layer-2-only UCIs (empty port fields) produce non-wildcard group."""
        ucis = [UCI_L2]
        groups = aggregation_service.build_wildcard_groups(ucis)
        assert len(groups) == 1
        wildcard = list(groups.keys())[0]
        assert not is_wildcard_uci(wildcard)

    def test_members_are_sorted(self, aggregation_service) -> None:
        """Members within a wildcard group are sorted alphabetically."""
        ucis = [UCI_TCP_B, UCI_TCP_A]
        groups = aggregation_service.build_wildcard_groups(ucis)
        wildcard = list(groups.keys())[0]
        assert groups[wildcard][0] == sorted(groups[wildcard][0])

    def test_all_three_ports_produce_double_wildcard(self, aggregation_service) -> None:
        """UCIs differing in both src and dst ports yield wildcards in both."""
        ucis = [UCI_TCP_A, UCI_TCP_B, UCI_TCP_C]
        groups = aggregation_service.build_wildcard_groups(ucis)
        assert len(groups) == 1
        wildcard = list(groups.keys())[0]
        parts = parse_uci(wildcard)
        assert parts[6] == "*"
        assert parts[7] == "*"
        assert len(groups[wildcard][0]) == 3


@pytest.mark.unit
class TestListIdsGrouped:
    """Tests for TimeseriesService.list_ids() with group_wildcards parameter."""

    def test_group_wildcards_false_returns_strings(self, timeseries_service, mock_influx_repo) -> None:
        """Default mode returns a flat list of UCI strings."""
        mock_influx_repo.list_ids_between.return_value = [UCI_TCP_A]
        result = timeseries_service.list_ids(
            start=datetime(2026, 1, 1),
            stop=datetime(2026, 1, 2),
        )
        assert isinstance(result, list)
        assert len(result) == 1
        assert isinstance(result[0], str)

    def test_group_wildcards_false_marks_unprofiled_ids(self, timeseries_service, mock_influx_repo) -> None:
        """Plain IDs expose profile state from the PostgreSQL-backed service."""
        mock_influx_repo.list_ids_between.return_value = [UCI_TCP_A]
        timeseries_service._postgres_repo = MagicMock(query_profiled_series_ids=MagicMock(return_value=set()))
        assert timeseries_service.profiled_series_ids([UCI_TCP_A]) == set()

    def test_concrete_port_is_profiled_by_collapsed_wildcard(self, timeseries_service, mock_influx_repo) -> None:
        """A concrete port matches a trained profile stored with wildcard ports."""
        mock_influx_repo.list_ids_between.return_value = [UCI_TCP_A, UCI_TCP_B]
        wildcard = "aa:bb:cc:dd:ee:01/aa:bb:cc:dd:ee:02/0//192.168.1.1//*/*/Ethernet:IPv4:TCP"
        timeseries_service._postgres_repo = MagicMock(
            query_profiled_series_ids=MagicMock(return_value={wildcard})
        )

        assert timeseries_service.profiled_series_ids([UCI_TCP_A]) == {UCI_TCP_A}

    def test_unprofiled_base_key_remains_unprofiled(self, timeseries_service, mock_influx_repo) -> None:
        """A base key with no bounds or frequency profile remains unprofiled."""
        timeseries_service._postgres_repo = MagicMock(query_profiled_series_ids=MagicMock(return_value=set()))

        assert timeseries_service.profiled_series_ids([UCI_TCP_A]) == set()

    def test_grouped_concrete_ports_use_collapsed_profile(self, timeseries_service, aggregation_service, mock_influx_repo) -> None:
        """Grouped concrete members resolve a profile stored on the wildcard UCI."""
        mock_influx_repo.list_ids_between.return_value = [UCI_TCP_A, UCI_TCP_B]
        wildcard = "aa:bb:cc:dd:ee:01/aa:bb:cc:dd:ee:02/0//192.168.1.1//*/*/Ethernet:IPv4:TCP"
        timeseries_service._postgres_repo = MagicMock(
            query_profiled_series_ids=MagicMock(return_value={wildcard})
        )

        result = timeseries_service.list_ids(
            start=datetime(2026, 1, 1),
            stop=datetime(2026, 1, 2),
            group_wildcards=True,
            aggregation_service=aggregation_service,
        )

        assert result[0]["profiled"] is True

    def test_group_wildcards_true_returns_dicts(
        self, timeseries_service, aggregation_service, mock_influx_repo
    ) -> None:
        """Grouped mode returns list of dicts with is_wildcard and member_count."""
        mock_influx_repo.list_ids_between.return_value = [UCI_TCP_A, UCI_TCP_B]
        result = timeseries_service.list_ids(
            start=datetime(2026, 1, 1),
            stop=datetime(2026, 1, 2),
            group_wildcards=True,
            aggregation_service=aggregation_service,
        )
        assert isinstance(result, list)
        assert len(result) == 1
        entry = result[0]
        assert isinstance(entry, dict)
        assert "uci" in entry
        assert "is_wildcard" in entry
        assert "member_count" in entry
        assert entry["is_wildcard"] is True
        assert entry["member_count"] == 2
        assert entry["rule_trained"] is False

    def test_group_wildcards_true_single_member_not_wildcard(
        self, timeseries_service, aggregation_service, mock_influx_repo
    ) -> None:
        """A single-member group is not marked as wildcard."""
        mock_influx_repo.list_ids_between.return_value = [UCI_TCP_A]
        result = timeseries_service.list_ids(
            start=datetime(2026, 1, 1),
            stop=datetime(2026, 1, 2),
            group_wildcards=True,
            aggregation_service=aggregation_service,
        )
        assert len(result) == 1
        assert result[0]["is_wildcard"] is False
        assert result[0]["member_count"] == 1

    def test_group_wildcards_true_without_service_falls_back(self, timeseries_service, mock_influx_repo) -> None:
        """group_wildcards=True without aggregation_service returns flat list."""
        mock_influx_repo.list_ids_between.return_value = [UCI_TCP_A, UCI_TCP_B]
        result = timeseries_service.list_ids(
            start=datetime(2026, 1, 1),
            stop=datetime(2026, 1, 2),
            group_wildcards=True,
            aggregation_service=None,
        )
        assert isinstance(result, list)
        assert len(result) == 2
        assert all(isinstance(r, str) for r in result)

    def test_group_wildcards_multiple_groups(self, timeseries_service, aggregation_service, mock_influx_repo) -> None:
        """Multiple disjoint base keys produce multiple dict entries."""
        mock_influx_repo.list_ids_between.return_value = [
            UCI_TCP_A,
            UCI_TCP_B,
            UCI_OTHER_HOST,
        ]
        result = timeseries_service.list_ids(
            start=datetime(2026, 1, 1),
            stop=datetime(2026, 1, 2),
            group_wildcards=True,
            aggregation_service=aggregation_service,
        )
        assert len(result) == 2
        wildcards = [e for e in result if e["is_wildcard"]]
        non_wildcards = [e for e in result if not e["is_wildcard"]]
        assert len(wildcards) == 1
        assert len(non_wildcards) == 1
        assert wildcards[0]["member_count"] == 2
        assert non_wildcards[0]["member_count"] == 1

    def test_group_wildcards_with_backend_collapsed_count(
        self, timeseries_service, aggregation_service, mock_influx_repo
    ) -> None:
        """Backend-wildcard UCIs receive collapsed_port_count from InfluxDB."""
        backend_wildcard = "aa:bb:cc:dd:ee:01/aa:bb:cc:dd:ee:02/0//192.168.1.1//*/*/Ethernet:IPv4:TCP"
        mock_influx_repo.list_ids_between.return_value = [backend_wildcard]
        mock_influx_repo.query_collapsed_port_counts.return_value = {backend_wildcard: 7}
        result = timeseries_service.list_ids(
            start=datetime(2026, 1, 1),
            stop=datetime(2026, 1, 2),
            group_wildcards=True,
            aggregation_service=aggregation_service,
        )
        assert len(result) == 1
        assert result[0]["is_wildcard"] is True
        assert result[0]["member_count"] == 1
        assert result[0]["collapsed_port_count"] == 7

    def test_group_wildcards_without_backend_count_defaults_none(
        self, timeseries_service, aggregation_service, mock_influx_repo
    ) -> None:
        """Client-side wildcard UCIs without backend field get None."""
        mock_influx_repo.list_ids_between.return_value = [UCI_TCP_A, UCI_TCP_B]
        mock_influx_repo.query_collapsed_port_counts.return_value = {}
        result = timeseries_service.list_ids(
            start=datetime(2026, 1, 1),
            stop=datetime(2026, 1, 2),
            group_wildcards=True,
            aggregation_service=aggregation_service,
        )
        assert len(result) == 1
        assert result[0]["is_wildcard"] is True
        assert result[0]["collapsed_port_count"] is None
