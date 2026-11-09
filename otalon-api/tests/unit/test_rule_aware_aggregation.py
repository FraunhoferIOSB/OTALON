"""Unit tests for rule-aware aggregation (with and without rules).

Tests cover the build_wildcard_groups and resolve_and_aggregate methods
of NetcapAggregationService when port-collapse rules are available
versus stateless fallback.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from unittest.mock import MagicMock

import polars as pl
import pytest

from otalon_api.domain.topology.uci import is_wildcard_uci, parse_uci
from otalon_api.repositories.port_collapse_repo import PortCollapseRepository
from otalon_api.services.aggregation_service import NetcapAggregationService

UCI_A = "aa:bb:cc:dd:ee:01/aa:bb:cc:dd:ee:02/0//192.168.1.1//1234/80/Ethernet:IPv4:TCP"
UCI_B = "aa:bb:cc:dd:ee:01/aa:bb:cc:dd:ee:02/0//192.168.1.1//5678/80/Ethernet:IPv4:TCP"
UCI_C = "aa:bb:cc:dd:ee:03/aa:bb:cc:dd:ee:04/0//10.0.0.1//1234/80/Ethernet:IPv4:TCP"

NORMALIZED_UCI = "aa:bb:cc:dd:ee:01/aa:bb:cc:dd:ee:02/0//192.168.1.1//*/80/Ethernet:IPv4:TCP"

_RULES_DF = pl.DataFrame(
    [
        {
            "src_mac": "aa:bb:cc:dd:ee:01",
            "dst_mac": "aa:bb:cc:dd:ee:02",
            "vlan": "0",
            "ip_proto": "",
            "src_ip": "192.168.1.1",
            "dst_ip": "",
            "protocols": "Ethernet:IPv4:TCP",
            "normalized_uci": NORMALIZED_UCI,
            "wildcard_src_port": True,
            "wildcard_dst_port": False,
            "bucket_seconds": 10,
        },
    ]
)


@pytest.fixture()
def mock_port_collapse_repo() -> MagicMock:
    """Create a mock PortCollapseRepository.

    Returns:
        A MagicMock mimicking PortCollapseRepository.
    """
    repo = MagicMock(spec=PortCollapseRepository)
    repo.get_rules.return_value = _RULES_DF
    return repo


@pytest.fixture()
def service_with_rules(
    mock_influx_repo: MagicMock,
    mock_settings: Any,
    mock_port_collapse_repo: MagicMock,
) -> NetcapAggregationService:
    """Create a NetcapAggregationService with rule-aware repo.

    Args:
        mock_influx_repo: Mocked InfluxDB repository.
        mock_settings: Test settings.
        mock_port_collapse_repo: Mocked port-collapse repo.

    Returns:
        A NetcapAggregationService configured with rules.
    """
    return NetcapAggregationService(
        mock_influx_repo,
        mock_settings,
        port_collapse_repo=mock_port_collapse_repo,
    )


@pytest.fixture()
def service_without_rules(
    mock_influx_repo: MagicMock,
    mock_settings: Any,
) -> NetcapAggregationService:
    """Create a NetcapAggregationService without rules (fallback mode).

    Args:
        mock_influx_repo: Mocked InfluxDB repository.
        mock_settings: Test settings.

    Returns:
        A NetcapAggregationService with no port-collapse repo.
    """
    return NetcapAggregationService(
        mock_influx_repo,
        mock_settings,
        port_collapse_repo=None,
    )


@pytest.mark.unit
class TestBuildWildcardGroupsWithRules:
    """Tests for build_wildcard_groups when rules are available."""

    def test_groups_use_normalized_uci_from_rules(self, service_with_rules: NetcapAggregationService) -> None:
        """Wildcard group key comes from rule's normalized_uci."""
        groups = service_with_rules.build_wildcard_groups([UCI_A, UCI_B])

        assert NORMALIZED_UCI in groups
        assert len(groups[NORMALIZED_UCI][0]) == 2
        assert groups[NORMALIZED_UCI][1] is True

    def test_unmatched_uci_becomes_own_group(self, service_with_rules: NetcapAggregationService) -> None:
        """UCIs not matching any rule form their own group."""
        groups = service_with_rules.build_wildcard_groups([UCI_A, UCI_C])

        assert len(groups) == 2
        unmatched = [value for value in groups.values() if UCI_C in value[0]]
        assert len(unmatched) == 1
        assert unmatched[0][1] is False

    def test_unmatched_same_base_ucis_share_stateless_group(self, service_with_rules: NetcapAggregationService) -> None:
        """Untrained same-base UCIs still collapse by literal ports."""
        unmatched_a = UCI_C.replace("1234/80", "2000/80")
        unmatched_b = UCI_C.replace("1234/80", "3000/80")

        groups = service_with_rules.build_wildcard_groups([unmatched_a, unmatched_b])

        assert len(groups) == 1
        wildcard, (members, rule_trained) = next(iter(groups.items()))
        assert is_wildcard_uci(wildcard)
        assert members == sorted([unmatched_a, unmatched_b])
        assert rule_trained is False

    def test_members_are_sorted(self, service_with_rules: NetcapAggregationService) -> None:
        """Members within a rule-based group are sorted."""
        groups = service_with_rules.build_wildcard_groups([UCI_B, UCI_A])

        members = groups[NORMALIZED_UCI][0]
        assert members == sorted(members)


DCE_RULE_FIELDS = {
    "src_mac": "aa:bb:cc:dd:ee:01",
    "dst_mac": "aa:bb:cc:dd:ee:02",
    "vlan": "0",
    "ip_proto": "",
    "src_ip": "192.168.1.1",
    "dst_ip": "",
    "protocols": "Ethernet:IPv4:TCP:DCE_RPC",
    "bucket_seconds": 10,
}


def _dce_uci(src_port: str, dst_port: str) -> str:
    """Build a concrete DCE/RPC UCI sharing the DCE rule base key.

    Args:
        src_port: Source port segment value.
        dst_port: Destination port segment value.

    Returns:
        A 9-field UCI string.
    """
    return "aa:bb:cc:dd:ee:01/aa:bb:cc:dd:ee:02/0//192.168.1.1//" f"{src_port}/{dst_port}/Ethernet:IPv4:TCP:DCE_RPC"


def _dce_rule_df(
    normalized_uci: str,
    wildcard_src_port: bool,
    wildcard_dst_port: bool,
) -> pl.DataFrame:
    """Build a single-rule DataFrame for the DCE base key.

    Args:
        normalized_uci: The rule's normalized UCI string.
        wildcard_src_port: Whether the rule wildcards the source port.
        wildcard_dst_port: Whether the rule wildcards the destination port.

    Returns:
        A one-row Polars DataFrame consumable by _df_to_rules.
    """
    return pl.DataFrame(
        [
            {
                **DCE_RULE_FIELDS,
                "normalized_uci": normalized_uci,
                "wildcard_src_port": wildcard_src_port,
                "wildcard_dst_port": wildcard_dst_port,
            }
        ]
    )


@pytest.mark.unit
class TestBuildGroupsFromRulesPortDivergence:
    """Tests for the port-divergence guard in _build_groups_from_rules.

    A concrete-port rule must not relabel a runtime UCI whose port differs
    from the rule's normalized_uci on a non-wildcarded port dimension; such
    UCIs fall through to stateless grouping. Wildcarded rules and exact port
    matches keep the existing relabel behavior.
    """

    def test_concrete_rule_with_diverged_port_not_relabeled(
        self,
        mock_influx_repo: MagicMock,
        mock_settings: Any,
        mock_port_collapse_repo: MagicMock,
    ) -> None:
        """Divergent-port UCIs are not relabeled to a stale concrete rule port.

        A non-wildcarded rule (ports 50000/50462) does not relabel runtime
        UCIs whose destination port differs from 50462; they form a stateless
        wildcard group instead of inheriting the stale rule port.
        """
        stale_normalized = _dce_uci("50000", "50462")
        mock_port_collapse_repo.get_rules.return_value = _dce_rule_df(stale_normalized, False, False)
        service = NetcapAggregationService(
            mock_influx_repo,
            mock_settings,
            port_collapse_repo=mock_port_collapse_repo,
        )

        rotated_a = _dce_uci("50000", "56247")
        rotated_b = _dce_uci("50000", "50460")
        groups = service.build_wildcard_groups([rotated_a, rotated_b])

        assert stale_normalized not in groups
        assert len(groups) == 1
        wildcard, (members, rule_trained) = next(iter(groups.items()))
        assert is_wildcard_uci(wildcard)
        assert "50462" not in wildcard
        assert members == sorted([rotated_a, rotated_b])
        assert rule_trained is False

    def test_wildcard_rule_relabeled_regardless_of_dst_port(
        self,
        mock_influx_repo: MagicMock,
        mock_settings: Any,
        mock_port_collapse_repo: MagicMock,
    ) -> None:
        """A dst-wildcarded rule relabels any runtime dst_port to its normalized_uci.

        Existing behavior is preserved: the wildcard flag covers the differing
        destination port dimension, so runtime UCIs are relabeled regardless of
        their concrete destination port value.
        """
        wildcard_normalized = _dce_uci("50000", "*")
        mock_port_collapse_repo.get_rules.return_value = _dce_rule_df(wildcard_normalized, False, True)
        service = NetcapAggregationService(
            mock_influx_repo,
            mock_settings,
            port_collapse_repo=mock_port_collapse_repo,
        )

        rotated_a = _dce_uci("50000", "56247")
        rotated_b = _dce_uci("50000", "50460")
        groups = service.build_wildcard_groups([rotated_a, rotated_b])

        assert wildcard_normalized in groups
        members, rule_trained = groups[wildcard_normalized]
        assert members == sorted([rotated_a, rotated_b])
        assert rule_trained is True

    def test_exact_port_match_relabeled(
        self,
        mock_influx_repo: MagicMock,
        mock_settings: Any,
        mock_port_collapse_repo: MagicMock,
    ) -> None:
        """A runtime UCI whose ports exactly match a non-wildcarded rule is relabeled.

        The port-divergence guard only diverts UCIs that differ on a
        non-wildcarded dimension; an exact match relabels as before.
        """
        exact_normalized = _dce_uci("50000", "50462")
        mock_port_collapse_repo.get_rules.return_value = _dce_rule_df(exact_normalized, False, False)
        service = NetcapAggregationService(
            mock_influx_repo,
            mock_settings,
            port_collapse_repo=mock_port_collapse_repo,
        )

        exact_runtime = _dce_uci("50000", "50462")
        groups = service.build_wildcard_groups([exact_runtime])

        assert exact_normalized in groups
        members, rule_trained = groups[exact_normalized]
        assert members == [exact_runtime]
        assert rule_trained is True


@pytest.mark.unit
class TestBuildWildcardGroupsWithoutRules:
    """Tests for build_wildcard_groups in stateless fallback mode."""

    def test_different_src_ports_become_wildcard(self, service_without_rules: NetcapAggregationService) -> None:
        """UCIs differing in src_port produce wildcard group."""
        groups = service_without_rules.build_wildcard_groups([UCI_A, UCI_B])

        assert len(groups) == 1
        wildcard = list(groups.keys())[0]
        assert is_wildcard_uci(wildcard)
        parts = parse_uci(wildcard)
        assert parts.src_port == "*"

    def test_empty_input_returns_empty(self, service_without_rules: NetcapAggregationService) -> None:
        """Empty UCI list returns empty dict."""
        groups = service_without_rules.build_wildcard_groups([])
        assert groups == {}


@pytest.mark.unit
class TestResolveAndAggregate:
    """Tests for resolve_and_aggregate with and without rules."""

    def test_with_concrete_rule_members_skips_list_ids(
        self,
        mock_influx_repo: MagicMock,
        mock_settings: Any,
        mock_port_collapse_repo: MagicMock,
    ) -> None:
        """When rules produce concrete (non-wildcard) member UCIs, the
        fast-path is used and ``list_ids_between`` is not called.

        Note: the original test expected the rule-aware path to always
        skip ``list_ids_between``. That contract does not hold because
        ``PortCollapseRule`` only stores the *normalized* (wildcard) UCI
        — there is no way to enumerate concrete InfluxDB member UCIs
        from rules alone when the rule itself wildcards a port. In that
        case the service must fall back to ``list_ids_between`` to find
        concrete IDs to feed ``query_timeseries_multi_ids_chunked``
        (which queries Influx by exact tag values, not patterns).

        The fast-path is therefore only available when the matching
        rule's ``normalized_uci`` is itself fully concrete (no ``*``),
        which is exercised here with a non-wildcard rule.
        """
        concrete_uci = "aa:bb:cc:dd:ee:01/aa:bb:cc:dd:ee:02/0//" "192.168.1.1//1234/80/Ethernet:IPv4:TCP"
        concrete_rule_df = pl.DataFrame(
            [
                {
                    "src_mac": "aa:bb:cc:dd:ee:01",
                    "dst_mac": "aa:bb:cc:dd:ee:02",
                    "vlan": "0",
                    "ip_proto": "",
                    "src_ip": "192.168.1.1",
                    "dst_ip": "",
                    "protocols": "Ethernet:IPv4:TCP",
                    "normalized_uci": concrete_uci,
                    "wildcard_src_port": False,
                    "wildcard_dst_port": False,
                    "bucket_seconds": 10,
                }
            ]
        )
        mock_port_collapse_repo.get_rules.return_value = concrete_rule_df

        service = NetcapAggregationService(
            mock_influx_repo,
            mock_settings,
            port_collapse_repo=mock_port_collapse_repo,
        )
        mock_influx_repo.query_timeseries_multi_ids_chunked.return_value = MagicMock(empty=True)

        service.resolve_and_aggregate(
            wildcard_uci=concrete_uci,
            start=datetime(2026, 1, 1),
            stop=datetime(2026, 1, 2),
            features=["packet_count"],
        )

        mock_influx_repo.list_ids_between.assert_not_called()

    def test_with_wildcard_rule_falls_back_to_list_ids(
        self,
        service_with_rules: NetcapAggregationService,
        mock_influx_repo: MagicMock,
    ) -> None:
        """When the matching rule is itself a wildcard (no concrete
        members derivable from rules alone), the service legitimately
        falls back to ``list_ids_between`` to discover concrete Influx
        UCIs matching the pattern.

        This documents the rule data-model constraint: a rule stores
        only its normalized (possibly wildcard) UCI, not the list of
        concrete UCIs it represents in Influx.
        """
        mock_influx_repo.list_ids_between.return_value = [UCI_A, UCI_B]
        mock_influx_repo.query_timeseries_multi_ids_chunked.return_value = MagicMock(empty=True)

        service_with_rules.resolve_and_aggregate(
            wildcard_uci=NORMALIZED_UCI,
            start=datetime(2026, 1, 1),
            stop=datetime(2026, 1, 2),
            features=["packet_count"],
        )

        mock_influx_repo.list_ids_between.assert_called_once()

    def test_without_rules_queries_all_ids(
        self,
        service_without_rules: NetcapAggregationService,
        mock_influx_repo: MagicMock,
    ) -> None:
        """Stateless fallback queries list_ids_between."""
        mock_influx_repo.list_ids_between.return_value = [UCI_A, UCI_B]
        mock_influx_repo.query_timeseries_multi_ids_chunked.return_value = MagicMock(empty=True)

        service_without_rules.resolve_and_aggregate(
            wildcard_uci=NORMALIZED_UCI,
            start=datetime(2026, 1, 1),
            stop=datetime(2026, 1, 2),
            features=["packet_count"],
        )

        mock_influx_repo.list_ids_between.assert_called_once()
