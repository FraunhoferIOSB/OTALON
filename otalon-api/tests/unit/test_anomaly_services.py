"""Unit tests for anomaly-related service classes.

Tests AnomalyService, AnomalyDetailsService, DashboardKpiService,
and BoundsService with mocked repositories.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock

import pandas as pd
import pytest

from otalon_api.domain.time import time_policy
from otalon_api.services.anomaly_details_service import AnomalyDetailsService
from otalon_api.services.anomaly_service import AnomalyService, _expand_series_ids_with_wildcards
from otalon_api.services.bounds_service import BoundsService
from otalon_api.services.dashboard_kpi_service import DashboardKpiService
from otalon_api.settings import Settings


class TestAnomalyServiceEmptyResults:
    """AnomalyService tests with empty repository results."""

    @pytest.mark.unit
    async def test_get_anomaly_groups_empty(
        self,
        mock_postgres_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """get_anomaly_groups with empty result returns row_count=0.

        Args:
            mock_postgres_repo: Mocked PostgresRepository.
            mock_settings: Test settings.
        """
        mock_postgres_repo.query_anomaly_groups.return_value = []

        service = AnomalyService(mock_postgres_repo, mock_settings)
        result = await service.get_anomaly_groups()

        assert result["row_count"] == 0
        assert result["data"] == []

    @pytest.mark.unit
    async def test_get_anomaly_groups_resolves_proto_hashes_on_conn_alarm(
        self,
        mock_postgres_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """Conn-primary alarms get their proto-hash series_ids resolved.

        Regression for the proto selector-table red-flag bug: a conn
        flood aggregates into a conn-primary alarm whose series_ids mix
        MACs, conn UCIs, and numeric proto hashes.  The resolver must
        translate the numeric hashes to readable protocols (so the proto
        table can match plaintext like ``Ethernet:ARP``) WITHOUT pulling
        MAC/UCI entries into the ``protocols`` field.

        Args:
            mock_postgres_repo: Mocked PostgresRepository.
            mock_settings: Test settings.
        """
        mock_postgres_repo.query_anomaly_groups.return_value = [
            {
                "id": "conn-alarm-1",
                "module": "conn",
                "series_ids": [
                    "7c:cb:e2:ea:0d:65",
                    "7c:cb:e2:ea:0d:65/a8:74:1d:02:99:8d//IPv4/x/y/0/0/Ethernet:IPv4:ICMP",
                    "1513662987",
                ],
                "primary_type": "icmp_flood",
            }
        ]
        resolver = MagicMock()
        resolver.resolve_many.return_value = ["Ethernet:ARP"]

        service = AnomalyService(mock_postgres_repo, mock_settings, proto_resolver=resolver)
        result = await service.get_anomaly_groups()

        resolver.resolve_many.assert_called_once_with(["1513662987"])
        assert result["data"][0]["protocols"] == [None, None, "Ethernet:ARP"]

    @pytest.mark.unit
    @pytest.mark.parametrize(
        ("module", "series_ids", "expected"),
        [
            ("proto_traffic", ["1513662987", "1513662988"], ["Ethernet:ARP", "Ethernet:IP"]),
            ("conn", ["uci", "1513662987"], [None, "Ethernet:ARP"]),
            ("multi", ["uci", "1513662987"], [None, "Ethernet:ARP"]),
        ],
    )
    async def test_protocols_are_index_parallel_for_all_modules(
        self,
        mock_postgres_repo: MagicMock,
        mock_settings: Settings,
        module: str,
        series_ids: list[str],
        expected: list[str | None],
    ) -> None:
        """Protocol labels align with series_ids and null non-protocol entries."""
        mock_postgres_repo.query_anomaly_groups.return_value = [
            {"id": "alarm", "module": module, "series_ids": series_ids}
        ]
        resolver = MagicMock()
        resolver.resolve_many.side_effect = lambda hashes: [
            {"1513662987": "Ethernet:ARP", "1513662988": "Ethernet:IP"}[h] for h in hashes
        ]

        service = AnomalyService(mock_postgres_repo, mock_settings, proto_resolver=resolver)
        result = await service.get_anomaly_groups()

        assert result["data"][0]["protocols"] == expected

    @pytest.mark.unit
    async def test_get_anomaly_intervals_empty(
        self,
        mock_postgres_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """get_anomaly_intervals with no matching groups returns row_count=0.

        Args:
            mock_postgres_repo: Mocked PostgresRepository.
            mock_settings: Test settings.
        """
        mock_postgres_repo.query_anomaly_groups.return_value = []

        service = AnomalyService(mock_postgres_repo, mock_settings)
        result = await service.get_anomaly_intervals(uci="nonexistent/uci/here")

        assert result["row_count"] == 0
        assert result["data"] == []

    @pytest.mark.unit
    async def test_get_anomaly_intervals_uci_not_in_groups(
        self,
        mock_postgres_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """get_anomaly_intervals with groups that do not contain target UCI.

        Args:
            mock_postgres_repo: Mocked PostgresRepository.
            mock_settings: Test settings.
        """
        mock_postgres_repo.query_anomaly_groups.return_value = [
            {
                "id": "group-1",
                "series_ids": ["other/uci/a", "other/uci/b"],
                "start_timestamp": "2026-01-01T00:00:00Z",
                "end_timestamp": "2026-01-01T01:00:00Z",
                "primary_type": "BoundViolation",
            }
        ]

        service = AnomalyService(mock_postgres_repo, mock_settings)
        result = await service.get_anomaly_intervals(uci="target/uci/not/present")

        assert result["row_count"] == 0
        assert result["data"] == []

    @pytest.mark.unit
    async def test_get_anomaly_intervals_uci_found_in_group(
        self,
        mock_postgres_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """get_anomaly_intervals finds intervals when UCI is in a group.

        Args:
            mock_postgres_repo: Mocked PostgresRepository.
            mock_settings: Test settings.
        """
        target_uci = "aa:bb/cc:dd/0//////Ethernet:PROFINET"
        mock_postgres_repo.query_anomaly_groups.return_value = [
            {
                "id": "group-1",
                "series_ids": [target_uci, "other/uci"],
                "start_timestamp": "2026-01-01T00:00:00Z",
                "end_timestamp": "2026-01-01T01:00:00Z",
                "primary_type": "T0846/pn_discovery",
            }
        ]

        service = AnomalyService(mock_postgres_repo, mock_settings)
        result = await service.get_anomaly_intervals(uci=target_uci)

        assert result["row_count"] == 1
        assert result["data"][0]["alarm_group_id"] == "group-1"

    @pytest.mark.unit
    async def test_get_anomaly_intervals_matches_across_module(
        self,
        mock_postgres_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """Intervals match a MAC even when the alarm aggregated conn-primary.

        Regression for the empty-markArea bug: a conn-level flood
        (e.g. icmp_flood) aggregates into a single conn-primary alarm
        whose ``series_ids`` still contain the affected MAC plus the
        conn UCIs.  The mac/proto intervals endpoints pass
        ``module=None`` so matching is purely series-id based; passing a
        module filter would drop this alarm and yield an empty band.

        Args:
            mock_postgres_repo: Mocked PostgresRepository.
            mock_settings: Test settings.
        """
        affected_mac = "7c:cb:e2:ea:0d:65"
        mock_postgres_repo.query_anomaly_groups.return_value = [
            {
                "id": "conn-alarm-1",
                "series_ids": [
                    affected_mac,
                    "7c:cb:e2:ea:0d:65/a8:74:1d:02:99:8d//IPv4/x/y/0/0/Ethernet:IPv4:ICMP",
                ],
                "start_timestamp": "2026-01-01T00:00:00Z",
                "end_timestamp": "2026-01-01T00:01:00Z",
                "primary_type": "icmp_flood",
            }
        ]

        service = AnomalyService(mock_postgres_repo, mock_settings)
        result = await service.get_anomaly_intervals(uci=affected_mac, module=None)

        mock_postgres_repo.query_anomaly_groups.assert_called_once()
        assert mock_postgres_repo.query_anomaly_groups.call_args.kwargs["module"] is None
        assert result["row_count"] == 1
        assert result["data"][0]["alarm_group_id"] == "conn-alarm-1"
        assert result["data"][0]["anomaly_type"] == "icmp_flood"

    @pytest.mark.unit
    async def test_get_anomaly_series_empty(
        self,
        mock_postgres_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """get_anomaly_series with no results returns empty data.

        Args:
            mock_postgres_repo: Mocked PostgresRepository.
            mock_settings: Test settings.
        """
        mock_postgres_repo.query_anomalies.return_value = []

        service = AnomalyService(mock_postgres_repo, mock_settings)
        result = await service.get_anomaly_series(module="netcap")

        assert result["row_count"] == 0
        assert result["data"] == []
        mock_postgres_repo.query_anomalies.assert_called_once_with(
            module="netcap",
            series_id=None,
            time_range=None,
        )


class TestExpandSeriesIdsWithWildcards:
    """Tests for the _expand_series_ids_with_wildcards helper."""

    @pytest.mark.unit
    def test_no_change_for_single_uci(self) -> None:
        """A single conn UCI produces no wildcard variant."""
        series = ["aa:bb/cc:dd/0/IPv4/1.2.3.4/5.6.7.8/1234/80/TCP"]
        result = _expand_series_ids_with_wildcards(series)
        assert result == series

    @pytest.mark.unit
    def test_no_change_for_identical_ports(self) -> None:
        """Two UCIs with identical ports produce no wildcard."""
        series = [
            "aa:bb/cc:dd/0/IPv4/1.2.3.4/5.6.7.8/1234/80/TCP",
            "aa:bb/cc:dd/0/IPv4/1.2.3.4/5.6.7.9/1234/80/TCP",
        ]
        result = _expand_series_ids_with_wildcards(series)
        assert len(result) == 2
        assert "*" not in "/".join(result)

    @pytest.mark.unit
    def test_wildcard_src_port(self) -> None:
        """Multiple source ports yield a wildcard in the src_port position."""
        series = [
            "aa:bb/cc:dd/0/IPv4/1.2.3.4/5.6.7.8/1234/80/TCP",
            "aa:bb/cc:dd/0/IPv4/1.2.3.4/5.6.7.8/5678/80/TCP",
        ]
        result = _expand_series_ids_with_wildcards(series)
        assert len(result) == 3
        assert "aa:bb/cc:dd/0/IPv4/1.2.3.4/5.6.7.8/*/80/TCP" in result

    @pytest.mark.unit
    def test_wildcard_dst_port(self) -> None:
        """Multiple destination ports yield a wildcard in the dst_port position."""
        series = [
            "aa:bb/cc:dd/0/IPv4/1.2.3.4/5.6.7.8/1234/80/TCP",
            "aa:bb/cc:dd/0/IPv4/1.2.3.4/5.6.7.8/1234/443/TCP",
        ]
        result = _expand_series_ids_with_wildcards(series)
        assert len(result) == 3
        assert "aa:bb/cc:dd/0/IPv4/1.2.3.4/5.6.7.8/1234/*/TCP" in result

    @pytest.mark.unit
    def test_wildcard_both_ports(self) -> None:
        """Different source AND destination ports yield wildcards in both positions."""
        series = [
            "aa:bb/cc:dd/0/IPv4/1.2.3.4/5.6.7.8/1234/80/TCP",
            "aa:bb/cc:dd/0/IPv4/1.2.3.4/5.6.7.8/5678/443/TCP",
        ]
        result = _expand_series_ids_with_wildcards(series)
        assert len(result) == 3
        assert "aa:bb/cc:dd/0/IPv4/1.2.3.4/5.6.7.8/*/*/TCP" in result

    @pytest.mark.unit
    def test_mixed_conn_and_non_conn_ids(self) -> None:
        """MAC addresses and proto hashes are preserved while conn UCIs are expanded."""
        series = [
            "aa:bb:cc:dd:ee:ff",
            "1513662987",
            "aa:bb/cc:dd/0/IPv4/1.2.3.4/5.6.7.8/1234/80/TCP",
            "aa:bb/cc:dd/0/IPv4/1.2.3.4/5.6.7.8/5678/80/TCP",
        ]
        result = _expand_series_ids_with_wildcards(series)
        assert "aa:bb:cc:dd:ee:ff" in result
        assert "1513662987" in result
        assert "aa:bb/cc:dd/0/IPv4/1.2.3.4/5.6.7.8/*/80/TCP" in result
        assert len([r for r in result if "*" in r]) == 1

    @pytest.mark.unit
    def test_multiple_independent_groups(self) -> None:
        """UCIs from different base keys each get their own wildcard."""
        series = [
            "aa:bb/cc:dd/0/IPv4/1.2.3.4/5.6.7.8/1234/80/TCP",
            "aa:bb/cc:dd/0/IPv4/1.2.3.4/5.6.7.8/5678/80/TCP",
            "aa:bb/cc:dd/0/IPv4/1.2.3.4/9.9.9.9/1111/22/TCP",
            "aa:bb/cc:dd/0/IPv4/1.2.3.4/9.9.9.9/2222/22/TCP",
        ]
        result = _expand_series_ids_with_wildcards(series)
        assert "aa:bb/cc:dd/0/IPv4/1.2.3.4/5.6.7.8/*/80/TCP" in result
        assert "aa:bb/cc:dd/0/IPv4/1.2.3.4/9.9.9.9/*/22/TCP" in result


class TestAnomalyGroupsWildcardExpansion:
    """Integration tests for wildcard expansion in get_anomaly_groups."""

    @pytest.mark.unit
    async def test_get_anomaly_groups_expands_wildcards(
        self,
        mock_postgres_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """Alarm groups with multiple conn UCIs get wildcard variants added."""
        mock_postgres_repo.query_anomaly_groups.return_value = [
            {
                "id": "group-1",
                "module": "conn",
                "series_ids": [
                    "aa:bb/cc:dd/0/IPv4/1.2.3.4/5.6.7.8/1234/80/TCP",
                    "aa:bb/cc:dd/0/IPv4/1.2.3.4/5.6.7.8/5678/80/TCP",
                ],
                "primary_type": "port_scan",
            }
        ]

        service = AnomalyService(mock_postgres_repo, mock_settings)
        result = await service.get_anomaly_groups()

        series_ids = result["data"][0]["series_ids"]
        assert "aa:bb/cc:dd/0/IPv4/1.2.3.4/5.6.7.8/*/80/TCP" in series_ids
        assert len(series_ids) == 3

    @pytest.mark.unit
    async def test_get_anomaly_intervals_matches_wildcard_uci(
        self,
        mock_postgres_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """Querying intervals with a wildcard UCI matches after expansion."""
        mock_postgres_repo.query_anomaly_groups.return_value = [
            {
                "id": "group-1",
                "series_ids": [
                    "aa:bb/cc:dd/0/IPv4/1.2.3.4/5.6.7.8/1234/80/TCP",
                    "aa:bb/cc:dd/0/IPv4/1.2.3.4/5.6.7.8/5678/80/TCP",
                ],
                "start_timestamp": "2026-01-01T00:00:00Z",
                "end_timestamp": "2026-01-01T01:00:00Z",
                "primary_type": "port_scan",
            }
        ]

        service = AnomalyService(mock_postgres_repo, mock_settings)
        wildcard = "aa:bb/cc:dd/0/IPv4/1.2.3.4/5.6.7.8/*/80/TCP"
        result = await service.get_anomaly_intervals(uci=wildcard)

        assert result["row_count"] == 1
        assert result["data"][0]["alarm_group_id"] == "group-1"


class TestAnomalyDetailsServiceEmptyResults:
    """AnomalyDetailsService tests with edge cases."""

    @pytest.mark.unit
    async def test_get_group_entities_nonexistent_group(
        self,
        mock_postgres_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """get_group_entities with non-existent group raises ValueError.

        Args:
            mock_postgres_repo: Mocked PostgresRepository.
            mock_settings: Test settings.
        """
        mock_postgres_repo.get_anomaly_group_by_id.return_value = None

        service = AnomalyDetailsService(mock_postgres_repo, mock_settings)

        with pytest.raises(ValueError, match="Alarm group not found"):
            await service.get_group_entities(group_id="nonexistent-uuid")

    @pytest.mark.unit
    async def test_get_group_entities_empty_series_ids(
        self,
        mock_postgres_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """get_group_entities with a group that has no series_ids.

        Args:
            mock_postgres_repo: Mocked PostgresRepository.
            mock_settings: Test settings.
        """
        mock_postgres_repo.get_anomaly_group_by_id.return_value = {
            "id": "empty-group",
            "series_ids": [],
        }

        service = AnomalyDetailsService(mock_postgres_repo, mock_settings)
        result = await service.get_group_entities(group_id="empty-group")

        assert result["row_count"] == 0
        assert result["data"] == []

    @pytest.mark.unit
    async def test_get_group_entities_non_list_series_ids(
        self,
        mock_postgres_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """get_group_entities with series_ids that is not a list.

        Args:
            mock_postgres_repo: Mocked PostgresRepository.
            mock_settings: Test settings.
        """
        mock_postgres_repo.get_anomaly_group_by_id.return_value = {
            "id": "bad-group",
            "series_ids": "not-a-list",
        }

        service = AnomalyDetailsService(mock_postgres_repo, mock_settings)
        result = await service.get_group_entities(group_id="bad-group")

        assert result["row_count"] == 0
        assert result["data"] == []


class TestDashboardKpiServiceSignalColor:
    """DashboardKpiService tests for signal color computation."""

    @pytest.mark.unit
    async def test_kpis_no_anomalies_success(
        self,
        mock_postgres_repo: MagicMock,
        mock_influx_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """Zero anomalies should produce 'success' signal color.

        Args:
            mock_postgres_repo: Mocked PostgresRepository.
            mock_influx_repo: Mocked InfluxRepository.
            mock_settings: Test settings.
        """
        mock_postgres_repo.query_dashboard_kpis.return_value = {
            "active_alarm_groups": 0,
            "total_alarm_groups": 0,
            "total_anomalies": 0,
            "affected_series_count": 0,
            "last_alarm_timestamp": None,
        }
        mock_postgres_repo.query_anomaly_groups.return_value = []
        mock_postgres_repo.query_device_count.return_value = 5
        mock_postgres_repo.query_connection_count.return_value = 10
        mock_influx_repo.query_top_connections.return_value = []

        service = DashboardKpiService(mock_postgres_repo, mock_influx_repo, mock_settings)
        result = await service.get_kpis()

        assert result["data"][0]["signal_color"] == "success"
        assert result["data"][0]["anomaly_count"] == 0

    @pytest.mark.unit
    async def test_kpis_benign_anomalies_warning(
        self,
        mock_postgres_repo: MagicMock,
        mock_influx_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """Only benign unconfirmed anomalies should produce 'warning' signal color.

        Args:
            mock_postgres_repo: Mocked PostgresRepository.
            mock_influx_repo: Mocked InfluxRepository.
            mock_settings: Test settings.
        """
        mock_postgres_repo.query_dashboard_kpis.return_value = {
            "active_alarm_groups": 1,
            "total_alarm_groups": 1,
            "total_anomalies": 5,
            "affected_series_count": 3,
            "last_alarm_timestamp": "2026-01-01T00:00:00",
        }
        mock_postgres_repo.query_anomaly_groups.return_value = [
            {"id": "g1", "confirmed": False, "primary_type": "BoundViolation"},
        ]
        mock_postgres_repo.query_device_count.return_value = 0
        mock_postgres_repo.query_connection_count.return_value = 0
        mock_influx_repo.query_top_connections.return_value = []

        service = DashboardKpiService(mock_postgres_repo, mock_influx_repo, mock_settings)
        result = await service.get_kpis()

        assert result["data"][0]["signal_color"] == "warning"

    @pytest.mark.unit
    async def test_kpis_red_anomalies_danger(
        self,
        mock_postgres_repo: MagicMock,
        mock_influx_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """Non-benign unconfirmed anomalies should produce 'danger' signal color.

        Args:
            mock_postgres_repo: Mocked PostgresRepository.
            mock_influx_repo: Mocked InfluxRepository.
            mock_settings: Test settings.
        """
        mock_postgres_repo.query_dashboard_kpis.return_value = {
            "active_alarm_groups": 2,
            "total_alarm_groups": 2,
            "total_anomalies": 10,
            "affected_series_count": 5,
            "last_alarm_timestamp": "2026-01-01T00:00:00",
        }
        mock_postgres_repo.query_anomaly_groups.return_value = [
            {"id": "g1", "confirmed": False, "primary_type": "T0846/pn_discovery"},
            {"id": "g2", "confirmed": False, "primary_type": "BoundViolation"},
        ]
        mock_postgres_repo.query_device_count.return_value = 0
        mock_postgres_repo.query_connection_count.return_value = 0
        mock_influx_repo.query_top_connections.return_value = []

        service = DashboardKpiService(mock_postgres_repo, mock_influx_repo, mock_settings)
        result = await service.get_kpis()

        assert result["data"][0]["signal_color"] == "danger"

    @pytest.mark.unit
    async def test_kpis_all_confirmed_success(
        self,
        mock_postgres_repo: MagicMock,
        mock_influx_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """All confirmed anomalies should produce 'success' signal color.

        Args:
            mock_postgres_repo: Mocked PostgresRepository.
            mock_influx_repo: Mocked InfluxRepository.
            mock_settings: Test settings.
        """
        mock_postgres_repo.query_dashboard_kpis.return_value = {
            "active_alarm_groups": 0,
            "total_alarm_groups": 3,
            "total_anomalies": 15,
            "affected_series_count": 10,
            "last_alarm_timestamp": "2026-01-01T00:00:00",
        }
        mock_postgres_repo.query_anomaly_groups.return_value = [
            {"id": "g1", "confirmed": True, "primary_type": "T0846/pn_discovery"},
            {"id": "g2", "confirmed": True, "primary_type": "BoundViolation"},
            {"id": "g3", "confirmed": True, "primary_type": "NoBounds"},
        ]
        mock_postgres_repo.query_device_count.return_value = 0
        mock_postgres_repo.query_connection_count.return_value = 0
        mock_influx_repo.query_top_connections.return_value = []

        service = DashboardKpiService(mock_postgres_repo, mock_influx_repo, mock_settings)
        result = await service.get_kpis()

        assert result["data"][0]["signal_color"] == "success"


class TestBoundsServiceEmptyResults:
    """BoundsService tests with empty timeseries data."""

    @pytest.mark.unit
    async def test_get_timeseries_with_bounds_empty_df(
        self,
        mock_influx_repo: MagicMock,
        mock_postgres_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """get_timeseries_with_bounds with empty InfluxDB result.

        Args:
            mock_influx_repo: Mocked InfluxRepository.
            mock_postgres_repo: Mocked PostgresRepository.
            mock_settings: Test settings.
        """
        mock_influx_repo.query_timeseries.return_value = pd.DataFrame()
        mock_postgres_repo.query_bounds.return_value = []

        service = BoundsService(mock_influx_repo, mock_postgres_repo, mock_settings)
        result = await service.get_timeseries_with_bounds(
            uci="test/uci",
            metric="mean_packet_size",
            start=pd.Timestamp("2026-01-01T00:00:00"),
            stop=pd.Timestamp("2026-01-01T01:00:00"),
        )

        assert result["row_count"] == 0
        assert result["data"] == []

    @pytest.mark.unit
    async def test_wildcard_conn_uses_profiled_sibling_bounds(
        self, mock_influx_repo: MagicMock, mock_postgres_repo: MagicMock, mock_settings: Settings
    ) -> None:
        """Wildcard aggregation reads bounds from a trained sibling."""
        wildcard = "aa:bb:cc:dd:ee:01/aa:bb:cc:dd:ee:02/0/17/192.0.2.1/192.0.2.2/*/*/UDP"
        sibling = wildcard.replace("*/*", "50000/56247")
        mock_influx_repo.query_timeseries.return_value = pd.DataFrame(
            {"time": pd.to_datetime(["2026-01-01T00:00:00"]), "mean_packet_size": [64.0]}
        )
        mock_postgres_repo.query_all_profiled_series_ids.return_value = {sibling}
        mock_postgres_repo.query_bounds.return_value = [{"lb_mean_packet_size": 50.0, "ub_mean_packet_size": 80.0}]
        service = BoundsService(mock_influx_repo, mock_postgres_repo, mock_settings)
        result = await service.get_timeseries_with_bounds(
            uci=wildcard,
            metric="mean_packet_size",
            start=pd.Timestamp("2026-01-01"),
            stop=pd.Timestamp("2026-01-01T01:00"),
            module="conn",
        )
        assert result["data"][0]["lower_bound"] == 50.0
        assert mock_postgres_repo.query_bounds.call_args.kwargs["series_id"] == sibling

    @pytest.mark.unit
    async def test_wildcard_conn_with_netcap_module_uses_profiled_sibling_bounds(
        self, mock_influx_repo: MagicMock, mock_postgres_repo: MagicMock, mock_settings: Settings
    ) -> None:
        """The generic chart route's netcap alias still resolves conn siblings."""
        wildcard = "aa:bb:cc:dd:ee:01/aa:bb:cc:dd:ee:02/0/17/192.0.2.1/192.0.2.2/*/*/UDP"
        sibling = wildcard.replace("*/*", "50000/56247")
        mock_influx_repo.query_timeseries.return_value = pd.DataFrame(
            {"time": pd.to_datetime(["2026-01-01T00:00:00"]), "packet_count": [4.0]}
        )
        mock_postgres_repo.query_all_profiled_series_ids.return_value = {sibling}
        mock_postgres_repo.query_bounds.return_value = [
            {"lower_bounds": {"packet_count": 0.8}, "upper_bounds": {"packet_count": 2.0}}
        ]
        service = BoundsService(mock_influx_repo, mock_postgres_repo, mock_settings)

        result = await service.get_timeseries_with_bounds(
            uci=wildcard,
            metric="packet_count",
            start=pd.Timestamp("2026-01-01"),
            stop=pd.Timestamp("2026-01-01T01:00"),
            module="netcap",
        )

        assert result["data"][0]["lower_bound"] == 0.8
        assert result["data"][0]["upper_bound"] == 2.0
        assert mock_postgres_repo.query_bounds.call_args.kwargs["series_id"] == sibling

    @pytest.mark.unit
    async def test_get_timeseries_with_bounds_with_data(
        self,
        mock_influx_repo: MagicMock,
        mock_postgres_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """get_timeseries_with_bounds with data and bounds merges correctly.

        Args:
            mock_influx_repo: Mocked InfluxRepository.
            mock_postgres_repo: Mocked PostgresRepository.
            mock_settings: Test settings.
        """
        ts_df = pd.DataFrame(
            {
                "time": pd.to_datetime(["2026-01-01T00:00:00", "2026-01-01T00:01:00"]),
                "mean_packet_size": [64.0, 70.0],
            }
        )
        mock_influx_repo.query_timeseries.return_value = ts_df
        mock_postgres_repo.query_bounds.return_value = [{"lb_mean_packet_size": 50.0, "ub_mean_packet_size": 80.0}]

        service = BoundsService(mock_influx_repo, mock_postgres_repo, mock_settings)
        result = await service.get_timeseries_with_bounds(
            uci="test/uci",
            metric="mean_packet_size",
            start=pd.Timestamp("2026-01-01T00:00:00"),
            stop=pd.Timestamp("2026-01-01T01:00:00"),
        )

        assert result["row_count"] == 2
        assert len(result["data"]) == 2
        assert result["data"][0]["lower_bound"] == 50.0
        assert result["data"][0]["upper_bound"] == 80.0
        assert result["data"][0]["violation_low"] is False
        assert result["data"][0]["violation_high"] is False

    @pytest.mark.unit
    async def test_known_bound_violation_reuses_detector_aggregation_contract(
        self,
        mock_influx_repo: MagicMock,
        mock_postgres_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """Known conn violations use persisted bucket width and feature rule."""
        mock_influx_repo.query_timeseries.return_value = pd.DataFrame(
            {"time": pd.to_datetime(["2026-01-01T00:00:00"]), "total_volume": [120.0]}
        )
        mock_postgres_repo.query_anomalies.return_value = [
            {"anomaly_type": "BoundViolation", "violated_features": ["total_volume"], "bucket_seconds": 60}
        ]
        mock_postgres_repo.query_bounds.return_value = [
            {"lower_bounds": {"total_volume": 48}, "upper_bounds": {"total_volume": 72}}
        ]

        service = BoundsService(mock_influx_repo, mock_postgres_repo, mock_settings)
        result = await service.get_timeseries_with_bounds(
            uci="a/b/c",
            metric="total_volume",
            start=pd.Timestamp("2026-01-01T00:00:00"),
            stop=pd.Timestamp("2026-01-01T00:02:00"),
            module="conn",
        )

        query = mock_influx_repo.query_timeseries.call_args.kwargs
        assert query["aggregate"] == "sum"
        assert query["bucket_seconds"] == 1
        assert result["data"][0]["value"] == 120.0
        assert result["data"][0]["violation_high"] is True

    @pytest.mark.unit
    async def test_extensive_live_metric_uses_native_bucket_without_anomaly(
        self,
        mock_influx_repo: MagicMock,
        mock_postgres_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """Total volume stays on the one-second training scale when the window fits the budget.

        The point budget (``sample_max_points=1000``) exceeds the 600s window so
        no downsampling is needed and the extensive metric keeps its native 1s
        bucket — the original detector contract for narrow windows.
        """
        mock_influx_repo.query_timeseries.return_value = pd.DataFrame(
            {"time": pd.to_datetime(["2026-01-01T00:00:00"]), "total_volume": [64.0]}
        )
        mock_postgres_repo.query_bounds.return_value = [
            {"lower_bounds": {"total_volume": 48}, "upper_bounds": {"total_volume": 72}}
        ]

        service = BoundsService(mock_influx_repo, mock_postgres_repo, mock_settings)
        await service.get_timeseries_with_bounds(
            uci="a/b/c",
            metric="total_volume",
            start=pd.Timestamp("2026-01-01T00:00:00"),
            stop=pd.Timestamp("2026-01-01T00:10:00"),
            module="netcap",
            sample_max_points=1000,
        )

        query = mock_influx_repo.query_timeseries.call_args.kwargs
        assert query["aggregate"] == "sum"
        assert query["bucket_seconds"] == 1

    @pytest.mark.unit
    async def test_packet_count_keeps_rate_aggregation_contract(
        self,
        mock_influx_repo: MagicMock,
        mock_postgres_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """Packet count remains mean-based after extensive metric fix."""
        mock_influx_repo.query_timeseries.return_value = pd.DataFrame(
            {"time": pd.to_datetime(["2026-01-01T00:00:00"]), "packet_count": [4.0]}
        )
        mock_postgres_repo.query_bounds.return_value = [
            {"lower_bounds": {"packet_count": 1}, "upper_bounds": {"packet_count": 8}}
        ]

        service = BoundsService(mock_influx_repo, mock_postgres_repo, mock_settings)
        await service.get_timeseries_with_bounds(
            uci="a/b/c",
            metric="packet_count",
            start=pd.Timestamp("2026-01-01T00:00:00"),
            stop=pd.Timestamp("2026-01-01T00:10:00"),
            module="netcap",
            sample_max_points=30,
        )

        query = mock_influx_repo.query_timeseries.call_args.kwargs
        assert query["aggregate"] == "mean"
        assert query["bucket_seconds"] is None

    @pytest.mark.unit
    async def test_persisted_detector_value_marks_live_mean_point(
        self,
        mock_influx_repo: MagicMock,
        mock_postgres_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """Stored detector value wins when live point is inside bounds."""
        timestamp = pd.Timestamp("2026-01-01T00:00:00")
        mock_influx_repo.query_timeseries.return_value = pd.DataFrame({"time": [timestamp], "total_volume": [60.0]})
        mock_postgres_repo.query_anomalies.return_value = [
            {
                "anomaly_type": "BoundViolation",
                "violated_features": ["total_volume"],
                "bucket_seconds": 60,
                "start_ts": timestamp,
                "value": 120.0,
            }
        ]
        mock_postgres_repo.query_bounds.return_value = [
            {"lower_bounds": {"total_volume": 48}, "upper_bounds": {"total_volume": 72}}
        ]

        service = BoundsService(mock_influx_repo, mock_postgres_repo, mock_settings)
        result = await service.get_timeseries_with_bounds(
            uci="a/b/c",
            metric="total_volume",
            start=timestamp,
            stop=timestamp + pd.Timedelta(minutes=2),
            module="conn",
        )

        assert result["data"][0]["value"] == 120.0
        assert result["data"][0]["violation_high"] is True

    @pytest.mark.unit
    async def test_persisted_feature_summary_supports_legacy_anomaly_rows(
        self,
        mock_influx_repo: MagicMock,
        mock_postgres_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """Feature summary fallback preserves markers when value is null."""
        timestamp = pd.Timestamp("2026-01-01T00:00:00")
        mock_influx_repo.query_timeseries.return_value = pd.DataFrame({"time": [timestamp], "total_volume": [60.0]})
        mock_postgres_repo.query_anomalies.return_value = [
            {
                "anomaly_type": "BoundViolation",
                "violated_features": ["total_volume"],
                "bucket_seconds": 60,
                "start_ts": timestamp,
                "value": None,
                "feature_summary": {"total_volume": {"max": 120.0}},
            }
        ]
        mock_postgres_repo.query_bounds.return_value = [
            {"lower_bounds": {"total_volume": 48}, "upper_bounds": {"total_volume": 72}}
        ]

        service = BoundsService(mock_influx_repo, mock_postgres_repo, mock_settings)
        result = await service.get_timeseries_with_bounds(
            uci="a/b/c",
            metric="total_volume",
            start=timestamp,
            stop=timestamp + pd.Timedelta(minutes=2),
            module="conn",
        )

        assert result["data"][0]["value"] == 120.0
        assert result["data"][0]["violation_high"] is True

    @pytest.mark.unit
    async def test_get_bounds_returns_raw_data(
        self,
        mock_influx_repo: MagicMock,
        mock_postgres_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """get_bounds returns raw PostgreSQL bounds data without modification.

        Args:
            mock_influx_repo: Mocked InfluxRepository.
            mock_postgres_repo: Mocked PostgresRepository.
            mock_settings: Test settings.
        """
        bounds_data = [{"module": "netcap", "series_id": "a/b", "lb_metric": 1.0, "ub_metric": 2.0}]
        mock_postgres_repo.query_bounds.return_value = bounds_data

        service = BoundsService(mock_influx_repo, mock_postgres_repo, mock_settings)
        result = await service.get_bounds(module="netcap", series_id="a/b")

        assert result["data"] == bounds_data
        assert result["row_count"] == 1


class TestBoundsServiceExtensiveSampling:
    """Extensive metrics downsample to mean-with-extrema over large windows.

    Regression for API-067: ``total_volume`` (an ``_EXTENSIVE_METRICS`` sum
    metric) was pinned to a 1-second native bucket regardless of window size.
    Over a 39-hour window that produced ~134k firehose rows the frontend
    could not render. The fix switches extensive metrics to ``aggregate="mean"``
    with a computed bucket (``bucket_seconds=None``) once the window exceeds
    the point budget, while ``preserve_extrema=True`` keeps the bucket max so
    in-window anomaly spikes still raise ``violation_high``.
    """

    @pytest.mark.unit
    async def test_extensive_metric_large_window_downsamples_to_mean(
        self,
        mock_influx_repo: MagicMock,
        mock_postgres_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """Large windows switch extensive metrics from sum/1s to mean/computed bucket.

        A 600s window with a 30-point budget must not request the 1s firehose.
        Instead the service asks InfluxDB for ``aggregate="mean"`` with
        ``bucket_seconds=None`` (InfluxDB derives the bucket from
        ``sample_max_points``) and ``preserve_extrema=True`` so the bucket
        ``max`` survives downsampling. A spike at the bucket mid-point must
        still flag ``violation_high`` against a per-second upper bound.
        """
        times = pd.to_datetime(pd.date_range("2026-01-01T00:00:00", periods=10, freq="60s"))
        aggregated_df = pd.DataFrame(
            {
                "time": times,
                "total_volume": [50.0] * 10,
                "total_volume_min": [50.0] * 10,
                "total_volume_max": [50.0] * 10,
            }
        )
        aggregated_df.loc[5, "total_volume_max"] = 99999.0

        firehose_times = pd.to_datetime(pd.date_range("2026-01-01T00:00:00", periods=1000, freq="1s"))
        firehose_df = pd.DataFrame({"time": firehose_times, "total_volume": [50.0] * 1000})
        firehose_df.loc[500, "total_volume"] = 99999.0

        def _select_df(*_args: Any, **kwargs: Any) -> pd.DataFrame:
            if kwargs.get("bucket_seconds") == 1:
                return firehose_df
            return aggregated_df

        mock_influx_repo.query_timeseries.side_effect = _select_df
        mock_postgres_repo.query_anomalies.return_value = []
        mock_postgres_repo.query_bounds.return_value = [
            {"lower_bounds": {"total_volume": 48}, "upper_bounds": {"total_volume": 72}}
        ]

        service = BoundsService(mock_influx_repo, mock_postgres_repo, mock_settings)
        result = await service.get_timeseries_with_bounds(
            uci="a/b/c",
            metric="total_volume",
            start=pd.Timestamp("2026-01-01T00:00:00"),
            stop=pd.Timestamp("2026-01-01T00:10:00"),
            module="netcap",
            sample_max_points=30,
        )

        query = mock_influx_repo.query_timeseries.call_args.kwargs
        assert query["aggregate"] == "mean"
        assert query["bucket_seconds"] is None
        assert query["preserve_extrema"] is True
        assert result["row_count"] == 10
        assert result["parameters"]["bucket_seconds"] > 1
        assert result["data"][5]["value_max"] == 99999.0
        assert result["data"][5]["violation_high"] is True

    @pytest.mark.unit
    async def test_extensive_metric_small_window_keeps_native_bucket(
        self,
        mock_influx_repo: MagicMock,
        mock_postgres_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """Small windows that fit the point budget keep the 1s native bucket.

        When ``window_seconds <= sample_max_points`` the extensive metric stays
        on ``aggregate="sum"`` with ``bucket_seconds=1`` so live high-cadence
        detail is preserved at narrow windows (the original detector contract).
        """
        mock_influx_repo.query_timeseries.return_value = pd.DataFrame(
            {"time": pd.to_datetime(["2026-01-01T00:00:00"]), "total_volume": [64.0]}
        )
        mock_postgres_repo.query_anomalies.return_value = []
        mock_postgres_repo.query_bounds.return_value = [
            {"lower_bounds": {"total_volume": 48}, "upper_bounds": {"total_volume": 72}}
        ]

        service = BoundsService(mock_influx_repo, mock_postgres_repo, mock_settings)
        await service.get_timeseries_with_bounds(
            uci="a/b/c",
            metric="total_volume",
            start=pd.Timestamp("2026-01-01T00:00:00"),
            stop=pd.Timestamp("2026-01-01T00:10:00"),
            module="netcap",
            sample_max_points=1000,
        )

        query = mock_influx_repo.query_timeseries.call_args.kwargs
        assert query["aggregate"] == "sum"
        assert query["bucket_seconds"] == 1


class TestBoundsServiceSourceResolution:
    """BoundsService maps MAC/Proto modules to their own measurement."""

    @pytest.mark.unit
    def test_resolve_source_mac(
        self,
        mock_influx_repo: MagicMock,
        mock_postgres_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """mac_traffic resolves to the mac_traffic measurement + mac_address tag."""
        service = BoundsService(mock_influx_repo, mock_postgres_repo, mock_settings)
        assert service._resolve_source("mac_traffic") == ("mac_traffic", "mac_address")

    @pytest.mark.unit
    def test_resolve_source_proto(
        self,
        mock_influx_repo: MagicMock,
        mock_postgres_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """proto_traffic resolves to the proto_traffic measurement + protocol tag."""
        service = BoundsService(mock_influx_repo, mock_postgres_repo, mock_settings)
        assert service._resolve_source("proto_traffic") == ("proto_traffic", "protocol")

    @pytest.mark.unit
    def test_resolve_source_conn_default(
        self,
        mock_influx_repo: MagicMock,
        mock_postgres_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """Unknown / conn modules fall back to the settings defaults."""
        service = BoundsService(mock_influx_repo, mock_postgres_repo, mock_settings)
        measurement, id_tag = service._resolve_source("conn")
        assert measurement == mock_settings.netcap_measurement
        assert id_tag == mock_settings.netcap_id_tag

    @pytest.mark.unit
    async def test_mac_bounds_query_uses_mac_measurement(
        self,
        mock_influx_repo: MagicMock,
        mock_postgres_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """A mac_traffic bounds lookup queries Influx with the MAC source.

        Regression for the MSAP P7 defect where MAC/Proto bounds queried
        the conn measurement and returned no envelope data.
        """
        mock_influx_repo.query_timeseries.return_value = pd.DataFrame()
        mock_postgres_repo.query_bounds.return_value = []

        service = BoundsService(mock_influx_repo, mock_postgres_repo, mock_settings)
        await service.get_timeseries_with_bounds(
            uci="a8:74:1d:18:c6:97",
            metric="out_total_packets",
            start=pd.Timestamp("2026-01-01T00:00:00"),
            stop=pd.Timestamp("2026-01-01T01:00:00"),
            module="mac_traffic",
            normalize=False,
        )

        kwargs = mock_influx_repo.query_timeseries.call_args.kwargs
        assert kwargs["measurement"] == "mac_traffic"
        assert kwargs["id_tag"] == "mac_address"
        assert kwargs["tags"] == {"mac_address": "a8:74:1d:18:c6:97"}

    @pytest.mark.unit
    async def test_proto_bounds_queries_influx_plaintext_pg_hash(
        self,
        mock_influx_repo: MagicMock,
        mock_postgres_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """A proto bounds lookup queries Influx by plaintext, PG by hash.

        Regression for the MSAP P7 defect where the proto bounds merge
        always failed: Influx tags by the plaintext ``protocol`` while
        bounds are persisted under the stable proto hash.
        """
        from otalon_api.domain.netcap.models import proto_series_hash

        mock_influx_repo.query_timeseries.return_value = pd.DataFrame()
        mock_postgres_repo.query_bounds.return_value = []

        service = BoundsService(mock_influx_repo, mock_postgres_repo, mock_settings)
        await service.get_timeseries_with_bounds(
            uci="Ethernet:ARP",
            metric="proto_total_packets",
            start=pd.Timestamp("2026-01-01T00:00:00"),
            stop=pd.Timestamp("2026-01-01T01:00:00"),
            module="proto_traffic",
            normalize=False,
        )

        influx_kwargs = mock_influx_repo.query_timeseries.call_args.kwargs
        assert influx_kwargs["measurement"] == "proto_traffic"
        assert influx_kwargs["tags"] == {"protocol": "Ethernet:ARP"}

        bounds_kwargs = mock_postgres_repo.query_bounds.call_args.kwargs
        assert bounds_kwargs["module"] == "proto_traffic"
        assert bounds_kwargs["series_id"] == proto_series_hash("Ethernet:ARP")
        assert bounds_kwargs["series_id"] == "1513662987"


class TestApi072AlarmTimestampOffset:
    """API-072: every alarm timestamp in API responses carries an ISO 8601 offset."""

    @staticmethod
    def _assert_offset(value: Any) -> None:
        """Assert a serialized timestamp ends with a +HH:MM / -HH:MM offset."""
        assert isinstance(value, str)
        assert value[-6] in "+-"
        assert value[-3] == ":"
        assert len(value[-6:]) == 6

    @pytest.mark.unit
    async def test_anomaly_groups_timestamps_carry_offset(
        self,
        mock_postgres_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """Alarm group start/end timestamps must carry a UTC offset (API-072).

        Args:
            mock_postgres_repo: Mocked PostgresRepository returning one
                aware UTC alarm group row (as psycopg2 does for
                ``timestamptz``).
            mock_settings: Test settings.
        """
        time_policy.configure_timezone("Europe/Berlin")
        mock_postgres_repo.count_anomaly_groups.return_value = 1
        mock_postgres_repo.query_anomaly_groups.return_value = [
            {
                "id": "g-072",
                "module": "mac_traffic",
                "series_ids": ["aa:bb:cc:dd:ee:ff"],
                "start_timestamp": datetime(2026, 1, 15, 13, 30, 0, tzinfo=timezone.utc),
                "end_timestamp": datetime(2026, 1, 15, 13, 30, 0, tzinfo=timezone.utc),
                "primary_type": "BoundViolation",
            }
        ]

        service = AnomalyService(mock_postgres_repo, mock_settings)
        result = await service.get_anomaly_groups(limit=10)

        row = result["data"][0]
        self._assert_offset(row["start_timestamp"])
        self._assert_offset(row["end_timestamp"])
        assert row["start_timestamp"] == "2026-01-15T14:30:00+01:00"

    @pytest.mark.unit
    async def test_anomaly_series_timestamps_carry_offset(
        self,
        mock_postgres_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """Anomaly series start/end_ts timestamps must carry a UTC offset (API-072).

        Args:
            mock_postgres_repo: Mocked PostgresRepository returning one
                aware UTC alarm row.
            mock_settings: Test settings.
        """
        time_policy.configure_timezone("Europe/Berlin")
        mock_postgres_repo.query_anomalies.return_value = [
            {
                "id": "a-072",
                "module": "mac_traffic",
                "series_id": "aa:bb:cc:dd:ee:ff",
                "start_ts": datetime(2026, 1, 15, 13, 30, 0, tzinfo=timezone.utc),
                "end_ts": datetime(2026, 1, 15, 13, 31, 0, tzinfo=timezone.utc),
                "primary_type": "BoundViolation",
            }
        ]

        service = AnomalyService(mock_postgres_repo, mock_settings)
        result = await service.get_anomaly_series(module="mac_traffic")

        row = result["data"][0]
        self._assert_offset(row["start_ts"])
        self._assert_offset(row["end_ts"])
        assert row["start_ts"] == "2026-01-15T14:30:00+01:00"

    @pytest.mark.unit
    async def test_anomaly_intervals_timestamps_carry_offset(
        self,
        mock_postgres_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """Interval start/end timestamps built for a UCI must carry a UTC offset (API-072).

        Args:
            mock_postgres_repo: Mocked PostgresRepository returning one
                alarm group matching the UCI.
            mock_settings: Test settings.
        """
        time_policy.configure_timezone("Europe/Berlin")
        uci = "aa:bb:cc:dd:ee:ff"
        mock_postgres_repo.query_anomaly_groups.return_value = [
            {
                "id": "i-072",
                "series_ids": [uci],
                "start_timestamp": datetime(2026, 1, 15, 13, 30, 0, tzinfo=timezone.utc),
                "end_timestamp": datetime(2026, 1, 15, 13, 30, 0, tzinfo=timezone.utc),
                "primary_type": "BoundViolation",
            }
        ]

        service = AnomalyService(mock_postgres_repo, mock_settings)
        result = await service.get_anomaly_intervals(uci=uci)

        record = result["data"][0]
        self._assert_offset(record["start_timestamp"])
        self._assert_offset(record["end_timestamp"])
        assert record["start_timestamp"] == "2026-01-15T14:30:00+01:00"

    @pytest.mark.unit
    async def test_kpi_parameters_echo_carries_offset(
        self,
        mock_postgres_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """Dashboard KPI parameter echo timestamps must carry a UTC offset (API-072).

        Args:
            mock_postgres_repo: Mocked PostgresRepository.
            mock_settings: Test settings.
        """
        time_policy.configure_timezone("Europe/Berlin")
        mock_postgres_repo.query_anomaly_groups.return_value = []
        mock_influx = MagicMock()
        mock_influx.list_ids_between.return_value = []
        mock_influx.query_protocol_count.return_value = 0
        mock_influx.query_top_connections.return_value = []

        service = DashboardKpiService(mock_postgres_repo, mock_influx, mock_settings)
        result = await service.get_kpis(
            start=datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc),
            stop=datetime(2026, 1, 15, 13, 0, 0, tzinfo=timezone.utc),
        )

        self._assert_offset(result["parameters"]["start"])
        self._assert_offset(result["parameters"]["stop"])
        assert result["parameters"]["start"] == "2026-01-15T13:00:00+01:00"
