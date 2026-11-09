"""Unit tests for DashboardKpiService time-range filtering (B-04b) and sparklines (F-13).

Verifies that get_kpis() passes the dashboard time window to
query_anomaly_groups() so that only alarm groups within the
requested range affect the signal color.  Also tests sparkline
enrichment for top connections.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from otalon_api.services.dashboard_kpi_service import DashboardKpiService, _resolve_stop
from otalon_api.settings import Settings


class TestDashboardKpiServiceTimeRange:
    """Tests verifying time_range is forwarded to query_anomaly_groups."""

    @pytest.mark.unit
    async def test_get_kpis_passes_time_range(
        self,
        mock_postgres_repo: MagicMock,
        mock_influx_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """get_kpis should pass (since_str, stop_str) to query_anomaly_groups.

        Args:
            mock_postgres_repo: Mocked PostgresRepository.
            mock_influx_repo: Mocked InfluxRepository.
            mock_settings: Test settings.
        """
        mock_postgres_repo.query_anomaly_groups.return_value = []
        mock_postgres_repo.query_device_count.return_value = 0
        mock_postgres_repo.query_connection_count.return_value = 0
        mock_influx_repo.query_top_connections.return_value = []

        service = DashboardKpiService(mock_postgres_repo, mock_influx_repo, mock_settings)
        start = datetime(2026, 4, 1, 10, 0, 0)
        stop = datetime(2026, 4, 1, 12, 0, 0)
        await service.get_kpis(start=start, stop=stop)

        args = mock_postgres_repo.query_anomaly_groups.call_args
        assert args.kwargs.get("time_range") is not None, "time_range must not be None when start/stop are provided"
        time_range = args.kwargs["time_range"]
        assert isinstance(time_range, tuple)
        assert len(time_range) == 2

    @pytest.mark.unit
    async def test_device_count_uses_windowed_mac_activity(
        self,
        mock_postgres_repo: MagicMock,
        mock_influx_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """Device KPI counts distinct MACs observed in requested window."""
        mock_postgres_repo.query_anomaly_groups.return_value = []
        mock_influx_repo.query_top_connections.return_value = []

        def ids_for_window(**kwargs: object) -> list[str]:
            if kwargs["start"] == "2026-04-01T08:00:00Z":
                return ["aa:aa:aa:aa:aa:01", "aa:aa:aa:aa:aa:02"]
            return ["aa:aa:aa:aa:aa:03"]

        mock_influx_repo.list_ids_between.side_effect = ids_for_window
        service = DashboardKpiService(mock_postgres_repo, mock_influx_repo, mock_settings)

        first = await service.get_kpis(
            start=datetime(2026, 4, 1, 10, 0, 0),
            stop=datetime(2026, 4, 1, 11, 0, 0),
        )
        second = await service.get_kpis(
            start=datetime(2026, 4, 1, 12, 0, 0),
            stop=datetime(2026, 4, 1, 13, 0, 0),
        )

        assert first["data"][0]["device_count"] == 2
        assert second["data"][0]["device_count"] == 1
        device_calls = [
            call for call in mock_influx_repo.list_ids_between.call_args_list if call.kwargs["id_tag"] == "mac_address"
        ]
        assert device_calls[0].kwargs["start"] == "2026-04-01T08:00:00Z"
        assert device_calls[1].kwargs["start"] == "2026-04-01T10:00:00Z"

    @pytest.mark.unit
    async def test_device_count_excludes_broadcast_and_multicast_macs(
        self,
        mock_postgres_repo: MagicMock,
        mock_influx_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """Device KPI counts only unicast MACs observed in requested window."""
        mock_postgres_repo.query_anomaly_groups.return_value = []
        mock_influx_repo.query_top_connections.return_value = []
        mock_influx_repo.list_ids_between.return_value = [
            "aa:bb:cc:dd:ee:ff",
            "ff:ff:ff:ff:ff:ff",
            "01:00:5e:00:00:16",
            "33:33:00:00:00:01",
        ]

        service = DashboardKpiService(mock_postgres_repo, mock_influx_repo, mock_settings)
        result = await service.get_kpis(
            start=datetime(2026, 4, 1, 10, 0, 0),
            stop=datetime(2026, 4, 1, 11, 0, 0),
        )

        assert result["data"][0]["device_count"] == 1

    @pytest.mark.unit
    async def test_get_kpis_default_time_range_not_none(
        self,
        mock_postgres_repo: MagicMock,
        mock_influx_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """get_kpis without start/stop should still pass a time_range (epoch to now).

        Args:
            mock_postgres_repo: Mocked PostgresRepository.
            mock_influx_repo: Mocked InfluxRepository.
            mock_settings: Test settings.
        """
        mock_postgres_repo.query_anomaly_groups.return_value = []
        mock_postgres_repo.query_device_count.return_value = 0
        mock_postgres_repo.query_connection_count.return_value = 0
        mock_influx_repo.query_top_connections.return_value = []

        service = DashboardKpiService(mock_postgres_repo, mock_influx_repo, mock_settings)
        await service.get_kpis()

        args = mock_postgres_repo.query_anomaly_groups.call_args
        time_range = args.kwargs.get("time_range")
        assert time_range is not None, "time_range should always be a tuple, never None"
        assert time_range[0] == "1970-01-01T00:00:00Z"
        assert time_range[1].endswith("Z")

    @pytest.mark.unit
    async def test_get_kpis_success_when_groups_outside_window(
        self,
        mock_postgres_repo: MagicMock,
        mock_influx_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """Signal is success when query_anomaly_groups returns empty (all outside window).

        Args:
            mock_postgres_repo: Mocked PostgresRepository.
            mock_influx_repo: Mocked InfluxRepository.
            mock_settings: Test settings.
        """
        mock_postgres_repo.query_anomaly_groups.return_value = []
        mock_postgres_repo.query_device_count.return_value = 0
        mock_postgres_repo.query_connection_count.return_value = 0
        mock_influx_repo.query_top_connections.return_value = []

        service = DashboardKpiService(mock_postgres_repo, mock_influx_repo, mock_settings)
        result = await service.get_kpis(
            start=datetime(2026, 4, 1, 23, 0, 0),
            stop=datetime(2026, 4, 1, 23, 5, 0),
        )

        assert result["data"][0]["signal_color"] == "success"

    @pytest.mark.unit
    async def test_get_kpis_danger_when_groups_inside_window(
        self,
        mock_postgres_repo: MagicMock,
        mock_influx_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """Signal is danger when non-benign unconfirmed group falls inside window.

        Args:
            mock_postgres_repo: Mocked PostgresRepository.
            mock_influx_repo: Mocked InfluxRepository.
            mock_settings: Test settings.
        """
        mock_postgres_repo.query_anomaly_groups.return_value = [
            {"id": "g1", "confirmed": False, "primary_type": "T0888/port_scan"},
        ]
        mock_postgres_repo.query_device_count.return_value = 0
        mock_postgres_repo.query_connection_count.return_value = 0
        mock_influx_repo.query_top_connections.return_value = []

        service = DashboardKpiService(mock_postgres_repo, mock_influx_repo, mock_settings)
        result = await service.get_kpis(
            start=datetime(2026, 4, 1, 17, 0, 0),
            stop=datetime(2026, 4, 1, 19, 0, 0),
        )

        assert result["data"][0]["signal_color"] == "danger"


class TestResolveStop:
    """Tests for the _resolve_stop helper function."""

    @pytest.mark.unit
    def test_resolve_stop_with_datetime(self) -> None:
        """_resolve_stop with a datetime returns a Z-string."""
        dt = datetime(2026, 4, 1, 12, 0, 0)
        result = _resolve_stop(dt)

        assert result.endswith("Z")
        assert "2026" in result

    @pytest.mark.unit
    def test_resolve_stop_none_returns_current_time(self) -> None:
        """_resolve_stop(None) returns a Z-string close to current UTC time."""
        result = _resolve_stop(None)

        assert result.endswith("Z")
        now_str = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H")
        assert result.startswith(now_str[:13])


class TestDashboardKpiTopConnections:
    """Tests for top connections in DashboardKpiService."""

    @pytest.mark.unit
    async def test_get_kpis_returns_top_connections_empty(
        self,
        mock_postgres_repo: MagicMock,
        mock_influx_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """get_kpis returns empty top_connections when InfluxDB returns no data."""
        mock_postgres_repo.query_anomaly_groups.return_value = []
        mock_postgres_repo.query_device_count.return_value = 0
        mock_postgres_repo.query_connection_count.return_value = 0
        mock_influx_repo.query_top_connections.return_value = []

        service = DashboardKpiService(mock_postgres_repo, mock_influx_repo, mock_settings)
        result = await service.get_kpis()

        assert result["data"][0]["top_connections"] == []

    @pytest.mark.unit
    async def test_get_kpis_returns_top_connections_with_data(
        self,
        mock_postgres_repo: MagicMock,
        mock_influx_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """get_kpis returns populated top_connections from InfluxDB data."""
        mock_postgres_repo.query_anomaly_groups.return_value = []
        mock_postgres_repo.query_device_count.return_value = 0
        mock_postgres_repo.query_connection_count.return_value = 0
        mock_influx_repo.query_top_connections.return_value = [
            {"uci": "a/b/c/d/e/f/g/h/TCP", "total_packets": 100, "total_bytes": 5000},
            {"uci": "x/y/z/d/e/f/g/h/UDP", "total_packets": 50, "total_bytes": 2000},
        ]

        service = DashboardKpiService(mock_postgres_repo, mock_influx_repo, mock_settings)
        result = await service.get_kpis()

        top = result["data"][0]["top_connections"]
        assert len(top) == 2
        assert top[0]["uci"] == "a/b/c/d/e/f/g/h/TCP"
        assert top[0]["packet_count"] == 100
        assert top[0]["byte_count"] == 5000
        assert top[0]["is_anomaly"] is False

    @pytest.mark.unit
    async def test_get_kpis_anomaly_enrichment(
        self,
        mock_postgres_repo: MagicMock,
        mock_influx_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """top_connections marks UCIs as anomaly when they appear in active unconfirmed groups."""
        mock_postgres_repo.query_anomaly_groups.return_value = [
            {
                "id": "g1",
                "confirmed": False,
                "is_active": True,
                "primary_type": "T0888/port_scan",
                "series_ids": ["a/b/c/d/e/f/g/h/TCP"],
            },
        ]
        mock_postgres_repo.query_device_count.return_value = 0
        mock_postgres_repo.query_connection_count.return_value = 0
        mock_influx_repo.query_top_connections.return_value = [
            {"uci": "a/b/c/d/e/f/g/h/TCP", "total_packets": 100, "total_bytes": 5000},
            {"uci": "x/y/z/d/e/f/g/h/UDP", "total_packets": 50, "total_bytes": 2000},
        ]

        service = DashboardKpiService(mock_postgres_repo, mock_influx_repo, mock_settings)
        result = await service.get_kpis()

        top = result["data"][0]["top_connections"]
        assert top[0]["is_anomaly"] is True
        assert top[1]["is_anomaly"] is False

    @pytest.mark.unit
    async def test_get_kpis_confirmed_group_not_anomaly(
        self,
        mock_postgres_repo: MagicMock,
        mock_influx_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """Confirmed alarm groups do not mark UCIs as anomaly."""
        mock_postgres_repo.query_anomaly_groups.return_value = [
            {
                "id": "g1",
                "confirmed": True,
                "is_active": True,
                "primary_type": "T0888/port_scan",
                "series_ids": ["a/b/c/d/e/f/g/h/TCP"],
            },
        ]
        mock_postgres_repo.query_device_count.return_value = 0
        mock_postgres_repo.query_connection_count.return_value = 0
        mock_influx_repo.query_top_connections.return_value = [
            {"uci": "a/b/c/d/e/f/g/h/TCP", "total_packets": 100, "total_bytes": 5000},
        ]

        service = DashboardKpiService(mock_postgres_repo, mock_influx_repo, mock_settings)
        result = await service.get_kpis()

        top = result["data"][0]["top_connections"]
        assert top[0]["is_anomaly"] is False


class TestDashboardKpiSparklines:
    """Tests for sparkline enrichment of top connections (F-13)."""

    @pytest.mark.unit
    async def test_get_kpis_sparkline_data_added(
        self,
        mock_postgres_repo: MagicMock,
        mock_influx_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """Sparkline data is attached to top connections when InfluxDB returns data.

        Args:
            mock_postgres_repo: Mocked PostgresRepository.
            mock_influx_repo: Mocked InfluxRepository.
            mock_settings: Test settings.
        """
        mock_postgres_repo.query_anomaly_groups.return_value = []
        mock_postgres_repo.query_device_count.return_value = 0
        mock_postgres_repo.query_connection_count.return_value = 0
        mock_influx_repo.query_top_connections.return_value = [
            {"uci": "a/b/c/d/e/f/g/h/TCP", "total_packets": 100, "total_bytes": 5000},
            {"uci": "x/y/z/d/e/f/g/h/UDP", "total_packets": 50, "total_bytes": 2000},
        ]
        mock_influx_repo.query_connection_sparklines.return_value = {
            "a/b/c/d/e/f/g/h/TCP": [10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120],
            "x/y/z/d/e/f/g/h/UDP": [5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55, 60],
        }

        service = DashboardKpiService(mock_postgres_repo, mock_influx_repo, mock_settings)
        result = await service.get_kpis()

        top = result["data"][0]["top_connections"]
        assert len(top) == 2
        assert top[0]["sparkline"] == [
            10,
            20,
            30,
            40,
            50,
            60,
            70,
            80,
            90,
            100,
            110,
            120,
        ]
        assert top[1]["sparkline"] == [5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55, 60]

    @pytest.mark.unit
    async def test_get_kpis_sparkline_empty_when_no_data(
        self,
        mock_postgres_repo: MagicMock,
        mock_influx_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """Sparkline is empty list when InfluxDB returns no sparkline data for a UCI.

        Args:
            mock_postgres_repo: Mocked PostgresRepository.
            mock_influx_repo: Mocked InfluxRepository.
            mock_settings: Test settings.
        """
        mock_postgres_repo.query_anomaly_groups.return_value = []
        mock_postgres_repo.query_device_count.return_value = 0
        mock_postgres_repo.query_connection_count.return_value = 0
        mock_influx_repo.query_top_connections.return_value = [
            {"uci": "a/b/c/d/e/f/g/h/TCP", "total_packets": 100, "total_bytes": 5000},
        ]
        mock_influx_repo.query_connection_sparklines.return_value = {}

        service = DashboardKpiService(mock_postgres_repo, mock_influx_repo, mock_settings)
        result = await service.get_kpis()

        top = result["data"][0]["top_connections"]
        assert top[0]["sparkline"] == []

    @pytest.mark.unit
    async def test_get_kpis_sparkline_partial_data(
        self,
        mock_postgres_repo: MagicMock,
        mock_influx_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """Sparkline defaults to empty list for UCIs missing from sparkline response.

        Args:
            mock_postgres_repo: Mocked PostgresRepository.
            mock_influx_repo: Mocked InfluxRepository.
            mock_settings: Test settings.
        """
        mock_postgres_repo.query_anomaly_groups.return_value = []
        mock_postgres_repo.query_device_count.return_value = 0
        mock_postgres_repo.query_connection_count.return_value = 0
        mock_influx_repo.query_top_connections.return_value = [
            {"uci": "a/b/c/d/e/f/g/h/TCP", "total_packets": 100, "total_bytes": 5000},
            {"uci": "x/y/z/d/e/f/g/h/UDP", "total_packets": 50, "total_bytes": 2000},
        ]
        mock_influx_repo.query_connection_sparklines.return_value = {
            "a/b/c/d/e/f/g/h/TCP": [10, 20, 30],
        }

        service = DashboardKpiService(mock_postgres_repo, mock_influx_repo, mock_settings)
        result = await service.get_kpis()

        top = result["data"][0]["top_connections"]
        assert top[0]["sparkline"] == [10, 20, 30]
        assert top[1]["sparkline"] == []

    @pytest.mark.unit
    async def test_get_kpis_sparkline_empty_when_no_top_connections(
        self,
        mock_postgres_repo: MagicMock,
        mock_influx_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """Sparkline query is not called when there are no top connections.

        Args:
            mock_postgres_repo: Mocked PostgresRepository.
            mock_influx_repo: Mocked InfluxRepository.
            mock_settings: Test settings.
        """
        mock_postgres_repo.query_anomaly_groups.return_value = []
        mock_postgres_repo.query_device_count.return_value = 0
        mock_postgres_repo.query_connection_count.return_value = 0
        mock_influx_repo.query_top_connections.return_value = []

        service = DashboardKpiService(mock_postgres_repo, mock_influx_repo, mock_settings)
        result = await service.get_kpis()

        assert result["data"][0]["top_connections"] == []
        mock_influx_repo.query_connection_sparklines.assert_not_called()

    @pytest.mark.unit
    async def test_get_kpis_sparkline_query_failure_graceful(
        self,
        mock_postgres_repo: MagicMock,
        mock_influx_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """Sparkline failure does not break get_kpis; items get empty sparkline.

        Args:
            mock_postgres_repo: Mocked PostgresRepository.
            mock_influx_repo: Mocked InfluxRepository.
            mock_settings: Test settings.
        """
        mock_postgres_repo.query_anomaly_groups.return_value = []
        mock_postgres_repo.query_device_count.return_value = 0
        mock_postgres_repo.query_connection_count.return_value = 0
        mock_influx_repo.query_top_connections.return_value = [
            {"uci": "a/b/c/d/e/f/g/h/TCP", "total_packets": 100, "total_bytes": 5000},
        ]
        mock_influx_repo.query_connection_sparklines.side_effect = RuntimeError("DB down")

        service = DashboardKpiService(mock_postgres_repo, mock_influx_repo, mock_settings)
        result = await service.get_kpis()

        top = result["data"][0]["top_connections"]
        assert top[0]["sparkline"] == []


class TestDashboardKpiTopAssets:
    """Tests for top assets in DashboardKpiService."""

    @pytest.mark.unit
    async def test_get_top_assets_empty(
        self,
        mock_postgres_repo: MagicMock,
        mock_influx_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """get_top_assets returns empty data when InfluxDB returns no MACs."""
        mock_postgres_repo.query_anomaly_groups.return_value = []
        mock_influx_repo.query_top_mac_addresses.return_value = []

        service = DashboardKpiService(mock_postgres_repo, mock_influx_repo, mock_settings)
        result = await service.get_top_assets()

        assert result["data"] == []
        assert result["row_count"] == 0

    @pytest.mark.unit
    async def test_get_top_assets_with_data(
        self,
        mock_postgres_repo: MagicMock,
        mock_influx_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """get_top_assets returns populated top assets from InfluxDB data."""
        mock_postgres_repo.query_anomaly_groups.return_value = []
        mock_influx_repo.query_top_mac_addresses.return_value = [
            {"id": "aa:bb:cc:dd:ee:ff", "total_packets": 100, "total_bytes": 5000},
            {"id": "11:22:33:44:55:66", "total_packets": 50, "total_bytes": 2000},
        ]
        mock_influx_repo.query_mac_sparklines.return_value = {}

        service = DashboardKpiService(mock_postgres_repo, mock_influx_repo, mock_settings)
        result = await service.get_top_assets()

        data = result["data"]
        assert len(data) == 2
        assert data[0]["id"] == "aa:bb:cc:dd:ee:ff"
        assert data[0]["packet_count"] == 100
        assert data[0]["byte_count"] == 5000
        assert data[0]["is_anomaly"] is False
        assert data[0]["sparkline"] == []

    @pytest.mark.unit
    async def test_get_top_assets_anomaly_enrichment(
        self,
        mock_postgres_repo: MagicMock,
        mock_influx_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """get_top_assets marks MACs as anomaly when they appear in active groups."""
        mock_postgres_repo.query_anomaly_groups.return_value = [
            {
                "id": "g1",
                "confirmed": False,
                "is_active": True,
                "primary_type": "T0888/port_scan",
                "series_ids": ["aa:bb:cc:dd:ee:ff"],
            },
        ]
        mock_influx_repo.query_top_mac_addresses.return_value = [
            {"id": "aa:bb:cc:dd:ee:ff", "total_packets": 100, "total_bytes": 5000},
            {"id": "11:22:33:44:55:66", "total_packets": 50, "total_bytes": 2000},
        ]
        mock_influx_repo.query_mac_sparklines.return_value = {}

        service = DashboardKpiService(mock_postgres_repo, mock_influx_repo, mock_settings)
        result = await service.get_top_assets()

        data = result["data"]
        assert data[0]["is_anomaly"] is True
        assert data[1]["is_anomaly"] is False

    @pytest.mark.unit
    async def test_get_top_assets_sparkline_data(
        self,
        mock_postgres_repo: MagicMock,
        mock_influx_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """Sparkline data is attached to top assets when InfluxDB returns data."""
        mock_postgres_repo.query_anomaly_groups.return_value = []
        mock_influx_repo.query_top_mac_addresses.return_value = [
            {"id": "aa:bb:cc:dd:ee:ff", "total_packets": 100, "total_bytes": 5000},
        ]
        mock_influx_repo.query_mac_sparklines.return_value = {
            "aa:bb:cc:dd:ee:ff": [10, 20, 30, 40, 50, 60],
        }

        service = DashboardKpiService(mock_postgres_repo, mock_influx_repo, mock_settings)
        result = await service.get_top_assets()

        data = result["data"]
        assert len(data) == 1
        assert data[0]["sparkline"] == [10, 20, 30, 40, 50, 60]


class TestDashboardKpiTopProtocols:
    """Tests for top protocols in DashboardKpiService."""

    @pytest.mark.unit
    async def test_get_top_protocols_empty(
        self,
        mock_postgres_repo: MagicMock,
        mock_influx_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """get_top_protocols returns empty data when InfluxDB returns no protocols."""
        mock_postgres_repo.query_anomaly_groups.return_value = []
        mock_influx_repo.query_top_protocols.return_value = []

        service = DashboardKpiService(mock_postgres_repo, mock_influx_repo, mock_settings)
        result = await service.get_top_protocols()

        assert result["data"] == []
        assert result["row_count"] == 0

    @pytest.mark.unit
    async def test_get_top_protocols_with_data(
        self,
        mock_postgres_repo: MagicMock,
        mock_influx_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """get_top_protocols returns populated top protocols from InfluxDB data."""
        mock_postgres_repo.query_anomaly_groups.return_value = []
        mock_influx_repo.query_top_protocols.return_value = [
            {"id": "Ethernet:TCP", "total_packets": 200, "total_bytes": 10000},
            {"id": "Ethernet:ARP", "total_packets": 80, "total_bytes": 4000},
        ]
        mock_influx_repo.query_proto_sparklines.return_value = {}

        service = DashboardKpiService(mock_postgres_repo, mock_influx_repo, mock_settings)
        result = await service.get_top_protocols()

        data = result["data"]
        assert len(data) == 2
        assert data[0]["id"] == "Ethernet:TCP"
        assert data[0]["protocol"] == "Ethernet:TCP"
        assert data[0]["packet_count"] == 200
        assert data[0]["byte_count"] == 10000
        assert data[0]["is_anomaly"] is False
        assert data[0]["sparkline"] == []

    @pytest.mark.unit
    async def test_get_top_protocols_anomaly_enrichment(
        self,
        mock_postgres_repo: MagicMock,
        mock_influx_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """get_top_protocols marks protocols as anomaly via hash matching."""
        from otalon_api.domain.netcap.models import proto_series_hash

        proto = "Ethernet:TCP"
        proto_hash = proto_series_hash(proto)

        mock_postgres_repo.query_anomaly_groups.return_value = [
            {
                "id": "g1",
                "confirmed": False,
                "is_active": True,
                "primary_type": "T0888/port_scan",
                "series_ids": [proto_hash],
            },
        ]
        mock_influx_repo.query_top_protocols.return_value = [
            {"id": proto, "total_packets": 200, "total_bytes": 10000},
            {"id": "Ethernet:ARP", "total_packets": 80, "total_bytes": 4000},
        ]
        mock_influx_repo.query_proto_sparklines.return_value = {}

        service = DashboardKpiService(mock_postgres_repo, mock_influx_repo, mock_settings)
        result = await service.get_top_protocols()

        data = result["data"]
        assert data[0]["is_anomaly"] is True
        assert data[1]["is_anomaly"] is False

    @pytest.mark.unit
    async def test_get_top_protocols_confirmed_not_anomaly(
        self,
        mock_postgres_repo: MagicMock,
        mock_influx_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """Confirmed proto alarm groups do not mark protocols as anomaly."""
        from otalon_api.domain.netcap.models import proto_series_hash

        proto = "Ethernet:TCP"
        proto_hash = proto_series_hash(proto)

        mock_postgres_repo.query_anomaly_groups.return_value = [
            {
                "id": "g1",
                "confirmed": True,
                "is_active": True,
                "primary_type": "T0888/port_scan",
                "series_ids": [proto_hash],
            },
        ]
        mock_influx_repo.query_top_protocols.return_value = [
            {"id": proto, "total_packets": 200, "total_bytes": 10000},
        ]
        mock_influx_repo.query_proto_sparklines.return_value = {}

        service = DashboardKpiService(mock_postgres_repo, mock_influx_repo, mock_settings)
        result = await service.get_top_protocols()

        data = result["data"]
        assert data[0]["is_anomaly"] is False

    @pytest.mark.unit
    async def test_get_top_protocols_sparkline_data(
        self,
        mock_postgres_repo: MagicMock,
        mock_influx_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """Sparkline data is attached to top protocols when InfluxDB returns data."""
        mock_postgres_repo.query_anomaly_groups.return_value = []
        mock_influx_repo.query_top_protocols.return_value = [
            {"id": "Ethernet:TCP", "total_packets": 200, "total_bytes": 10000},
        ]
        mock_influx_repo.query_proto_sparklines.return_value = {
            "Ethernet:TCP": [5, 10, 15, 20],
        }

        service = DashboardKpiService(mock_postgres_repo, mock_influx_repo, mock_settings)
        result = await service.get_top_protocols()

        data = result["data"]
        assert len(data) == 1
        assert data[0]["sparkline"] == [5, 10, 15, 20]


class TestTopConnectionItemSchema:
    """Tests for TopConnectionItem schema with sparkline field (F-13)."""

    @pytest.mark.unit
    def test_schema_default_sparkline_empty(self) -> None:
        """TopConnectionItem defaults sparkline to empty list."""
        from otalon_api.api.schemas.dashboard import TopConnectionItem

        item = TopConnectionItem(uci="a/b", packet_count=10, byte_count=100)
        assert item.sparkline == []

    @pytest.mark.unit
    def test_schema_sparkline_with_data(self) -> None:
        """TopConnectionItem accepts sparkline data."""
        from otalon_api.api.schemas.dashboard import TopConnectionItem

        data = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120]
        item = TopConnectionItem(uci="a/b", packet_count=10, byte_count=100, sparkline=data)
        assert item.sparkline == data
        assert len(item.sparkline) == 12

    @pytest.mark.unit
    def test_schema_serialization_includes_sparkline(self) -> None:
        """TopConnectionItem serialization includes sparkline field."""
        from otalon_api.api.schemas.dashboard import TopConnectionItem

        item = TopConnectionItem(uci="a/b", packet_count=10, byte_count=100, sparkline=[1, 2, 3])
        d = item.model_dump()
        assert "sparkline" in d
        assert d["sparkline"] == [1, 2, 3]


class TestTopAssetItemSchema:
    """Tests for TopAssetItem schema."""

    @pytest.mark.unit
    def test_schema_default_sparkline_empty(self) -> None:
        """TopAssetItem defaults sparkline to empty list."""
        from otalon_api.api.schemas.dashboard import TopAssetItem

        item = TopAssetItem(id="aa:bb:cc:dd:ee:ff", packet_count=10, byte_count=100)
        assert item.sparkline == []

    @pytest.mark.unit
    def test_schema_serialization_includes_fields(self) -> None:
        """TopAssetItem serialization includes all metric fields."""
        from otalon_api.api.schemas.dashboard import TopAssetItem

        item = TopAssetItem(
            id="aa:bb:cc:dd:ee:ff",
            packet_count=10,
            byte_count=100,
            is_anomaly=True,
            sparkline=[1, 2, 3],
        )
        d = item.model_dump()
        assert d["id"] == "aa:bb:cc:dd:ee:ff"
        assert d["packet_count"] == 10
        assert d["byte_count"] == 100
        assert d["is_anomaly"] is True
        assert d["sparkline"] == [1, 2, 3]


class TestTopProtocolItemSchema:
    """Tests for TopProtocolItem schema."""

    @pytest.mark.unit
    def test_schema_default_sparkline_empty(self) -> None:
        """TopProtocolItem defaults sparkline to empty list."""
        from otalon_api.api.schemas.dashboard import TopProtocolItem

        item = TopProtocolItem(id="Ethernet:TCP", protocol="Ethernet:TCP", packet_count=10, byte_count=100)
        assert item.sparkline == []

    @pytest.mark.unit
    def test_schema_serialization_includes_fields(self) -> None:
        """TopProtocolItem serialization includes all metric fields."""
        from otalon_api.api.schemas.dashboard import TopProtocolItem

        item = TopProtocolItem(
            id="Ethernet:TCP",
            protocol="Ethernet:TCP",
            packet_count=10,
            byte_count=100,
            is_anomaly=False,
            sparkline=[4, 5, 6],
        )
        d = item.model_dump()
        assert d["id"] == "Ethernet:TCP"
        assert d["protocol"] == "Ethernet:TCP"
        assert d["packet_count"] == 10
        assert d["byte_count"] == 100
        assert d["is_anomaly"] is False
        assert d["sparkline"] == [4, 5, 6]
