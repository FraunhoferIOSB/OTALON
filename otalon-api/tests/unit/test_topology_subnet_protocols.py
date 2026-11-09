"""Unit tests for GET /api/v1/topology/subnet-protocols.

Covers PROFINET detection, empty data, invalid CIDR, and error handling.
"""

from __future__ import annotations

from collections.abc import Generator
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from otalon_api.dependencies import get_settings, get_topology_service
from otalon_api.main import app
from otalon_api.services.topology_service import TopologyService
from otalon_api.settings import Settings

ENDPOINT = "/api/v1/topology/subnet-protocols"
TEST_API_KEY = "test-secret-key"


def _make_settings() -> Settings:
    """Create test settings with the given admin API key.

    Returns:
        A Settings instance suitable for testing.
    """
    return Settings(
        influxdb_host="localhost",
        influxdb_port=8181,
        influx_token="test-token",
        influxdb_org="test-org",
        influxdb_database="netcap",
        postgres_host="localhost",
        postgres_port=5432,
        postgres_user="test",
        postgres_password="test",
        postgres_database="test",
        admin_api_key=TEST_API_KEY,
        api_port=8090,
        netcap_measurement="network_metrics",
        netcap_id_tag="uci",
        netcap_sparse_port_threshold=10,
        default_sample_max_points=500,
        topology_subnet_protocols_lookback_hours=168,
    )


def _build_test_client(mock_influx: MagicMock, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    """Wire up dependency overrides and return an authenticated test client.

    Args:
        mock_influx: Mocked InfluxRepository.
        monkeypatch: Used to arm the auth middleware (it reads settings via a
            direct function call, not FastAPI's ``Depends``, so
            ``app.dependency_overrides`` alone cannot reach it).

    Returns:
        A configured, pre-authenticated ``TestClient``.
    """
    settings = _make_settings()
    mock_pg = MagicMock()
    service = TopologyService(mock_pg, mock_influx, settings)

    app.dependency_overrides[get_topology_service] = lambda: service
    app.dependency_overrides[get_settings] = lambda: settings
    monkeypatch.setattr("otalon_api.middleware.auth.get_settings", lambda: settings)

    client = TestClient(app, headers={"X-API-Key": TEST_API_KEY}, raise_server_exceptions=False)
    return client


@pytest.fixture(autouse=True)
def _cleanup_overrides() -> Generator[None, None, None]:
    """Remove dependency overrides after each test."""
    yield
    app.dependency_overrides.clear()


class TestSubnetProtocolsSuccess:
    """Tests for successful subnet-protocols queries."""

    @pytest.mark.unit
    def test_profinet_present(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A subnet containing a PROFINET connection returns the token."""
        mock_influx = MagicMock()
        mock_influx.list_ids_between = MagicMock(
            return_value=[
                "aa:bb:cc:dd:ee:ff/11:22:33:44:55:66/0/ipv4/192.168.0.10/192.168.0.20/34962/34964/PROFINET_RT",
            ]
        )
        client = _build_test_client(mock_influx, monkeypatch)
        response = client.get(f"{ENDPOINT}?subnet=192.168.0.0/24")

        assert response.status_code == 200
        data = response.json()
        assert data["subnet"] == "192.168.0.0/24"
        assert "PROFINET_RT" in data["protocols"]
        assert data["seen"] is True

    @pytest.mark.unit
    def test_source_ip_in_subnet(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An edge counts when only the source IP is inside the subnet."""
        mock_influx = MagicMock()
        mock_influx.list_ids_between = MagicMock(
            return_value=[
                "aa:bb:cc:dd:ee:ff/11:22:33:44:55:66/0/ipv4/10.0.0.5/192.168.1.20/502/502/MODBUS",
            ]
        )
        client = _build_test_client(mock_influx, monkeypatch)
        response = client.get(f"{ENDPOINT}?subnet=10.0.0.0/8")

        assert response.status_code == 200
        data = response.json()
        assert "MODBUS" in data["protocols"]
        assert data["seen"] is True

    @pytest.mark.unit
    def test_dst_ip_in_subnet(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An edge counts when only the destination IP is inside the subnet."""
        mock_influx = MagicMock()
        mock_influx.list_ids_between = MagicMock(
            return_value=[
                "aa:bb:cc:dd:ee:ff/11:22:33:44:55:66/0/ipv4/10.0.0.5/192.168.1.20/502/502/MODBUS",
            ]
        )
        client = _build_test_client(mock_influx, monkeypatch)
        response = client.get(f"{ENDPOINT}?subnet=192.168.1.0/24")

        assert response.status_code == 200
        data = response.json()
        assert "MODBUS" in data["protocols"]
        assert data["seen"] is True

    @pytest.mark.unit
    def test_no_data(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A subnet with no matching connections returns empty protocols."""
        mock_influx = MagicMock()
        mock_influx.list_ids_between = MagicMock(return_value=[])
        client = _build_test_client(mock_influx, monkeypatch)
        response = client.get(f"{ENDPOINT}?subnet=10.0.0.0/24")

        assert response.status_code == 200
        data = response.json()
        assert data["subnet"] == "10.0.0.0/24"
        assert data["protocols"] == []
        assert data["seen"] is False

    @pytest.mark.unit
    def test_multiple_protocols_deduplicated(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Duplicate protocols across edges are deduplicated and sorted."""
        mock_influx = MagicMock()
        mock_influx.list_ids_between = MagicMock(
            return_value=[
                "aa:bb:cc:dd:ee:ff/11:22:33:44:55:66/0/ipv4/192.168.0.10/192.168.0.20/34962/34964/PROFINET_RT",
                "aa:bb:cc:dd:ee:ff/11:22:33:44:55:77/0/ipv4/192.168.0.10/192.168.0.30/44818/44818/EIP",
                "aa:bb:cc:dd:ee:ff/11:22:33:44:55:88/0/ipv4/192.168.0.10/192.168.0.40/34962/34964/PROFINET_RT",
            ]
        )
        client = _build_test_client(mock_influx, monkeypatch)
        response = client.get(f"{ENDPOINT}?subnet=192.168.0.0/24")

        assert response.status_code == 200
        data = response.json()
        assert data["protocols"] == ["EIP", "PROFINET_RT"]
        assert data["seen"] is True


class TestSubnetProtocolsL2Profinet:
    """UI-016 Cause 2: PROFINET RT frames are L2-only (no IP header).

    The cyclic IO (``PROFINET_RT_IO``), clock-sync (``PROFINET_RT_PTCP``)
    and discovery (``PROFINET_RT_DCP``) families ride directly on Ethernet
    and therefore carry no source/destination IP, so the IP-CIDR filter
    cannot place them in any subnet.  These fixtures use the real producer
    UCI shape (blank IP/port segments, ``PROFINET_*`` tokens in the
    protocol stack) and assert the L2 signal is surfaced regardless.
    """

    @pytest.mark.unit
    def test_l2_rt_io_detected_without_ip(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A pure-L2 ``PROFINET_RT_IO`` UCI (no IP) is reported as present."""
        mock_influx = MagicMock()
        mock_influx.list_ids_between = MagicMock(
            return_value=[
                "00:01:05:93:50:9b/a8:74:1d:02:99:8d/0//////Ethernet:VLAN:PROFINET_RT:PROFINET_RT_IO",
            ]
        )
        client = _build_test_client(mock_influx, monkeypatch)
        response = client.get(f"{ENDPOINT}?subnet=192.168.0.0/24")

        assert response.status_code == 200
        data = response.json()
        assert "PROFINET_RT_IO" in data["protocols"]
        assert data["seen"] is True

    @pytest.mark.unit
    def test_l2_rt_ptcp_detected_without_ip(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A pure-L2 ``PROFINET_RT_PTCP`` UCI (no IP) is reported as present."""
        mock_influx = MagicMock()
        mock_influx.list_ids_between = MagicMock(
            return_value=[
                "00:01:05:93:50:9b/a8:74:1d:02:99:8d/0//////Ethernet:PROFINET_RT:PROFINET_RT_PTCP",
            ]
        )
        client = _build_test_client(mock_influx, monkeypatch)
        response = client.get(f"{ENDPOINT}?subnet=192.168.0.0/24")

        assert response.status_code == 200
        data = response.json()
        assert "PROFINET_RT_PTCP" in data["protocols"]
        assert data["seen"] is True

    @pytest.mark.unit
    def test_live_mix_rt_io_and_ptcp_and_dce_rpc(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The live testbed mix: L2 RT_IO/RT_PTCP plus IP-bearing DCE_RPC.

        Mirrors the UI-016 field observation — multiple L2-only RT frames
        (invisible to the old IP filter) alongside the IP-bearing DCE_RPC
        context channel.  All PROFINET families must surface.
        """
        mock_influx = MagicMock()
        mock_influx.list_ids_between = MagicMock(
            return_value=[
                # 6x L2-only cyclic IO (no IP) — formerly invisible
                *[
                    f"00:01:05:93:50:9{i}/a8:74:1d:02:99:8d/0//////Ethernet:VLAN:PROFINET_RT:PROFINET_RT_IO"
                    for i in range(6)
                ],
                # 1x L2-only PTCP clock sync (no IP) — formerly invisible
                "00:01:05:93:50:aa/a8:74:1d:02:99:8d/0//////Ethernet:PROFINET_RT:PROFINET_RT_PTCP",
                # 2x IP-bearing DCE_RPC context channel — already caught by IP filter
                "00:01:05:93:50:9b/a8:74:1d:02:99:8d/0/ipv4/192.168.0.10/192.168.0.20/49152/34964/Ethernet:IPv4:UDP:PROFINET_DCE_RPC",
            ]
        )
        client = _build_test_client(mock_influx, monkeypatch)
        response = client.get(f"{ENDPOINT}?subnet=192.168.0.0/24")

        assert response.status_code == 200
        data = response.json()
        protocols = data["protocols"]
        assert "PROFINET_RT_IO" in protocols
        assert "PROFINET_RT_PTCP" in protocols
        assert any("PROFINET" in p for p in protocols)
        assert data["seen"] is True

    @pytest.mark.unit
    def test_non_profinet_l2_not_misclassified(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A non-PROFINET L2 frame (no IP) must NOT yield a PROFINET signal."""
        mock_influx = MagicMock()
        mock_influx.list_ids_between = MagicMock(
            return_value=[
                "00:01:05:93:50:9b/ff:ff:ff:ff:ff:ff/0//////Ethernet:ARP",
                "00:01:05:93:50:9b/01:80:c2:00:00:00/0//////Ethernet:LLDP",
            ]
        )
        client = _build_test_client(mock_influx, monkeypatch)
        response = client.get(f"{ENDPOINT}?subnet=192.168.0.0/24")

        assert response.status_code == 200
        data = response.json()
        assert not any("PROFINET" in p for p in data["protocols"])


class TestSubnetProtocolsErrors:
    """Tests for error handling on the subnet-protocols endpoint."""

    @pytest.mark.unit
    def test_invalid_cidr(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A malformed subnet string returns 422."""
        mock_influx = MagicMock()
        mock_influx.list_ids_between = MagicMock(return_value=[])
        client = _build_test_client(mock_influx, monkeypatch)
        response = client.get(f"{ENDPOINT}?subnet=not-a-cidr")

        assert response.status_code == 422
        assert "Invalid CIDR" in response.json()["detail"]

    @pytest.mark.unit
    def test_invalid_cidr_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An empty subnet string returns 422."""
        mock_influx = MagicMock()
        mock_influx.list_ids_between = MagicMock(return_value=[])
        client = _build_test_client(mock_influx, monkeypatch)
        response = client.get(f"{ENDPOINT}?subnet=")

        assert response.status_code == 422
        assert "Invalid CIDR" in response.json()["detail"]


class TestSubnetProtocolsLookback:
    """API-010: subnet-protocols must apply a bounded lookback window."""

    @pytest.mark.unit
    def test_lookback_window_applied(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Influx query range respects topology_subnet_protocols_lookback_hours."""
        mock_influx = MagicMock()
        mock_influx.list_ids_between = MagicMock(return_value=[])
        settings = _make_settings()
        settings.topology_subnet_protocols_lookback_hours = 6
        mock_pg = MagicMock()
        service = TopologyService(mock_pg, mock_influx, settings)
        app.dependency_overrides[get_topology_service] = lambda: service
        app.dependency_overrides[get_settings] = lambda: settings
        monkeypatch.setattr("otalon_api.middleware.auth.get_settings", lambda: settings)

        client = TestClient(app, headers={"X-API-Key": TEST_API_KEY}, raise_server_exceptions=False)
        response = client.get(f"{ENDPOINT}?subnet=192.168.0.0/24")
        assert response.status_code == 200

        mock_influx.list_ids_between.assert_called_once()
        call_args = mock_influx.list_ids_between.call_args
        start_str = call_args.kwargs.get("start") or call_args.args[2]
        start_dt = datetime.fromisoformat(start_str.replace("Z", "+00:00"))
        delta = (datetime.now(timezone.utc) - start_dt).total_seconds() / 3600
        # Allow small execution time slack; start should be roughly 6 h ago.
        assert 5.5 <= delta <= 7.0, f"Expected ~6 h lookback, got {delta:.2f} h"
