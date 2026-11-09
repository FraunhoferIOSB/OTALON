"""Unit tests for the B-20 network throughput sparkline feature.

Tests cover:
- InfluxRepository.query_network_throughput() SQL generation and result parsing
- DashboardKpiService.get_throughput() delegation and response structure
- GET /api/v1/dashboard/throughput endpoint schema compliance
"""

from __future__ import annotations

from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pandas as pd
import pytest
from fastapi.testclient import TestClient

from otalon_api.api.schemas.dashboard import ThroughputDataPoint, ThroughputResponse
from otalon_api.repositories.influx_repo import InfluxRepository
from otalon_api.services.dashboard_kpi_service import DashboardKpiService


@pytest.fixture()
def mock_influx_client():
    """Create an InfluxRepository with a mocked InfluxDBClient3.

    Yields:
        A tuple of (InfluxRepository, MagicMock) where the mock represents
        the underlying ``_client``.
    """
    with patch("otalon_api.repositories.influx_repo.InfluxDBClient3", autospec=True) as mock_cls:
        mock_client = MagicMock()
        mock_cls.return_value = mock_client
        repo = InfluxRepository(
            host="localhost",
            port=8181,
            token="test-token",
            org="test-org",
            database="netcap",
        )
        yield repo, mock_client


def _make_query_result(df: pd.DataFrame) -> MagicMock:
    """Wrap a DataFrame in a mock query result with a ``to_pandas()`` method.

    Args:
        df: DataFrame to return from the mock.

    Returns:
        MagicMock with ``to_pandas`` returning *df*.
    """
    result = MagicMock()
    result.to_pandas.return_value = df
    return result


@pytest.mark.unit
class TestQueryNetworkThroughput:
    """Tests for InfluxRepository.query_network_throughput()."""

    def test_returns_list_of_dicts(self, mock_influx_client):
        """query_network_throughput returns list of dicts with correct keys."""
        repo, client = mock_influx_client
        df_result = pd.DataFrame(
            {
                "bucket": pd.to_datetime(["2025-01-01T00:00:00Z", "2025-01-01T00:01:00Z"]),
                "total_bytes": [50000, 60000],
                "total_packets": [100, 120],
            }
        )
        client.query.return_value = _make_query_result(df_result)

        rows, bucket_seconds = repo.query_network_throughput(
            measurement="network_metrics",
            start="2025-01-01T00:00:00Z",
            stop="2025-01-01T01:00:00Z",
            buckets=60,
        )

        assert len(rows) == 2
        assert rows[0]["total_bytes"] == 50000
        assert rows[0]["total_packets"] == 100
        assert "timestamp" in rows[0]
        assert isinstance(bucket_seconds, int)
        assert bucket_seconds > 0

    def test_sql_contains_sum_date_bin_group_by(self, mock_influx_client):
        """query_network_throughput generates correct SQL structure."""
        repo, client = mock_influx_client
        df_result = pd.DataFrame()
        client.query.return_value = _make_query_result(df_result)

        repo.query_network_throughput(
            measurement="network_metrics",
            start="2025-01-01T00:00:00Z",
            stop="2025-01-01T01:00:00Z",
            buckets=60,
        )

        sql = client.query.call_args[0][0]
        assert "date_bin(" in sql.lower()
        assert "SUM" in sql
        assert "total_volume" in sql
        assert "packet_count" in sql
        assert "GROUP BY" in sql
        assert "ORDER BY" in sql

    def test_empty_result_returns_empty_list(self, mock_influx_client):
        """query_network_throughput returns ([], bucket_seconds) for empty data."""
        repo, client = mock_influx_client
        df_result = pd.DataFrame()
        client.query.return_value = _make_query_result(df_result)

        rows, bucket_seconds = repo.query_network_throughput(
            measurement="network_metrics",
            start="2025-01-01T00:00:00Z",
            stop="2025-01-01T01:00:00Z",
        )

        assert rows == []
        assert isinstance(bucket_seconds, int)
        assert bucket_seconds > 0

    def test_exception_returns_empty_list(self, mock_influx_client):
        """query_network_throughput returns empty list on exception."""
        repo, client = mock_influx_client
        client.query.side_effect = Exception("connection refused")

        rows, bucket_seconds = repo.query_network_throughput(
            measurement="network_metrics",
            start="2025-01-01T00:00:00Z",
            stop="2025-01-01T01:00:00Z",
        )

        assert rows == []
        assert isinstance(bucket_seconds, int)

    def test_bucket_seconds_calculation(self, mock_influx_client):
        """Bucket seconds is derived from time range and desired bucket count."""
        repo, client = mock_influx_client
        df_result = pd.DataFrame()
        client.query.return_value = _make_query_result(df_result)

        _, bucket_seconds = repo.query_network_throughput(
            measurement="network_metrics",
            start="2025-01-01T00:00:00Z",
            stop="2025-01-01T01:00:00Z",
            buckets=60,
        )

        assert bucket_seconds == 60

    def test_larger_window_increases_bucket(self, mock_influx_client):
        """A 24h window with 60 buckets yields a bucket size > 60s."""
        repo, client = mock_influx_client
        df_result = pd.DataFrame()
        client.query.return_value = _make_query_result(df_result)

        _, bucket_seconds = repo.query_network_throughput(
            measurement="network_metrics",
            start="2025-01-01T00:00:00Z",
            stop="2025-01-02T00:00:00Z",
            buckets=60,
        )

        assert bucket_seconds >= 300

    def test_where_clause_uses_start_stop(self, mock_influx_client):
        """WHERE clause contains the aligned start and stop timestamps."""
        repo, client = mock_influx_client
        df_result = pd.DataFrame()
        client.query.return_value = _make_query_result(df_result)

        repo.query_network_throughput(
            measurement="network_metrics",
            start="2025-06-15T10:00:00Z",
            stop="2025-06-15T11:00:00Z",
        )

        sql = client.query.call_args[0][0]
        assert "2025-06-15T10:00:00" in sql
        assert "2025-06-15T11:00:00" in sql


@pytest.mark.unit
class TestDashboardKpiServiceThroughput:
    """Tests for DashboardKpiService.get_throughput()."""

    async def test_get_throughput_returns_correct_structure(
        self,
        mock_postgres_repo: MagicMock,
        mock_influx_repo: MagicMock,
        mock_settings,
    ) -> None:
        """get_throughput returns dict with data, bucket_seconds, parameters."""
        mock_influx_repo.query_network_throughput.return_value = (
            [
                {
                    "timestamp": "2025-01-01T00:00:00",
                    "total_bytes": 1000,
                    "total_packets": 10,
                },
                {
                    "timestamp": "2025-01-01T00:01:00",
                    "total_bytes": 2000,
                    "total_packets": 20,
                },
            ],
            60,
        )

        service = DashboardKpiService(mock_postgres_repo, mock_influx_repo, mock_settings)
        result = await service.get_throughput(
            start=datetime(2025, 1, 1, 0, 0, 0),
            stop=datetime(2025, 1, 1, 1, 0, 0),
            buckets=60,
        )

        assert "data" in result
        assert "bucket_seconds" in result
        assert "parameters" in result
        assert len(result["data"]) == 2
        assert result["bucket_seconds"] == 60

    async def test_get_throughput_empty_data(
        self,
        mock_postgres_repo: MagicMock,
        mock_influx_repo: MagicMock,
        mock_settings,
    ) -> None:
        """get_throughput with no data returns empty list."""
        mock_influx_repo.query_network_throughput.return_value = ([], 60)

        service = DashboardKpiService(mock_postgres_repo, mock_influx_repo, mock_settings)
        result = await service.get_throughput()

        assert result["data"] == []
        assert result["bucket_seconds"] == 60

    async def test_get_throughput_default_window(
        self,
        mock_postgres_repo: MagicMock,
        mock_influx_repo: MagicMock,
        mock_settings,
    ) -> None:
        """get_throughput without start/stop uses a default 1-hour window."""
        mock_influx_repo.query_network_throughput.return_value = ([], 60)

        service = DashboardKpiService(mock_postgres_repo, mock_influx_repo, mock_settings)
        await service.get_throughput()

        call_kwargs = mock_influx_repo.query_network_throughput.call_args.kwargs
        assert call_kwargs["start"] is not None
        assert call_kwargs["stop"] is not None
        assert call_kwargs["buckets"] == 60

    async def test_get_throughput_passes_buckets(
        self,
        mock_postgres_repo: MagicMock,
        mock_influx_repo: MagicMock,
        mock_settings,
    ) -> None:
        """get_throughput forwards custom bucket count to the repository."""
        mock_influx_repo.query_network_throughput.return_value = ([], 30)

        service = DashboardKpiService(mock_postgres_repo, mock_influx_repo, mock_settings)
        await service.get_throughput(buckets=120)

        call_kwargs = mock_influx_repo.query_network_throughput.call_args.kwargs
        assert call_kwargs["buckets"] == 120


@pytest.mark.unit
class TestThroughputSchemas:
    """Tests for the B-20 Pydantic schemas."""

    def test_throughput_data_point_valid(self) -> None:
        """ThroughputDataPoint accepts valid data."""
        point = ThroughputDataPoint(
            timestamp="2025-01-01T00:00:00",
            total_bytes=1000,
            total_packets=10,
        )
        assert point.timestamp == "2025-01-01T00:00:00"
        assert point.total_bytes == 1000
        assert point.total_packets == 10

    def test_throughput_response_valid(self) -> None:
        """ThroughputResponse accepts valid data."""
        response = ThroughputResponse(
            data=[
                ThroughputDataPoint(
                    timestamp="2025-01-01T00:00:00",
                    total_bytes=1000,
                    total_packets=10,
                ),
            ],
            bucket_seconds=60,
            parameters={"start": "2025-01-01T00:00:00", "stop": "2025-01-01T01:00:00"},
        )
        assert len(response.data) == 1
        assert response.bucket_seconds == 60

    def test_throughput_response_empty_data(self) -> None:
        """ThroughputResponse accepts empty data list."""
        response = ThroughputResponse(
            data=[],
            bucket_seconds=60,
            parameters={},
        )
        assert response.data == []


@pytest.mark.unit
class TestThroughputEndpoint:
    """Tests for GET /api/v1/dashboard/throughput."""

    def test_endpoint_returns_200(self, api_client: TestClient) -> None:
        """Throughput endpoint returns 200 with valid mocked service."""
        from otalon_api.dependencies import get_dashboard_kpi_service
        from otalon_api.main import app

        mock_service = MagicMock()
        mock_service.get_throughput = AsyncMock(
            return_value={
                "data": [
                    {
                        "timestamp": "2025-01-01T00:00:00",
                        "total_bytes": 1000,
                        "total_packets": 10,
                    },
                ],
                "bucket_seconds": 60,
                "parameters": {"start": None, "stop": None, "buckets": 60},
            }
        )

        app.dependency_overrides[get_dashboard_kpi_service] = lambda: mock_service
        try:
            response = api_client.get("/api/v1/dashboard/throughput")
            assert response.status_code == 200
            body = response.json()
            assert "data" in body
            assert "bucket_seconds" in body
            assert "parameters" in body
            assert body["bucket_seconds"] == 60
        finally:
            app.dependency_overrides.clear()

    def test_endpoint_validates_buckets_min(self, api_client: TestClient) -> None:
        """Throughput endpoint rejects buckets < 10."""
        response = api_client.get("/api/v1/dashboard/throughput?buckets=5")
        assert response.status_code == 422

    def test_endpoint_validates_buckets_max(self, api_client: TestClient) -> None:
        """Throughput endpoint rejects buckets > 300."""
        response = api_client.get("/api/v1/dashboard/throughput?buckets=500")
        assert response.status_code == 422

    def test_endpoint_500_on_service_error(self, api_client: TestClient) -> None:
        """Throughput endpoint returns 500 when service raises."""
        from otalon_api.dependencies import get_dashboard_kpi_service
        from otalon_api.main import app

        mock_service = MagicMock()
        mock_service.get_throughput = AsyncMock(side_effect=Exception("db error"))

        app.dependency_overrides[get_dashboard_kpi_service] = lambda: mock_service
        try:
            response = api_client.get("/api/v1/dashboard/throughput")
            assert response.status_code == 500
        finally:
            app.dependency_overrides.clear()
