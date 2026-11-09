"""Unit tests for the anomaly intervals endpoint and related service logic.

Covers B-15 fixes:
- B-15-1: start >= stop validation → HTTP 400
- B-15-2: primary_type list serialization → str
- B-15-3: empty interval results
- B-15-4: psycopg2.OperationalError → HTTP 504
- B-15-5: statement_timeout reset on pooled connection after _execute_query_with_timeout
"""

from __future__ import annotations

from unittest.mock import MagicMock

import psycopg2
import pytest
from fastapi.testclient import TestClient

from otalon_api.main import app
from otalon_api.services.anomaly_service import AnomalyService, _build_intervals_for_uci
from otalon_api.settings import Settings


class TestB15InputValidation:
    """B-15-1: start >= stop validation on GET /api/v1/anomalies/intervals."""

    @pytest.mark.unit
    def test_start_equal_to_stop_returns_400(self, api_client: TestClient) -> None:
        """Equal start and stop timestamps must return HTTP 400.

        Args:
            api_client: FastAPI test client fixture.
        """
        ts = "2026-03-01T00:00:00Z"
        response = api_client.get(
            "/api/v1/anomalies/intervals",
            params={"uci": "aa:bb/cc:dd", "start": ts, "stop": ts},
            headers={"X-API-Key": "test-suite-key-do-not-use-in-prod"},
        )
        assert response.status_code == 400
        assert "start must be before stop" in response.json()["detail"]

    @pytest.mark.unit
    def test_start_after_stop_returns_400(self, api_client: TestClient) -> None:
        """start > stop must return HTTP 400.

        Args:
            api_client: FastAPI test client fixture.
        """
        response = api_client.get(
            "/api/v1/anomalies/intervals",
            params={
                "uci": "aa:bb/cc:dd",
                "start": "2026-03-15T00:00:00Z",
                "stop": "2026-03-01T00:00:00Z",
            },
            headers={"X-API-Key": "test-suite-key-do-not-use-in-prod"},
        )
        assert response.status_code == 400
        assert "start must be before stop" in response.json()["detail"]

    @pytest.mark.unit
    def test_start_before_stop_accepted(
        self,
        mock_postgres_repo: MagicMock,
        mock_settings: Settings,
        api_client: TestClient,
    ) -> None:
        """Valid start < stop combination must not be rejected by validation.

        The service is mocked to avoid actual DB calls; only the 400 guard is tested.

        Args:
            mock_postgres_repo: Mocked PostgresRepository.
            mock_settings: Test settings.
            api_client: FastAPI test client fixture.
        """
        mock_postgres_repo.query_anomaly_groups.return_value = []

        response = api_client.get(
            "/api/v1/anomalies/intervals",
            params={
                "uci": "aa:bb/cc:dd",
                "start": "2026-03-01T00:00:00Z",
                "stop": "2026-03-15T00:00:00Z",
            },
            headers={"X-API-Key": "test-suite-key-do-not-use-in-prod"},
        )
        assert response.status_code != 400

    @pytest.mark.unit
    def test_no_timestamps_accepted(self, api_client: TestClient) -> None:
        """Request without start/stop must not trigger the validation guard.

        Args:
            api_client: FastAPI test client fixture.
        """
        response = api_client.get(
            "/api/v1/anomalies/intervals",
            params={"uci": "aa:bb/cc:dd"},
            headers={"X-API-Key": "test-suite-key-do-not-use-in-prod"},
        )
        assert response.status_code != 400


class TestB15PrimaryTypeSerialization:
    """B-15-2: primary_type list/scalar normalization in _build_intervals_for_uci."""

    @pytest.mark.unit
    def test_primary_type_list_joined_to_string(self) -> None:
        """A list primary_type must be joined into a comma-separated string.

        The AlarmIntervalItem schema requires str|None; a raw list would cause
        a Pydantic validation error (HTTP 500).
        """
        uci = "aa:bb/cc:dd"
        groups = [
            {
                "id": "group-1",
                "series_ids": [uci],
                "start_timestamp": "2026-01-01T00:00:00Z",
                "end_timestamp": "2026-01-01T01:00:00Z",
                "primary_type": ["BoundViolation", "T0846/pn_discovery"],
            }
        ]
        result = _build_intervals_for_uci(groups, uci)

        assert len(result) == 1
        anomaly_type = result[0]["anomaly_type"]
        assert isinstance(anomaly_type, str)
        assert "BoundViolation" in anomaly_type
        assert "T0846/pn_discovery" in anomaly_type

    @pytest.mark.unit
    def test_primary_type_string_passed_through(self) -> None:
        """A string primary_type must be returned unchanged.

        Args: (implicit via closure)
        """
        uci = "aa:bb/cc:dd"
        groups = [
            {
                "id": "group-2",
                "series_ids": [uci],
                "start_timestamp": "2026-01-01T00:00:00Z",
                "end_timestamp": "2026-01-01T01:00:00Z",
                "primary_type": "BoundViolation",
            }
        ]
        result = _build_intervals_for_uci(groups, uci)

        assert result[0]["anomaly_type"] == "BoundViolation"

    @pytest.mark.unit
    def test_primary_type_none_returns_none(self) -> None:
        """A None primary_type must produce anomaly_type=None.

        Args: (implicit via closure)
        """
        uci = "aa:bb/cc:dd"
        groups = [
            {
                "id": "group-3",
                "series_ids": [uci],
                "start_timestamp": "2026-01-01T00:00:00Z",
                "end_timestamp": "2026-01-01T01:00:00Z",
                "primary_type": None,
            }
        ]
        result = _build_intervals_for_uci(groups, uci)

        assert result[0]["anomaly_type"] is None

    @pytest.mark.unit
    def test_primary_type_single_item_list(self) -> None:
        """A single-item list primary_type must produce a plain string.

        Args: (implicit via closure)
        """
        uci = "aa:bb/cc:dd"
        groups = [
            {
                "id": "group-4",
                "series_ids": [uci],
                "start_timestamp": "2026-01-01T00:00:00Z",
                "end_timestamp": "2026-01-01T01:00:00Z",
                "primary_type": ["OnlyType"],
            }
        ]
        result = _build_intervals_for_uci(groups, uci)

        assert result[0]["anomaly_type"] == "OnlyType"

    @pytest.mark.unit
    def test_primary_type_empty_list_produces_empty_string(self) -> None:
        """An empty list primary_type must produce an empty string.

        Args: (implicit via closure)
        """
        uci = "aa:bb/cc:dd"
        groups = [
            {
                "id": "group-5",
                "series_ids": [uci],
                "start_timestamp": "2026-01-01T00:00:00Z",
                "end_timestamp": "2026-01-01T01:00:00Z",
                "primary_type": [],
            }
        ]
        result = _build_intervals_for_uci(groups, uci)

        assert result[0]["anomaly_type"] == ""


class TestB15EmptyResults:
    """B-15-3: Empty result sets for get_anomaly_intervals."""

    @pytest.mark.unit
    async def test_empty_groups_returns_empty_data(
        self,
        mock_postgres_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """No alarm groups must produce data=[] and row_count=0.

        Args:
            mock_postgres_repo: Mocked PostgresRepository.
            mock_settings: Test settings.
        """
        mock_postgres_repo.query_anomaly_groups.return_value = []
        service = AnomalyService(mock_postgres_repo, mock_settings)

        result = await service.get_anomaly_intervals(uci="test/uci")

        assert result["data"] == []
        assert result["row_count"] == 0

    @pytest.mark.unit
    async def test_groups_without_matching_uci_returns_empty(
        self,
        mock_postgres_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """Alarm groups not containing the target UCI must yield empty results.

        Args:
            mock_postgres_repo: Mocked PostgresRepository.
            mock_settings: Test settings.
        """
        mock_postgres_repo.query_anomaly_groups.return_value = [
            {
                "id": "g1",
                "series_ids": ["other/uci"],
                "start_timestamp": "2026-01-01T00:00:00Z",
                "end_timestamp": "2026-01-02T00:00:00Z",
                "primary_type": "BoundViolation",
            }
        ]
        service = AnomalyService(mock_postgres_repo, mock_settings)

        result = await service.get_anomaly_intervals(uci="not/present")

        assert result["data"] == []
        assert result["row_count"] == 0

    @pytest.mark.unit
    async def test_matching_uci_produces_correct_interval(
        self,
        mock_postgres_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """Group containing the target UCI must appear in data with correct fields.

        Args:
            mock_postgres_repo: Mocked PostgresRepository.
            mock_settings: Test settings.
        """
        uci = "aa:bb/cc:dd/0//////Ethernet:PROFINET"
        mock_postgres_repo.query_anomaly_groups.return_value = [
            {
                "id": "group-abc",
                "series_ids": [uci, "other/uci"],
                "start_timestamp": "2026-01-01T00:00:00Z",
                "end_timestamp": "2026-01-01T01:00:00Z",
                "primary_type": "T0846/pn_discovery",
            }
        ]
        service = AnomalyService(mock_postgres_repo, mock_settings)

        result = await service.get_anomaly_intervals(uci=uci)

        assert result["row_count"] == 1
        interval = result["data"][0]
        assert interval["alarm_group_id"] == "group-abc"
        assert interval["anomaly_type"] == "T0846/pn_discovery"


class TestB15DatabaseTimeoutHandling:
    """B-15-4: psycopg2.OperationalError propagates as HTTP 504."""

    @pytest.mark.unit
    async def test_db_operational_error_raises_504(
        self,
        mock_postgres_repo: MagicMock,
        mock_settings: Settings,
        api_client: TestClient,
    ) -> None:
        """psycopg2.OperationalError from the repo must yield HTTP 504.

        The service layer propagates the OperationalError; the router
        converts it to a 504 response.

        Args:
            mock_postgres_repo: Mocked PostgresRepository.
            mock_settings: Test settings.
            api_client: FastAPI test client fixture.
        """
        from otalon_api import dependencies

        mock_postgres_repo.query_anomaly_groups.side_effect = psycopg2.OperationalError(
            "canceling statement due to statement timeout"
        )

        original_factory = dependencies.get_anomaly_service

        def patched_factory() -> AnomalyService:
            return AnomalyService(mock_postgres_repo, mock_settings)

        app.dependency_overrides[dependencies.get_anomaly_service] = patched_factory
        try:
            response = api_client.get(
                "/api/v1/anomalies/intervals",
                params={
                    "uci": "aa:bb/cc:dd",
                    "start": "2026-03-01T00:00:00Z",
                    "stop": "2026-03-15T00:00:00Z",
                },
                headers={"X-API-Key": "test-suite-key-do-not-use-in-prod"},
            )
        finally:
            app.dependency_overrides.pop(dependencies.get_anomaly_service, None)

        assert response.status_code == 504
        assert "timed out" in response.json()["detail"].lower()


class TestB15TimeoutReset:
    """B-15-5: statement_timeout is reset to 0 on the connection before returning to pool."""

    @pytest.mark.unit
    def test_statement_timeout_reset_after_successful_query(self) -> None:
        """After _execute_query_with_timeout succeeds, the connection must have its
        statement_timeout reset to 0 so that subsequent queries on the same pooled
        connection are not accidentally cancelled.
        """
        from otalon_api.repositories.postgres_repo import PostgresRepository

        repo = PostgresRepository(host="localhost", port=5432, user="u", password="p", database="d")

        mock_cursor = MagicMock()
        mock_cursor.__enter__ = MagicMock(return_value=mock_cursor)
        mock_cursor.__exit__ = MagicMock(return_value=False)
        mock_cursor.fetchall.return_value = []

        mock_conn = MagicMock()
        mock_conn.autocommit = True
        mock_conn.cursor.return_value = mock_cursor

        mock_pool = MagicMock()
        mock_pool.closed = False
        mock_pool.getconn.return_value = mock_conn
        repo._pool = mock_pool

        repo._execute_query_with_timeout("SELECT 1", timeout_seconds=5)

        execute_calls = [str(c) for c in mock_cursor.execute.call_args_list]
        reset_calls = [c for c in execute_calls if "statement_timeout = 0" in c]
        assert len(reset_calls) >= 1, (
            "statement_timeout must be reset to 0 after the query so that "
            "reused pooled connections do not inherit the timeout."
        )

    @pytest.mark.unit
    def test_statement_timeout_reset_after_failed_query(self) -> None:
        """When the query raises psycopg2.OperationalError (timeout), the
        connection is returned to the pool with close=True so that the
        polluted statement_timeout state is never reused.
        """
        from otalon_api.repositories.postgres_repo import PostgresRepository

        repo = PostgresRepository(host="localhost", port=5432, user="u", password="p", database="d")

        mock_cursor = MagicMock()
        mock_cursor.__enter__ = MagicMock(return_value=mock_cursor)
        mock_cursor.__exit__ = MagicMock(return_value=False)

        call_count = 0

        def raise_on_second_execute(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                raise psycopg2.OperationalError("canceling statement due to statement timeout")

        mock_cursor.execute.side_effect = raise_on_second_execute

        mock_conn = MagicMock()
        mock_conn.autocommit = True
        mock_conn.cursor.return_value = mock_cursor

        mock_pool = MagicMock()
        mock_pool.closed = False
        mock_pool.getconn.return_value = mock_conn
        repo._pool = mock_pool

        with pytest.raises(psycopg2.OperationalError):
            repo._execute_query_with_timeout("SELECT 1", timeout_seconds=5)

        mock_pool.putconn.assert_called_once_with(mock_conn, close=True)
