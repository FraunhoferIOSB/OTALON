"""Unit tests for the operations router.

Covers auth protection, response shape, and the absence of secrets in the
payload. The pipeline service is injected via ``app.dependency_overrides``
so that FastAPI actually resolves the mock (module-level ``patch`` does not
override an already-captured ``Depends`` reference) and **no** real
Influx/Postgres connection is opened. Every test clears its override in a
``finally`` block so state never leaks between tests.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterator
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from otalon_api.dependencies import get_operations_pipeline_service
from otalon_api.main import app
from otalon_api.services.operations_pipeline_service import (
    DetectionFreshness,
    InfluxFreshness,
    PipelineFreshness,
    SourceFreshness,
)
from otalon_api.settings import Settings


def _make_settings(api_key: str = "test-secret") -> Settings:
    """Create test settings with the given admin API key."""
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
        admin_api_key=api_key,
        api_port=8090,
        netcap_measurement="network_metrics",
        netcap_id_tag="uci",
        netcap_sparse_port_threshold=10,
        default_sample_max_points=500,
    )


def _fresh_snapshot() -> PipelineFreshness:
    """Return a deterministic *populated* pipeline freshness snapshot.

    The snapshot carries realistic timestamps, ages, records-per-hour and a
    detection cycle so that the secret-leak assertion runs against a full
    payload rather than an empty ``no-data`` body.
    """
    now = datetime.now(timezone.utc)
    return PipelineFreshness(
        sources=[
            SourceFreshness(
                name="conn",
                last_record=now,
                age_seconds=2,
                state="current",
                records_per_hour=100,
                expected_interval_seconds=5,
            ),
            SourceFreshness(
                name="mac",
                last_record=now,
                age_seconds=2,
                state="current",
                records_per_hour=80,
                expected_interval_seconds=5,
            ),
            SourceFreshness(
                name="proto",
                last_record=now,
                age_seconds=2,
                state="current",
                records_per_hour=60,
                expected_interval_seconds=5,
            ),
        ],
        influx=InfluxFreshness(last_write=now, age_seconds=2),
        detection=DetectionFreshness(
            last_cycle=now,
            age_seconds=10,
            duration_seconds=None,
            series_evaluated=42,
        ),
        backlog=None,
    )


class _MockPipelineService:
    """Minimal stand-in for OperationsPipelineService in router tests.

    Records whether each coroutine was actually awaited so tests can prove
    the injected mock — not the real service — served the request.
    """

    def __init__(self) -> None:
        """Initialize call-tracking flags."""
        self.pipeline_awaited = False
        self.attention_awaited = False

    async def get_pipeline(self) -> PipelineFreshness:
        """Return a deterministic populated snapshot."""
        self.pipeline_awaited = True
        return _fresh_snapshot()

    async def get_attention(self) -> list[dict[str, Any]]:
        """Return one stale-source finding."""
        self.attention_awaited = True
        return [
            {
                "priority": "High",
                "kind": "warn",
                "title": "Protocols source stale — <1 min since last record",
                "link": {"label": "Data Sources", "route": "/operations/data-sources"},
            }
        ]


@pytest.fixture()
def mock_service() -> Iterator[_MockPipelineService]:
    """Inject a mock pipeline service via ``app.dependency_overrides``.

    Yields:
        The installed :class:`_MockPipelineService`. The override is removed
        in a ``finally`` block so it never leaks into another test.
    """
    service = _MockPipelineService()
    app.dependency_overrides[get_operations_pipeline_service] = lambda: service
    try:
        yield service
    finally:
        app.dependency_overrides.pop(get_operations_pipeline_service, None)


@pytest.mark.unit
class TestOperationsAuth:
    """Auth tests for the /api/v1/operations prefix."""

    def test_pipeline_401_without_key(self) -> None:
        """GET /pipeline without API key returns 401 when key is configured."""
        settings = _make_settings()
        with patch("otalon_api.middleware.auth.get_settings", return_value=settings):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get("/api/v1/operations/pipeline")
            assert response.status_code == 401

    def test_pipeline_200_with_key(self, mock_service: _MockPipelineService) -> None:
        """GET /pipeline with a valid API key returns the snapshot from the mock."""
        settings = _make_settings()
        with patch("otalon_api.middleware.auth.get_settings", return_value=settings):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get(
                "/api/v1/operations/pipeline",
                headers={"X-API-Key": "test-secret"},
            )

            assert response.status_code == 200
            data = response.json()
            assert len(data["sources"]) == 3
            for source in data["sources"]:
                assert source["state"] in ("current", "stale", "no-data")
            assert mock_service.pipeline_awaited is True

    def test_attention_protected(self) -> None:
        """GET /attention rejects unauthenticated requests."""
        settings = _make_settings()
        with patch("otalon_api.middleware.auth.get_settings", return_value=settings):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get("/api/v1/operations/attention")
            assert response.status_code == 401

    def test_public_status_still_unprotected(self) -> None:
        """The /api/v1/status/health endpoint remains public."""
        settings = _make_settings()
        with patch("otalon_api.middleware.auth.get_settings", return_value=settings):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get("/api/v1/status/health")
            assert response.status_code != 401


@pytest.mark.unit
class TestOperationsFailClosed:
    """Fail-closed behavior when no admin key is configured."""

    def test_operations_503_when_key_unset(self) -> None:
        """Operations reads return 503 (not pass-through) when key is unset."""
        settings = _make_settings(api_key="")
        with patch("otalon_api.middleware.auth.get_settings", return_value=settings):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get("/api/v1/operations/pipeline")
            assert response.status_code == 503
            assert response.json()["detail"] == "API key authentication unavailable"

    def test_attention_503_when_key_unset(self) -> None:
        """Attention reads also fail closed when key is unset."""
        settings = _make_settings(api_key="")
        with patch("otalon_api.middleware.auth.get_settings", return_value=settings):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get("/api/v1/operations/attention")
            assert response.status_code == 503

    def test_public_status_still_public_when_key_unset(self) -> None:
        """Public health stays reachable even when the admin key is unset."""
        settings = _make_settings(api_key="")
        with patch("otalon_api.middleware.auth.get_settings", return_value=settings):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get("/api/v1/status/health")
            assert response.status_code != 401
            assert response.status_code != 503


@pytest.mark.unit
class TestOperationsPipelineResponse:
    """Response-shape tests for /api/v1/operations/pipeline."""

    def test_response_has_three_sources(self, mock_service: _MockPipelineService) -> None:
        """The response contains conn, mac, and proto entries."""
        settings = _make_settings()
        with patch("otalon_api.middleware.auth.get_settings", return_value=settings):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get(
                "/api/v1/operations/pipeline",
                headers={"X-API-Key": "test-secret"},
            )
            data = response.json()
            names = {s["name"] for s in data["sources"]}
            assert names == {"conn", "mac", "proto"}
            assert mock_service.pipeline_awaited is True

    def test_response_includes_influx_and_detection(self, mock_service: _MockPipelineService) -> None:
        """The response includes influx, detection and backlog fields."""
        settings = _make_settings()
        with patch("otalon_api.middleware.auth.get_settings", return_value=settings):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get(
                "/api/v1/operations/pipeline",
                headers={"X-API-Key": "test-secret"},
            )
            data = response.json()
            assert "influx" in data
            assert "detection" in data
            assert "backlog" in data

    def test_response_does_not_leak_secrets(self, mock_service: _MockPipelineService) -> None:
        """A *populated* response body contains no token/password/secret fields."""
        settings = _make_settings()
        with patch("otalon_api.middleware.auth.get_settings", return_value=settings):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get(
                "/api/v1/operations/pipeline",
                headers={"X-API-Key": "test-secret"},
            )
            # Assert against the populated mock payload, not a no-data body.
            assert mock_service.pipeline_awaited is True
            data = response.json()
            assert data["sources"][0]["last_record"] is not None
            body = response.text.lower()
            assert "token" not in body
            assert "password" not in body
            assert "secret" not in body


@pytest.mark.unit
class TestOperationsAttentionResponse:
    """Response-shape tests for /api/v1/operations/attention."""

    def test_attention_uses_mock_and_omits_priority_codes(self, mock_service: _MockPipelineService) -> None:
        """Attention is served by the mock and carries no raw priority codes."""
        settings = _make_settings()
        with patch("otalon_api.middleware.auth.get_settings", return_value=settings):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get(
                "/api/v1/operations/attention",
                headers={"X-API-Key": "test-secret"},
            )
            assert response.status_code == 200
            assert mock_service.attention_awaited is True
            body = response.text
            assert "P2" not in body
            assert "P3" not in body


@pytest.mark.unit
class TestOperationsRouterDoesNotTouchRepositories:
    """Prove the router unit tests never open a real repository connection."""

    def test_unit_tests_do_not_construct_repositories(self, mock_service: _MockPipelineService) -> None:
        """With the service overridden, no InfluxDB/Postgres client is created.

        Sentinels replace the repository constructors so that any attempt to
        instantiate them (which the overridden service must not do) fails the
        test loudly instead of silently hitting :8181/:5432.
        """
        settings = _make_settings()

        def _boom(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("unit test must not construct a real repository")

        with (
            patch("otalon_api.middleware.auth.get_settings", return_value=settings),
            patch("otalon_api.dependencies.get_influx_repo", side_effect=_boom),
            patch("otalon_api.dependencies.get_postgres_repo", side_effect=_boom),
        ):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get(
                "/api/v1/operations/pipeline",
                headers={"X-API-Key": "test-secret"},
            )

        assert response.status_code == 200
        assert mock_service.pipeline_awaited is True
