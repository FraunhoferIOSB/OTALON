"""Unit tests for the /api/v1/operations/passive-discovery route.

Covers auth protection, the exact read-only response shape, and the
runtime-control capability flag. The service is injected via
``app.dependency_overrides`` so FastAPI resolves the mock and no real
Postgres connection is opened. Overrides are cleared in ``finally``.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Iterator
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from otalon_api.dependencies import get_passive_discovery_service
from otalon_api.main import app
from otalon_api.services.passive_discovery_service import PassiveDiscoveryStatus
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


class _MockPassiveDiscoveryService:
    """Stand-in returning a deterministic current snapshot."""

    def __init__(self) -> None:
        """Track whether the coroutine was awaited."""
        self.awaited = False

    async def get_status(self) -> PassiveDiscoveryStatus:
        """Return a populated current snapshot."""
        self.awaited = True
        now = datetime.now(timezone.utc)
        return PassiveDiscoveryStatus(
            observed_asset_count=10,
            observed_interface_count=10,
            latest_seen_at=now - timedelta(seconds=30),
            first_seen_at=now - timedelta(days=19),
            age_seconds=30,
            freshness="current",
            runtime_control_enabled=False,
        )


@pytest.fixture()
def mock_service() -> Iterator[_MockPassiveDiscoveryService]:
    """Inject the mock passive-discovery service via dependency override."""
    service = _MockPassiveDiscoveryService()
    app.dependency_overrides[get_passive_discovery_service] = lambda: service
    try:
        yield service
    finally:
        app.dependency_overrides.pop(get_passive_discovery_service, None)


@pytest.mark.unit
class TestPassiveDiscoveryRoute:
    """Tests for the read-only passive-discovery status endpoint."""

    def test_401_without_key(self) -> None:
        """The route is protected under the operations prefix."""
        settings = _make_settings()
        with patch("otalon_api.middleware.auth.get_settings", return_value=settings):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get("/api/v1/operations/passive-discovery")
            assert response.status_code == 401

    def test_200_returns_producer_truth(self, mock_service: _MockPassiveDiscoveryService) -> None:
        """With a valid key the endpoint returns the persisted producer facts."""
        settings = _make_settings()
        with patch("otalon_api.middleware.auth.get_settings", return_value=settings):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get(
                "/api/v1/operations/passive-discovery",
                headers={"X-API-Key": "test-secret"},
            )
            assert response.status_code == 200
            data = response.json()
            assert data["observed_asset_count"] == 10
            assert data["observed_interface_count"] == 10
            assert data["freshness"] == "current"
            assert data["latest_seen_at"] is not None
            assert data["runtime_control_enabled"] is False
            assert mock_service.awaited is True

    def test_capability_never_true(self, mock_service: _MockPassiveDiscoveryService) -> None:
        """runtime_control_enabled must stay false (UI-015 deferred)."""
        settings = _make_settings()
        with patch("otalon_api.middleware.auth.get_settings", return_value=settings):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get(
                "/api/v1/operations/passive-discovery",
                headers={"X-API-Key": "test-secret"},
            )
            assert response.json()["runtime_control_enabled"] is False
