"""Unit tests for the /api/v1/operations/capture-status route."""

from __future__ import annotations

from typing import Iterator
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from otalon_api.dependencies import get_capture_status_service
from otalon_api.main import app
from otalon_api.services.capture_status_service import CaptureStatusResult
from otalon_api.settings import Settings


def _make_settings(api_key: str = "test-secret") -> Settings:
    """Create test settings with the given admin API key."""
    return Settings(
        influxdb_host="localhost",
        influxdb_port=8181,
        influxdb_token="test-token",
        influxdb_org="test-org",
        influxdb_database="netcap",
        postgres_host="localhost",
        postgres_port=5432,
        postgres_user="test",
        postgres_password="test",
        postgres_database="test",
        admin_api_key=api_key,
        api_port=8090,
        pcap_recorder_host="recorder-test",
        pcap_recorder_port=9090,
        pcap_recorder_timeout_s=1.0,
        netcap_measurement="network_metrics",
        netcap_id_tag="uci",
        netcap_sparse_port_threshold=10,
        default_sample_max_points=500,
    )


class _MockCaptureService:
    """Minimal stand-in for CaptureStatusService in router tests."""

    def __init__(self) -> None:
        """Initialize call-tracking flags."""
        self.status_awaited = False

    async def get_status(self) -> CaptureStatusResult:
        """Return a deterministic populated snapshot."""
        self.status_awaited = True
        return CaptureStatusResult(
            interface="enp5s0",
            link_up=True,
            recording=True,
            drops_24h_pct=None,
            overflows=None,
        )


@pytest.fixture()
def mock_service() -> Iterator[_MockCaptureService]:
    """Inject a mock capture status service via ``app.dependency_overrides``."""
    service = _MockCaptureService()
    app.dependency_overrides[get_capture_status_service] = lambda: service
    try:
        yield service
    finally:
        app.dependency_overrides.pop(get_capture_status_service, None)


@pytest.mark.unit
class TestCaptureStatusAuth:
    """Auth tests for the capture-status endpoint."""

    def test_capture_status_401_without_key(self) -> None:
        """GET without API key returns 401 when admin key is configured."""
        settings = _make_settings()
        with patch("otalon_api.middleware.auth.get_settings", return_value=settings):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get("/api/v1/operations/capture-status")
            assert response.status_code == 401

    def test_capture_status_200_with_key(self, mock_service: _MockCaptureService) -> None:
        """GET with valid key returns the snapshot from the mock."""
        settings = _make_settings()
        with patch("otalon_api.middleware.auth.get_settings", return_value=settings):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get(
                "/api/v1/operations/capture-status",
                headers={"X-API-Key": "test-secret"},
            )

            assert response.status_code == 200
            data = response.json()
            assert data["interface"] == "enp5s0"
            assert data["link_up"] is True
            assert data["recording"] is True
            assert mock_service.status_awaited is True


@pytest.mark.unit
class TestCaptureStatusFailClosed:
    """Fail-closed behavior when no admin key is configured."""

    def test_capture_status_503_when_key_unset(self) -> None:
        """Operations capture-status returns 503 (not pass-through) when key unset."""
        settings = _make_settings(api_key="")
        with patch("otalon_api.middleware.auth.get_settings", return_value=settings):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get("/api/v1/operations/capture-status")
            assert response.status_code == 503
            assert response.json()["detail"] == "API key authentication unavailable"


@pytest.mark.unit
class TestCaptureStatusResponse:
    """Response-shape tests for /api/v1/operations/capture-status."""

    def test_response_has_all_fields(self, mock_service: _MockCaptureService) -> None:
        """The response contains every capture-status field."""
        settings = _make_settings()
        with patch("otalon_api.middleware.auth.get_settings", return_value=settings):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get(
                "/api/v1/operations/capture-status",
                headers={"X-API-Key": "test-secret"},
            )
            data = response.json()
            assert "interface" in data
            assert "link_up" in data
            assert "recording" in data
            assert "drops_24h_pct" in data
            assert "overflows" in data

    def test_response_does_not_leak_secrets(self, mock_service: _MockCaptureService) -> None:
        """A populated response body contains no token/password/secret fields."""
        settings = _make_settings()
        with patch("otalon_api.middleware.auth.get_settings", return_value=settings):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get(
                "/api/v1/operations/capture-status",
                headers={"X-API-Key": "test-secret"},
            )
            assert mock_service.status_awaited is True
            body = response.text.lower()
            assert "token" not in body
            assert "password" not in body
            assert "secret" not in body


@pytest.mark.unit
class TestCaptureStatusDoesNotMutate:
    """Prove the GET endpoint is read-only and does not alter capture state."""

    def test_get_status_only_reads_via_service(self, mock_service: _MockCaptureService) -> None:
        """The route delegates to the service's read-only ``get_status``.

        The endpoint exposes no start/stop/reconfigure verb: only ``GET`` is
        routed, and it resolves solely through the injected service, which is
        itself a read-only proxy.
        """
        settings = _make_settings()
        with patch("otalon_api.middleware.auth.get_settings", return_value=settings):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get(
                "/api/v1/operations/capture-status",
                headers={"X-API-Key": "test-secret"},
            )
            assert response.status_code == 200
            assert mock_service.status_awaited is True

            # No mutating verb is accepted on the capture-status route.
            for verb in (client.post, client.put, client.delete, client.patch):
                mutate = verb(
                    "/api/v1/operations/capture-status",
                    headers={"X-API-Key": "test-secret"},
                )
                assert mutate.status_code == 405
