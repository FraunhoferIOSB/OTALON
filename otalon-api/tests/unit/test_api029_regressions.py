"""Regression tests for API-029 and related suite findings."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from otalon_api.main import app
from otalon_api.middleware.auth import PROTECTED_PATH_PREFIXES, PUBLIC_PROBE_PATHS
from otalon_api.middleware.rate_limit import lookup_rate_limiter
from otalon_api.services.topology_service import TopologyService
from otalon_api.settings import Settings


def _settings() -> Settings:
    """Return settings with one valid operator API key."""
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
        admin_api_key="test-key",
        api_port=8090,
        netcap_measurement="network_metrics",
        netcap_id_tag="uci",
        netcap_sparse_port_threshold=10,
        default_sample_max_points=500,
    )


@pytest.mark.unit
def test_every_registered_api_route_is_deny_by_default() -> None:
    """Every registered route is covered except explicit probe endpoints."""
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        if route.path in PUBLIC_PROBE_PATHS:
            continue
        assert any(route.path.startswith(prefix) for prefix in PROTECTED_PATH_PREFIXES)


@pytest.mark.unit
def test_topology_devices_excludes_other_segments() -> None:
    """Device inventory only returns interfaces in 192.168.0.0/24."""
    postgres = MagicMock()
    postgres.query_devices.return_value = [{"id": 1}, {"id": 2}]
    postgres.query_devices_total_count.return_value = 2
    postgres.query_network_interfaces_for_devices.return_value = {
        1: [{"ipv4_address": "192.168.0.10"}],
        2: [{"ipv4_address": "10.105.1.5"}],
    }
    postgres.query_device_topology_view.return_value = {}
    postgres.query_network_interface_ports_view.return_value = {}
    service = TopologyService(postgres, MagicMock(), _settings())

    result = asyncio.run(service.get_devices(limit=100, offset=0))

    assert result["total"] == 1
    assert [device["id"] for device in result["devices"]] == [1]


@pytest.mark.unit
def test_lookup_requires_auth_and_enforces_rate_limit() -> None:
    """Lookup rejects unauthenticated requests and throttles authenticated ones."""
    lookup_rate_limiter._requests.clear()
    service = MagicMock()
    service.lookup_vulnerabilities = AsyncMock(return_value=(200, {"job_id": "job"}))
    app.state.scan_proxy_service = service
    try:
        with patch("otalon_api.middleware.auth.get_settings", return_value=_settings()):
            client = TestClient(app, headers={"X-API-Key": ""})
            assert client.post("/api/v1/vulnerabilities/lookup", json={}).status_code == 401
            client = TestClient(app, headers={"X-API-Key": "test-key"})
            responses = [client.post("/api/v1/vulnerabilities/lookup", json={}) for _ in range(6)]
        assert [response.status_code for response in responses] == [200] * 5 + [429]
    finally:
        lookup_rate_limiter._requests.clear()


@pytest.mark.unit
def test_security_headers_are_present_and_process_time_is_absent() -> None:
    """API responses include browser hardening headers without timing leakage."""
    with patch("otalon_api.middleware.auth.get_settings", return_value=_settings()):
        response = TestClient(app, headers={"X-API-Key": ""}).get("/livez")

    assert response.status_code == 200
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["content-security-policy"] == "frame-ancestors 'none'"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "x-process-time" not in response.headers
