"""Unit tests for the ``/readyz`` readiness probe.

Covers the happy path (both dependencies up) and several failure-injection
scenarios (one dependency down, both down, exception, timeout) to ensure
the endpoint returns the expected HTTP status code and structured body.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from otalon_api.api.schemas.common import ReadinessResponse
from otalon_api.dependencies import get_influx_repo, get_postgres_repo
from otalon_api.main import app
from otalon_api.settings import Settings

_TEST_KEY = "test-suite-key-do-not-use-in-prod"


def _authed_client() -> TestClient:
    """Return a TestClient with a valid operator key armed for detail probes."""
    return TestClient(app, headers={"X-API-Key": _TEST_KEY})


@pytest.fixture()
def stub_repos():
    """Yield (postgres_mock, influx_mock) wired into the app via overrides.

    Yields:
        Tuple of (postgres_mock, influx_mock). Both come pre-wired with a
        passing ``health_check`` so individual tests only need to override
        the relevant side of the failure they want to inject.
    """
    pg = MagicMock()
    pg.health_check = MagicMock(return_value=True)
    influx = MagicMock()
    influx.health_check = AsyncMock(return_value=True)

    app.dependency_overrides[get_postgres_repo] = lambda: pg
    app.dependency_overrides[get_influx_repo] = lambda: influx
    with patch("otalon_api.middleware.auth.get_settings", return_value=Settings(admin_api_key=_TEST_KEY)):
        try:
            yield pg, influx
        finally:
            app.dependency_overrides.pop(get_postgres_repo, None)
            app.dependency_overrides.pop(get_influx_repo, None)


@pytest.mark.unit
def test_readyz_happy_path(stub_repos) -> None:
    """All dependencies up → HTTP 200 with status='ready'."""
    client = _authed_client()
    resp = client.get("/readyz?detail=true")
    assert resp.status_code == 200
    body = ReadinessResponse.model_validate(resp.json())
    assert body.status == "ready"
    assert {c.name for c in body.components} == {"postgres", "influxdb"}
    assert all(c.ready for c in body.components)


@pytest.mark.unit
def test_readyz_postgres_down(stub_repos) -> None:
    """PostgreSQL down → HTTP 503 with postgres.ready=False."""
    pg, _ = stub_repos
    pg.health_check = MagicMock(return_value=False)
    client = _authed_client()
    resp = client.get("/readyz?detail=true")
    assert resp.status_code == 503
    body = ReadinessResponse.model_validate(resp.json())
    assert body.status == "not_ready"
    by_name = {c.name: c for c in body.components}
    assert by_name["postgres"].ready is False
    assert by_name["influxdb"].ready is True


@pytest.mark.unit
def test_readyz_influx_down(stub_repos) -> None:
    """InfluxDB down → HTTP 503 with influxdb.ready=False."""
    _, influx = stub_repos
    influx.health_check = AsyncMock(return_value=False)
    client = _authed_client()
    resp = client.get("/readyz?detail=true")
    assert resp.status_code == 503
    body = ReadinessResponse.model_validate(resp.json())
    by_name = {c.name: c for c in body.components}
    assert by_name["postgres"].ready is True
    assert by_name["influxdb"].ready is False


@pytest.mark.unit
def test_readyz_both_down(stub_repos) -> None:
    """Both dependencies down → HTTP 503 and neither is ready."""
    pg, influx = stub_repos
    pg.health_check = MagicMock(return_value=False)
    influx.health_check = AsyncMock(return_value=False)
    client = _authed_client()
    resp = client.get("/readyz?detail=true")
    assert resp.status_code == 503
    body = ReadinessResponse.model_validate(resp.json())
    assert body.status == "not_ready"
    assert not any(c.ready for c in body.components)


@pytest.mark.unit
def test_readyz_postgres_raises(stub_repos) -> None:
    """Exception from postgres.health_check is reported as not ready."""
    pg, _ = stub_repos
    pg.health_check = MagicMock(side_effect=RuntimeError("pool exhausted"))
    client = _authed_client()
    resp = client.get("/readyz?detail=true")
    assert resp.status_code == 503
    body = ReadinessResponse.model_validate(resp.json())
    pg_status = next(c for c in body.components if c.name == "postgres")
    assert pg_status.ready is False
    assert "pool exhausted" in pg_status.detail


@pytest.mark.unit
def test_readyz_influx_timeout(stub_repos) -> None:
    """A hanging influx probe must be reported as timed out, not block."""
    _, influx = stub_repos

    async def _hang() -> bool:
        await asyncio.sleep(5.0)
        return True

    influx.health_check = _hang

    import otalon_api.api.v1.status as status_module

    original = status_module.READYZ_PROBE_TIMEOUT_S
    status_module.READYZ_PROBE_TIMEOUT_S = 0.05
    try:
        client = _authed_client()
        resp = client.get("/readyz?detail=true")
    finally:
        status_module.READYZ_PROBE_TIMEOUT_S = original

    assert resp.status_code == 503
    body = ReadinessResponse.model_validate(resp.json())
    influx_status = next(c for c in body.components if c.name == "influxdb")
    assert influx_status.ready is False
    assert "timeout" in influx_status.detail.lower()
