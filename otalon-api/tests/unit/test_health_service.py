"""Unit tests for HealthService build_probes, check_http, check_tcp, check_docker, and check_all.

Tests probe construction, HTTP/TCP/Docker health checks with mocked I/O, and the
aggregated check_all workflow.  The _compute_overall_status method is already
covered in test_phase3_services.py and intentionally skipped here.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from otalon_api.services.health_service import HealthService, ServiceProbe
from otalon_api.settings import Settings


def _test_settings(**overrides: Any) -> Settings:
    """Create a Settings instance with test defaults.

    Args:
        **overrides: Keyword arguments forwarded to ``Settings`` to override defaults.

    Returns:
        Settings configured for testing.
    """
    defaults: dict[str, Any] = {
        "influxdb_host": "localhost",
        "influxdb_port": 8181,
        "influxdb_token": "test-token",
        "influxdb_org": "test-org",
        "influxdb_database": "netcap",
        "postgres_host": "localhost",
        "postgres_port": 5432,
        "postgres_user": "test",
        "postgres_password": "test",
        "postgres_database": "test",
        "admin_api_key": "test-key",
        "api_port": 8090,
        "netcap_measurement": "network_metrics",
        "netcap_id_tag": "uci",
        "netcap_sparse_port_threshold": 10,
        "utc_offset_hours": 1,
        "default_sample_max_points": 500,
    }
    defaults.update(overrides)
    return Settings(**defaults)


def _find_probe(probes: list[ServiceProbe], name: str) -> ServiceProbe:
    """Find a probe by name in a list of probes.

    Args:
        probes: List of ServiceProbe instances.
        name: The probe name to search for.

    Returns:
        The matching ServiceProbe.

    Raises:
        ValueError: If no probe with the given name is found.
    """
    for p in probes:
        if p.name == name:
            return p
    raise ValueError(f"Probe '{name}' not found in {[p.name for p in probes]}")


class TestBuildProbes:
    """Tests for HealthService._build_probes() probe construction."""

    @pytest.mark.unit
    def test_probe_count(self) -> None:
        """Seven probes are built: 6 core + optional OTALON-AI."""
        service = HealthService(_test_settings())
        probes = service._build_probes()
        assert len(probes) == 7

    @pytest.mark.unit
    def test_mcp_probe_uses_health_path(self) -> None:
        """The OTALON-MCP probe uses /health as its path."""
        service = HealthService(_test_settings())
        probes = service._build_probes()
        mcp_probe = _find_probe(probes, "OTALON-MCP")
        assert mcp_probe.path == "/health"

    @pytest.mark.unit
    def test_influxdb_probe_uses_health_path(self) -> None:
        """The InfluxDB probe uses /health as its path."""
        service = HealthService(_test_settings())
        probes = service._build_probes()
        influx_probe = _find_probe(probes, "InfluxDB")
        assert influx_probe.path == "/health"

    @pytest.mark.unit
    def test_influxdb_probe_includes_auth_header(self) -> None:
        """The InfluxDB probe includes an Authorization Bearer header when a token is configured."""
        settings = _test_settings()
        settings = settings.model_copy(update={"influxdb_token": "my-secret"})
        service = HealthService(settings)
        probes = service._build_probes()
        influx_probe = _find_probe(probes, "InfluxDB")
        assert influx_probe.headers is not None
        assert influx_probe.headers["Authorization"] == "Bearer my-secret"

    @pytest.mark.unit
    def test_influxdb_probe_no_auth_when_token_empty(self) -> None:
        """The InfluxDB probe has no auth header when the token is empty."""
        settings = _test_settings()
        settings = settings.model_copy(update={"influxdb_token": ""})
        service = HealthService(settings)
        probes = service._build_probes()
        influx_probe = _find_probe(probes, "InfluxDB")
        assert influx_probe.headers is None

    @pytest.mark.unit
    def test_all_probes_use_configured_timeout(self) -> None:
        """All probes use the health_check_timeout_s value from settings."""
        service = HealthService(_test_settings(health_check_timeout_s=7.5))
        probes = service._build_probes()
        for probe in probes:
            assert probe.timeout_s == 7.5

    @pytest.mark.unit
    def test_network_traffic_recorder_probe_uses_health_path(self) -> None:
        """The Network Traffic Recorder probe uses /health as its path."""
        service = HealthService(_test_settings())
        probes = service._build_probes()
        recorder_probe = _find_probe(probes, "Network Traffic Recorder")
        assert recorder_probe.path == "/health"

    @pytest.mark.unit
    def test_cyberclas_probe_uses_docker_type(self) -> None:
        """The OTALON-CLAS probe uses docker as its probe type and has the expected container name."""
        service = HealthService(_test_settings())
        probes = service._build_probes()
        cyberclas_probe = _find_probe(probes, "OTALON-CLAS")
        assert cyberclas_probe.probe_type == "docker"
        assert cyberclas_probe.container_name == "otalon-clas"

    @pytest.mark.unit
    def test_cyberclas_probe_has_correct_container_name(self) -> None:
        """The OTALON-CLAS probe container name comes from settings."""
        service = HealthService(_test_settings(otalon_clas_container_name="custom-container"))
        probes = service._build_probes()
        cyberclas_probe = _find_probe(probes, "OTALON-CLAS")
        assert cyberclas_probe.container_name == "custom-container"

    @pytest.mark.unit
    def test_ai_probe_is_optional(self) -> None:
        """The OTALON-AI probe is marked optional."""
        service = HealthService(_test_settings())
        probes = service._build_probes()
        ai_probe = _find_probe(probes, "OTALON-AI")
        assert ai_probe.optional is True

    @pytest.mark.unit
    def test_ai_probe_parses_url(self) -> None:
        """The OTALON-AI probe host/port are parsed from ai_url."""
        service = HealthService(_test_settings(ai_url="http://ai-host:9123"))
        probes = service._build_probes()
        ai_probe = _find_probe(probes, "OTALON-AI")
        assert ai_probe.host == "ai-host"
        assert ai_probe.port == 9123


class TestCheckHttp:
    """Tests for HealthService._check_http() with mocked httpx.AsyncClient."""

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_http_probe_running_on_200(self) -> None:
        """A successful HTTP 200 response marks the probe as running."""
        service = HealthService(_test_settings())
        probe = ServiceProbe(
            name="TestSvc",
            probe_type="http",
            host="localhost",
            port=9999,
            path="/health",
        )

        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("otalon_api.services.health_service.httpx.AsyncClient", return_value=mock_client):
            result = await service._check_http(probe)

        assert result["name"] == "TestSvc"
        assert result["running"] is True

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_http_probe_not_running_on_404(self) -> None:
        """An HTTP 404 response (raise_for_status raises) marks the probe as not running."""
        service = HealthService(_test_settings())
        probe = ServiceProbe(
            name="TestSvc",
            probe_type="http",
            host="localhost",
            port=9999,
            path="/health",
        )

        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock(
            side_effect=httpx.HTTPStatusError("Not Found", request=MagicMock(), response=MagicMock())
        )

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("otalon_api.services.health_service.httpx.AsyncClient", return_value=mock_client):
            result = await service._check_http(probe)

        assert result["name"] == "TestSvc"
        assert result["running"] is False

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_http_probe_not_running_on_timeout(self) -> None:
        """A timeout exception marks the probe as not running."""
        service = HealthService(_test_settings())
        probe = ServiceProbe(
            name="TestSvc",
            probe_type="http",
            host="localhost",
            port=9999,
            path="/health",
        )

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.TimeoutException("connection timed out"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("otalon_api.services.health_service.httpx.AsyncClient", return_value=mock_client):
            result = await service._check_http(probe)

        assert result["name"] == "TestSvc"
        assert result["running"] is False

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_http_probe_not_running_on_connection_error(self) -> None:
        """A connection error marks the probe as not running."""
        service = HealthService(_test_settings())
        probe = ServiceProbe(
            name="TestSvc",
            probe_type="http",
            host="localhost",
            port=9999,
            path="/health",
        )

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("connection refused"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("otalon_api.services.health_service.httpx.AsyncClient", return_value=mock_client):
            result = await service._check_http(probe)

        assert result["name"] == "TestSvc"
        assert result["running"] is False


class TestCheckTcp:
    """Tests for HealthService._check_tcp() with mocked asyncio.open_connection."""

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_tcp_probe_running_on_connect(self) -> None:
        """A successful TCP connection marks the probe as running."""
        service = HealthService(_test_settings())
        probe = ServiceProbe(name="Postgres", probe_type="tcp", host="localhost", port=5432)

        mock_writer = MagicMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch(
            "otalon_api.services.health_service.asyncio.open_connection",
            new_callable=AsyncMock,
        ) as mock_conn:
            mock_conn.return_value = (MagicMock(), mock_writer)
            result = await service._check_tcp(probe)

        assert result["name"] == "Postgres"
        assert result["running"] is True

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_tcp_probe_not_running_on_timeout(self) -> None:
        """A timeout during TCP connection marks the probe as not running."""
        service = HealthService(_test_settings())
        probe = ServiceProbe(name="Postgres", probe_type="tcp", host="localhost", port=5432)

        with patch(
            "otalon_api.services.health_service.asyncio.open_connection",
            new_callable=AsyncMock,
        ) as mock_conn:
            mock_conn.side_effect = asyncio.TimeoutError()
            with patch(
                "otalon_api.services.health_service.asyncio.wait_for",
                side_effect=asyncio.TimeoutError(),
            ):
                result = await service._check_tcp(probe)

        assert result["name"] == "Postgres"
        assert result["running"] is False


class TestCheckDocker:
    """Tests for HealthService._check_docker() with mocked Docker SDK."""

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_docker_probe_running_when_container_running(self) -> None:
        """A running Docker container marks the probe as running."""
        service = HealthService(_test_settings())
        probe = ServiceProbe(
            name="Cyberclas-ICS",
            probe_type="docker",
            host="",
            port=0,
            container_name="otalon-clas",
        )
        mock_container = MagicMock()
        mock_container.status = "running"
        mock_client = MagicMock()
        mock_client.containers.get.return_value = mock_container
        mock_docker_module = MagicMock()
        mock_docker_module.from_env.return_value = mock_client

        with patch.dict("sys.modules", {"docker": mock_docker_module}):
            result = await service._check_docker(probe)

        assert result["name"] == "Cyberclas-ICS"
        assert result["running"] is True

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_docker_probe_not_running_when_container_exited(self) -> None:
        """An exited Docker container marks the probe as not running."""
        service = HealthService(_test_settings())
        probe = ServiceProbe(
            name="Cyberclas-ICS",
            probe_type="docker",
            host="",
            port=0,
            container_name="otalon-clas",
        )
        mock_container = MagicMock()
        mock_container.status = "exited"
        mock_client = MagicMock()
        mock_client.containers.get.return_value = mock_container
        mock_docker_module = MagicMock()
        mock_docker_module.from_env.return_value = mock_client

        with patch.dict("sys.modules", {"docker": mock_docker_module}):
            result = await service._check_docker(probe)

        assert result["name"] == "Cyberclas-ICS"
        assert result["running"] is False
        assert "exited" in result["detail"]

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_docker_probe_not_running_on_exception(self) -> None:
        """A Docker SDK exception marks the probe as not running."""
        service = HealthService(_test_settings())
        probe = ServiceProbe(
            name="Cyberclas-ICS",
            probe_type="docker",
            host="",
            port=0,
            container_name="otalon-clas",
        )
        mock_docker_module = MagicMock()
        mock_docker_module.from_env.side_effect = Exception("Docker not available")

        with patch.dict("sys.modules", {"docker": mock_docker_module}):
            result = await service._check_docker(probe)

        assert result["name"] == "Cyberclas-ICS"
        assert result["running"] is False


class TestCheckAll:
    """Tests for HealthService.check_all() aggregated health check workflow."""

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_check_all_returns_services_and_overall(self) -> None:
        """check_all() returns a dict with 'services' list and 'overall_status' string."""
        service = HealthService(_test_settings())

        async def _fake_http(probe: ServiceProbe) -> dict[str, Any]:
            """Return a successful HTTP probe result."""
            return {
                "name": probe.name,
                "running": True,
                "detail": "ok in 1 ms",
                "timestamp": 0.0,
            }

        async def _fake_tcp(probe: ServiceProbe) -> dict[str, Any]:
            """Return a successful TCP probe result."""
            return {
                "name": probe.name,
                "running": True,
                "detail": "ok in 1 ms",
                "timestamp": 0.0,
            }

        async def _fake_docker(probe: ServiceProbe) -> dict[str, Any]:
            """Return a successful Docker probe result."""
            return {
                "name": probe.name,
                "running": True,
                "detail": "ok in 1 ms",
                "timestamp": 0.0,
            }

        with (
            patch.object(service, "_check_http", side_effect=_fake_http),
            patch.object(service, "_check_tcp", side_effect=_fake_tcp),
            patch.object(service, "_check_docker", side_effect=_fake_docker),
        ):
            result = await service.check_all()

        assert "services" in result
        assert "overall_status" in result
        assert isinstance(result["services"], list)
        assert len(result["services"]) == 7
        assert result["overall_status"] == "healthy"
        for service in result["services"]:
            assert service["classification"] in ("core", "optional")
            assert service["status"] == "healthy"
        service_names = {s["name"] for s in result["services"]}
        assert service_names == {
            "Postgres",
            "InfluxDB",
            "Network Traffic Recorder",
            "CyberScan-ICS",
            "OTALON-MCP",
            "OTALON-CLAS",
            "OTALON-AI",
        }

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_check_all_optional_down_is_not_configured_not_failed(self) -> None:
        """A down optional AI service is 'not-configured' and does not fail the suite."""
        service = HealthService(_test_settings())

        async def _fake_http(probe: ServiceProbe) -> dict[str, Any]:
            """HTTP probe: only the optional OTALON-AI is down."""
            running = probe.name != "OTALON-AI"
            return {
                "name": probe.name,
                "running": running,
                "detail": "ok in 1 ms" if running else "connection refused",
                "timestamp": 0.0,
            }

        async def _fake_ok(probe: ServiceProbe) -> dict[str, Any]:
            """TCP/Docker probe: always running."""
            return {"name": probe.name, "running": True, "detail": "ok in 1 ms", "timestamp": 0.0}

        with (
            patch.object(service, "_check_http", side_effect=_fake_http),
            patch.object(service, "_check_tcp", side_effect=_fake_ok),
            patch.object(service, "_check_docker", side_effect=_fake_ok),
        ):
            result = await service.check_all()

        by_name = {s["name"]: s for s in result["services"]}
        assert by_name["OTALON-AI"]["status"] == "not-configured"
        assert by_name["OTALON-AI"]["running"] is False
        assert by_name["Postgres"]["status"] == "healthy"
        # Optional not-configured must NOT drag the aggregate down.
        assert result["overall_status"] == "healthy"

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_check_all_core_down_is_failed(self) -> None:
        """A down core service is reported with status 'failed'."""
        service = HealthService(_test_settings())

        async def _fake_http(probe: ServiceProbe) -> dict[str, Any]:
            """HTTP probe: all running."""
            return {"name": probe.name, "running": True, "detail": "ok", "timestamp": 0.0}

        async def _fake_tcp(probe: ServiceProbe) -> dict[str, Any]:
            """TCP probe (Postgres): down."""
            return {"name": probe.name, "running": False, "detail": "refused", "timestamp": 0.0}

        async def _fake_docker(probe: ServiceProbe) -> dict[str, Any]:
            """Docker probe: running."""
            return {"name": probe.name, "running": True, "detail": "ok", "timestamp": 0.0}

        with (
            patch.object(service, "_check_http", side_effect=_fake_http),
            patch.object(service, "_check_tcp", side_effect=_fake_tcp),
            patch.object(service, "_check_docker", side_effect=_fake_docker),
        ):
            result = await service.check_all()

        by_name = {s["name"]: s for s in result["services"]}
        assert by_name["Postgres"]["status"] == "failed"
