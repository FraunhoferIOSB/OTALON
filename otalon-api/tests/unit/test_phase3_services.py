"""Unit tests for Phase-3 services (Topology, Health, Docker, Compose, Env, Classification).

Tests core service behavior using mocked dependencies.
"""

from __future__ import annotations

import tempfile
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from otalon_api.domain.topology.classification import (
    DEVICE_TYPE_APPLICATION_SERVER,
    DEVICE_TYPE_CONTROL_SERVER,
    DEVICE_TYPE_DATA_GATEWAY,
    DEVICE_TYPE_DATA_HISTORIAN,
    DEVICE_TYPE_DCS_CONTROLLER,
    DEVICE_TYPE_FIELD_IO,
    DEVICE_TYPE_FIREWALL,
    DEVICE_TYPE_HMI,
    DEVICE_TYPE_IED,
    DEVICE_TYPE_JUMP_HOST,
    DEVICE_TYPE_OTHER,
    DEVICE_TYPE_PAC,
    DEVICE_TYPE_PLC,
    DEVICE_TYPE_ROUTERS,
    DEVICE_TYPE_RTU,
    DEVICE_TYPE_SAFETY_CONTROLLER,
    DEVICE_TYPE_SWITCH,
    DEVICE_TYPE_VPN_SERVER,
    DEVICE_TYPE_WORKSTATION,
    classify_device_type,
)
from otalon_api.repositories.postgres_repo import PostgresRepository
from otalon_api.services.compose_runner import ALLOWED_ACTIONS, ALLOWED_SERVICES, ComposeRunner
from otalon_api.services.docker_service import ALLOWED_SERVICES as DOCKER_ALLOWED_SERVICES, DockerService
from otalon_api.services.env_compose_service import EnvComposeService, _is_sensitive, _mask_value, _validate_updates
from otalon_api.services.health_service import HealthService
from otalon_api.services.topology_service import TopologyService
from otalon_api.settings import Settings


def _test_settings() -> Settings:
    """Create a Settings instance with test defaults.

    Returns:
        Settings configured for testing.
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
        admin_api_key="test-key",
        api_port=8090,
        netcap_measurement="network_metrics",
        netcap_id_tag="uci",
        netcap_sparse_port_threshold=10,
        default_sample_max_points=500,
    )


class TestClassifyDeviceType:
    """Tests for classify_device_type() classification logic."""

    @pytest.mark.unit
    def test_plc_keywords(self) -> None:
        """PLC-related keywords classify as PLC."""
        assert classify_device_type("S7-300 PLC") == DEVICE_TYPE_PLC
        assert classify_device_type("Controller Unit") == DEVICE_TYPE_PLC
        assert classify_device_type("s7-1200") == DEVICE_TYPE_PLC

    @pytest.mark.unit
    def test_asset_keywords(self) -> None:
        """Representative MITRE asset keywords classify to specific types."""
        assert classify_device_type("Industrial PC") == DEVICE_TYPE_WORKSTATION
        assert classify_device_type("Control Server") == DEVICE_TYPE_CONTROL_SERVER
        assert classify_device_type("Application Server") == DEVICE_TYPE_APPLICATION_SERVER
        assert classify_device_type("Data Historian") == DEVICE_TYPE_DATA_HISTORIAN
        assert classify_device_type("Data Gateway") == DEVICE_TYPE_DATA_GATEWAY
        assert classify_device_type("Firewall") == DEVICE_TYPE_FIREWALL
        assert classify_device_type("Jump Host") == DEVICE_TYPE_JUMP_HOST
        assert classify_device_type("VPN Server") == DEVICE_TYPE_VPN_SERVER
        assert classify_device_type("Router") == DEVICE_TYPE_ROUTERS
        assert classify_device_type("Switch") == DEVICE_TYPE_SWITCH
        assert classify_device_type("DCS Controller") == DEVICE_TYPE_DCS_CONTROLLER
        assert classify_device_type("Safety Controller") == DEVICE_TYPE_SAFETY_CONTROLLER
        assert classify_device_type("PAC") == DEVICE_TYPE_PAC
        assert classify_device_type("RTU") == DEVICE_TYPE_RTU
        assert classify_device_type("IED") == DEVICE_TYPE_IED

    @pytest.mark.unit
    def test_field_io_keywords(self) -> None:
        """Field I/O keywords classify as Field I/O."""
        assert classify_device_type("Field I/O Module") == DEVICE_TYPE_FIELD_IO
        assert classify_device_type("I/O Block") == DEVICE_TYPE_FIELD_IO

    @pytest.mark.unit
    def test_hmi_keywords(self) -> None:
        """HMI-related keywords classify as HMI."""
        assert classify_device_type("HMI Touch Panel") == DEVICE_TYPE_HMI
        assert classify_device_type("Display Unit") == DEVICE_TYPE_HMI
        assert classify_device_type("Panel") == DEVICE_TYPE_HMI

    @pytest.mark.unit
    def test_unknown_returns_other(self) -> None:
        """Unknown or empty strings classify as Other."""
        assert classify_device_type("Unknown Device") == DEVICE_TYPE_OTHER
        assert classify_device_type("") == DEVICE_TYPE_OTHER
        assert classify_device_type(None) == DEVICE_TYPE_OTHER

    @pytest.mark.unit
    def test_priority_plc_over_ipc(self) -> None:
        """PLC keyword takes priority over IPC when both match."""
        assert classify_device_type("PLC Server") == DEVICE_TYPE_PLC

    @pytest.mark.unit
    def test_workstation_keyword_takes_priority_over_field_io(self) -> None:
        """Workstation keyword takes priority over field I/O keyword."""
        assert classify_device_type("PC with IO") == DEVICE_TYPE_WORKSTATION


class TestTopologyServiceEmpty:
    """Tests for TopologyService with empty or minimal data."""

    @pytest.mark.unit
    def test_empty_scan_results_produces_empty_graph(self) -> None:
        """build_graph() with no devices and no UCIs returns empty graph."""
        pg = MagicMock(spec=PostgresRepository)
        pg.query_devices = MagicMock(return_value=[])
        pg.query_anomaly_groups = MagicMock(return_value=[])

        influx = MagicMock()
        influx.list_ids_between = MagicMock(return_value=[])

        service = TopologyService(pg, influx, _test_settings())
        result = service.build_graph(
            start=datetime(2026, 3, 6, 21, 0, tzinfo=timezone.utc),
            stop=datetime(2026, 3, 6, 22, 0, tzinfo=timezone.utc),
        )

        assert result["nodes"] == []
        assert result["edges"] == []
        assert result["meta"]["node_count"] == 0
        assert result["meta"]["edge_count"] == 0

    @pytest.mark.unit
    def test_node_limit_truncates(self) -> None:
        """build_graph() with node_limit truncates the node list."""
        pg = MagicMock(spec=PostgresRepository)
        devices = [
            {
                "id": i,
                "name": f"dev{i}",
                "alias": "",
                "device_type_name": "",
                "device_role": "",
                "mac": f"aa:bb:cc:dd:ee:{i:02x}",
                "ip4_addresses": [f"10.0.0.{i}"],
            }
            for i in range(1, 11)
        ]
        pg.query_devices = MagicMock(return_value=devices)
        pg.query_anomaly_groups = MagicMock(return_value=[])

        influx = MagicMock()
        ucis = [
            f"aa:bb:cc:dd:ee:{i:02x}/aa:bb:cc:dd:ee:{(i%10)+1:02x}/0/0x0800/10.0.0.{i}/10.0.0.{(i%10)+1}/80/443/TCP"
            for i in range(1, 11)
        ]
        influx.list_ids_between = MagicMock(return_value=ucis)

        service = TopologyService(pg, influx, _test_settings())
        result = service.build_graph(
            start=datetime(2026, 3, 6, 21, 0, tzinfo=timezone.utc),
            stop=datetime(2026, 3, 6, 22, 0, tzinfo=timezone.utc),
            node_limit=5,
        )

        assert result["meta"]["node_count"] <= 5
        assert result["meta"]["truncated"] is True

    @pytest.mark.unit
    def test_deterministic_sorting_anomaly_first(self) -> None:
        """_sort_nodes_deterministic() puts anomaly nodes before normal ones."""
        nodes = [
            {"id": "1", "label": "Z-Device", "type": "Other", "isAnomaly": False},
            {"id": "2", "label": "A-Device", "type": "PLC", "isAnomaly": True},
            {"id": "3", "label": "M-Device", "type": "IO", "isAnomaly": False},
        ]

        sorted_nodes = TopologyService._sort_nodes_deterministic(nodes)

        assert sorted_nodes[0]["id"] == "2"
        assert sorted_nodes[0]["isAnomaly"] is True
        assert all(not n["isAnomaly"] for n in sorted_nodes[1:])

    @pytest.mark.unit
    def test_deterministic_sorting_alphabetical(self) -> None:
        """_sort_nodes_deterministic() sorts non-anomaly nodes alphabetically."""
        nodes = [
            {"id": "1", "label": "Z-Device", "type": "Other", "isAnomaly": False},
            {"id": "2", "label": "A-Device", "type": "Other", "isAnomaly": False},
            {"id": "3", "label": "M-Device", "type": "Other", "isAnomaly": False},
        ]

        sorted_nodes = TopologyService._sort_nodes_deterministic(nodes)

        labels = [n["label"] for n in sorted_nodes]
        assert labels == ["A-Device", "M-Device", "Z-Device"]


class TestHealthServiceOverallStatus:
    """Tests for HealthService._compute_overall_status() logic."""

    @pytest.mark.unit
    def test_all_healthy(self) -> None:
        """All probes healthy returns 'healthy'."""
        services = [
            {"name": "A", "running": True, "detail": "ok", "timestamp": 0.0},
            {"name": "B", "running": True, "detail": "ok", "timestamp": 0.0},
        ]
        assert HealthService._compute_overall_status(services) == "healthy"

    @pytest.mark.unit
    def test_one_unhealthy_returns_degraded(self) -> None:
        """One unhealthy probe returns 'degraded'."""
        services = [
            {"name": "A", "running": True, "detail": "ok", "timestamp": 0.0},
            {"name": "B", "running": False, "detail": "fail", "timestamp": 0.0},
        ]
        assert HealthService._compute_overall_status(services) == "degraded"

    @pytest.mark.unit
    def test_all_unhealthy(self) -> None:
        """All probes unhealthy returns 'unhealthy'."""
        services = [
            {"name": "A", "running": False, "detail": "fail", "timestamp": 0.0},
            {"name": "B", "running": False, "detail": "fail", "timestamp": 0.0},
        ]
        assert HealthService._compute_overall_status(services) == "unhealthy"

    @pytest.mark.unit
    def test_empty_services_returns_unhealthy(self) -> None:
        """Empty service list returns 'unhealthy'."""
        assert HealthService._compute_overall_status([]) == "unhealthy"

    @pytest.mark.unit
    def test_optional_failure_does_not_fail_suite(self) -> None:
        """A failed optional service keeps the suite healthy when core is healthy."""
        services = [
            {"name": "Core", "running": True, "detail": "ok", "timestamp": 0.0, "classification": "core"},
            {"name": "Optional", "running": False, "detail": "fail", "timestamp": 0.0, "classification": "optional"},
        ]
        assert HealthService._compute_overall_status(services) == "healthy"

    @pytest.mark.unit
    def test_only_optional_services_considers_all(self) -> None:
        """When only optional services exist, they are considered for aggregate status."""
        services = [
            {"name": "OptionalA", "running": True, "detail": "ok", "timestamp": 0.0, "classification": "optional"},
            {"name": "OptionalB", "running": False, "detail": "fail", "timestamp": 0.0, "classification": "optional"},
        ]
        assert HealthService._compute_overall_status(services) == "degraded"


class TestHealthServiceDeriveStatus:
    """Tests for the explicit truthful per-service status derivation."""

    @pytest.mark.unit
    def test_running_service_is_healthy(self) -> None:
        """A reachable service is reported as 'healthy'."""
        assert HealthService._derive_status(running=True, optional=False) == "healthy"
        assert HealthService._derive_status(running=True, optional=True) == "healthy"

    @pytest.mark.unit
    def test_down_core_service_is_failed(self) -> None:
        """A down core service is reported as 'failed'."""
        assert HealthService._derive_status(running=False, optional=False) == "failed"

    @pytest.mark.unit
    def test_down_optional_service_is_not_configured(self) -> None:
        """A down optional service is 'not-configured', distinct from 'failed'."""
        assert HealthService._derive_status(running=False, optional=True) == "not-configured"


class TestDockerServiceAllowlist:
    """Tests for DockerService container allowlist validation."""

    @pytest.mark.unit
    def test_allowed_container_passes(self) -> None:
        """A container name in the allowlist returns True."""
        assert DockerService._is_allowed_container("postgres") is True
        assert DockerService._is_allowed_container("influxdb3") is True

    @pytest.mark.unit
    def test_disallowed_container_rejected(self) -> None:
        """A container name not in the allowlist returns False."""
        assert DockerService._is_allowed_container("evil-container") is False
        assert DockerService._is_allowed_container("") is False

    @pytest.mark.unit
    def test_get_logs_disallowed_raises(self) -> None:
        """get_container_logs() with disallowed name raises ValueError."""
        service = DockerService(settings=_test_settings())
        with pytest.raises(ValueError, match="not in the allowed services list"):
            service.get_container_logs("evil-container")


class TestComposeRunnerAllowlist:
    """Tests for ComposeRunner action and service allowlist validation."""

    @pytest.mark.unit
    def test_invalid_action_raises(self) -> None:
        """run_action() with invalid action raises ValueError."""
        runner = ComposeRunner(settings=_test_settings())
        with pytest.raises(ValueError, match="Action .* is not allowed"):
            runner.run_action("rm", "postgres")

    @pytest.mark.unit
    def test_invalid_service_raises(self) -> None:
        """run_action() with invalid service raises ValueError."""
        runner = ComposeRunner(settings=_test_settings())
        with pytest.raises(ValueError, match="Service .* is not allowed"):
            runner.run_action("restart", "evil-service")

    @pytest.mark.unit
    def test_allowed_actions_are_known(self) -> None:
        """All allowed actions are from the expected set."""
        expected = {"up", "stop", "restart", "recreate"}
        assert ALLOWED_ACTIONS == expected

    @pytest.mark.unit
    def test_allowed_services_are_known(self) -> None:
        """All allowed services match Docker and Compose allowlists."""
        assert ALLOWED_SERVICES == DOCKER_ALLOWED_SERVICES


class TestEnvComposeService:
    """Tests for EnvComposeService key validation and masking."""

    @pytest.mark.unit
    def test_validate_disallowed_key(self) -> None:
        """Validation rejects keys not in the allowed list."""
        errors = _validate_updates({"UNKNOWN_KEY": "value"})
        assert any("not allowed" in e for e in errors)

    @pytest.mark.unit
    def test_validate_empty_token(self) -> None:
        """Validation rejects empty INFLUX_TOKEN."""
        errors = _validate_updates({"INFLUX_TOKEN": ""})
        assert any("must not be empty" in e for e in errors)

    @pytest.mark.unit
    def test_validate_invalid_influx_url(self) -> None:
        """Validation rejects INFLUX_URL that doesn't start with http(s)."""
        errors = _validate_updates({"INFLUX_URL": "ftp://wrong"})
        assert any("must start with http" in e for e in errors)

    @pytest.mark.unit
    def test_validate_rejects_readonly_derived_dsn(self) -> None:
        """POSTGRES_DSN is a derived read-only key and is never editable."""
        errors = _validate_updates({"POSTGRES_DSN": "postgresql://u:p@pg/db"})
        assert any("is not allowed" in e for e in errors)

    @pytest.mark.unit
    def test_validate_empty_tz(self) -> None:
        """Validation rejects empty TZ value."""
        errors = _validate_updates({"TZ": ""})
        assert any("must not be empty" in e for e in errors)

    @pytest.mark.unit
    def test_validate_good_updates_pass(self) -> None:
        """Valid updates pass without errors."""
        errors = _validate_updates({"INFLUX_URL": "http://localhost:8181", "TZ": "Europe/Berlin"})
        assert errors == []

    @pytest.mark.unit
    def test_mask_value_short(self) -> None:
        """Short values (<=6 chars) are fully masked."""
        assert _mask_value("abc") == "***"
        assert _mask_value("12") == "**"

    @pytest.mark.unit
    def test_mask_value_long(self) -> None:
        """Long values show first/last 3 characters with stars in between."""
        masked = _mask_value("my-secret-token-value")
        assert masked.startswith("my-")
        assert masked.endswith("lue")
        assert "*" in masked

    @pytest.mark.unit
    def test_mask_value_empty(self) -> None:
        """Empty values return empty string."""
        assert _mask_value("") == ""

    @pytest.mark.unit
    def test_is_sensitive_token(self) -> None:
        """Keys containing TOKEN are considered sensitive."""
        assert _is_sensitive("INFLUX_TOKEN") is True
        assert _is_sensitive("API_TOKEN") is True

    @pytest.mark.unit
    def test_is_sensitive_password(self) -> None:
        """Keys containing PASSWORD are considered sensitive."""
        assert _is_sensitive("POSTGRES_PASSWORD") is True

    @pytest.mark.unit
    def test_is_sensitive_normal(self) -> None:
        """Normal keys are not considered sensitive."""
        assert _is_sensitive("TZ") is False
        assert _is_sensitive("INFLUX_URL") is False

    @pytest.mark.unit
    def test_load_nonexistent_file(self) -> None:
        """Loading from a non-existent file path results in empty entries."""
        settings = _test_settings()
        settings_copy = settings.model_copy(update={"env_compose_path": "/tmp/nonexistent_env_file_12345.env"})
        service = EnvComposeService(settings_copy)
        service.load()
        assert service.to_dict() == {}

    @pytest.mark.unit
    def test_load_and_read_env_file(self) -> None:
        """Load a real temp env file and read key-value pairs."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write("# comment\n")
            f.write("TZ=Europe/Berlin\n")
            f.write("INFLUX_URL=http://localhost:8181\n")
            f.write("\n")
            f.write("INFLUX_TOKEN=secret123\n")
            path = f.name

        settings = _test_settings()
        settings_copy = settings.model_copy(update={"env_compose_path": path})
        service = EnvComposeService(settings_copy)
        service.load()

        env_dict = service.to_dict()
        assert env_dict["TZ"] == "Europe/Berlin"
        assert env_dict["INFLUX_URL"] == "http://localhost:8181"
        assert env_dict["INFLUX_TOKEN"] == "secret123"

    @pytest.mark.unit
    def test_get_masked_env_hides_secrets(self) -> None:
        """get_masked_env() masks sensitive values."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write("INFLUX_TOKEN=my-super-secret-token\n")
            f.write("TZ=Europe/Berlin\n")
            path = f.name

        settings = _test_settings()
        settings_copy = settings.model_copy(update={"env_compose_path": path})
        service = EnvComposeService(settings_copy)
        service.load()

        masked = service.get_masked_env()
        assert masked["TZ"] == "Europe/Berlin"
        assert masked["INFLUX_TOKEN"] != "my-super-secret-token"
        assert "*" in masked["INFLUX_TOKEN"]
