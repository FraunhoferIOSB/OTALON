"""Unit tests for the API-key authentication middleware.

Tests that the ApiKeyAuthMiddleware correctly protects admin endpoints,
allows public paths through, and handles disabled authentication.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from otalon_common.auth import UserRole

from otalon_api.dependencies import (
    get_dashboard_user_state_repo,
    get_health_incident_service,
    get_health_service,
    get_operations_maintenance_service,
)
from otalon_api.main import app
from otalon_api.middleware.session_auth import SESSION_COOKIE_NAME
from otalon_api.repositories.identity_repo import UserEntry
from otalon_api.settings import Settings

OPERATOR_ROLE_KEY = "op-secret-key"
VIEWER_ROLE_KEY = "view-secret-key"
ROLE_ALLOWED_KEYS = f"ops:operator:{OPERATOR_ROLE_KEY},watcher:viewer:{VIEWER_ROLE_KEY}"
OPERATIONS_MUTATION = "/api/v1/operations/support-bundle"
DASHBOARD_LAYOUT = "/api/v1/dashboard/layout"
DASHBOARD_TOUR = "/api/v1/dashboard/tour"


def _make_settings(api_key: str = "test-secret-key") -> Settings:
    """Create test settings with the given admin API key.

    Args:
        api_key: Value for ``admin_api_key``.

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
        admin_api_key=api_key,
        api_port=8090,
        netcap_measurement="network_metrics",
        netcap_id_tag="uci",
        netcap_sparse_port_threshold=10,
        default_sample_max_points=500,
    )


class TestApiKeyAuthMiddleware:
    """Tests for ApiKeyAuthMiddleware protecting admin endpoints."""

    @pytest.mark.unit
    def test_admin_no_api_key_returns_401(self) -> None:
        """Request to /api/v1/admin/* without API key returns 401."""
        settings = _make_settings()
        with patch("otalon_api.middleware.auth.get_settings", return_value=settings):
            client = TestClient(app, headers={"X-API-Key": ""}, raise_server_exceptions=False)
            response = client.get("/api/v1/admin/containers")
            assert response.status_code == 401

    @pytest.mark.unit
    def test_admin_wrong_api_key_returns_401(self) -> None:
        """Request to /api/v1/admin/* with wrong API key returns 401."""
        settings = _make_settings()
        with patch("otalon_api.middleware.auth.get_settings", return_value=settings):
            client = TestClient(app, headers={"X-API-Key": ""}, raise_server_exceptions=False)
            response = client.get(
                "/api/v1/admin/containers",
                headers={"X-API-Key": "wrong-key"},
            )
            assert response.status_code == 401

    @pytest.mark.unit
    def test_admin_correct_api_key_passes(self) -> None:
        """Request to /api/v1/admin/* with correct API key is forwarded.

        The request may still fail (e.g. 500) because the Docker service
        is not available, but it must NOT be 401.
        """
        settings = _make_settings()
        with patch("otalon_api.middleware.auth.get_settings", return_value=settings):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get(
                "/api/v1/admin/containers",
                headers={"X-API-Key": "test-secret-key"},
            )
            assert response.status_code != 401

    @pytest.mark.unit
    def test_public_health_endpoint_no_key(self) -> None:
        """Request to /api/v1/status/health without key passes auth (not 401)."""
        settings = _make_settings()
        with patch("otalon_api.middleware.auth.get_settings", return_value=settings):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get("/api/v1/status/health")
            assert response.status_code != 401

    @pytest.mark.unit
    def test_public_livez_endpoint_no_key(self) -> None:
        """Request to /livez without key returns 200."""
        settings = _make_settings()
        with patch("otalon_api.middleware.auth.get_settings", return_value=settings):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get("/livez")
            assert response.status_code == 200
            assert response.json()["status"] == "alive"

    @pytest.mark.unit
    def test_public_readyz_endpoint_no_key(self) -> None:
        """Bare readiness probe remains available without credentials."""
        settings = _make_settings()
        with patch("otalon_api.middleware.auth.get_settings", return_value=settings):
            response = TestClient(app, raise_server_exceptions=False).get("/readyz")
            assert response.status_code == 200
            assert response.json() == {"status": "ok"}

    @pytest.mark.unit
    def test_docs_endpoint_no_key(self) -> None:
        """API documentation is protected by deny-by-default auth."""
        settings = _make_settings()
        with patch("otalon_api.middleware.auth.get_settings", return_value=settings):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get("/docs", headers={"X-API-Key": ""})
            assert response.status_code == 401

    @pytest.mark.unit
    def test_auth_disabled_when_key_empty(self) -> None:
        """When no key is configured, admin requests fail closed with 503."""
        settings = _make_settings(api_key="")
        with patch("otalon_api.middleware.auth.get_settings", return_value=settings):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get("/api/v1/admin/containers", headers={"X-API-Key": ""})
            assert response.status_code == 503

    @pytest.mark.unit
    def test_operations_prefix_present(self) -> None:
        """The operations prefix is in the protected list."""
        from otalon_api.middleware.auth import PROTECTED_PATH_PREFIXES

        assert "/" in PROTECTED_PATH_PREFIXES

    @pytest.mark.unit
    def test_operations_pipeline_401_without_key(self) -> None:
        """Request to /api/v1/operations/pipeline without key returns 401."""
        settings = _make_settings()
        with patch("otalon_api.middleware.auth.get_settings", return_value=settings):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get("/api/v1/operations/pipeline")
            assert response.status_code == 401

    @pytest.mark.unit
    def test_operations_pipeline_200_with_key(self) -> None:
        """Request to /api/v1/operations/pipeline with correct key is not 401."""
        settings = _make_settings()
        with patch("otalon_api.middleware.auth.get_settings", return_value=settings):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get(
                "/api/v1/operations/pipeline",
                headers={"X-API-Key": "test-secret-key"},
            )
            assert response.status_code != 401

    @pytest.mark.unit
    def test_operations_unconfigured_returns_503(self) -> None:
        """Operations remains unavailable when its key registry is empty."""
        settings = _make_settings(api_key="")
        with patch("otalon_api.middleware.auth.get_settings", return_value=settings):
            response = TestClient(app, headers={"X-API-Key": ""}, raise_server_exceptions=False).get(
                "/api/v1/operations/pipeline"
            )
            assert response.status_code == 503


class _StubMaintenanceService:
    """Minimal maintenance-service stub for the operations mutation success path."""

    def create_support_bundle(self, output_dir: Any) -> dict[str, Any]:
        """Return a fixed manifest without touching the filesystem."""
        return {"bundle": "stub", "output_dir": str(output_dir)}


class TestOperationsMutationRoleGate:
    """Role enforcement on mutating Operations routes (arch ARCH-1 / P3-TEST-1)."""

    @pytest.mark.unit
    def test_mutation_with_viewer_key_returns_403(self) -> None:
        """A configured viewer key cannot reach an Operations mutation handler."""
        settings = _make_settings(api_key="")
        settings.otalon_api_allowed_keys = ROLE_ALLOWED_KEYS
        with patch("otalon_api.middleware.auth.get_settings", return_value=settings):
            client = TestClient(
                app,
                headers={"X-API-Key": VIEWER_ROLE_KEY},
                raise_server_exceptions=False,
            )
            response = client.post(OPERATIONS_MUTATION, json={"output_dir": "/tmp/x"})
            assert response.status_code == 403
            assert OPERATOR_ROLE_KEY not in response.text
            assert VIEWER_ROLE_KEY not in response.text

    @pytest.mark.unit
    def test_mutation_with_operator_key_succeeds(self) -> None:
        """An operator key passes the role gate and reaches the (mocked) handler."""
        settings = _make_settings(api_key="")
        settings.otalon_api_allowed_keys = ROLE_ALLOWED_KEYS
        app.dependency_overrides[get_operations_maintenance_service] = _StubMaintenanceService
        try:
            with patch("otalon_api.middleware.auth.get_settings", return_value=settings):
                client = TestClient(
                    app,
                    headers={"X-API-Key": OPERATOR_ROLE_KEY},
                    raise_server_exceptions=False,
                )
                response = client.post(OPERATIONS_MUTATION, json={"output_dir": "/tmp/x"})
            assert response.status_code == 200
            assert response.json()["bundle"] == "stub"
        finally:
            app.dependency_overrides.clear()

    @pytest.mark.unit
    def test_mutation_without_key_returns_401(self) -> None:
        """A mutating Operations route without a key is rejected at the boundary."""
        settings = _make_settings(api_key="")
        settings.otalon_api_allowed_keys = ROLE_ALLOWED_KEYS
        with patch("otalon_api.middleware.auth.get_settings", return_value=settings):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.post(OPERATIONS_MUTATION, json={"output_dir": "/tmp/x"})
            assert response.status_code == 401

    @pytest.mark.unit
    def test_operations_read_allows_viewer_key(self) -> None:
        """A viewer key still passes for Operations reads (read contract unchanged)."""
        settings = _make_settings(api_key="")
        settings.otalon_api_allowed_keys = ROLE_ALLOWED_KEYS
        with patch("otalon_api.middleware.auth.get_settings", return_value=settings):
            client = TestClient(
                app,
                headers={"X-API-Key": VIEWER_ROLE_KEY},
                raise_server_exceptions=False,
            )
            response = client.get("/api/v1/operations/pipeline")
            assert response.status_code != 401
            assert response.status_code != 403

    @pytest.mark.unit
    def test_read_accepts_valid_session_without_api_key(self) -> None:
        """Product sessions authenticate protected GET routes without keys."""
        settings = _make_settings()
        session_repo = MagicMock()
        session_repo.validate_and_touch.return_value = UserEntry(
            id=1,
            username="viewer",
            password_hash="hash",
            role=UserRole.VIEWER,
            must_change_password=False,
            disabled=False,
            last_login_at=None,
        )
        with (
            patch("otalon_api.middleware.auth.get_settings", return_value=settings),
            patch("otalon_api.middleware.session_auth.get_session_repo", return_value=session_repo),
        ):
            client = TestClient(app, raise_server_exceptions=False)
            client.cookies.set(SESSION_COOKIE_NAME, "valid-session")
            response = client.get("/api/v1/timeseries/features")
        assert response.status_code == 200

    @pytest.mark.unit
    def test_detailed_health_accepts_valid_session_without_api_key(self) -> None:
        """UI-154 regression: detailed health honours a product session like any
        other protected read, instead of being treated as the unconditionally
        session-exempt plain probe."""
        settings = _make_settings()
        session_repo = MagicMock()
        session_repo.validate_and_touch.return_value = UserEntry(
            id=1,
            username="viewer",
            password_hash="hash",
            role=UserRole.VIEWER,
            must_change_password=False,
            disabled=False,
            last_login_at=None,
        )
        fake_health = MagicMock()
        fake_health.check_all = AsyncMock(return_value={"services": [], "overall_status": "healthy"})
        empty_summaries = {
            "active_incidents": [],
            "unacknowledged_incidents": [],
            "recent_incidents": [],
        }
        fake_incidents = MagicMock()
        fake_incidents.summaries_async = AsyncMock(return_value=empty_summaries)
        fake_incidents.latch_overall_status = lambda payload, summaries: None
        dependencies = (get_health_service, get_health_incident_service)
        previous = {dependency: app.dependency_overrides.get(dependency) for dependency in dependencies}
        present = {dependency: dependency in app.dependency_overrides for dependency in dependencies}
        app.dependency_overrides[get_health_service] = lambda: fake_health
        app.dependency_overrides[get_health_incident_service] = lambda: fake_incidents
        try:
            with (
                patch("otalon_api.middleware.auth.get_settings", return_value=settings),
                patch("otalon_api.middleware.session_auth.get_session_repo", return_value=session_repo),
            ):
                client = TestClient(app, raise_server_exceptions=False)
                client.cookies.set(SESSION_COOKIE_NAME, "valid-session")
                response = client.get("/api/v1/status/health", params={"detail": "true"})
            session_repo.validate_and_touch.assert_called_once_with("valid-session")
        finally:
            for dependency in dependencies:
                if present[dependency]:
                    app.dependency_overrides[dependency] = previous[dependency]
                else:
                    app.dependency_overrides.pop(dependency, None)
        assert response.status_code == 200

    @pytest.mark.unit
    def test_detailed_health_without_credentials_returns_401(self) -> None:
        """Detailed health stays closed without a session or an operator key,
        even though the plain (non-detailed) probe is fully public."""
        settings = _make_settings()
        with (
            patch("otalon_api.middleware.auth.get_settings", return_value=settings),
            patch("otalon_api.middleware.session_auth.get_session_repo") as get_repo,
        ):
            get_repo.return_value.validate_and_touch.return_value = None
            response = TestClient(app, raise_server_exceptions=False).get(
                "/api/v1/status/health", params={"detail": "true"}
            )
        assert response.status_code == 401

    @pytest.mark.unit
    def test_read_without_credentials_returns_401(self) -> None:
        """Protected reads remain closed without either credential."""
        settings = _make_settings()
        with (
            patch("otalon_api.middleware.auth.get_settings", return_value=settings),
            patch("otalon_api.middleware.session_auth.get_session_repo") as get_repo,
        ):
            get_repo.return_value.validate_and_touch.return_value = None
            response = TestClient(app, raise_server_exceptions=False).get("/api/v1/timeseries/features")
        assert response.status_code == 401

    @pytest.mark.unit
    def test_mutation_with_session_without_api_key_returns_401(self) -> None:
        """Product sessions cannot replace operator keys on mutations."""
        settings = _make_settings()
        session_repo = MagicMock()
        session_repo.validate_and_touch.return_value = UserEntry(
            id=1,
            username="viewer",
            password_hash="hash",
            role=UserRole.VIEWER,
            must_change_password=False,
            disabled=False,
            last_login_at=None,
        )
        with (
            patch("otalon_api.middleware.auth.get_settings", return_value=settings),
            patch("otalon_api.middleware.session_auth.get_session_repo", return_value=session_repo),
        ):
            client = TestClient(app, raise_server_exceptions=False)
            client.cookies.set(SESSION_COOKIE_NAME, "valid-session")
            response = client.post(OPERATIONS_MUTATION, json={"output_dir": "/tmp/x"})
        assert response.status_code == 401


def _session_user(*, forced: bool = False, role: UserRole = UserRole.VIEWER) -> UserEntry:
    """Create a deterministic session user for dashboard state tests."""
    return UserEntry(
        id=1,
        username="viewer",
        password_hash="hash",
        role=role,
        must_change_password=forced,
        disabled=False,
        last_login_at=None,
    )


def _layout_payload() -> dict[str, object]:
    """Return a schema-valid dashboard layout payload."""
    return {
        "version": 2,
        "layout": [{"i": "signal", "x": 0, "y": 0, "w": 2, "h": 1}],
        "hidden": [],
    }


class TestDashboardSessionOwnedMutations:
    """Method+path-scoped session ownership for the dashboard state PUTs."""

    @pytest.mark.unit
    @pytest.mark.parametrize(
        ("path", "body"),
        [
            (DASHBOARD_LAYOUT, _layout_payload()),
            (DASHBOARD_TOUR, {"completed": True}),
        ],
    )
    def test_session_put_passes_without_api_key(self, path: str, body: dict[str, object]) -> None:
        """A session-carrying PUT on both state paths passes with no key."""
        settings = _make_settings()
        session_repo = MagicMock()
        session_repo.validate_and_touch.return_value = _session_user()
        state_repo = MagicMock()
        app.dependency_overrides[get_dashboard_user_state_repo] = lambda: state_repo
        try:
            with (
                patch("otalon_api.middleware.auth.get_settings", return_value=settings),
                patch(
                    "otalon_api.middleware.session_auth.get_session_repo",
                    return_value=session_repo,
                ),
            ):
                client = TestClient(app, raise_server_exceptions=False)
                client.cookies.set(SESSION_COOKIE_NAME, "valid-session")
                response = client.put(path, json=body)
        finally:
            app.dependency_overrides.clear()
        assert response.status_code == 200

    @pytest.mark.unit
    def test_anonymous_put_returns_401(self) -> None:
        """Anonymous dashboard state PUT is rejected before the registry."""
        settings = _make_settings()
        state_repo = MagicMock()
        app.dependency_overrides[get_dashboard_user_state_repo] = lambda: state_repo
        try:
            with (
                patch("otalon_api.middleware.auth.get_settings", return_value=settings),
                patch("otalon_api.middleware.session_auth.get_session_repo"),
            ):
                client = TestClient(app, raise_server_exceptions=False)
                layout = client.put(DASHBOARD_LAYOUT, json=_layout_payload())
                tour = client.put(DASHBOARD_TOUR, json={"completed": True})
        finally:
            app.dependency_overrides.clear()
        assert layout.status_code == 401
        assert tour.status_code == 401
        state_repo.set_layout.assert_not_called()
        state_repo.set_tour_completed.assert_not_called()

    @pytest.mark.unit
    def test_forced_change_session_put_returns_403(self) -> None:
        """A forced-change session cannot write dashboard state."""
        settings = _make_settings()
        session_repo = MagicMock()
        session_repo.validate_and_touch.return_value = _session_user(forced=True)
        state_repo = MagicMock()
        app.dependency_overrides[get_dashboard_user_state_repo] = lambda: state_repo
        try:
            with (
                patch("otalon_api.middleware.auth.get_settings", return_value=settings),
                patch(
                    "otalon_api.middleware.session_auth.get_session_repo",
                    return_value=session_repo,
                ),
            ):
                client = TestClient(app, raise_server_exceptions=False)
                client.cookies.set(SESSION_COOKIE_NAME, "forced-session")
                layout = client.put(DASHBOARD_LAYOUT, json=_layout_payload())
                tour = client.put(DASHBOARD_TOUR, json={"completed": True})
        finally:
            app.dependency_overrides.clear()
        assert layout.status_code == 403
        assert tour.status_code == 403
        assert layout.json()["detail"] == "Password change required"
        state_repo.set_layout.assert_not_called()
        state_repo.set_tour_completed.assert_not_called()

    @pytest.mark.unit
    def test_operator_key_without_session_put_returns_401(self) -> None:
        """An operator key does not satisfy the dashboard state PUTs."""
        settings = _make_settings()
        state_repo = MagicMock()
        app.dependency_overrides[get_dashboard_user_state_repo] = lambda: state_repo
        try:
            with (
                patch("otalon_api.middleware.auth.get_settings", return_value=settings),
                patch("otalon_api.middleware.session_auth.get_session_repo"),
            ):
                client = TestClient(
                    app,
                    headers={"X-API-Key": "test-secret-key"},
                    raise_server_exceptions=False,
                )
                response = client.put(DASHBOARD_LAYOUT, json=_layout_payload())
        finally:
            app.dependency_overrides.clear()
        assert response.status_code == 401
        state_repo.set_layout.assert_not_called()

    @pytest.mark.unit
    def test_dashboard_gets_keep_existing_read_rules(self) -> None:
        """Session reads pass; anonymous dashboard reads stay 401."""
        settings = _make_settings()
        session_repo = MagicMock()
        session_repo.validate_and_touch.return_value = _session_user()
        state_repo = MagicMock()
        state_repo.get_layout.return_value = _layout_payload()
        app.dependency_overrides[get_dashboard_user_state_repo] = lambda: state_repo
        try:
            with (
                patch("otalon_api.middleware.auth.get_settings", return_value=settings),
                patch(
                    "otalon_api.middleware.session_auth.get_session_repo",
                    return_value=session_repo,
                ),
            ):
                session_client = TestClient(app, raise_server_exceptions=False)
                session_client.cookies.set(SESSION_COOKIE_NAME, "valid-session")
                with_session = session_client.get(DASHBOARD_LAYOUT)
                anonymous = TestClient(app, raise_server_exceptions=False).get(DASHBOARD_LAYOUT)
        finally:
            app.dependency_overrides.clear()
        assert with_session.status_code == 200
        assert anonymous.status_code == 401
