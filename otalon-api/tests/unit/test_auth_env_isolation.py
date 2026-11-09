"""Regression tests for API-020 — auth must not depend on the host ``.env``.

``src/otalon_api/settings.py`` loads the repo-root ``.env`` as a pydantic ``env_file``.
Before this guard, a host that defined ``ADMIN_API_KEY`` armed the fail-closed
registry in ``src/otalon_api/middleware/auth.py`` during the test run, so 17 tests that
expected an unauthenticated 200 got a 401 instead — the same commit passed on a
clean checkout and failed on a configured host.

``tests/conftest.py`` now neutralises the auth-relevant environment variables
before importing the app. These tests pin both halves of that contract:

* the ambient environment leaks no key into the test session, and
* auth still genuinely rejects when a test arms it on purpose, so the guard
  cannot silently disable authentication coverage.
"""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

from otalon_api.main import app
from otalon_api.middleware.auth import get_api_key_registry
from otalon_api.settings import Settings

pytestmark = pytest.mark.unit

_PROTECTED_PATH = "/api/v1/operations/configuration/boot"


def _settings_with_key(api_key: str) -> Settings:
    """Build minimal settings carrying the given admin API key."""
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


class TestAmbientEnvIsolation:
    """The host ``.env`` must not arm auth during the test session."""

    @pytest.mark.parametrize("env_key", ["ADMIN_API_KEY", "OTALON_API_ALLOWED_KEYS"])
    def test_auth_env_var_is_neutralised(self, env_key: str) -> None:
        """conftest blanks the auth env vars regardless of the host ``.env``."""
        assert os.environ.get(env_key) == ""

    def test_registry_is_unconfigured_without_explicit_setup(self) -> None:
        """With no test-supplied key the registry holds no entries."""
        assert get_api_key_registry().configured is False


class TestAuthStillArms:
    """Auth must reject when a test arms it — the guard is not a bypass."""

    def test_missing_key_is_rejected_when_configured(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A protected path returns 401 without the header."""
        settings = _settings_with_key("armed-secret")
        monkeypatch.setattr("otalon_api.middleware.auth.get_settings", lambda: settings)
        monkeypatch.setattr("otalon_api.dependencies.get_settings", lambda: settings)
        client = TestClient(app, raise_server_exceptions=False)
        assert client.get(_PROTECTED_PATH).status_code == 401

    def test_wrong_key_is_rejected_when_configured(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A protected path returns 401 for a non-matching key."""
        settings = _settings_with_key("armed-secret")
        monkeypatch.setattr("otalon_api.middleware.auth.get_settings", lambda: settings)
        monkeypatch.setattr("otalon_api.dependencies.get_settings", lambda: settings)
        client = TestClient(app, raise_server_exceptions=False)
        response = client.get(_PROTECTED_PATH, headers={"X-API-Key": "wrong-secret"})
        assert response.status_code == 401
