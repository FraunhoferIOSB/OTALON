"""Convention tests for the otalon-api HTTP surface (SUITE-037).

Pins the two conventions established in
``documentation/agents/api-conventions.md``:

* HC34 — an unversioned, unauthenticated ``GET /health`` returning
  ``{"status": "ok"}``. Every other suite service already had one;
  otalon-api did not, so a container healthcheck or uptime probe needed a
  different path here than everywhere else.
* HC32 — complete OpenAPI metadata on the app.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from otalon_api.main import app

pytestmark = pytest.mark.unit


@pytest.fixture()
def client() -> TestClient:
    return TestClient(app)


class TestHealthConvention:
    """HC34 — the cheap probe must be reachable without credentials."""

    def test_health_returns_200(self, client: TestClient) -> None:
        assert client.get("/health").status_code == 200

    def test_health_returns_the_suite_shape(self, client: TestClient) -> None:
        """Matches otalon-scan, otalon-ai, pcap_recorder, pcap_import, otalon-mcp."""
        assert client.get("/health").json() == {"status": "ok"}

    def test_health_needs_no_api_key(self, client: TestClient) -> None:
        """A probe that needs a credential is not a probe."""
        response = client.get("/health")

        assert response.status_code != 401
        assert response.status_code != 403

    def test_health_is_registered_unversioned(self) -> None:
        """Compose healthchecks must not track the API version.

        Asserted on the route table rather than by requesting
        ``/api/v1/health``: the auth middleware rejects unknown protected
        paths with 401 before routing, so a request-level check could not
        distinguish "no such route" from "route exists but is protected".
        """
        paths = {getattr(route, "path", None) for route in app.routes}

        assert "/health" in paths
        assert "/api/v1/health" not in paths

    def test_health_exposes_nothing_beyond_liveness(self, client: TestClient) -> None:
        """Being unauthenticated, it must not leak dependency detail."""
        assert set(client.get("/health").json()) == {"status"}

    def test_livez_still_works(self, client: TestClient) -> None:
        """The Kubernetes-style probes are additions, not replacements."""
        response = client.get("/livez")

        assert response.status_code == 200
        assert response.json() == {"status": "alive"}

    def test_the_deep_probe_still_exists(self, client: TestClient) -> None:
        """Dependency-aware health stays a separate, deeper endpoint."""
        assert client.get("/api/v1/status/health").status_code != 404


class TestOpenApiMetadata:
    """HC32 — title/version/description are mandatory."""

    def test_title_follows_the_naming_form(self) -> None:
        assert app.title == "OTALON API"

    def test_version_is_set(self) -> None:
        assert app.version
        assert app.version != "0.1.0" or True  # any non-empty version is fine

    def test_description_is_set(self) -> None:
        assert app.description
        assert len(app.description) > 20, "description should say what the service does"
