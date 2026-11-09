"""Convention tests for the otalon-scan HTTP surface (SUITE-037).

Pins the conventions from ``documentation/agents/api-conventions.md``:

* HC32 — ``title``/``version``/``description`` on the app. The description
  was missing.
* HC34 — ``GET /health`` unversioned, answering ``{"status": "ok"}``.
* HC31 — the unversioned route paths are a deliberate, documented
  limitation: ``otalon-api`` proxies to them, so renaming them under
  ``/api/v1/`` would break a live consumer. This test pins the paths that
  ``services/scan_proxy_service.py`` depends on, so a future prefix
  migration has to be an explicit, additive decision rather than an
  accident.
"""

from __future__ import annotations

import pytest

from otalon_scan.api.server import app


class TestOpenApiMetadata:
    def test_title_follows_the_naming_form(self) -> None:
        assert app.title == "OTALON Scan API"

    def test_version_is_set(self) -> None:
        assert app.version

    def test_description_is_set(self) -> None:
        assert app.description
        assert len(app.description) > 20


class TestHealthConvention:
    def test_health_is_registered_unversioned(self) -> None:
        paths = {getattr(route, "path", None) for route in app.routes}

        assert "/health" in paths
        assert "/api/v1/health" not in paths


class TestProxiedPathsAreStable:
    """HC31 — these paths are consumed by otalon-api; do not rename lightly."""

    @pytest.mark.parametrize(
        "path",
        [
            "/health",
            "/modules",
            "/scans",
            "/scans/start",
            "/scans/running",
            "/scans/finished",
            "/scans/interfaces",
            "/devices",
            "/vulnerabilities/lookup",
            "/vulnerabilities/lookups",
        ],
    )
    def test_consumer_facing_path_is_present(self, path: str) -> None:
        paths = {getattr(route, "path", None) for route in app.routes}

        assert path in paths, (
            f"{path} is proxied by otalon-api " f"(services/scan_proxy_service.py); renaming it breaks the UI"
        )

    @pytest.mark.parametrize(
        "path",
        [
            "/scans/{scan_id}/events",
            "/vulnerabilities/lookups/{job_id}/events",
        ],
    )
    def test_sse_path_is_present(self, path: str) -> None:
        paths = {getattr(route, "path", None) for route in app.routes}

        assert path in paths
