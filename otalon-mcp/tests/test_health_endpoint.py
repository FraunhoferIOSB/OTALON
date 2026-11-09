"""Tests for the /health endpoint and _build_http_app wrapper in server.py."""

from unittest.mock import MagicMock

import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.testclient import TestClient

from otalon_mcp.server import _build_http_app, _health_check


def _make_mock_request() -> Request:
    """Create a minimal Starlette Request suitable for _health_check."""
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/health",
        "query_string": b"",
        "headers": [],
    }
    return Request(scope)


def _make_mock_mcp() -> MagicMock:
    """Create a MagicMock FastMCP that returns empty Starlette apps."""
    mock_mcp = MagicMock()
    mock_mcp.streamable_http_app.return_value = Starlette()
    mock_mcp.sse_app.return_value = Starlette()
    return mock_mcp


class TestHealthEndpoint:
    """Tests for the _health_check async handler."""

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_health_check_function_returns_json_response(self) -> None:
        """Calling _health_check directly returns a JSONResponse with status ok."""
        request = _make_mock_request()
        response = await _health_check(request)

        assert isinstance(response, JSONResponse)
        assert response.status_code == 200
        assert response.body == b'{"status":"ok"}'

    @pytest.mark.unit
    def test_health_returns_200_with_ok_status(self) -> None:
        """GET /health on the wrapped app returns HTTP 200 and {"status": "ok"}."""
        mock_mcp = _make_mock_mcp()
        app = _build_http_app(mock_mcp, "streamable-http")
        client = TestClient(app)

        response = client.get("/health")

        assert response.status_code == 200
        assert response.json() == {"status": "ok"}

    @pytest.mark.unit
    def test_mcp_route_requires_valid_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """MCP routes reject missing keys while health stays public."""
        monkeypatch.setenv("OTALON_MCP_ALLOWED_KEYS", "test:operator:secret-key")
        mock_mcp = _make_mock_mcp()
        app = _build_http_app(mock_mcp, "streamable-http")
        client = TestClient(app)

        assert client.get("/health").status_code == 200
        assert client.post("/mcp").status_code == 401
        assert client.post("/mcp", headers={"X-API-Key": "wrong"}).status_code == 401


class TestBuildHttpApp:
    """Tests for _build_http_app Starlette wrapper construction."""

    @pytest.mark.unit
    def test_build_http_app_streamable_http(self) -> None:
        """With transport='streamable-http', _build_http_app calls mcp.streamable_http_app()."""
        mock_mcp = _make_mock_mcp()

        app = _build_http_app(mock_mcp, "streamable-http")

        mock_mcp.streamable_http_app.assert_called_once()
        mock_mcp.sse_app.assert_not_called()
        assert isinstance(app, Starlette)

    @pytest.mark.unit
    def test_build_http_app_sse(self) -> None:
        """With transport='sse', _build_http_app calls mcp.sse_app()."""
        mock_mcp = _make_mock_mcp()

        app = _build_http_app(mock_mcp, "sse")

        mock_mcp.sse_app.assert_called_once()
        mock_mcp.streamable_http_app.assert_not_called()
        assert isinstance(app, Starlette)

    @pytest.mark.unit
    def test_build_http_app_health_route_exists(self) -> None:
        """The returned app has a /health route that responds to GET requests."""
        mock_mcp = _make_mock_mcp()
        app = _build_http_app(mock_mcp, "streamable-http")
        client = TestClient(app)

        response = client.get("/health")

        assert response.status_code == 200
        assert response.json() == {"status": "ok"}

    @pytest.mark.unit
    def test_build_http_app_post_health_not_ok(self) -> None:
        """POST to /health does not return a successful response."""
        mock_mcp = _make_mock_mcp()
        app = _build_http_app(mock_mcp, "streamable-http")
        client = TestClient(app, raise_server_exceptions=False)

        response = client.post("/health")

        assert response.status_code >= 400
