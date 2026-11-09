"""API integration tests for ``DELETE /devices/{device_id}``.

Uses FastAPI's :class:`TestClient` with a stub repository (no Postgres
required). Mirrors the style of :mod:`tests.integration.test_api_auth`:

- missing ``X-API-Key`` → 401
- viewer key → 403
- operator key + stub repo returns False → 404 with the explicit
  ``"Device not found"`` detail (not FastAPI's generic 404)
- operator key + stub repo returns True → 204 with empty body
- repository not initialised → 500

The full Postgres-backed cascade is covered by
:mod:`tests.integration.test_delete_device` against the live DB.
"""

from __future__ import annotations

from typing import Iterator

import pytest
from fastapi.testclient import TestClient

import otalon_scan.api.server as server_mod
from otalon_scan.api.server import app
from otalon_scan.core.auth import get_allowed_keys, set_allowed_keys

_VIEWER_KEY = "viewer-secret-0123456789"
_OPERATOR_KEY = "operator-secret-0123456789"


@pytest.fixture
def auth_client() -> Iterator[TestClient]:
    """Yield a :class:`TestClient` with a known allow-list installed."""
    previous = get_allowed_keys()
    set_allowed_keys(
        {
            _VIEWER_KEY: ("ui-prod", "viewer"),
            _OPERATOR_KEY: ("mcp-prod", "operator"),
        }
    )
    try:
        yield TestClient(app)
    finally:
        set_allowed_keys(previous)


class _StubRepo:
    """Stub repository that records the requested id and replays a fixed reply."""

    def __init__(self, *, exists: bool) -> None:
        self.exists = exists
        self.calls: list[int] = []

    async def ping(self) -> None:
        return None

    async def delete_device(self, device_id: int) -> bool:
        self.calls.append(device_id)
        return self.exists


def test_delete_device_requires_api_key(auth_client: TestClient) -> None:
    """``DELETE /devices/{id}`` without ``X-API-Key`` SHALL return 401."""
    response = auth_client.delete("/devices/123")
    assert response.status_code == 401


def test_delete_device_rejects_viewer(auth_client: TestClient) -> None:
    """A viewer key SHALL receive 403; the endpoint is operator-only."""
    response = auth_client.delete("/devices/123", headers={"X-API-Key": _VIEWER_KEY})
    assert response.status_code == 403


def test_delete_device_returns_404_when_repo_returns_false(
    auth_client: TestClient,
) -> None:
    """Operator key + non-existent device SHALL return 404 with our explicit detail."""
    stub = _StubRepo(exists=False)
    previous_repo = server_mod.app.state.api_state.repo
    server_mod.app.state.api_state.repo = stub
    try:
        response = auth_client.delete("/devices/999999", headers={"X-API-Key": _OPERATOR_KEY})
        assert response.status_code == 404
        assert response.json() == {"detail": "Device not found"}
        assert stub.calls == [999999]
    finally:
        server_mod.app.state.api_state.repo = previous_repo


def test_delete_device_returns_204_on_success(auth_client: TestClient) -> None:
    """Operator key + existing device SHALL return 204 with no body."""
    stub = _StubRepo(exists=True)
    previous_repo = server_mod.app.state.api_state.repo
    server_mod.app.state.api_state.repo = stub
    try:
        response = auth_client.delete("/devices/42", headers={"X-API-Key": _OPERATOR_KEY})
        assert response.status_code == 204
        assert response.content == b""
        assert stub.calls == [42]
    finally:
        server_mod.app.state.api_state.repo = previous_repo


def test_delete_device_returns_500_when_repo_not_initialized(
    auth_client: TestClient,
) -> None:
    """If the lifespan startup did not run, the handler SHALL return 500."""
    previous_repo = server_mod.app.state.api_state.repo
    server_mod.app.state.api_state.repo = None
    try:
        response = auth_client.delete("/devices/1", headers={"X-API-Key": _OPERATOR_KEY})
        assert response.status_code == 500
        assert response.json() == {"detail": "Repository not initialized"}
    finally:
        server_mod.app.state.api_state.repo = previous_repo
