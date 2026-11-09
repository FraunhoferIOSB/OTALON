"""API integration tests for ``DELETE /devices`` (bulk reaper).

Uses FastAPI's :class:`TestClient` with a stub repository (no Postgres
required). Mirrors the style of
:mod:`tests.integration.test_delete_device_api`:

- missing ``X-API-Key`` → 401
- viewer key → 403
- empty ``ids`` list → 422 (FastAPI validation)
- non-positive id → 422 (model_validator)
- operator key + stub returning a mixed result → 200 with body
- repository not initialised → 500

The full Postgres-backed cascade is covered by
:mod:`tests.integration.test_delete_devices` against the live DB.
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


class _BulkStubRepo:
    """Stub repository that records the requested ids and replays a fixed reply."""

    def __init__(self, *, deleted: list[int], not_found: list[int]) -> None:
        self._deleted = deleted
        self._not_found = not_found
        self.calls: list[list[int]] = []

    async def ping(self) -> None:
        return None

    async def delete_devices(self, device_ids: list[int]) -> dict[str, list[int]]:
        self.calls.append(list(device_ids))
        return {"deleted": self._deleted, "not_found": self._not_found}


def test_bulk_delete_requires_api_key(auth_client: TestClient) -> None:
    """``DELETE /devices`` without ``X-API-Key`` SHALL return 401."""
    response = auth_client.request("DELETE", "/devices", json={"ids": [1, 2]})
    assert response.status_code == 401


def test_bulk_delete_rejects_viewer(auth_client: TestClient) -> None:
    """A viewer key SHALL receive 403; the endpoint is operator-only."""
    response = auth_client.request(
        "DELETE",
        "/devices",
        json={"ids": [1, 2]},
        headers={"X-API-Key": _VIEWER_KEY},
    )
    assert response.status_code == 403


def test_bulk_delete_empty_list_returns_422(auth_client: TestClient) -> None:
    """Empty ``ids`` SHALL be rejected as a validation error."""
    response = auth_client.request(
        "DELETE",
        "/devices",
        json={"ids": []},
        headers={"X-API-Key": _OPERATOR_KEY},
    )
    assert response.status_code == 422


def test_bulk_delete_rejects_non_positive_id(auth_client: TestClient) -> None:
    """A zero or negative id SHALL be rejected by the model validator."""
    response = auth_client.request(
        "DELETE",
        "/devices",
        json={"ids": [1, 0, 3]},
        headers={"X-API-Key": _OPERATOR_KEY},
    )
    assert response.status_code == 422


def test_bulk_delete_rejects_oversize_batch(auth_client: TestClient) -> None:
    """More than 500 ids SHALL be rejected by ``max_length`` constraint."""
    response = auth_client.request(
        "DELETE",
        "/devices",
        json={"ids": list(range(1, 502))},
        headers={"X-API-Key": _OPERATOR_KEY},
    )
    assert response.status_code == 422


def test_bulk_delete_returns_200_with_mixed_result(
    auth_client: TestClient,
) -> None:
    """Operator key + mixed result SHALL return 200 with both arrays."""
    stub = _BulkStubRepo(deleted=[1, 3], not_found=[2])
    previous_repo = server_mod.app.state.api_state.repo
    server_mod.app.state.api_state.repo = stub
    try:
        response = auth_client.request(
            "DELETE",
            "/devices",
            json={"ids": [1, 2, 3]},
            headers={"X-API-Key": _OPERATOR_KEY},
        )
        assert response.status_code == 200
        body = response.json()
        assert body == {"deleted": [1, 3], "not_found": [2]}
        assert stub.calls == [[1, 2, 3]]
    finally:
        server_mod.app.state.api_state.repo = previous_repo


def test_bulk_delete_returns_500_when_repo_not_initialized(
    auth_client: TestClient,
) -> None:
    """If the lifespan startup did not run, the handler SHALL return 500."""
    previous_repo = server_mod.app.state.api_state.repo
    server_mod.app.state.api_state.repo = None
    try:
        response = auth_client.request(
            "DELETE",
            "/devices",
            json={"ids": [1]},
            headers={"X-API-Key": _OPERATOR_KEY},
        )
        assert response.status_code == 500
        assert response.json() == {"detail": "Repository not initialized"}
    finally:
        server_mod.app.state.api_state.repo = previous_repo
