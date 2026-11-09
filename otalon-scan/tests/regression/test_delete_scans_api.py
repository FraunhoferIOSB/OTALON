"""API integration tests for ``DELETE /scans`` (bulk reaper).

Uses FastAPI's :class:`TestClient` with a stub repository (no Postgres
required). Mirrors the style of
:mod:`tests.integration.test_delete_devices_api`:

- missing ``X-API-Key`` → 401
- viewer key → 403
- empty ``ids`` list → 422 (FastAPI validation)
- operator key + stub returning a mixed result → 200 with body
- repository not initialised → 500
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

    def __init__(self, *, deleted: list[str], not_found: list[str]) -> None:
        self._deleted = deleted
        self._not_found = not_found
        self.calls: list[list[str]] = []

    async def ping(self) -> None:
        return None

    async def delete_scans(self, scan_ids: list[str]) -> dict[str, list[str]]:
        self.calls.append(list(scan_ids))
        return {"deleted": self._deleted, "not_found": self._not_found}


def test_bulk_delete_requires_api_key(auth_client: TestClient) -> None:
    """``DELETE /scans`` without ``X-API-Key`` SHALL return 401."""
    response = auth_client.request("DELETE", "/scans", json={"ids": ["a", "b"]})
    assert response.status_code == 401


def test_bulk_delete_rejects_viewer(auth_client: TestClient) -> None:
    """A viewer key SHALL receive 403; the endpoint is operator-only."""
    response = auth_client.request(
        "DELETE",
        "/scans",
        json={"ids": ["a", "b"]},
        headers={"X-API-Key": _VIEWER_KEY},
    )
    assert response.status_code == 403


def test_bulk_delete_empty_list_returns_422(auth_client: TestClient) -> None:
    """Empty ``ids`` SHALL be rejected as a validation error."""
    response = auth_client.request(
        "DELETE",
        "/scans",
        json={"ids": []},
        headers={"X-API-Key": _OPERATOR_KEY},
    )
    assert response.status_code == 422


def test_bulk_delete_rejects_oversize_batch(auth_client: TestClient) -> None:
    """More than 500 ids SHALL be rejected by ``max_length`` constraint."""
    response = auth_client.request(
        "DELETE",
        "/scans",
        json={"ids": [f"scan-{i}" for i in range(501)]},
        headers={"X-API-Key": _OPERATOR_KEY},
    )
    assert response.status_code == 422


def test_bulk_delete_returns_200_with_mixed_result(
    auth_client: TestClient,
) -> None:
    """Operator key + mixed result SHALL return 200 with both arrays."""
    stub = _BulkStubRepo(deleted=["s1", "s3"], not_found=["s2"])
    previous_repo = server_mod.app.state.api_state.repo
    server_mod.app.state.api_state.repo = stub
    try:
        response = auth_client.request(
            "DELETE",
            "/scans",
            json={"ids": ["s1", "s2", "s3"]},
            headers={"X-API-Key": _OPERATOR_KEY},
        )
        assert response.status_code == 200
        body = response.json()
        assert body == {"deleted": ["s1", "s3"], "not_found": ["s2"]}
        assert stub.calls == [["s1", "s2", "s3"]]
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
            "/scans",
            json={"ids": ["s1"]},
            headers={"X-API-Key": _OPERATOR_KEY},
        )
        assert response.status_code == 500
        assert response.json() == {"detail": "Repository not initialized"}
    finally:
        server_mod.app.state.api_state.repo = previous_repo
