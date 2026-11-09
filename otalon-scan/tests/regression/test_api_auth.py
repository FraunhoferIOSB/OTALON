"""Integration tests for the API-key auth layer (Phase 5 / scan--api-auth).

These tests drive the real ``otalon_scan.api.server.app`` through FastAPI's
:class:`TestClient` and override the allow-list on a per-test basis via
:func:`otalon_scan.core.auth.set_allowed_keys`. Going through ``TestClient`` (and
its synchronous request loop) gives us cheap, deterministic coverage of
the dependency chain without spinning up uvicorn.

The lifespan startup is bypassed entirely by *not* using
``with TestClient(...) as c:`` — FastAPI then skips ``lifespan``, which
keeps these tests independent of PostgreSQL and of any module-discovery
    side-effects. The seeded ``OTALON_SCAN_ALLOWED_KEYS`` in
``conftest._set_env_for_tests`` only matters when a test does enter the
lifespan; here we set allow-lists explicitly.

Coverage matrix (mapped to ``scan--api-auth`` scenarios):

- missing ``X-API-Key`` header → 401
- wrong key → 401
- valid viewer on read endpoint → 200 (or non-auth error like 500)
- valid viewer on mutating endpoint → 403
- valid operator on mutating endpoint → reaches the handler (NOT 401/403)
- ``GET /health`` without auth → 200
- key rotation: two keys with the same name both work; removing one
  revokes only that key.
"""

from __future__ import annotations

from typing import Iterator

import pytest
from fastapi.testclient import TestClient

from otalon_scan.api.server import app
from otalon_scan.core.auth import get_allowed_keys, set_allowed_keys

# ---- Allow-list helpers ----

_VIEWER_KEY = "viewer-secret-0123456789"
_OPERATOR_KEY = "operator-secret-0123456789"
_OLD_OPERATOR_KEY = "operator-secret-OLD-0123"
_NEW_OPERATOR_KEY = "operator-secret-NEW-0123"


@pytest.fixture
def auth_client() -> Iterator[TestClient]:
    """Yield a :class:`TestClient` with a known allow-list installed.

    Saves and restores the previous allow-list so independent tests do
    not leak state. The lifespan is intentionally not entered (no
    ``with`` block on ``TestClient``) so PostgreSQL is not required.
    """
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


@pytest.fixture
def rotation_client() -> Iterator[TestClient]:
    """Yield a TestClient pre-loaded with two keys sharing one logical name.

    Mirrors the spec's key-rotation scenario: ``mcp-prod`` has both an
    old and a new key valid simultaneously.
    """
    previous = get_allowed_keys()
    set_allowed_keys(
        {
            _OLD_OPERATOR_KEY: ("mcp-prod", "operator"),
            _NEW_OPERATOR_KEY: ("mcp-prod", "operator"),
        }
    )
    try:
        yield TestClient(app)
    finally:
        set_allowed_keys(previous)


# ---- Basic auth flow ----


def test_health_endpoint_is_unauthenticated(auth_client: TestClient) -> None:
    """``GET /health`` SHALL be reachable without any ``X-API-Key`` header.

    HC4 (2026-05-18): ``/health`` now pings the database. This test
    bypasses the lifespan, so we install a stub repo with an async
    ``ping`` that succeeds — that proves the endpoint itself is
    unauthenticated. See ``test_health_endpoint_returns_503_when_db_unreachable``
    for the failure path.
    """
    import otalon_scan.api.server as server_mod

    class _StubRepo:
        async def ping(self) -> None:
            return None

    previous_repo = server_mod.app.state.api_state.repo
    server_mod.app.state.api_state.repo = _StubRepo()
    try:
        response = auth_client.get("/health")
        assert response.status_code == 200
        assert response.json().get("status") == "ok"
    finally:
        server_mod.app.state.api_state.repo = previous_repo


def test_missing_api_key_returns_401(auth_client: TestClient) -> None:
    """A protected endpoint without ``X-API-Key`` SHALL return 401."""
    response = auth_client.get("/scans/running")
    assert response.status_code == 401
    assert "missing" in response.json().get("detail", "").lower()


def test_invalid_api_key_returns_401(auth_client: TestClient) -> None:
    """A protected endpoint with an unknown key SHALL return 401."""
    response = auth_client.get(
        "/scans/running",
        headers={"X-API-Key": "this-key-does-not-exist-anywhere"},
    )
    assert response.status_code == 401
    assert "invalid" in response.json().get("detail", "").lower()


def test_empty_api_key_header_returns_401(auth_client: TestClient) -> None:
    """An empty ``X-API-Key`` header SHALL be treated like a missing one."""
    response = auth_client.get("/scans/running", headers={"X-API-Key": ""})
    assert response.status_code == 401


# ---- Role enforcement ----


def test_viewer_key_accepted_on_read_endpoint(auth_client: TestClient) -> None:
    """A viewer key SHALL pass the auth dependency on a read endpoint.

    The handler itself may still fail (e.g. 500 because the lifespan was
    skipped and ``_manager`` is None). The contract under test here is
    auth: the response status SHALL NOT be 401 or 403.
    """
    response = auth_client.get("/scans/running", headers={"X-API-Key": _VIEWER_KEY})
    assert response.status_code not in (401, 403), response.text


def test_viewer_key_rejected_on_mutating_endpoint(auth_client: TestClient) -> None:
    """A viewer key SHALL receive 403 on a mutating endpoint."""
    response = auth_client.post(
        "/scans/start",
        json={"module_name": "modules/arp_scan", "overrides": {}},
        headers={"X-API-Key": _VIEWER_KEY},
    )
    assert response.status_code == 403
    detail = response.json().get("detail", "").lower()
    assert "viewer" in detail and "operator" in detail


def test_operator_key_accepted_on_mutating_endpoint(auth_client: TestClient) -> None:
    """An operator key SHALL pass the auth dependency on a mutating endpoint.

    The actual scan launch may fail (e.g. 500 because the lifespan was
    not entered and ``_manager`` is None) — that is not under test here.
    What we assert is the inverse: the auth dependency SHALL NOT reject
    with 401 or 403.
    """
    response = auth_client.post(
        "/scans/start",
        json={"module_name": "modules/arp_scan", "overrides": {}},
        headers={"X-API-Key": _OPERATOR_KEY},
    )
    assert response.status_code not in (401, 403), response.text


def test_operator_key_accepted_on_read_endpoint(auth_client: TestClient) -> None:
    """An operator key SHALL also satisfy a ``viewer`` requirement."""
    response = auth_client.get("/scans/running", headers={"X-API-Key": _OPERATOR_KEY})
    assert response.status_code not in (401, 403), response.text


# ---- Coverage of every protected route ----


@pytest.mark.parametrize(
    "method,path",
    [
        ("GET", "/modules"),
        ("GET", "/modules/arp_scan/config"),
        ("GET", "/scans/running"),
        ("GET", "/scans/finished"),
        ("GET", "/scans/00000000-0000-0000-0000-000000000000/results"),
        ("GET", "/scans/00000000-0000-0000-0000-000000000000/events"),
        ("POST", "/scans/start"),
        ("POST", "/scans/00000000-0000-0000-0000-000000000000/stop"),
    ],
)
def test_every_protected_route_returns_401_without_key(auth_client: TestClient, method: str, path: str) -> None:
    """Every route except ``GET /health`` SHALL require an ``X-API-Key`` header."""
    response = auth_client.request(method, path, json={} if method == "POST" else None)
    assert response.status_code == 401, (method, path, response.text)


# ---- Key rotation ----


def test_key_rotation_both_keys_accepted(rotation_client: TestClient) -> None:
    """During a rotation window, both the old and the new key SHALL work."""
    for key in (_OLD_OPERATOR_KEY, _NEW_OPERATOR_KEY):
        response = rotation_client.get("/scans/running", headers={"X-API-Key": key})
        assert response.status_code not in (401, 403), (key, response.text)


def test_key_rotation_removing_one_revokes_only_that_key(
    rotation_client: TestClient,
) -> None:
    """Removing the old key from the allow-list SHALL revoke only the old key.

    The new key SHALL continue to authenticate as the same logical caller.
    """
    # Remove the old key while keeping the new one.
    current = get_allowed_keys()
    current.pop(_OLD_OPERATOR_KEY, None)
    set_allowed_keys(current)

    old_response = rotation_client.get("/scans/running", headers={"X-API-Key": _OLD_OPERATOR_KEY})
    assert old_response.status_code == 401, old_response.text

    new_response = rotation_client.get("/scans/running", headers={"X-API-Key": _NEW_OPERATOR_KEY})
    assert new_response.status_code not in (401, 403), new_response.text


# ---- Header name is case-insensitive (HTTP-level guarantee) ----


def test_header_name_is_case_insensitive(auth_client: TestClient) -> None:
    """The ``X-API-Key`` header is matched case-insensitively (HTTP spec)."""
    response = auth_client.get("/scans/running", headers={"x-api-key": _VIEWER_KEY})
    assert response.status_code not in (401, 403), response.text
