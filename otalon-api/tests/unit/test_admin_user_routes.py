"""Wave B endpoint and repository tests for product-user administration."""

from __future__ import annotations

from collections.abc import Generator
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from otalon_common.auth import UserRole, hash_password

from otalon_api.dependencies import get_session_repo, get_user_repo
from otalon_api.main import app
from otalon_api.middleware.session_auth import SESSION_COOKIE_NAME
from otalon_api.repositories.identity_repo import LastActiveAdminError, SessionRepository, UserEntry, UserRepository


def _entry(
    user_id: int = 1,
    role: UserRole = UserRole.ADMIN,
    username: str = "admin",
    must_change_password: bool = False,
) -> UserEntry:
    """Create a non-forced deterministic identity for route tests."""
    return UserEntry(
        id=user_id,
        username=username,
        password_hash=hash_password("test-password"),
        role=role,
        must_change_password=must_change_password,
        disabled=False,
        last_login_at=None,
        created_at=datetime.now(timezone.utc),
    )


def _client(user: UserEntry | None) -> tuple[TestClient, MagicMock]:
    """Build client with a scripted middleware session repository."""
    sessions = MagicMock()
    sessions.validate_and_touch.return_value = user
    middleware_patch = patch("otalon_api.middleware.session_auth.get_session_repo", return_value=sessions)
    middleware_patch.start()
    app.dependency_overrides[get_session_repo] = lambda: sessions
    app.dependency_overrides[get_user_repo] = lambda: MagicMock()
    client = TestClient(app, base_url="https://testserver")
    if user is not None:
        client.cookies.set(SESSION_COOKIE_NAME, "session-token")
    return client, sessions


@pytest.fixture(autouse=True)
def _clear_overrides() -> Generator[None, None, None]:
    """Clear application dependency overrides around each route test."""
    app.dependency_overrides.clear()
    yield
    patch.stopall()
    app.dependency_overrides.clear()


@pytest.mark.parametrize("method", ["get", "post", "patch", "delete"])
def test_admin_routes_without_cookie_return_401(method: str) -> None:
    """Every product-user management route rejects anonymous callers."""
    client, _sessions = _client(None)
    path = "/api/v1/admin/users"
    response = client.request(method.upper(), path, json={"username": "x", "role": "viewer"})
    assert response.status_code == 401


@pytest.mark.parametrize("role", [UserRole.VIEWER, UserRole.OPERATOR])
def test_non_admin_roles_return_403(role: UserRole) -> None:
    """Viewer and operator sessions cannot reach admin user management."""
    client, _sessions = _client(_entry(role=role))
    assert client.get("/api/v1/admin/users").status_code == 403


def test_create_user_returns_one_time_password_without_hash() -> None:
    """Creation persists a forced-change user and never returns its hash."""
    admin = _entry()
    users = MagicMock()
    created = _entry(2, UserRole.OPERATOR, "operator", must_change_password=True)
    users.create_user.return_value = created
    client, _sessions = _client(admin)
    app.dependency_overrides[get_user_repo] = lambda: users
    with patch("otalon_api.api.v1.admin_users.generate_bootstrap_password", return_value="once-only"):
        response = client.post("/api/v1/admin/users", json={"username": "operator", "role": "operator"})
    assert response.status_code == 201
    assert response.json()["one_time_password"] == "once-only"
    assert "password_hash" not in response.text
    users.create_user.assert_called_once_with("operator", UserRole.OPERATOR, "once-only")


def test_invalid_role_returns_422() -> None:
    """Role values outside the UserRole enum fail Pydantic validation."""
    client, _sessions = _client(_entry())
    response = client.post("/api/v1/admin/users", json={"username": "bad", "role": "superuser"})
    assert response.status_code == 422


def test_update_delete_and_self_delete_safety() -> None:
    """Admin can update/delete another user but cannot delete itself."""
    admin = _entry()
    users = MagicMock()
    users.update_user.return_value = _entry(2, UserRole.VIEWER, "viewer")
    users.delete_user.return_value = True
    client, sessions = _client(admin)
    app.dependency_overrides[get_user_repo] = lambda: users
    app.dependency_overrides[get_session_repo] = lambda: sessions
    updated = client.patch("/api/v1/admin/users/2", json={"role": "viewer"})
    assert updated.status_code == 200
    deleted = client.delete("/api/v1/admin/users/2")
    assert deleted.status_code == 200
    self_delete = client.delete("/api/v1/admin/users/1")
    assert self_delete.status_code == 403
    sessions.revoke_for_user.assert_called_once_with(2)


@pytest.mark.parametrize("payload", [{"role": "viewer"}, {"disabled": True}])
def test_last_active_admin_update_returns_409(payload: dict[str, object]) -> None:
    """Role removal and disabling of the last active admin are rejected."""
    users = MagicMock()
    users.update_user.side_effect = LastActiveAdminError
    client, _sessions = _client(_entry())
    app.dependency_overrides[get_user_repo] = lambda: users

    response = client.patch("/api/v1/admin/users/1", json=payload)

    assert response.status_code == 409
    assert response.json()["detail"] == "Cannot remove the last active administrator"


def test_last_active_admin_delete_returns_409() -> None:
    """Deleting the last active admin is rejected after self-delete check."""
    users = MagicMock()
    users.delete_user.side_effect = LastActiveAdminError
    client, _sessions = _client(_entry(2, UserRole.ADMIN, "other-admin"))
    app.dependency_overrides[get_user_repo] = lambda: users

    response = client.delete("/api/v1/admin/users/1")

    assert response.status_code == 409
    assert response.json()["detail"] == "Cannot remove the last active administrator"


def test_reset_password_revokes_target_sessions_and_forces_change() -> None:
    """Reset stores forced-change state and revokes every target session."""
    admin = _entry()
    target = _entry(2, UserRole.OPERATOR, "operator", must_change_password=True)
    users = MagicMock()
    users.reset_password.return_value = True
    users.find_by_id.return_value = target
    client, sessions = _client(admin)
    app.dependency_overrides[get_user_repo] = lambda: users
    with patch("otalon_api.api.v1.admin_users.generate_bootstrap_password", return_value="reset-once"):
        response = client.post("/api/v1/admin/users/2/reset-password")
    assert response.status_code == 200
    assert response.json()["one_time_password"] == "reset-once"
    users.reset_password.assert_called_once_with(2, "reset-once")
    sessions.revoke_for_user.assert_called_once_with(2)


def test_duplicate_username_returns_409() -> None:
    """Unique username violations become a conflict response."""
    import psycopg2.errors

    admin = _entry()
    users = MagicMock()
    users.create_user.side_effect = psycopg2.errors.UniqueViolation()
    client, _sessions = _client(admin)
    app.dependency_overrides[get_user_repo] = lambda: users
    response = client.post("/api/v1/admin/users", json={"username": "admin", "role": "viewer"})
    assert response.status_code == 409


def test_repository_create_hashes_password_and_sets_forced_change() -> None:
    """UserRepository sends Argon2id hash and forced-change flag to PostgreSQL."""
    postgres = MagicMock()
    postgres._execute_query.return_value = [
        {
            "id": 2,
            "username": "operator",
            "password_hash": "$argon2id$hash",
            "role": "operator",
            "must_change_password": True,
            "disabled": False,
            "last_login_at": None,
            "created_at": None,
        }
    ]
    user = UserRepository(postgres).create_user("operator", UserRole.OPERATOR, "once")
    params = postgres._execute_query.call_args.args[1]
    assert user.must_change_password is True
    assert params["password_hash"].startswith("$argon2id$")
    assert params["password_hash"] != "once"


def test_session_repository_reset_path_exposes_no_password() -> None:
    """Session repository revocation targets user without logging secrets."""
    postgres = MagicMock()
    SessionRepository(postgres).revoke_for_user(2)
    statement, params = postgres._execute_command.call_args.args
    assert "password" not in statement.lower()
    assert params == {"user_id": 2}
