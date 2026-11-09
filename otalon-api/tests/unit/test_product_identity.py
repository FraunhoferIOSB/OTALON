"""Wave A tests for schema, repositories, middleware, and auth routes."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from otalon_common.auth import UserRole

from otalon_api.dependencies import get_session_repo, get_user_repo
from otalon_api.main import app
from otalon_api.middleware.session_auth import SESSION_COOKIE_NAME, _session_required
from otalon_api.repositories.identity_repo import (
    SessionRepository,
    UserEntry,
    UserRepository,
    bootstrap_identity,
)
from otalon_api.repositories.identity_schema import ensure_identity_schema


class _Cursor:
    """Small scripted cursor for schema and bootstrap repository tests."""

    def __init__(self, count: int = 0, row: dict[str, Any] | None = None) -> None:
        self.count = count
        self.row = row
        self.executed: list[str] = []
        self._last = ""

    def __enter__(self) -> "_Cursor":
        return self

    def __exit__(self, *_args: Any) -> None:
        return None

    def execute(self, statement: str, _params: Any = None) -> None:
        self.executed.append(statement)
        self._last = statement

    def fetchone(self) -> Any:
        if "COUNT" in self._last:
            return (self.count,)
        return self.row


class _Connection:
    """Context-manager connection backed by one scripted cursor."""

    def __init__(self, cursor: _Cursor) -> None:
        self.cursor_value = cursor
        self.commits = 0

    def __enter__(self) -> "_Connection":
        return self

    def __exit__(self, *_args: Any) -> None:
        return None

    def cursor(self, **_kwargs: Any) -> _Cursor:
        return self.cursor_value

    def commit(self) -> None:
        self.commits += 1


def _user(*, forced: bool = False, role: str = "admin") -> UserEntry:
    """Create deterministic user identity for middleware tests."""
    return UserEntry(
        id=1,
        username="admin",
        password_hash="hash",
        role=UserRole(role),
        must_change_password=forced,
        disabled=False,
        last_login_at=None,
    )


def test_identity_schema_is_idempotent() -> None:
    """Identity schema bootstrap can run twice without error."""
    cursor = _Cursor()
    connection = _Connection(cursor)
    repo = MagicMock()
    repo.connection.return_value = connection
    ensure_identity_schema(repo)
    ensure_identity_schema(repo)
    assert connection.commits == 2
    assert sum("CREATE TABLE IF NOT EXISTS users" in sql for sql in cursor.executed) == 2


def test_identity_schema_creates_dashboard_user_state_idempotently() -> None:
    """The dashboard_user_state table bootstraps exactly like users/sessions."""
    cursor = _Cursor()
    connection = _Connection(cursor)
    repo = MagicMock()
    repo.connection.return_value = connection
    ensure_identity_schema(repo)
    ensure_identity_schema(repo)
    assert connection.commits == 2
    assert sum("CREATE TABLE IF NOT EXISTS dashboard_user_state" in sql for sql in cursor.executed) == 2


def test_dashboard_user_state_cascades_on_user_delete() -> None:
    """The state row follows its user on delete (FK ON DELETE CASCADE)."""
    cursor = _Cursor()
    connection = _Connection(cursor)
    repo = MagicMock()
    repo.connection.return_value = connection
    ensure_identity_schema(repo)
    ddl = next(sql for sql in cursor.executed if "dashboard_user_state" in sql)
    normalized = " ".join(ddl.split())
    assert "user_id BIGINT PRIMARY KEY" in normalized
    assert "layout JSONB" in normalized
    assert "tour_completed JSONB" in normalized
    assert "updated_at TIMESTAMPTZ" in normalized
    assert "REFERENCES users(id) ON DELETE CASCADE" in normalized


def test_bootstrap_creates_once_when_users_empty() -> None:
    """Second bootstrap check does not insert another admin."""
    cursor = _Cursor(count=0)
    connection = _Connection(cursor)
    repo = MagicMock()
    repo.connection.return_value = connection
    users = UserRepository(repo)
    assert users.create_bootstrap_admin("one-time") is True
    cursor.count = 1
    assert users.create_bootstrap_admin("another") is False
    assert sum("INSERT INTO users" in sql for sql in cursor.executed) == 1


def test_bootstrap_logs_password_only_when_inserted() -> None:
    """Bootstrap emits one intended credential line and no restart reseed line."""
    cursor = _Cursor(count=0)
    connection = _Connection(cursor)
    repo = MagicMock()
    repo.connection.return_value = connection
    with patch("otalon_api.repositories.identity_repo.logger") as logger:
        assert bootstrap_identity(repo) is True
        cursor.count = 1
        assert bootstrap_identity(repo) is False
    logger.warning.assert_called_once()
    assert "admin_api_key" not in str(logger.warning.call_args)


def test_authenticate_uses_same_argon2_verifier_for_unknown_and_wrong_user() -> None:
    """Known and unknown usernames both execute one verifier call."""
    repo = MagicMock()
    users = UserRepository(repo)
    known = _user()
    repo._execute_query.side_effect = [
        [
            {
                "id": known.id,
                "username": known.username,
                "password_hash": known.password_hash,
                "role": known.role.value,
                "must_change_password": False,
                "disabled": False,
                "last_login_at": None,
            }
        ],
        [],
    ]
    with patch("otalon_api.repositories.identity_repo.verify_password", return_value=False) as verifier:
        assert users.authenticate("admin", "wrong") is None
        assert users.authenticate("missing", "wrong") is None
    assert verifier.call_count == 2


def test_session_validation_touches_sliding_expiry() -> None:
    """Valid session update extends expiry by 24 hours on every request."""
    row = {
        "id": 1,
        "username": "admin",
        "password_hash": "hash",
        "role": "admin",
        "must_change_password": False,
        "disabled": False,
        "last_login_at": None,
    }
    cursor = _Cursor(row=row)
    connection = _Connection(cursor)
    repo = MagicMock()
    repo.connection.return_value = connection
    result = SessionRepository(repo).validate_and_touch("opaque-session")
    assert result is not None
    assert any("expires_at=now() +" in sql and "24 hours" in sql for sql in cursor.executed)
    assert all("opaque-session" not in sql for sql in cursor.executed)


@pytest.mark.parametrize(
    ("base_url", "forwarded_proto", "secure"),
    [
        ("https://testserver", None, True),
        ("http://testserver", None, False),
        ("http://testserver", "https", True),
    ],
)
def test_auth_routes_set_cookie_for_request_scheme(base_url: str, forwarded_proto: str | None, secure: bool) -> None:
    """Login cookie follows direct or forwarded request scheme."""
    users = MagicMock()
    users.authenticate.return_value = _user()
    sessions = MagicMock()
    sessions.create.return_value = "opaque-session"
    app.dependency_overrides[get_user_repo] = lambda: users
    app.dependency_overrides[get_session_repo] = lambda: sessions
    try:
        with patch("otalon_api.middleware.session_auth.get_session_repo", return_value=sessions):
            client = TestClient(app, base_url=base_url)
            headers = {"X-Forwarded-Proto": forwarded_proto} if forwarded_proto else None
            login = client.post(
                "/api/v1/auth/login",
                json={"username": "admin", "password": "password"},
                headers=headers,
            )
            assert login.status_code == 200
            cookie = login.headers["set-cookie"]
            assert "HttpOnly" in cookie
            assert ("Secure" in cookie) is secure
            assert "SameSite=lax" in cookie
            assert "opaque-session" not in login.text
            sessions.validate_and_touch.return_value = _user()
            if secure:
                client.cookies.set(SESSION_COOKIE_NAME, "opaque-session")
            me = client.get("/api/v1/auth/me")
            assert me.status_code == 200
            logged_out = client.post("/api/v1/auth/logout")
            assert logged_out.status_code == 200
            sessions.revoke.assert_called_once_with("opaque-session")
    finally:
        app.dependency_overrides.clear()


def test_forced_change_gate_blocks_product_user_path() -> None:
    """Forced-change session is rejected before protected handler execution."""
    sessions = MagicMock()
    sessions.validate_and_touch.return_value = _user(forced=True)
    app.dependency_overrides[get_session_repo] = lambda: sessions
    try:
        with patch("otalon_api.middleware.session_auth.get_session_repo", return_value=sessions):
            client = TestClient(app)
            client.cookies.set(SESSION_COOKIE_NAME, "opaque-session")
            response = client.get("/api/v1/admin/users")
            assert response.status_code == 403
            assert response.json()["detail"] == "Password change required"
    finally:
        app.dependency_overrides.clear()


def test_missing_product_session_is_rejected_before_handler() -> None:
    """Protected product path without cookie returns 401."""
    response = TestClient(app).get("/api/v1/admin/users")
    assert response.status_code == 401


def test_session_protection_matches_only_named_requests() -> None:
    """Only the named mutation requests require product sessions."""
    assert _session_required("POST", "/api/v1/operations/reset") is True
    assert _session_required("POST", "/api/v1/operations/restore") is True
    assert _session_required("POST", "/api/v1/operations/services/action") is True
    assert _session_required("PUT", "/api/v1/dashboard/layout") is True
    assert _session_required("PUT", "/api/v1/dashboard/tour") is True
    assert _session_required("GET", "/api/v1/operations/reset") is False
    assert _session_required("POST", "/api/v1/operations/reset/postgresql/preview") is False
    assert _session_required("GET", "/api/v1/operations/pipeline") is False
    assert _session_required("GET", "/api/v1/dashboard/layout") is False
    assert _session_required("POST", "/api/v1/dashboard/layout") is False
