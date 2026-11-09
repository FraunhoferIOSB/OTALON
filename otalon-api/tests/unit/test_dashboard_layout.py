"""Unit tests for the per-account dashboard state endpoints.

Covers GET/PUT ``/api/v1/dashboard/layout`` and GET/PUT
``/api/v1/dashboard/tour`` under the session-cookie contract (UI-199,
UI-200 wave A): own-row reads/writes, 422 payload caps, and the explicit
security negatives (anonymous, invalid session, operator-key-only,
forced-change, viewer role, body-supplied ``user_id``).
"""

from __future__ import annotations

from collections.abc import Generator
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from otalon_common.auth import UserRole

from otalon_api.dependencies import get_dashboard_user_state_repo
from otalon_api.main import app
from otalon_api.middleware.session_auth import SESSION_COOKIE_NAME
from otalon_api.repositories.identity_repo import UserEntry
from otalon_api.settings import Settings

LAYOUT_ENDPOINT = "/api/v1/dashboard/layout"
TOUR_ENDPOINT = "/api/v1/dashboard/tour"
OPERATOR_API_KEY = "test-secret"


@pytest.fixture(autouse=True)
def _cleanup_overrides() -> Generator[None, None, None]:
    """Remove dependency overrides after each test."""
    yield
    app.dependency_overrides.clear()


def _user(user_id: int = 1, role: str = "viewer", forced: bool = False) -> UserEntry:
    """Create a deterministic session user entry."""
    return UserEntry(
        id=user_id,
        username=f"user{user_id}",
        password_hash="hash",
        role=UserRole(role),
        must_change_password=forced,
        disabled=False,
        last_login_at=None,
    )


def _state_repo() -> MagicMock:
    """Create a dashboard-state repository mock with sensible defaults."""
    repo = MagicMock()
    repo.get_layout.return_value = None
    repo.get_tour_completed.return_value = False
    return repo


def _valid_payload() -> dict[str, object]:
    """Return a schema-valid dashboard layout payload."""
    return {
        "version": 2,
        "layout": [{"i": "signal", "x": 0, "y": 0, "w": 2, "h": 1}],
        "hidden": [],
    }


def _request(
    user: UserEntry | None,
    state_repo: MagicMock,
    method: str,
    path: str,
    json_body: Any = None,
    *,
    api_key: str | None = None,
) -> Any:
    """Issue one authenticated-as-*user* request against the app.

    Patches the middleware settings and session repository the same way
    ``test_auth_middleware.py`` does, sets the session cookie only when a
    user is given, and routes the state repository through the override.
    """
    sessions = MagicMock()
    sessions.validate_and_touch.return_value = user
    app.dependency_overrides[get_dashboard_user_state_repo] = lambda: state_repo
    headers = {"X-API-Key": api_key} if api_key else None
    with (
        patch(
            "otalon_api.middleware.auth.get_settings",
            return_value=Settings(admin_api_key=OPERATOR_API_KEY),
        ),
        patch("otalon_api.middleware.session_auth.get_session_repo", return_value=sessions),
    ):
        client = TestClient(app, headers=headers, raise_server_exceptions=False)
        if user is not None:
            client.cookies.set(SESSION_COOKIE_NAME, "opaque-session")
        return client.request(method, path, json=json_body)


class TestGetDashboardLayout:
    """Tests for GET /api/v1/dashboard/layout (session-bound, own row)."""

    @pytest.mark.unit
    def test_get_returns_own_row(self) -> None:
        """GET with a valid session returns the caller's stored layout."""
        repo = _state_repo()
        payload = {
            "version": 2,
            "layout": [{"i": "signal", "x": 0, "y": 0, "w": 2, "h": 1}],
            "hidden": ["topConnections"],
        }
        repo.get_layout.return_value = payload

        response = _request(_user(), repo, "GET", LAYOUT_ENDPOINT)

        assert response.status_code == 200
        assert response.json() == payload
        repo.get_layout.assert_called_once_with(1)

    @pytest.mark.unit
    def test_get_without_row_returns_404(self) -> None:
        """GET returns 404 when the caller has no stored layout yet."""
        repo = _state_repo()

        response = _request(_user(), repo, "GET", LAYOUT_ENDPOINT)

        assert response.status_code == 404
        assert "No dashboard layout saved" in response.json()["detail"]

    @pytest.mark.unit
    def test_get_anonymous_returns_401(self) -> None:
        """Anonymous GET stays rejected by the deny-by-default surface."""
        repo = _state_repo()

        response = _request(None, repo, "GET", LAYOUT_ENDPOINT)

        assert response.status_code == 401

    @pytest.mark.unit
    def test_get_key_only_without_session_returns_401(self) -> None:
        """A valid operator key alone no longer reads a layout (D4)."""
        repo = _state_repo()
        repo.get_layout.return_value = _valid_payload()

        response = _request(None, repo, "GET", LAYOUT_ENDPOINT, api_key=OPERATOR_API_KEY)

        assert response.status_code == 401
        repo.get_layout.assert_not_called()

    @pytest.mark.unit
    def test_get_forced_change_session_degrades_to_401(self) -> None:
        """A forced-change session is never attached on reads (D6)."""
        repo = _state_repo()
        repo.get_layout.return_value = _valid_payload()

        response = _request(_user(forced=True), repo, "GET", LAYOUT_ENDPOINT)

        assert response.status_code == 401
        repo.get_layout.assert_not_called()


class TestPutDashboardLayout:
    """Tests for PUT /api/v1/dashboard/layout (session-authed, caps kept)."""

    @pytest.mark.unit
    def test_put_persists_own_row(self) -> None:
        """PUT stores the payload on the session user's own row."""
        repo = _state_repo()
        payload = {
            "version": 2,
            "layout": [
                {"i": "signal", "x": 0, "y": 0, "w": 2, "h": 1},
                {"i": "assets", "x": 2, "y": 0, "w": 2, "h": 1},
            ],
            "hidden": ["recentAlarms"],
        }

        response = _request(_user(user_id=7), repo, "PUT", LAYOUT_ENDPOINT, payload)

        assert response.status_code == 200
        assert response.json() == payload
        repo.set_layout.assert_called_once_with(7, payload)

    @pytest.mark.unit
    def test_put_viewer_session_returns_200(self) -> None:
        """A viewer-role session may write its own state (design D5)."""
        repo = _state_repo()

        response = _request(_user(role="viewer"), repo, "PUT", LAYOUT_ENDPOINT, _valid_payload())

        assert response.status_code == 200
        repo.set_layout.assert_called_once_with(1, _valid_payload())

    @pytest.mark.unit
    def test_put_invalid_version_returns_422(self) -> None:
        """PUT with an unsupported version returns 422 and writes nothing."""
        repo = _state_repo()

        response = _request(_user(), repo, "PUT", LAYOUT_ENDPOINT, {"version": 1, "layout": [], "hidden": []})

        assert response.status_code == 422
        repo.set_layout.assert_not_called()

    @pytest.mark.unit
    def test_put_missing_layout_returns_422(self) -> None:
        """PUT without the layout array returns 422."""
        repo = _state_repo()

        response = _request(_user(), repo, "PUT", LAYOUT_ENDPOINT, {"version": 2, "hidden": []})

        assert response.status_code == 422
        repo.set_layout.assert_not_called()

    @pytest.mark.unit
    def test_put_invalid_item_returns_422(self) -> None:
        """PUT with a layout item missing required fields returns 422."""
        repo = _state_repo()

        response = _request(
            _user(),
            repo,
            "PUT",
            LAYOUT_ENDPOINT,
            {"version": 2, "layout": [{"i": "signal", "x": "not-an-int"}], "hidden": []},
        )

        assert response.status_code == 422
        repo.set_layout.assert_not_called()

    @pytest.mark.unit
    def test_put_layout_too_large_returns_422(self) -> None:
        """PUT with more than 64 layout items returns 422."""
        repo = _state_repo()
        payload = {
            "version": 2,
            "layout": [{"i": f"w{i:02d}", "x": i % 8, "y": 0, "w": 1, "h": 1} for i in range(65)],
            "hidden": [],
        }

        response = _request(_user(), repo, "PUT", LAYOUT_ENDPOINT, payload)

        assert response.status_code == 422
        repo.set_layout.assert_not_called()

    @pytest.mark.unit
    def test_put_hidden_too_large_returns_422(self) -> None:
        """PUT with more than 64 hidden widget ids returns 422."""
        repo = _state_repo()
        payload = {
            "version": 2,
            "layout": [],
            "hidden": [f"w{i}" for i in range(65)],
        }

        response = _request(_user(), repo, "PUT", LAYOUT_ENDPOINT, payload)

        assert response.status_code == 422
        repo.set_layout.assert_not_called()

    @pytest.mark.unit
    def test_put_widget_id_too_long_returns_422(self) -> None:
        """PUT with a widget id longer than 64 chars returns 422."""
        repo = _state_repo()
        payload = {
            "version": 2,
            "layout": [{"i": "x" * 65, "x": 0, "y": 0, "w": 1, "h": 1}],
            "hidden": [],
        }

        response = _request(_user(), repo, "PUT", LAYOUT_ENDPOINT, payload)

        assert response.status_code == 422
        repo.set_layout.assert_not_called()

    @pytest.mark.unit
    def test_put_y_too_large_returns_422(self) -> None:
        """PUT with a y coordinate above 1000 returns 422."""
        repo = _state_repo()
        payload = {
            "version": 2,
            "layout": [{"i": "signal", "x": 0, "y": 1001, "w": 1, "h": 1}],
            "hidden": [],
        }

        response = _request(_user(), repo, "PUT", LAYOUT_ENDPOINT, payload)

        assert response.status_code == 422
        repo.set_layout.assert_not_called()

    @pytest.mark.unit
    def test_put_at_caps_round_trips(self) -> None:
        """PUT at the caps persists and a follow-up GET echoes the payload."""
        repo = _state_repo()
        payload = {
            "version": 2,
            "layout": [{"i": "y" * 64, "x": 7, "y": 1000, "w": 1, "h": 8} for _ in range(64)],
            "hidden": [f"h{i:02d}" for i in range(64)],
        }
        repo.get_layout.return_value = payload

        put = _request(_user(), repo, "PUT", LAYOUT_ENDPOINT, payload)
        get = _request(_user(), repo, "GET", LAYOUT_ENDPOINT)

        assert put.status_code == 200
        assert put.json() == payload
        repo.set_layout.assert_called_once_with(1, payload)
        assert get.status_code == 200
        assert get.json() == payload

    @pytest.mark.unit
    def test_put_repo_failure_returns_500(self) -> None:
        """A repository failure surfaces as 500 without inventing state."""
        repo = _state_repo()
        repo.set_layout.side_effect = RuntimeError("database unavailable")

        response = _request(_user(), repo, "PUT", LAYOUT_ENDPOINT, _valid_payload())

        assert response.status_code == 500
        assert "Failed to save dashboard layout" in response.json()["detail"]


class TestDashboardTour:
    """Tests for GET/PUT /api/v1/dashboard/tour (global per-account flag)."""

    @pytest.mark.unit
    def test_get_defaults_to_false(self) -> None:
        """GET returns 200 with completed=false when no row exists."""
        repo = _state_repo()

        response = _request(_user(), repo, "GET", TOUR_ENDPOINT)

        assert response.status_code == 200
        assert response.json() == {"completed": False}
        repo.get_tour_completed.assert_called_once_with(1)

    @pytest.mark.unit
    def test_get_returns_completed_flag(self) -> None:
        """GET returns the stored account-wide completion flag."""
        repo = _state_repo()
        repo.get_tour_completed.return_value = True

        response = _request(_user(), repo, "GET", TOUR_ENDPOINT)

        assert response.status_code == 200
        assert response.json() == {"completed": True}

    @pytest.mark.unit
    def test_put_round_trips_completion(self) -> None:
        """PUT stores the global flag on the session user's own row."""
        repo = _state_repo()
        repo.get_tour_completed.return_value = True

        put = _request(_user(user_id=7), repo, "PUT", TOUR_ENDPOINT, {"completed": True})
        get = _request(_user(user_id=7), repo, "GET", TOUR_ENDPOINT)

        assert put.status_code == 200
        assert put.json() == {"completed": True}
        repo.set_tour_completed.assert_called_once_with(7, True)
        assert get.status_code == 200
        assert get.json() == {"completed": True}

    @pytest.mark.unit
    def test_put_invalid_body_returns_422(self) -> None:
        """PUT with a non-boolean completed field returns 422."""
        repo = _state_repo()

        response = _request(_user(), repo, "PUT", TOUR_ENDPOINT, {"completed": "not-a-bool"})

        assert response.status_code == 422
        repo.set_tour_completed.assert_not_called()

    @pytest.mark.unit
    def test_get_anonymous_returns_401(self) -> None:
        """Anonymous tour GET stays rejected."""
        repo = _state_repo()

        response = _request(None, repo, "GET", TOUR_ENDPOINT)

        assert response.status_code == 401


class TestDashboardStateSecurityNegatives:
    """Explicit security negatives for the session-owned PUT contract."""

    @pytest.mark.unit
    def test_anonymous_put_returns_401_and_writes_nothing(self) -> None:
        """Anonymous PUT is rejected with 401 before any write."""
        repo = _state_repo()

        response = _request(None, repo, "PUT", LAYOUT_ENDPOINT, _valid_payload())

        assert response.status_code == 401
        assert response.json()["detail"] == "Authentication required"
        repo.set_layout.assert_not_called()

    @pytest.mark.unit
    def test_anonymous_tour_put_returns_401_and_writes_nothing(self) -> None:
        """Anonymous tour PUT is rejected with 401 before any write."""
        repo = _state_repo()

        response = _request(None, repo, "PUT", TOUR_ENDPOINT, {"completed": True})

        assert response.status_code == 401
        repo.set_tour_completed.assert_not_called()

    @pytest.mark.unit
    def test_revoked_session_returns_401_and_writes_nothing(self) -> None:
        """A revoked/expired session (validation returns None) gets 401."""
        repo = _state_repo()
        sessions_repo = MagicMock()
        sessions_repo.validate_and_touch.return_value = None
        app.dependency_overrides[get_dashboard_user_state_repo] = lambda: repo
        with (
            patch(
                "otalon_api.middleware.auth.get_settings",
                return_value=Settings(admin_api_key=OPERATOR_API_KEY),
            ),
            patch(
                "otalon_api.middleware.session_auth.get_session_repo",
                return_value=sessions_repo,
            ),
        ):
            client = TestClient(app, raise_server_exceptions=False)
            client.cookies.set(SESSION_COOKIE_NAME, "revoked-session")
            response = client.put(LAYOUT_ENDPOINT, json=_valid_payload())

        assert response.status_code == 401
        assert response.json()["detail"] == "Authentication required"
        repo.set_layout.assert_not_called()

    @pytest.mark.unit
    def test_operator_key_without_session_returns_401(self) -> None:
        """A valid operator key does not satisfy the dashboard PUT (D7)."""
        repo = _state_repo()

        response = _request(
            None,
            repo,
            "PUT",
            LAYOUT_ENDPOINT,
            _valid_payload(),
            api_key=OPERATOR_API_KEY,
        )

        assert response.status_code == 401
        assert response.json()["detail"] == "Authentication required"
        repo.set_layout.assert_not_called()

    @pytest.mark.unit
    def test_forced_change_session_put_returns_403(self) -> None:
        """A must_change_password session cannot write state (D6)."""
        repo = _state_repo()

        response = _request(_user(forced=True), repo, "PUT", LAYOUT_ENDPOINT, _valid_payload())

        assert response.status_code == 403
        assert response.json()["detail"] == "Password change required"
        repo.set_layout.assert_not_called()

    @pytest.mark.unit
    def test_forced_change_session_tour_put_returns_403(self) -> None:
        """A must_change_password session cannot write the tour flag."""
        repo = _state_repo()

        response = _request(_user(forced=True), repo, "PUT", TOUR_ENDPOINT, {"completed": True})

        assert response.status_code == 403
        assert response.json()["detail"] == "Password change required"
        repo.set_tour_completed.assert_not_called()

    @pytest.mark.unit
    def test_body_supplied_user_id_is_ignored(self) -> None:
        """A forged user_id in the body never changes the stored row's owner."""
        repo = _state_repo()
        forged = {**_valid_payload(), "user_id": 42}

        response = _request(_user(user_id=1), repo, "PUT", LAYOUT_ENDPOINT, forged)

        assert response.status_code == 200
        repo.set_layout.assert_called_once_with(1, _valid_payload())

    @pytest.mark.unit
    def test_second_user_put_never_touches_first_user_row(self) -> None:
        """User B's PUT writes only B's row; A's row is untouched (D9)."""
        repo = _state_repo()
        user_a_payload = _valid_payload()
        repo.get_layout.return_value = user_a_payload

        response = _request(_user(user_id=2), repo, "PUT", LAYOUT_ENDPOINT, _valid_payload())

        assert response.status_code == 200
        repo.set_layout.assert_called_once_with(2, _valid_payload())
        repo.get_layout.assert_not_called()
