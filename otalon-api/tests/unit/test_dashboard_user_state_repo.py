"""Unit tests for DashboardUserStateRepository (UI-199/UI-200 wave A).

Covers the upsert round-trip SQL, the tour-flag default on a missing row,
and per-user row isolation, using a scripted PostgreSQL backend following
the existing repo-test pattern (see ``test_product_identity.py``).
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

import pytest

from otalon_api.repositories.dashboard_user_state_repo import DashboardUserStateRepository


class _ScriptedPostgres:
    """PostgreSQL stub recording queries and serving scripted rows."""

    def __init__(self, rows: list[dict[str, Any]] | None = None) -> None:
        self.rows = rows or []
        self.queries: list[tuple[str, dict[str, Any] | None]] = []
        self.commands: list[tuple[str, dict[str, Any] | None]] = []

    def _execute_query(self, sql: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        self.queries.append((sql, params))
        return self.rows

    def _execute_command(self, sql: str, params: dict[str, Any] | None = None) -> None:
        self.commands.append((sql, params))


def _payload() -> dict[str, Any]:
    """Return a schema-valid layout payload dump."""
    return {
        "version": 2,
        "layout": [{"i": "signal", "x": 0, "y": 0, "w": 2, "h": 1}],
        "hidden": ["recentAlarms"],
    }


class TestDashboardUserStateRepository:
    """Repo behaviour for layout and tour columns of dashboard_user_state."""

    @pytest.mark.unit
    def test_get_layout_returns_stored_document(self) -> None:
        """get_layout returns the row's layout document for the user."""
        backend = _ScriptedPostgres(rows=[{"layout": _payload()}])
        repo = DashboardUserStateRepository(backend)

        assert repo.get_layout(5) == _payload()
        assert backend.queries[0][1] == {"user_id": 5}

    @pytest.mark.unit
    def test_get_layout_missing_row_returns_none(self) -> None:
        """get_layout returns None when the account has no row."""
        backend = _ScriptedPostgres(rows=[])
        repo = DashboardUserStateRepository(backend)

        assert repo.get_layout(5) is None

    @pytest.mark.unit
    def test_set_layout_upserts_on_conflict(self) -> None:
        """set_layout issues an upsert bound to the user id argument."""
        backend = _ScriptedPostgres()
        repo = DashboardUserStateRepository(backend)

        repo.set_layout(5, _payload())

        sql, params = backend.commands[0]
        assert "ON CONFLICT (user_id) DO UPDATE" in sql
        assert "dashboard_user_state" in sql
        assert params == {"user_id": 5, "layout": json.dumps(_payload())}

    @pytest.mark.unit
    def test_get_tour_completed_defaults_false_on_missing_row(self) -> None:
        """get_tour_completed returns False when no row exists yet."""
        backend = _ScriptedPostgres(rows=[])
        repo = DashboardUserStateRepository(backend)

        assert repo.get_tour_completed(5) is False

    @pytest.mark.unit
    def test_get_tour_completed_returns_stored_flag(self) -> None:
        """get_tour_completed returns the stored JSONB boolean."""
        backend = _ScriptedPostgres(rows=[{"tour_completed": True}])
        repo = DashboardUserStateRepository(backend)

        assert repo.get_tour_completed(5) is True

    @pytest.mark.unit
    def test_set_tour_completed_upserts_on_conflict(self) -> None:
        """set_tour_completed issues an upsert for the global flag."""
        backend = _ScriptedPostgres()
        repo = DashboardUserStateRepository(backend)

        repo.set_tour_completed(5, True)

        sql, params = backend.commands[0]
        assert "ON CONFLICT (user_id) DO UPDATE" in sql
        assert params == {"user_id": 5, "completed": "true"}

    @pytest.mark.unit
    def test_second_user_queries_never_touch_first_user_row(self) -> None:
        """Every statement is scoped to exactly the supplied user id."""
        backend = _ScriptedPostgres(rows=[{"layout": _payload()}])
        repo = DashboardUserStateRepository(backend)

        repo.set_layout(2, _payload())
        repo.set_tour_completed(2, True)
        repo.get_layout(2)
        repo.get_tour_completed(2)

        for sql, params in backend.commands + backend.queries:
            assert params is not None
            assert params["user_id"] == 2

    @pytest.mark.unit
    def test_repo_constructs_over_shared_postgres(self) -> None:
        """The repo keeps the injected PostgreSQL backend instance."""
        backend = MagicMock()
        repo = DashboardUserStateRepository(backend)

        repo.get_layout(1)

        backend._execute_query.assert_called_once()
