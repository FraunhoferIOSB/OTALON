"""Repository for per-account dashboard user state (layout + tour flag)."""

from __future__ import annotations

import json
from typing import Any

from otalon_api.repositories.postgres_repo import PostgresRepository


class DashboardUserStateRepository:
    """Database access for the per-account ``dashboard_user_state`` row.

    One row per product user keyed by ``users.id`` (cascade-deleted with
    the user). ``layout`` and ``tour_completed`` are JSONB columns that
    stay ``NULL`` until the account's first write. The acting ``user_id``
    is always a method argument supplied by the caller from the validated
    session — never part of a persisted payload.
    """

    def __init__(self, postgres_repo: PostgresRepository) -> None:
        """Initialize repository over shared PostgreSQL access.

        Args:
            postgres_repo: Shared PostgreSQL repository backed by a pool.
        """
        self._postgres = postgres_repo

    def get_layout(self, user_id: int) -> dict[str, Any] | None:
        """Return the user's stored layout document, or ``None``.

        Args:
            user_id: Owner account identifier from the validated session.

        Returns:
            The stored layout document, or ``None`` when the account has
            no saved layout yet.
        """
        rows = self._postgres._execute_query(
            "SELECT layout FROM dashboard_user_state WHERE user_id = %(user_id)s",
            {"user_id": user_id},
        )
        if not rows:
            return None
        layout = rows[0].get("layout")
        return dict(layout) if isinstance(layout, dict) else None

    def set_layout(self, user_id: int, payload: dict[str, Any]) -> None:
        """Upsert the user's layout document, leaving tour state untouched.

        Args:
            user_id: Owner account identifier from the validated session.
            payload: Pydantic-validated ``DashboardLayoutPayload`` dump.
        """
        self._postgres._execute_command(
            "INSERT INTO dashboard_user_state (user_id, layout) "
            "VALUES (%(user_id)s, %(layout)s::jsonb) "
            "ON CONFLICT (user_id) DO UPDATE "
            "SET layout = %(layout)s::jsonb, updated_at = now()",
            {"user_id": user_id, "layout": json.dumps(payload)},
        )

    def get_tour_completed(self, user_id: int) -> bool:
        """Return the account's global tour-completion flag.

        Args:
            user_id: Owner account identifier from the validated session.

        Returns:
            ``True`` when the tour is completed account-wide, ``False``
            when no flag has been stored yet (the default state).
        """
        rows = self._postgres._execute_query(
            "SELECT tour_completed FROM dashboard_user_state WHERE user_id = %(user_id)s",
            {"user_id": user_id},
        )
        if not rows:
            return False
        return bool(rows[0].get("tour_completed"))

    def set_tour_completed(self, user_id: int, completed: bool) -> None:
        """Upsert the account's global tour flag, leaving layout untouched.

        Args:
            user_id: Owner account identifier from the validated session.
            completed: Global completion flag (one flag for all pages).
        """
        self._postgres._execute_command(
            "INSERT INTO dashboard_user_state (user_id, tour_completed) "
            "VALUES (%(user_id)s, %(completed)s::jsonb) "
            "ON CONFLICT (user_id) DO UPDATE "
            "SET tour_completed = %(completed)s::jsonb, updated_at = now()",
            {"user_id": user_id, "completed": json.dumps(completed)},
        )
