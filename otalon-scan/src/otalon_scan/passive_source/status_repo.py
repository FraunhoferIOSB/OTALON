"""Asynchronous status repository for the passive asset seeder.

Writes the ``passive_seeder_status`` row created by Alembic revision ``0013``.
The row is what makes the worker's state observable outside ``docker logs``: a
disabled seeder, a seeder erroring on every cycle, and a healthy seeder are
otherwise indistinguishable to the api and the UI.

The table is schema-managed by Alembic. This module issues DML only — it never
creates or alters the table, matching the ``scan--persistence-pipeline`` rule
that removed ``Base.metadata.create_all`` from the startup path.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Final

from loguru import logger
from otalon_common.runtime import OTALON_SCAN_SERVICE
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine

STATE_RUNNING: Final[str] = "running"
"""State recorded after a cycle that completed without error."""

STATE_DISABLED: Final[str] = "disabled"
"""State recorded while the effective enabled flag is false."""

STATE_ERROR: Final[str] = "error"
"""State recorded after a cycle that raised."""

_UPSERT_STATUS = text(
    """
    INSERT INTO passive_seeder_status
        (service, state, last_cycle_at, last_error, rows_seeded, poll_interval_s, updated_at)
    VALUES
        (:service, :state, :last_cycle_at, :last_error, :rows_seeded, :poll_interval_s, :updated_at)
    ON CONFLICT (service) DO UPDATE SET
        state = EXCLUDED.state,
        last_cycle_at = EXCLUDED.last_cycle_at,
        last_error = EXCLUDED.last_error,
        rows_seeded = EXCLUDED.rows_seeded,
        poll_interval_s = EXCLUDED.poll_interval_s,
        updated_at = EXCLUDED.updated_at
    """
)


class PassiveSeederStatusRepo:
    """Upserts the seeder's status row on the ``service`` primary key.

    Args:
        engine: Async engine bound to the otalon-scan PostgreSQL database.
        service: Owning service identifier; defaults to the manifest constant.
    """

    def __init__(self, engine: AsyncEngine, *, service: str = OTALON_SCAN_SERVICE) -> None:
        """Initialize the repository."""
        self._engine = engine
        self._service = service

    async def upsert(
        self,
        *,
        state: str,
        poll_interval_s: int,
        rows_seeded: int = 0,
        last_error: str | None = None,
        last_cycle_at: datetime | None = None,
    ) -> None:
        """Persist the seeder's current status.

        A write failure is logged and swallowed: status persistence is
        observability, and losing it must not terminate the poll loop or mask
        the cycle result that produced it.

        Args:
            state: One of ``running``, ``disabled``, ``error``.
            poll_interval_s: The interval actually in effect for this cycle.
            rows_seeded: Interface rows written by this cycle.
            last_error: Message of the failed cycle, or ``None`` to clear it.
            last_cycle_at: Cycle timestamp; defaults to now in UTC.
        """
        now = datetime.now(timezone.utc)
        params = {
            "service": self._service,
            "state": state,
            "last_cycle_at": last_cycle_at or now,
            "last_error": last_error,
            "rows_seeded": rows_seeded,
            "poll_interval_s": poll_interval_s,
            "updated_at": now,
        }
        try:
            async with self._engine.begin() as conn:
                await conn.execute(_UPSERT_STATUS, params)
        except SQLAlchemyError as exc:
            logger.warning(
                "passive_seeder: status upsert failed state={} exception={} " "event=status_upsert_failed",
                state,
                type(exc).__name__,
            )
