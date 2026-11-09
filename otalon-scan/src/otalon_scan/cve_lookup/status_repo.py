"""Asynchronous persisted status repository for the CVE lookup worker."""

from __future__ import annotations

from datetime import datetime, timezone

from loguru import logger
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine

_UPSERT_STATUS = text(
    """
    INSERT INTO cve_lookup_worker_status
        (service, state, last_run_at, last_error, findings_count, interval_s, updated_at)
    VALUES
        (:service, :state, :last_run_at, :last_error, :findings_count, :interval_s, :updated_at)
    ON CONFLICT (service) DO UPDATE SET
        state = EXCLUDED.state,
        last_run_at = EXCLUDED.last_run_at,
        last_error = EXCLUDED.last_error,
        findings_count = EXCLUDED.findings_count,
        interval_s = EXCLUDED.interval_s,
        updated_at = EXCLUDED.updated_at
    """
)


class CveLookupStatusRepo:
    """Upsert one status row for the CVE lookup worker."""

    def __init__(self, engine: AsyncEngine, *, service: str = "otalon-scan-cve-lookup") -> None:
        """Initialize repository with async database engine."""
        self._engine = engine
        self._service = service

    async def upsert(
        self,
        *,
        state: str,
        interval_s: int,
        findings_count: int = 0,
        last_error: str | None = None,
        last_run_at: datetime | None = None,
    ) -> None:
        """Persist current worker state without interrupting worker loop."""
        now = datetime.now(timezone.utc)
        params = {
            "service": self._service,
            "state": state,
            "last_run_at": last_run_at or now,
            "last_error": last_error,
            "findings_count": findings_count,
            "interval_s": interval_s,
            "updated_at": now,
        }
        try:
            async with self._engine.begin() as conn:
                await conn.execute(_UPSERT_STATUS, params)
        except SQLAlchemyError as exc:
            logger.warning(
                "cve_lookup: status upsert failed state={} exception={} event=status_upsert_failed",
                state,
                type(exc).__name__,
            )
