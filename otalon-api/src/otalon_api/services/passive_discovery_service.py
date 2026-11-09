"""Passive-discovery status service.

Computes a read-only status snapshot for the Passive Discovery producer
consumed by the Operations / Data Sources page. The snapshot is derived
purely from persisted ``network_interfaces`` rows tagged
``source='passive'`` (written by the ``otalon-scan-passive-seeder``
container). It never inspects the seeder process, container health, or
generic API liveness, and it never exposes a runtime enable/disable or
reconfigure control: that control plane is boot/env-managed and remains
deferred under UI-015.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Literal

from loguru import logger

if TYPE_CHECKING:
    from otalon_api.repositories.postgres_repo import PostgresRepository
    from otalon_api.settings import Settings

PassiveFreshness = Literal["current", "stale", "no-data"]


@dataclass(frozen=True)
class PassiveDiscoveryStatus:
    """Read-only passive-discovery status snapshot.

    Attributes:
        observed_asset_count: Distinct devices carrying a passive
            interface (persisted producer truth).
        observed_interface_count: Passive ``network_interfaces`` rows.
        latest_seen_at: Most recent persisted ``last_seen_passive_at``
            timestamp, or ``None`` when no passive rows exist.
        first_seen_at: Earliest persisted ``first_seen_passive_at``
            timestamp, or ``None``.
        age_seconds: Age of ``latest_seen_at`` in seconds, or ``None``
            when there is no data.
        freshness: ``current`` when the latest observation is within the
            stale threshold, ``stale`` when older, ``no-data`` when no
            passive inventory has ever been persisted.
        runtime_control_enabled: Always ``False`` — the seeder is a
            separate boot/env-managed container and no runtime control
            plane is implemented (UI-015 deferred).
    """

    observed_asset_count: int
    observed_interface_count: int
    latest_seen_at: datetime | None
    first_seen_at: datetime | None
    age_seconds: int | None
    freshness: PassiveFreshness
    runtime_control_enabled: bool


class PassiveDiscoveryService:
    """Compute read-only passive-discovery status from persisted facts."""

    STALE_MULTIPLIER: int = 3
    DEFAULT_POLL_INTERVAL_SECONDS: int = 60

    def __init__(
        self,
        postgres_repo: "PostgresRepository",
        settings: "Settings",
    ) -> None:
        """Initialize with repository and settings dependencies.

        Args:
            postgres_repo: PostgreSQL repository for the passive
                inventory aggregate.
            settings: Application settings for the stale threshold.
        """
        self._postgres = postgres_repo
        self._settings = settings

    @property
    def _poll_interval_seconds(self) -> int:
        """Expected seeder poll cadence in seconds.

        The seeder emits ``poll_finished`` roughly every 60 seconds; the
        derived stale threshold is ``STALE_MULTIPLIER x`` this cadence.
        """
        return self.DEFAULT_POLL_INTERVAL_SECONDS

    def _now(self) -> datetime:
        """Return the current time in UTC."""
        return datetime.now(timezone.utc)

    @staticmethod
    def _as_utc(value: datetime) -> datetime:
        """Coerce a possibly-naive timestamp to timezone-aware UTC.

        Args:
            value: A ``datetime`` that may be naive or aware.

        Returns:
            The same instant expressed in UTC.
        """
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    def _derive(self, summary: dict[str, Any], now: datetime) -> PassiveDiscoveryStatus:
        """Derive the status snapshot from a raw aggregate row.

        Args:
            summary: Aggregate dict from
                :meth:`PostgresRepository.query_passive_discovery_summary`.
            now: The reference clock for freshness classification.

        Returns:
            A fully-derived :class:`PassiveDiscoveryStatus`.
        """
        interface_count = int(summary.get("observed_interface_count", 0) or 0)
        asset_count = int(summary.get("observed_asset_count", 0) or 0)
        latest_raw = summary.get("latest_seen_at")
        first_raw = summary.get("first_seen_at")
        latest = self._as_utc(latest_raw) if isinstance(latest_raw, datetime) else None
        first = self._as_utc(first_raw) if isinstance(first_raw, datetime) else None

        if interface_count == 0 or latest is None:
            return PassiveDiscoveryStatus(
                observed_asset_count=asset_count,
                observed_interface_count=interface_count,
                latest_seen_at=latest,
                first_seen_at=first,
                age_seconds=None,
                freshness="no-data",
                runtime_control_enabled=False,
            )

        age_seconds = max(0, int((now - latest).total_seconds()))
        threshold = self.STALE_MULTIPLIER * self._poll_interval_seconds
        freshness: PassiveFreshness = "current" if age_seconds <= threshold else "stale"
        return PassiveDiscoveryStatus(
            observed_asset_count=asset_count,
            observed_interface_count=interface_count,
            latest_seen_at=latest,
            first_seen_at=first,
            age_seconds=age_seconds,
            freshness=freshness,
            runtime_control_enabled=False,
        )

    async def get_status(self) -> PassiveDiscoveryStatus:
        """Fetch and derive the passive-discovery status snapshot.

        Runs the blocking PostgreSQL aggregate in a thread so the FastAPI
        event loop is not stalled. On any query failure a truthful
        ``no-data`` snapshot is returned rather than a fabricated state.

        Returns:
            A :class:`PassiveDiscoveryStatus` snapshot.
        """
        now = self._now()

        def _run() -> dict[str, Any]:
            return self._postgres.query_passive_discovery_summary()

        try:
            summary = await asyncio.to_thread(_run)
        except Exception as exc:
            logger.error("PassiveDiscoveryService query failed: {}", exc)
            summary = {
                "observed_interface_count": 0,
                "observed_asset_count": 0,
                "latest_seen_at": None,
                "first_seen_at": None,
            }
        return self._derive(summary, now)
