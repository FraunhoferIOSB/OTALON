"""Anomaly-suppression service for the persistence boundary.

Loads active per-``series_id`` suppression rows from the
``anomaly_suppression`` table and exposes a fast in-memory lookup so the
:class:`~otalon_clas.detection.anomaly_persister.AnomalyPersister` can
drop operator-confirmed false positives BEFORE writing them to the
``anomalies`` / ``alarms`` tables.

A row is "active" when ``expires_at IS NULL`` or ``expires_at > NOW()``.
The lookup is cached for ``cache_ttl_s`` seconds; the persistence path
hits the DB at most once per batch unless the cache expires mid-cycle.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Iterable

from otalon_clas.common.postgres_connector import (AnomalySuppression,
                                                     PostgresConnector)
from loguru import logger
from sqlalchemy import or_


@dataclass(frozen=True, slots=True)
class SuppressionEntry:
    """An active suppression rule resolved into plain data.

    Used as the per-row lookup result from
    :meth:`SuppressionService.is_suppressed`.
    """

    suppression_id: int
    series_id: str
    suppressed_types: frozenset[str]
    reason: str


class SuppressionService:
    """In-memory cache over the ``anomaly_suppression`` table.

    A single instance is shared across one prediction batch. The cache
    is refreshed lazily when :meth:`active_suppressions` is invoked
    after the TTL has expired; callers that want a fresh read can call
    :meth:`invalidate` explicitly (used by the MCP write tools when they
    add or remove a suppression).
    """

    def __init__(self, connector: PostgresConnector, cache_ttl_s: int = 30) -> None:
        """Create the service.

        Args:
            connector: Postgres connector to fetch suppression rows.
            cache_ttl_s: Cache lifetime in seconds. ``0`` disables
                caching (every lookup re-queries the DB).
        """
        self._connector = connector
        self._cache_ttl_s = max(0, int(cache_ttl_s))
        self._cache: Dict[str, SuppressionEntry] = {}
        self._cache_loaded_at: float = 0.0

    def invalidate(self) -> None:
        """Drop the cached suppression set so the next call re-queries."""
        self._cache.clear()
        self._cache_loaded_at = 0.0

    def active_suppressions(self) -> Dict[str, SuppressionEntry]:
        """Return all active suppressions keyed by ``series_id``.

        Refreshes the cache from the DB when the TTL has expired. The
        returned dict is a shallow copy so callers may not mutate the
        internal cache directly.
        """
        now = time.monotonic()
        if self._cache_loaded_at and (now - self._cache_loaded_at) < self._cache_ttl_s:
            return dict(self._cache)
        self._reload()
        return dict(self._cache)

    def is_suppressed(
        self, series_id: str, anomaly_type: str
    ) -> SuppressionEntry | None:
        """Return the matching suppression entry, or None.

        An entry matches when:

        * a row exists for ``series_id``;
        * the row is active (no expiry, or expiry in the future);
        * ``anomaly_type`` is in the row's ``suppressed_types`` set.
        """
        entry = self.active_suppressions().get(series_id)
        if entry is None:
            return None
        if anomaly_type in entry.suppressed_types:
            return entry
        return None

    def _reload(self) -> None:
        """Refresh the in-memory cache from the ``anomaly_suppression`` table."""
        now = datetime.now(timezone.utc)
        cache: Dict[str, SuppressionEntry] = {}
        with self._connector.session() as session:
            rows = (
                session.query(AnomalySuppression)
                .filter(
                    or_(
                        AnomalySuppression.expires_at.is_(None),
                        AnomalySuppression.expires_at > now,
                    )
                )
                .all()
            )
            for row in rows:
                types: Iterable[str] = row.suppressed_types or ()
                normalized = frozenset(str(t) for t in types if t)
                if not normalized:
                    continue
                cache[str(row.series_id)] = SuppressionEntry(
                    suppression_id=int(row.id),
                    series_id=str(row.series_id),
                    suppressed_types=normalized,
                    reason=str(row.reason),
                )
        self._cache = cache
        self._cache_loaded_at = time.monotonic()
        logger.debug(
            "SuppressionService cache reloaded: {count} active suppressions",
            count=len(cache),
        )
