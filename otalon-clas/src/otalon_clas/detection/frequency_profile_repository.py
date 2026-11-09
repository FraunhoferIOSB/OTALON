"""Persistence repository for frequency profiles.

Encapsulates the PostgreSQL side of the
``cyberclas--frequency-profile-persistence`` capability:

* Bootstrap load of all persisted profiles into the in-memory cache on
  LIVE boot (:meth:`load_all`).
* Single-profile refresh after a NOTIFY (:meth:`load_one`).
* Stats-only UPSERT issued by ``train()`` that NEVER touches the two
  override columns (``tolerance_factor_override``,
  ``absence_factor_override``) — design.md Decision 3 / Fork 3 = a.
  With ``replace=True`` the same call additionally deletes the module's
  rows the training run no longer covers, so a retrain swaps the
  module's profile set instead of stacking on top of every earlier run
  (same semantics as ``BoundsRepository.save(replace=True)``).
* A background invalidator thread that LISTENs on the configured PG
  channel and forwards each ``(module, series_id)`` payload to the
  monitor's :meth:`apply_invalidation`, plus a periodic refresh as a
  safety net for missed notifies (Decision 2 / Fork 2 = c).

All persistence behaviour is gated by the
``frequency_monitor.persistence_enabled`` config flag in the caller —
this module assumes it is only instantiated when the flag is ``True``.
"""

from __future__ import annotations

import json
import select
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Callable, Optional, cast

from loguru import logger
from sqlalchemy import text
from sqlalchemy.orm import Session

from otalon_clas.common.postgres_connector import FrequencyProfile, PostgresConnector

if TYPE_CHECKING:
    from otalon_clas.detection.frequency_monitor import _SeriesFrequencyProfile

_NOTIFY_POLL_TIMEOUT_S: float = 1.0


@dataclass(frozen=True)
class StatsWriteResult:
    """Outcome of one :meth:`FrequencyProfileRepository.upsert_stats` call.

    ``survivors`` maps every written ``series_id`` to its
    ``(tolerance_override, absence_override)`` as they stand AFTER the
    write, so the caller can mirror operator overrides back into the
    in-memory cache without a second round-trip.

    ``deleted`` lists the ``series_id``s removed because ``replace=True``
    and the training run no longer covers them. It is always empty for
    ``replace=False``.
    """

    survivors: dict[str, tuple[float | None, float | None]] = field(default_factory=dict)
    deleted: tuple[str, ...] = ()
    preserved: tuple[str, ...] = ()


def _as_utc(value: datetime) -> datetime:
    """Return a timezone-aware UTC datetime for a naive or aware input.

    SQLite round-trips ``DateTime(timezone=True)`` columns as naive
    values, so persisted timestamps must be normalised before they can
    be compared with the timezone-aware runtime ones.
    """
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


class FrequencyProfileRepository:
    """ORM-backed accessor for ``frequency_profiles``.

    Owns no DDL — :class:`PostgresConnector.create_tables` provisions
    the two tables on otalon-clas boot. All reads return plain
    :class:`_SeriesFrequencyProfile` dataclasses so the monitor can
    drop them straight into its in-memory cache.
    """

    def __init__(self, connector: PostgresConnector) -> None:
        """Wire the repository to a shared :class:`PostgresConnector`."""
        self._connector = connector

    def load_all(self, module: str) -> dict[str, "_SeriesFrequencyProfile"]:
        """Return every persisted profile for ``module`` keyed by ``series_id``.

        The result is suitable for direct assignment into
        :attr:`FrequencyMonitor._profiles`.
        """
        from otalon_clas.detection.frequency_monitor import _SeriesFrequencyProfile

        out: dict[str, _SeriesFrequencyProfile] = {}
        with self._connector.session() as session:
            rows = session.query(FrequencyProfile).filter(FrequencyProfile.module == module).all()
            for row in rows:
                out[str(row.series_id)] = _SeriesFrequencyProfile(
                    mean_interval=float(row.mean_interval),
                    std_interval=float(row.std_interval),
                    last_seen=row.last_seen,
                    tolerance_factor_override=(
                        float(row.tolerance_factor_override) if row.tolerance_factor_override is not None else None
                    ),
                    absence_factor_override=(
                        float(row.absence_factor_override) if row.absence_factor_override is not None else None
                    ),
                )
        return out

    def load_one(self, module: str, series_id: str) -> "_SeriesFrequencyProfile | None":
        """Return one persisted profile, or ``None`` if the row is gone."""
        from otalon_clas.detection.frequency_monitor import _SeriesFrequencyProfile

        with self._connector.session() as session:
            row = (
                session.query(FrequencyProfile)
                .filter(
                    FrequencyProfile.module == module,
                    FrequencyProfile.series_id == series_id,
                )
                .one_or_none()
            )
            if row is None:
                return None
            return _SeriesFrequencyProfile(
                mean_interval=float(row.mean_interval),
                std_interval=float(row.std_interval),
                last_seen=row.last_seen,
                tolerance_factor_override=(
                    float(row.tolerance_factor_override) if row.tolerance_factor_override is not None else None
                ),
                absence_factor_override=(
                    float(row.absence_factor_override) if row.absence_factor_override is not None else None
                ),
            )

    def upsert_stats(
        self,
        module: str,
        profiles: dict[str, "_SeriesFrequencyProfile"],
        *,
        replace: bool = False,
        discard_overrides: bool = False,
    ) -> StatsWriteResult:
        """Stats-only UPSERT for the freshly trained profiles.

        Writes ``mean_interval``, ``std_interval``, ``last_seen``,
        ``trained_at`` only. The update path deliberately excludes the
        two override columns so any operator tuning survives re-training
        (design.md Decision 3 / Fork 3 = a).

        Args:
            module: Cyberclas module name.
            profiles: Freshly trained ``series_id -> profile`` mapping.
            replace: When ``True``, the module's persisted profile set is
                fully replaced by ``profiles``: rows for the module whose
                ``series_id`` is not in ``profiles`` are deleted in the
                SAME transaction as the upsert, so one training run swaps
                the module's profile set atomically and no series from an
                earlier run lingers. Mirrors the established
                ``BoundsRepository.save(replace=True)`` semantics. When
                ``False`` (default) the legacy additive upsert is kept.
            discard_overrides: Explicitly allow replacement to delete stale
                rows carrying operator overrides. Defaults to ``False`` so a
                retrain cannot silently discard operator configuration.

        Returns:
            A :class:`StatsWriteResult` carrying the surviving override
            columns per written series and the series ids deleted by the
            replace path.

        Raises:
            ValueError: When ``replace=True`` and ``profiles`` is empty.
                An empty retrain result would otherwise wipe every
                profile for the module and leave absence detection blind.
                The raise happens before the transaction opens, so no
                rows are touched. Same guard as
                ``BoundsRepository.save``.
        """
        if not profiles:
            if replace:
                raise ValueError(
                    f"FrequencyProfileRepository[{module}]: refusing replace=True "
                    "with an empty profile set; an empty retrain window would "
                    "wipe every frequency profile. Check the training window/data."
                )
            return StatsWriteResult()

        now = datetime.now(timezone.utc)
        # Use a dialect-agnostic two-step that works on both PostgreSQL
        # and SQLite (the latter being the test backend). The semantics
        # — never write the override columns on update — are the same.
        survivors: dict[str, tuple[float | None, float | None]] = {}
        deleted: tuple[str, ...] = ()
        preserved: tuple[str, ...] = ()
        with self._connector.session() as session:
            existing = (
                session.query(FrequencyProfile)
                .filter(
                    FrequencyProfile.module == module,
                    FrequencyProfile.series_id.in_(list(profiles.keys())),
                )
                .all()
            )
            existing_map = {str(row.series_id): row for row in existing}

            for series_id, profile in profiles.items():
                row = existing_map.get(series_id)
                if row is None:
                    new_row = FrequencyProfile(
                        module=module,
                        series_id=series_id,
                        mean_interval=float(profile.mean_interval),
                        std_interval=float(profile.std_interval),
                        last_seen=profile.last_seen,
                        trained_at=now,
                        tolerance_factor_override=None,
                        absence_factor_override=None,
                    )
                    session.add(new_row)
                    survivors[series_id] = (None, None)
                else:
                    # Stats-only update — DO NOT touch override columns.
                    row.mean_interval = float(profile.mean_interval)
                    row.std_interval = float(profile.std_interval)
                    if profile.last_seen is not None:
                        row.last_seen = profile.last_seen
                    row.trained_at = now
                    survivors[series_id] = (
                        (float(row.tolerance_factor_override) if row.tolerance_factor_override is not None else None),
                        (float(row.absence_factor_override) if row.absence_factor_override is not None else None),
                    )

            if replace:
                deleted, preserved = self._delete_stale(
                    session, module, set(profiles), discard_overrides=discard_overrides
                )
        return StatsWriteResult(survivors=survivors, deleted=deleted, preserved=preserved)

    @staticmethod
    def _delete_stale(
        session: Session,
        module: str,
        keep: set[str],
        *,
        discard_overrides: bool,
    ) -> tuple[tuple[str, ...], tuple[str, ...]]:
        """Delete this module's rows whose ``series_id`` is not in ``keep``.

        Runs inside the caller's session so the delete shares the upsert
        transaction — a crash mid-run rolls the whole swap back rather
        than leaving a half-deleted profile set.

        The pending inserts are flushed first and the survivors are then
        filtered in Python rather than with a ``NOT IN`` clause, so the
        statement stays free of dialect-specific SQL and of a parameter
        list that grows with the trained series count. Both PostgreSQL
        and the SQLite test backend execute this identically.
        """
        session.flush()
        rows = session.query(FrequencyProfile).filter(FrequencyProfile.module == module).all()
        removed: list[str] = []
        preserved: list[str] = []
        for row in rows:
            series_id = str(row.series_id)
            if series_id in keep:
                continue
            has_override = row.tolerance_factor_override is not None or row.absence_factor_override is not None
            if has_override and not discard_overrides:
                preserved.append(series_id)
                continue
            session.delete(row)
            removed.append(series_id)
        if removed:
            logger.info(
                "FrequencyProfileRepository[{}]: replace=True deleted {} stale profile(s)",
                module,
                len(removed),
            )
        if preserved:
            logger.warning(
                "FrequencyProfileRepository[{}]: preserved {} stale profile(s) "
                "with operator overrides; set discard_overrides=True to delete",
                module,
                len(preserved),
            )
        return tuple(sorted(removed)), tuple(sorted(preserved))

    def update_last_seen(self, module: str, last_seen: dict[str, datetime]) -> int:
        """Persist runtime ``last_seen`` timestamps for existing profiles.

        This is the counterpart to :meth:`upsert_stats` for the DETECTION
        hot path. ``upsert_stats`` is called only from the training path,
        so without this method the persisted ``last_seen`` freezes at the
        last training run and a container restart resumes absence
        detection from a stale timestamp.

        Deliberately narrow — it writes exactly ONE column:

        * ``tolerance_factor_override`` / ``absence_factor_override`` are
          never touched, so operator tuning survives (design.md Decision
          3 / Fork 3 = a, same rule as ``upsert_stats``).
        * ``trained_at`` is never bumped. That column answers "when was
          this profile trained"; observing traffic is not training, and
          ``bootstrap_from_repository`` relies on it staying truthful.
        * ``mean_interval`` / ``std_interval`` are not touched — the
          runtime does not re-derive them.

        Rows that do not exist are skipped rather than inserted: a
        ``last_seen`` without trained statistics would be a profile
        without a cadence, which the absence check cannot evaluate.
        A monotonic guard keeps an older timestamp from overwriting a
        newer persisted one (possible when several writers race).

        Args:
            module: Cyberclas module name.
            last_seen: Mapping of ``series_id`` → observation timestamp.

        Returns:
            Number of rows actually updated.
        """
        if not last_seen:
            return 0

        updated = 0
        with self._connector.session() as session:
            rows = (
                session.query(FrequencyProfile)
                .filter(
                    FrequencyProfile.module == module,
                    FrequencyProfile.series_id.in_(list(last_seen.keys())),
                )
                .all()
            )
            for row in rows:
                candidate = last_seen.get(str(row.series_id))
                if candidate is None:
                    continue
                persisted = cast(Optional[datetime], row.last_seen)
                if persisted is not None and _as_utc(persisted) >= _as_utc(candidate):
                    continue
                row.last_seen = candidate  # type: ignore[assignment]  # SQLAlchemy 1.x Column descriptor
                updated += 1
        return updated

    def restore_profiles(
        self,
        module: str,
        profiles: dict[str, "_SeriesFrequencyProfile"],
    ) -> None:
        """Restore exact persisted frequency rows during publication rollback."""
        with self._connector.session() as session:
            session.query(FrequencyProfile).filter(FrequencyProfile.module == module).delete()
            now = datetime.now(timezone.utc)
            for series_id, profile in profiles.items():
                session.add(
                    FrequencyProfile(
                        module=module,
                        series_id=series_id,
                        mean_interval=float(profile.mean_interval),
                        std_interval=float(profile.std_interval),
                        last_seen=profile.last_seen,
                        trained_at=now,
                        tolerance_factor_override=profile.tolerance_factor_override,
                        absence_factor_override=profile.absence_factor_override,
                    )
                )

    def snapshot_profiles(self, module: str) -> list[dict[str, object]]:
        """Capture exact persisted rows for one module."""
        with self._connector.session() as session:
            rows = session.query(FrequencyProfile).filter(FrequencyProfile.module == module).all()
            return [
                {
                    "module": row.module,
                    "series_id": row.series_id,
                    "mean_interval": row.mean_interval,
                    "std_interval": row.std_interval,
                    "last_seen": row.last_seen,
                    "trained_at": row.trained_at,
                    "tolerance_factor_override": row.tolerance_factor_override,
                    "absence_factor_override": row.absence_factor_override,
                }
                for row in rows
            ]

    def restore_snapshot(self, module: str, rows: list[dict[str, object]]) -> None:
        """Restore exact persisted frequency rows for one module."""
        with self._connector.session() as session:
            session.query(FrequencyProfile).filter(FrequencyProfile.module == module).delete()
            for row in rows:
                session.add(FrequencyProfile(**row))


class FrequencyProfileInvalidator:
    """Background thread that LISTENs for cache-invalidation NOTIFYs.

    Combines the two cache-invalidation paths from design.md Decision 2
    (Fork 2 = c):

    * Immediate path — a dedicated psycopg2 connection runs
      ``LISTEN <channel>`` and forwards each payload to the supplied
      ``on_invalidate`` callback. The payload is a JSON object of the
      shape ``{"module": ..., "series_id": ...}``.
    * Safety-net path — every ``refresh_interval_seconds`` the thread
      triggers a full bootstrap reload through ``on_periodic_refresh``
      so missed notifies (listener reconnect, dropped packet) do not
      leave the cache stale indefinitely.

    The invalidator only runs on PostgreSQL backends. With any other
    dialect (e.g. the SQLite test backend) :meth:`start` is a no-op so
    tests that wire a real :class:`FrequencyProfileRepository` against
    SQLite do not crash on the LISTEN syntax.
    """

    def __init__(
        self,
        connector: PostgresConnector,
        channel: str,
        refresh_interval_seconds: int,
        on_invalidate: Callable[[str, str], None],
        on_periodic_refresh: Callable[[], None],
    ) -> None:
        """Wire the invalidator without starting the background thread."""
        self._connector = connector
        self._channel = channel
        self._refresh_interval_seconds = max(1, int(refresh_interval_seconds))
        self._on_invalidate = on_invalidate
        self._on_periodic_refresh = on_periodic_refresh
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> bool:
        """Start the LISTEN thread. Returns ``True`` when actually started.

        Returns ``False`` (and emits a single INFO log) when the engine
        is not a PostgreSQL backend, because LISTEN/NOTIFY is a PG-only
        feature. The periodic refresh path is still useful in that
        case, so the thread runs in a periodic-only mode.
        """
        if self._thread is not None:
            return True
        dialect = self._connector.engine.dialect.name
        self._thread = threading.Thread(
            target=self._run,
            name=f"frequency-profile-invalidator-{self._channel}",
            daemon=True,
        )
        self._thread.start()
        logger.info(
            "FrequencyProfileInvalidator started " "(channel={}, refresh={}s, dialect={})",
            self._channel,
            self._refresh_interval_seconds,
            dialect,
        )
        return True

    def stop(self, timeout: float = 5.0) -> None:
        """Signal the thread to stop and wait briefly for it to exit."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None

    def _run(self) -> None:
        """Thread main: open a raw connection, LISTEN, dispatch payloads."""
        dialect = self._connector.engine.dialect.name
        if dialect != "postgresql":
            # Periodic-refresh-only mode for non-PG backends. Useful
            # for tests and for the (unlikely) case where the operator
            # points otalon-clas at a different DB.
            self._run_periodic_only()
            return

        try:
            raw_conn = self._connector.engine.raw_connection()
        except Exception as exc:
            logger.exception(
                "FrequencyProfileInvalidator: failed to open raw connection: {}",
                exc,
            )
            self._run_periodic_only()
            return

        try:
            raw_conn.set_isolation_level(0)  # autocommit
            cursor = raw_conn.cursor()
            cursor.execute(f"LISTEN {self._channel};")
            cursor.close()
            last_refresh = time.monotonic()
            while not self._stop_event.is_set():
                if select.select([raw_conn], [], [], _NOTIFY_POLL_TIMEOUT_S) == (
                    [],
                    [],
                    [],
                ):
                    if time.monotonic() - last_refresh >= self._refresh_interval_seconds:
                        self._safe_periodic_refresh()
                        last_refresh = time.monotonic()
                    continue
                raw_conn.poll()
                while raw_conn.notifies:
                    notify = raw_conn.notifies.pop(0)
                    self._dispatch_payload(notify.payload)
                if time.monotonic() - last_refresh >= self._refresh_interval_seconds:
                    self._safe_periodic_refresh()
                    last_refresh = time.monotonic()
        except Exception as exc:
            logger.exception("FrequencyProfileInvalidator: listener loop crashed: {}", exc)
        finally:
            try:
                raw_conn.close()
            except Exception:
                pass

    def _run_periodic_only(self) -> None:
        """Fallback loop with no LISTEN — just periodic refreshes."""
        while not self._stop_event.is_set():
            if self._stop_event.wait(self._refresh_interval_seconds):
                break
            self._safe_periodic_refresh()

    def _dispatch_payload(self, payload: str) -> None:
        """Parse the JSON NOTIFY payload and forward to the callback."""
        if not payload:
            return
        try:
            data = json.loads(payload)
            module = str(data.get("module", ""))
            series_id = str(data.get("series_id", ""))
        except (TypeError, ValueError) as exc:
            logger.warning(
                "FrequencyProfileInvalidator: malformed NOTIFY payload {!r}: {}",
                payload,
                exc,
            )
            return
        if not module or not series_id:
            logger.warning(
                "FrequencyProfileInvalidator: NOTIFY missing module/series_id: {!r}",
                payload,
            )
            return
        try:
            self._on_invalidate(module, series_id)
        except Exception as exc:
            logger.exception(
                "FrequencyProfileInvalidator: invalidation callback raised: {}",
                exc,
            )

    def _safe_periodic_refresh(self) -> None:
        """Run the periodic refresh, swallowing exceptions."""
        try:
            self._on_periodic_refresh()
        except Exception as exc:
            logger.exception("FrequencyProfileInvalidator: periodic refresh raised: {}", exc)


def emit_notify(connector: PostgresConnector, channel: str, module: str, series_id: str) -> None:
    """Emit a cache-invalidation NOTIFY for one profile.

    Used by both the MCP write tools (which mutate ``frequency_profiles``
    directly) and by tests. The payload shape mirrors what
    :meth:`FrequencyProfileInvalidator._dispatch_payload` expects.

    Silently logs and continues on non-PostgreSQL backends so test
    repositories backed by SQLite do not blow up.
    """
    if connector.engine.dialect.name != "postgresql":
        logger.debug(
            "emit_notify skipped (dialect={}): channel={} module={} series_id={}",
            connector.engine.dialect.name,
            channel,
            module,
            series_id,
        )
        return
    payload = json.dumps({"module": module, "series_id": series_id})
    with connector.engine.begin() as conn:
        # ``NOTIFY`` parameters are not bindable — quote the payload manually.
        safe_payload = payload.replace("'", "''")
        conn.execute(text(f"NOTIFY {channel}, '{safe_payload}'"))
