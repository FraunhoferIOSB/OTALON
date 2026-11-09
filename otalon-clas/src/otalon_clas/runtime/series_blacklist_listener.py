"""PostgreSQL listener forcing series-blacklist re-reads (CLAS-071 D8).

Listens on the ``cyberclas_runtime_invalidation`` channel and sets the
:class:`~otalon_clas.runtime.series_blacklist_source.SeriesBlacklistSource`
dirty flag whenever a payload names the otalon-clas series-blacklist
key. Shapes:

* own dedicated raw connection — ``LISTEN`` needs a persistent session
  and must not occupy (or race on) a pool connection;
* periodic fallback — every ``periodic_dirty_interval_seconds`` (30 s
  by default, decision D13) the dirty flag is set regardless, so a lost
  NOTIFY self-heals by TTL semantics;
* poll-only degradation on non-PostgreSQL backends (same fallback as
  :class:`~otalon_clas.runtime.bounds_invalidator.BoundsInvalidator`);
* reconnect loop with backoff — unlike the CLAS-058 no-retry pattern,
  a dropped connection logs, waits and re-listens instead of killing
  the thread; the periodic fallback covers the outage window.
"""

from __future__ import annotations

import json
import select
import threading
import time
from collections.abc import Callable
from typing import Any

from loguru import logger
from otalon_common.runtime import OTALON_CLAS_SERVICE

from otalon_clas.common.postgres_connector import PostgresConnector
from otalon_clas.runtime.series_blacklist_source import SERIES_BLACKLIST_KEY

SERIES_BLACKLIST_INVALIDATION_CHANNEL = "cyberclas_runtime_invalidation"
"""Channel the API emits its series-blacklist write NOTIFY on (D10)."""

_NOTIFY_POLL_TIMEOUT_S = 1.0
_RECONNECT_BACKOFF_BASE_S = 1.0
_RECONNECT_BACKOFF_MAX_S = 30.0


class SeriesBlacklistListener:
    """LISTEN/NOTIFY accelerator for the series-blacklist runtime source.

    Args:
        connector: PostgreSQL connector; a dedicated raw connection is
            derived from its engine (never the session pool).
        on_invalidation: Zero-arg callback invoked on a matching
            notification payload (typically ``source.mark_dirty``).
        periodic_dirty_interval_seconds: Periodic fallback interval;
            defaults to the documented 30 s (D13) and applies to BOTH the
            LISTEN loop and the poll-only degradation.
    """

    def __init__(
        self,
        connector: PostgresConnector,
        on_invalidation: Callable[[], None],
        periodic_dirty_interval_seconds: float = 30.0,
    ) -> None:
        """Wire the listener without starting its background thread."""
        self._connector = connector
        self._on_invalidation = on_invalidation
        self._periodic_interval = max(1.0, float(periodic_dirty_interval_seconds))
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> bool:
        """Start LISTEN/NOTIFY processing and the periodic fallback."""
        if self._thread is not None:
            return True
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="cyberclas-series-blacklist-listener",
            daemon=True,
        )
        self._thread.start()
        return True

    def stop(self, timeout: float = 5.0) -> None:
        """Stop the listener thread and wait for its exit."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None

    def _run(self) -> None:
        """Run the PostgreSQL LISTEN loop or the periodic-only fallback."""
        if self._connector.engine.dialect.name != "postgresql":
            self._run_periodic_only()
            return
        backoff = _RECONNECT_BACKOFF_BASE_S
        while not self._stop_event.is_set():
            raw_conn = self._try_listen_connection()
            if raw_conn is None:
                if self._stop_event.wait(backoff):
                    return
                backoff = min(backoff * 2, _RECONNECT_BACKOFF_MAX_S)
                continue
            backoff = _RECONNECT_BACKOFF_BASE_S
            try:
                self._run_listener(raw_conn)
            except Exception as exc:
                logger.warning(
                    "SeriesBlacklistListener: listener session lost ({}); " "reconnecting after {}s",
                    exc,
                    backoff,
                )
            finally:
                self._close_quietly(raw_conn)

    def _try_listen_connection(self) -> Any | None:
        """Open a dedicated session and register the channel LISTEN."""
        try:
            raw_conn = self._connector.engine.raw_connection()
            raw_conn.set_isolation_level(0)
            cursor = raw_conn.cursor()
            cursor.execute(f"LISTEN {SERIES_BLACKLIST_INVALIDATION_CHANNEL};")
            cursor.close()
            return raw_conn
        except Exception as exc:
            logger.warning(
                "SeriesBlacklistListener: could not open LISTEN session ({}); " "periodic fallback covers the outage",
                exc,
            )
            return None

    @staticmethod
    def _close_quietly(raw_conn: Any) -> None:
        """Close a raw session, swallowing a double-close error."""
        try:
            raw_conn.close()
        except Exception:
            pass

    def _run_listener(self, raw_conn: Any) -> None:
        """Dispatch notifications and periodic fallback dirty marks."""
        last_periodic = time.monotonic()
        while not self._stop_event.is_set():
            if select.select([raw_conn], [], [], _NOTIFY_POLL_TIMEOUT_S)[0]:
                raw_conn.poll()
                while raw_conn.notifies:
                    self._dispatch(raw_conn.notifies.pop(0).payload)
            if time.monotonic() - last_periodic >= self._periodic_interval:
                self._mark_dirty_safely()
                last_periodic = time.monotonic()

    def _run_periodic_only(self) -> None:
        """Degrade to periodic re-reads when LISTEN is unavailable."""
        logger.info(
            "SeriesBlacklistListener: non-PostgreSQL backend; periodic " "re-read every {}s",
            self._periodic_interval,
        )
        while not self._stop_event.wait(self._periodic_interval):
            self._mark_dirty_safely()

    def _mark_dirty_safely(self) -> None:
        """Set the dirty flag through the callback, never raising."""
        try:
            self._on_invalidation()
        except Exception as exc:
            logger.exception("SeriesBlacklistListener: dirty callback failed: {}", exc)

    def _dispatch(self, payload: str) -> None:
        """Set the dirty flag only for a matching service+key payload."""
        try:
            data = json.loads(payload)
            service = str(data.get("service", ""))
            key = str(data.get("key", ""))
        except (TypeError, ValueError, AttributeError) as exc:
            logger.warning(
                "SeriesBlacklistListener: malformed payload {!r}: {}",
                payload,
                exc,
            )
            return
        if service != OTALON_CLAS_SERVICE or key != SERIES_BLACKLIST_KEY:
            logger.debug(
                "SeriesBlacklistListener: ignoring payload for ({!r}, {!r})",
                service,
                key,
            )
            return
        self._mark_dirty_safely()
