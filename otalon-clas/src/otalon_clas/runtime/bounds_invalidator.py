"""PostgreSQL listener for operator bounds corrections."""

from __future__ import annotations

import json
import select
import threading
import time
from collections.abc import Callable
from typing import Any

from loguru import logger

from otalon_clas.common.postgres_connector import PostgresConnector

BOUNDS_INVALIDATION_CHANNEL = "cyberclas_bounds_invalidation"
_NOTIFY_POLL_TIMEOUT_S = 1.0


class BoundsInvalidator:
    """Invalidate module caches from bounds NOTIFYs with poll fallback."""

    def __init__(
        self,
        connector: PostgresConnector,
        poll_interval_seconds: int,
        on_invalidate: Callable[[str, str], None],
        on_periodic_refresh: Callable[[], None],
    ) -> None:
        """Wire the invalidator without starting its background thread."""
        self._connector = connector
        self._poll_interval_seconds = max(1, int(poll_interval_seconds))
        self._on_invalidate = on_invalidate
        self._on_periodic_refresh = on_periodic_refresh
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> bool:
        """Start LISTEN/NOTIFY processing and periodic fallback polling."""
        if self._thread is not None:
            return True
        self._thread = threading.Thread(
            target=self._run,
            name="cyberclas-bounds-invalidator",
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
        """Run PostgreSQL LISTEN or periodic-only fallback."""
        if self._connector.engine.dialect.name != "postgresql":
            self._run_periodic_only()
            return
        try:
            raw_conn = self._connector.engine.raw_connection()
        except Exception as exc:
            logger.exception("BoundsInvalidator: raw connection failed: {}", exc)
            self._run_periodic_only()
            return
        try:
            raw_conn.set_isolation_level(0)
            cursor = raw_conn.cursor()
            cursor.execute(f"LISTEN {BOUNDS_INVALIDATION_CHANNEL};")
            cursor.close()
            self._run_listener(raw_conn)
        except Exception as exc:
            logger.exception("BoundsInvalidator: listener loop crashed: {}", exc)
        finally:
            raw_conn.close()

    def _run_listener(self, raw_conn: Any) -> None:
        """Dispatch notifications and run periodic fallback refreshes."""
        last_poll = time.monotonic()
        while not self._stop_event.is_set():
            if select.select([raw_conn], [], [], _NOTIFY_POLL_TIMEOUT_S)[0]:
                raw_conn.poll()
                while raw_conn.notifies:
                    self._dispatch(raw_conn.notifies.pop(0).payload)
            if time.monotonic() - last_poll >= self._poll_interval_seconds:
                try:
                    self._on_periodic_refresh()
                except Exception as exc:
                    logger.exception("BoundsInvalidator: periodic refresh failed: {}", exc)
                last_poll = time.monotonic()

    def _run_periodic_only(self) -> None:
        """Run fallback refreshes when LISTEN is unavailable."""
        while not self._stop_event.wait(self._poll_interval_seconds):
            try:
                self._on_periodic_refresh()
            except Exception as exc:
                logger.exception("BoundsInvalidator: periodic refresh failed: {}", exc)

    def _dispatch(self, payload: str) -> None:
        """Parse sender payload and forward its module and series."""
        try:
            data = json.loads(payload)
            module = str(data.get("module", ""))
            series_id = str(data.get("series_id", ""))
        except (TypeError, ValueError) as exc:
            logger.warning("BoundsInvalidator: malformed payload {!r}: {}", payload, exc)
            return
        if not module or not series_id:
            logger.warning("BoundsInvalidator: payload missing module/series_id: {!r}", payload)
            return
        try:
            self._on_invalidate(module, series_id)
        except Exception as exc:
            logger.exception("BoundsInvalidator: invalidation callback failed: {}", exc)
