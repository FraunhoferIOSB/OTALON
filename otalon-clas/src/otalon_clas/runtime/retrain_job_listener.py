"""LISTEN/NOTIFY dispatcher for runtime retrain jobs.

A dedicated background thread runs ``LISTEN cyberclas_retrain_job`` and
forwards each ``{"job_ref": ...}`` payload to a callback. A periodic poll
of ``retrain_jobs WHERE state='queued'`` acts as a safety net for missed
NOTIFYs. On non-PostgreSQL backends the listener degrades to poll-only.
"""

from __future__ import annotations

import json
import select
import threading
import time
from typing import Callable

from loguru import logger

from otalon_clas.common.postgres_connector import PostgresConnector
from otalon_clas.runtime.retrain_job_repository import RetrainJobRepository

_NOTIFY_POLL_TIMEOUT_S: float = 1.0
_DEFAULT_POLL_INTERVAL_S: int = 30


class RetrainJobListener:
    """Background listener for queued retrain jobs.

    Args:
        connector: PostgreSQL connector used to open a raw LISTEN
            connection and to poll queued rows.
        poll_interval_seconds: How often to re-scan ``retrain_jobs`` for
            queued rows as a missed-NOTIFY safety net.
        on_job_ref: Callback invoked with the ``job_ref`` string for each
            queued job discovered via NOTIFY or polling.
    """

    def __init__(
        self,
        connector: PostgresConnector,
        poll_interval_seconds: int,
        on_job_ref: Callable[[str], None],
    ) -> None:
        """Wire the listener without starting its thread."""
        self._connector = connector
        self._poll_interval_seconds = max(1, int(poll_interval_seconds))
        self._on_job_ref = on_job_ref
        self._repository = RetrainJobRepository(connector)
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> bool:
        """Start the listener thread."""
        if self._thread is not None:
            return True
        self._thread = threading.Thread(
            target=self._run,
            name="cyberclas-retrain-job-listener",
            daemon=True,
        )
        self._thread.start()
        logger.info(
            "RetrainJobListener started (poll_safety={}s)",
            self._poll_interval_seconds,
        )
        return True

    def stop(self, timeout: float = 5.0) -> None:
        """Signal the listener to stop and wait for it to exit."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None

    def _run(self) -> None:
        """Thread main: LISTEN when possible, always poll periodically."""
        dialect = self._connector.engine.dialect.name
        if dialect != "postgresql":
            self._run_poll_only()
            return

        try:
            raw_conn = self._connector.engine.raw_connection()
        except Exception as exc:
            logger.exception("RetrainJobListener: failed raw connection: {}", exc)
            self._run_poll_only()
            return

        try:
            raw_conn.set_isolation_level(0)
            cursor = raw_conn.cursor()
            cursor.execute("LISTEN cyberclas_retrain_job;")
            cursor.close()
            last_poll = time.monotonic()
            while not self._stop_event.is_set():
                ready = select.select([raw_conn], [], [], _NOTIFY_POLL_TIMEOUT_S)
                if ready[0]:
                    raw_conn.poll()
                    while raw_conn.notifies:
                        notify = raw_conn.notifies.pop(0)
                        self._dispatch(notify.payload)
                if time.monotonic() - last_poll >= self._poll_interval_seconds:
                    self._poll_queued()
                    last_poll = time.monotonic()
        except Exception as exc:
            logger.exception("RetrainJobListener: listener loop crashed: {}", exc)
        finally:
            try:
                raw_conn.close()
            except Exception:
                pass

    def _run_poll_only(self) -> None:
        """Fallback loop without LISTEN."""
        while not self._stop_event.is_set():
            if self._stop_event.wait(self._poll_interval_seconds):
                break
            self._poll_queued()

    def _poll_queued(self) -> None:
        """Forward every queued job ref to the callback."""
        try:
            for job_ref in self._repository.fetch_queued_refs():
                self._dispatch(json.dumps({"job_ref": job_ref}))
        except Exception as exc:
            logger.exception("RetrainJobListener: poll queued failed: {}", exc)

    def _dispatch(self, payload: str) -> None:
        """Parse the NOTIFY payload and forward the job_ref."""
        if not payload:
            return
        try:
            data = json.loads(payload)
            job_ref = str(data.get("job_ref", ""))
        except (TypeError, ValueError) as exc:
            logger.warning(
                "RetrainJobListener: malformed payload {!r}: {}",
                payload,
                exc,
            )
            return
        if not job_ref:
            logger.warning(
                "RetrainJobListener: payload missing job_ref: {!r}",
                payload,
            )
            return
        try:
            self._on_job_ref(job_ref)
        except Exception as exc:
            logger.exception("RetrainJobListener: callback raised: {}", exc)
