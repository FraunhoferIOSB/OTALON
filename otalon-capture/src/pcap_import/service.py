"""Single-slot import service: accept one job, work it, stay alive.

The service owns the worker's entire runtime state. It deliberately holds no
internal queue: a job pushed while another is running is refused so the owner
keeps it and delivers it again later. Queueing belongs to the job store.

Every outcome — success, failure, cancellation — returns the worker to the
``idle`` state, so a single bad capture file can never take the worker down.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from loguru import logger

from .models import (
    PHASE_LABELS,
    PHASE_ORDINALS,
    PHASE_TOTAL,
    HealthResponse,
    ImportPhase,
    ImportRequest,
    ImportState,
    ImportStatus,
    JobUpdate,
)
from .reporter import JobReporter, NullJobReporter
from .runner import ImportCancelled, ImportRunner, ProgressCallback


class WorkerBusyError(RuntimeError):
    """Raised when a job is pushed while another import is in progress."""

    def __init__(self, display_id: Optional[str]) -> None:
        """Record which job currently occupies the worker.

        Args:
            display_id: Identifier of the running job, if known.
        """

        self.display_id = display_id
        super().__init__(f"Worker is busy with job '{display_id}'.")


class NoActiveImportError(RuntimeError):
    """Raised when cancellation is requested while the worker is idle."""


def _now() -> datetime:
    """Return the current UTC time; used for job bookkeeping only.

    Measurement timestamps never come from here — they are read from the
    capture records themselves in the write path.
    """

    return datetime.now(tz=timezone.utc)


class ImportService:
    """Coordinate acceptance, execution and reporting of import jobs."""

    def __init__(
        self,
        runner: ImportRunner,
        reporter: Optional[JobReporter] = None,
    ) -> None:
        """Wire the execution strategy and the progress sink.

        Args:
            runner: Executes a single import job.
            reporter: Delivers progress to the job owner. Defaults to a
                reporter that discards updates.
        """

        self._runner = runner
        self._reporter: JobReporter = reporter if reporter is not None else NullJobReporter()
        self._lock = threading.Lock()
        self._status = ImportStatus(state=ImportState.IDLE)
        self._cancel_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    @property
    def status(self) -> ImportStatus:
        """Return a snapshot of the worker's current status."""

        with self._lock:
            return self._status.model_copy(deep=True)

    @property
    def busy(self) -> bool:
        """Whether an import currently occupies the worker."""

        with self._lock:
            return self._status.state in {ImportState.RUNNING, ImportState.CANCELLING}

    def health(self) -> HealthResponse:
        """Return the health payload describing readiness and occupancy."""

        snapshot = self.status
        occupied = snapshot.state in {ImportState.RUNNING, ImportState.CANCELLING}
        return HealthResponse(
            status="ok",
            busy=occupied,
            state=snapshot.state,
            display_id=snapshot.display_id if occupied else None,
        )

    def submit(self, job: ImportRequest) -> datetime:
        """Accept ``job`` for asynchronous processing.

        Args:
            job: The import job pushed by its owner.

        Returns:
            The acceptance timestamp.

        Raises:
            WorkerBusyError: When another import is already in progress.
        """

        with self._lock:
            if self._status.state in {ImportState.RUNNING, ImportState.CANCELLING}:
                raise WorkerBusyError(self._status.display_id)
            accepted_at = _now()
            self._cancel_event = threading.Event()
            self._status = ImportStatus(
                state=ImportState.RUNNING,
                display_id=job.display_id,
                phase=ImportPhase.ACCEPTED,
                phase_current=PHASE_ORDINALS[ImportPhase.ACCEPTED],
                phase_total=PHASE_TOTAL,
                latest_event="Auftrag angenommen",
                started_at=accepted_at,
            )
            cancel_event = self._cancel_event
            self._thread = threading.Thread(
                target=self._execute,
                args=(job, cancel_event),
                name=f"pcap-import-{job.display_id}",
                daemon=True,
            )
            self._thread.start()
        logger.info("Import job {display_id} accepted.", display_id=job.display_id)
        self._report(
            job.display_id,
            JobUpdate(state=ImportState.RUNNING, latest_event="Auftrag angenommen"),
        )
        return accepted_at

    def cancel(self) -> str:
        """Request cancellation of the running import.

        Returns:
            The display identifier of the job being cancelled.

        Raises:
            NoActiveImportError: When no import is currently running.
        """

        with self._lock:
            if self._status.state not in {ImportState.RUNNING, ImportState.CANCELLING}:
                raise NoActiveImportError("No import is currently running.")
            display_id = self._status.display_id or ""
            self._status = self._status.model_copy(
                update={
                    "state": ImportState.CANCELLING,
                    "latest_event": "Abbruch angefordert",
                }
            )
            self._cancel_event.set()
        logger.info("Cancellation requested for import job {display_id}.", display_id=display_id)
        self._report(
            display_id,
            JobUpdate(state=ImportState.CANCELLING, latest_event="Abbruch angefordert"),
        )
        return display_id

    def wait_for_idle(self, timeout: Optional[float] = None) -> bool:
        """Block until the current import finished; primarily for tests.

        Args:
            timeout: Maximum seconds to wait, or ``None`` to wait indefinitely.

        Returns:
            ``True`` when the worker is idle, ``False`` on timeout.
        """

        with self._lock:
            thread = self._thread
        if thread is not None:
            thread.join(timeout=timeout)
        return not self.busy

    def _execute(self, job: ImportRequest, cancel_event: threading.Event) -> None:
        """Run one job to a terminal state without ever escaping an exception."""

        try:
            result = self._runner.run(job, self._make_progress(job.display_id), cancel_event)
        except ImportCancelled as cancelled:
            self._finish_cancelled(job, str(cancelled))
        except BaseException as error:  # noqa: BLE001 - a bad job must not kill the worker
            if cancel_event.is_set():
                self._finish_cancelled(job, "Import wurde abgebrochen.")
            else:
                self._finish_failed(job, error)
        else:
            if cancel_event.is_set():
                self._finish_cancelled(job, "Import wurde abgebrochen.")
            else:
                self._finish_completed(job, result)

    def _make_progress(self, display_id: str) -> ProgressCallback:
        """Build the progress callback handed to the runner."""

        def progress(phase: ImportPhase, event: str) -> None:
            self._advance(display_id, phase, event)

        return progress

    def _advance(self, display_id: str, phase: ImportPhase, event: str) -> None:
        """Record a phase transition locally and report it to the owner."""

        with self._lock:
            if self._status.display_id != display_id:
                return
            self._status = self._status.model_copy(
                update={
                    "phase": phase,
                    "phase_current": PHASE_ORDINALS[phase],
                    "latest_event": event,
                }
            )
        self._report(
            display_id,
            JobUpdate(
                phase_current=PHASE_ORDINALS[phase],
                phase_total=PHASE_TOTAL,
                phase_label=PHASE_LABELS[phase],
                latest_event=event,
            ),
        )

    def _finish_completed(self, job: ImportRequest, result: Dict[str, Any]) -> None:
        """Move the job to ``completed`` and free the worker."""

        logger.info("Import job {display_id} completed.", display_id=job.display_id)
        self._settle(
            job.display_id,
            ImportState.COMPLETED,
            latest_event="Import abgeschlossen",
            result=result,
        )

    def _finish_failed(self, job: ImportRequest, error: BaseException) -> None:
        """Move the job to ``failed``, carrying a diagnostic message."""

        diagnosis = f"{type(error).__name__}: {error}"
        logger.exception(
            "Import job {display_id} failed: {error}",
            display_id=job.display_id,
            error=diagnosis,
        )
        self._settle(
            job.display_id,
            ImportState.FAILED,
            latest_event="Import fehlgeschlagen",
            error=diagnosis,
        )

    def _finish_cancelled(self, job: ImportRequest, message: str) -> None:
        """Move the job to ``cancelled`` and free the worker."""

        logger.info("Import job {display_id} cancelled.", display_id=job.display_id)
        self._settle(
            job.display_id,
            ImportState.CANCELLED,
            latest_event=message or "Import abgebrochen",
        )

    def _settle(
        self,
        display_id: str,
        state: ImportState,
        latest_event: str,
        result: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None,
    ) -> None:
        """Apply a terminal state, return the worker to idle, then report.

        The local slot is released *before* the outbound report so a slow or
        unreachable owner can never keep the worker occupied.
        """

        finished_at = _now()
        with self._lock:
            self._status = ImportStatus(
                state=state,
                display_id=display_id,
                phase=ImportPhase.FINISHED,
                phase_current=PHASE_ORDINALS[ImportPhase.FINISHED],
                phase_total=PHASE_TOTAL,
                latest_event=latest_event,
                started_at=self._status.started_at,
                finished_at=finished_at,
                error=error,
                result=result,
            )
            self._thread = None
        self._report(
            display_id,
            JobUpdate(
                state=state,
                phase_current=PHASE_ORDINALS[ImportPhase.FINISHED],
                phase_total=PHASE_TOTAL,
                phase_label=PHASE_LABELS[ImportPhase.FINISHED],
                latest_event=latest_event,
                error=error,
                result=result,
            ),
        )

    def _report(self, display_id: str, update: JobUpdate) -> None:
        """Deliver an update, absorbing every reporting error.

        Reporting is best-effort by design: the owner endpoint may not exist
        yet, and an outage there must not affect the import or the worker.
        """

        if not display_id:
            return
        try:
            self._reporter.report(display_id, update)
        except Exception as error:  # noqa: BLE001 - reporting must never break the worker
            logger.warning(
                "Reporting update for job {display_id} raised {error}; continuing.",
                display_id=display_id,
                error=error,
            )
