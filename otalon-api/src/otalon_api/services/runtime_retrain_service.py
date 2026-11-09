"""Runtime retrain orchestrator for otalon-clas.

Replaces the env/restart orchestration in ``boundary_retrain_service.py``.
Starts a retrain by writing a ``retrain_jobs`` row and emitting a PostgreSQL
NOTIFY, then exposes poll-based status. No ``.env.compose`` mutation, no
Docker lifecycle, no container restart/recreate is performed.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from math import ceil
from typing import Any, Literal

from loguru import logger

from otalon_api.domain.operations import OperationsJobCreate
from otalon_api.domain.time.intervals import normalize_intervals
from otalon_api.domain.time.validation import RuntimeRetrainValidationError
from otalon_api.repositories.operations_jobs_repo import OperationsJobsRepository
from otalon_api.repositories.postgres_repo import PostgresRepository
from otalon_api.repositories.runtime_retrain_repo import RuntimeRetrainRepo
from otalon_api.settings import Settings

_WINDOW_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?$"
)

RetrainScope = Literal["bounds", "ml"]
RetrainState = Literal["idle", "queued", "running", "publishing", "succeeded", "failed", "rejected"]


class RuntimeRetrainBusy(RuntimeError):
    """Raised when a second start request arrives while a job is in flight."""


class RuntimeRetrainCooldown(RuntimeError):
    """Raised when a terminal retrain is still inside its cooldown window."""

    def __init__(self, message: str, retry_after: int) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class RuntimeRetrainSnapshotError(RuntimeError):
    """Raised when a reserved bounds job cannot snapshot existing bounds."""


@dataclass
class RetrainStatus:
    """Status snapshot surfaced by the training endpoints."""

    state: RetrainState
    detail: str
    job_ref: str | None = None
    scope: RetrainScope | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    window_start: str | None = None
    window_stop: str | None = None
    intervals: list[tuple[str, str]] = field(default_factory=list)
    history_snapshot_rows: int = 0
    error: str | None = None
    mitre_file: str | None = None
    busy: bool = field(init=False)

    def __post_init__(self) -> None:
        """Derive the busy flag from the runtime state."""
        self.busy = self.state in {"queued", "running", "publishing"}

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serialisable dict representation."""
        return {
            "state": self.state,
            "detail": self.detail,
            "job_ref": self.job_ref,
            "scope": self.scope,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "window_start": self.window_start,
            "window_stop": self.window_stop,
            "intervals": self.intervals,
            "history_snapshot_rows": self.history_snapshot_rows,
            "error": self.error,
            "mitre_file": self.mitre_file,
            "busy": self.busy,
        }


def _normalize_iso(value: str) -> str:
    """Normalize an ISO-8601 window string for ``datetime.fromisoformat``.

    Accepts a space or ``T`` separator, optional fractional seconds, and an
    optional ``Z``/numeric UTC offset. Returns a string ``fromisoformat`` can
    parse on all supported Python versions (``Z`` -> ``+00:00``).
    """
    text = value.strip().replace(" ", "T")
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    return text


def validate_window(window_start: str, window_stop: str) -> None:
    """Validate ISO-8601 retrain window strings with ``start < stop``.

    Raises:
        RuntimeRetrainValidationError: On any validation failure.
    """
    for label, value in (("window_start", window_start), ("window_stop", window_stop)):
        if not isinstance(value, str) or not value.strip():
            raise RuntimeRetrainValidationError(f"{label} must be a non-empty ISO-8601 string")
        if not _WINDOW_RE.match(value):
            raise RuntimeRetrainValidationError(f"{label}={value!r} is not ISO-8601 'YYYY-MM-DD HH:MM[:SS]'")
    try:
        start_dt = datetime.fromisoformat(_normalize_iso(window_start))
        stop_dt = datetime.fromisoformat(_normalize_iso(window_stop))
    except ValueError as exc:
        raise RuntimeRetrainValidationError(f"Could not parse retrain window: {exc}") from exc
    if (start_dt.tzinfo is None) != (stop_dt.tzinfo is None):
        start_dt = start_dt.replace(tzinfo=timezone.utc) if start_dt.tzinfo is None else start_dt
        stop_dt = stop_dt.replace(tzinfo=timezone.utc) if stop_dt.tzinfo is None else stop_dt
    if start_dt >= stop_dt:
        raise RuntimeRetrainValidationError(
            f"window_start ({window_start}) must be strictly less than window_stop ({window_stop})"
        )


class RuntimeRetrainService:
    """DB-backed runtime retrain orchestrator.

    Args:
        settings: Application settings.
        postgres_repo: Shared PostgreSQL repository.
        stale_timeout_s: Heartbeat age after which a running/publishing job
            is reaped to failed.
    """

    def __init__(
        self,
        settings: Settings,
        postgres_repo: PostgresRepository,
        operations_repo: OperationsJobsRepository | None = None,
        *,
        stale_timeout_s: float = 45.0,
    ) -> None:
        """Initialize the service with a row-level repository wrapper."""
        self._settings = settings
        self._repo = RuntimeRetrainRepo(postgres_repo)
        self._operations = operations_repo
        self._stale_timeout_s = stale_timeout_s

    def _reap(self) -> None:
        """Run the heartbeat-timeout reaper."""
        try:
            reaped = self._repo.reap_stale_jobs(self._stale_timeout_s)
            if reaped:
                logger.warning("RuntimeRetrainService: reaped {} stale job(s)", reaped)
        except Exception:
            logger.exception("RuntimeRetrainService: reaper failed")

    async def start(
        self,
        window_start: str,
        window_stop: str,
        *,
        requested_by: str | None = None,
        intervals: list[tuple[str, str]] | None = None,
    ) -> RetrainStatus:
        """Start a bounds+frequency runtime retrain.

        The single-flight reservation is one atomic DB statement, and the
        bounds snapshot is taken only AFTER the slot is reserved so a
        rejected (409) request never writes a misleading ``bounds_history``
        snapshot (audit B-01).

        Raises:
            RuntimeRetrainValidationError: On invalid window.
            RuntimeRetrainBusy: When another job is non-terminal.
        """
        validate_window(window_start, window_stop)
        canonical_intervals = normalize_intervals(intervals, window_start=window_start, window_stop=window_stop)
        self._reap()

        job_ref = self._repo.generate_job_ref()
        operation = await self._create_operation(
            OperationsJobCreate(
                type="training",
                title="Bounds and frequency runtime retrain",
                trigger="operator",
                actor=requested_by,
                params={
                    "retrain_job_ref": job_ref,
                    "scope": "bounds",
                    "window_start": window_start,
                    "window_stop": window_stop,
                    "intervals": canonical_intervals,
                },
                idempotency_key=f"retrain:{job_ref}",
            ),
        )
        try:
            reserved = self._repo.try_reserve_queued(
                job_ref=job_ref,
                scope="bounds_frequency",
                window_start=window_start,
                window_stop=window_stop,
                intervals=canonical_intervals,
                requested_by=requested_by,
                detail="queued for runtime retrain",
                operations_job_id=operation.id if operation else None,
            )
        except Exception as exc:
            await self._fail_operation(operation, f"reservation failed: {type(exc).__name__}")
            raise
        if not reserved:
            await self._fail_operation(operation, "runtime retrain already in progress")
            raise RuntimeRetrainBusy("runtime retrain already in progress")

        terminal_at = self._repo.get_latest_terminal_finished_at(exclude_job_ref=job_ref)
        cooldown_s = self._settings.retrain_cooldown_minutes * 60
        if terminal_at is not None and cooldown_s > 0:
            age_s = (datetime.now(tz=timezone.utc) - terminal_at).total_seconds()
            if age_s < cooldown_s:
                retry_after = max(1, ceil(cooldown_s - age_s))
                self._repo.reject_reserved_job(job_ref, "runtime retrain cooldown active")
                raise RuntimeRetrainCooldown("runtime retrain cooldown active", retry_after)

        try:
            history_rows = self._snapshot_bounds()
        except RuntimeRetrainSnapshotError as exc:
            self._repo.fail_reserved_job(job_ref, str(exc))
            await self._fail_operation(operation, str(exc))
            raise
        if history_rows:
            self._repo.set_history_snapshot_rows(job_ref, history_rows)
        self._repo.emit_notify(job_ref)
        return RetrainStatus(
            state="queued",
            detail="runtime retrain queued",
            job_ref=job_ref,
            scope="bounds",
            window_start=window_start,
            window_stop=window_stop,
            intervals=canonical_intervals,
            history_snapshot_rows=history_rows,
        )

    async def start_classifier(
        self,
        window_start: str,
        window_stop: str,
        mitre_file: str,
        *,
        requested_by: str | None = None,
        intervals: list[tuple[str, str]] | None = None,
    ) -> RetrainStatus:
        """Start a classifier runtime retrain.

        Reservation is atomic and shares the single-flight slot with the
        bounds scope (audit B-01). The classifier scope skips the bounds
        snapshot.

        Raises:
            RuntimeRetrainValidationError: On invalid window or missing MITRE file.
            RuntimeRetrainBusy: When another job is non-terminal.
        """
        validate_window(window_start, window_stop)
        canonical_intervals = normalize_intervals(intervals, window_start=window_start, window_stop=window_stop)
        if not mitre_file or not str(mitre_file).strip():
            raise RuntimeRetrainValidationError("mitre_file is required for classifier retrain")

        job_ref = self._repo.generate_job_ref()
        operation = await self._create_operation(
            OperationsJobCreate(
                type="training",
                title="Classifier runtime retrain",
                trigger="operator",
                actor=requested_by,
                params={
                    "retrain_job_ref": job_ref,
                    "scope": "ml",
                    "window_start": window_start,
                    "window_stop": window_stop,
                    "intervals": canonical_intervals,
                    "mitre_file": mitre_file,
                },
                idempotency_key=f"retrain:{job_ref}",
            ),
        )
        try:
            reserved = self._repo.try_reserve_queued(
                job_ref=job_ref,
                scope="classifier",
                window_start=window_start,
                window_stop=window_stop,
                intervals=canonical_intervals,
                mitre_file=str(mitre_file).strip(),
                requested_by=requested_by,
                detail="queued for classifier runtime retrain",
                operations_job_id=operation.id if operation else None,
            )
        except Exception as exc:
            await self._fail_operation(operation, f"reservation failed: {type(exc).__name__}")
            raise
        if not reserved:
            await self._fail_operation(operation, "runtime retrain already in progress")
            raise RuntimeRetrainBusy("runtime retrain already in progress")

        terminal_at = self._repo.get_latest_terminal_finished_at(exclude_job_ref=job_ref)
        cooldown_s = self._settings.retrain_cooldown_minutes * 60
        if terminal_at is not None and cooldown_s > 0:
            age_s = (datetime.now(tz=timezone.utc) - terminal_at).total_seconds()
            if age_s < cooldown_s:
                retry_after = max(1, ceil(cooldown_s - age_s))
                self._repo.reject_reserved_job(job_ref, "runtime retrain cooldown active")
                raise RuntimeRetrainCooldown("runtime retrain cooldown active", retry_after)

        self._repo.emit_notify(job_ref)
        return RetrainStatus(
            state="queued",
            detail="classifier runtime retrain queued",
            job_ref=job_ref,
            scope="ml",
            window_start=window_start,
            window_stop=window_stop,
            intervals=canonical_intervals,
            mitre_file=str(mitre_file).strip(),
        )

    async def _create_operation(self, payload: OperationsJobCreate) -> Any:
        """Create canonical projection when production wiring provides it."""
        if self._operations is None:
            return None
        return await asyncio.to_thread(self._operations.create, payload)

    async def _fail_operation(self, operation: Any, error: str) -> None:
        """Fail a provisional canonical row without masking retrain errors."""
        if operation is not None and self._operations is not None:
            await asyncio.to_thread(self._operations.fail, operation.id, error)

    def _snapshot_bounds(self) -> int:
        """Snapshot productive bounds, failing closed when persistence fails."""
        try:
            return self._repo.snapshot_bounds_to_history(
                module="conn",
                reason=f"runtime-retrain snapshot ({datetime.now(tz=timezone.utc).isoformat()})",
            )
        except Exception as exc:
            logger.exception("RuntimeRetrainService: bounds snapshot failed")
            raise RuntimeRetrainSnapshotError(f"bounds snapshot failed: {exc}") from exc

    def get_status(self) -> RetrainStatus:
        """Return the current or most recent job status."""
        self._reap()
        row = self._repo.get_latest_status()
        if row is None:
            return RetrainStatus(state="idle", detail="no runtime retrain jobs yet")
        return self._row_to_status(row)

    def _row_to_status(self, row: dict[str, Any]) -> RetrainStatus:
        """Map a ``retrain_jobs`` row dict to the public status shape."""
        state: RetrainState = row.get("state") or "idle"
        scope: RetrainScope | None = None
        raw_scope = row.get("scope")
        if raw_scope == "bounds_frequency":
            scope = "bounds"
        elif raw_scope == "classifier":
            scope = "ml"
        started = row.get("started_at")
        finished = row.get("finished_at")
        return RetrainStatus(
            state=state,
            detail=row.get("detail") or "",
            job_ref=row.get("job_ref"),
            scope=scope,
            started_at=started,
            finished_at=finished,
            window_start=row.get("window_start"),
            window_stop=row.get("window_stop"),
            intervals=[tuple(interval) for interval in (row.get("intervals") or [])],
            history_snapshot_rows=int(row.get("history_snapshot_rows") or 0),
            error=row.get("error"),
            mitre_file=row.get("mitre_file"),
        )
