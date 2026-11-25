"""Ownership, delivery and reconciliation of PCAP import jobs (UI-078, B6–B12).

otalon-api is the **sole PostgreSQL writer** for import jobs. The
worker never touches the database; it receives a push and reports back
over HTTP. Everything that makes that arrangement survivable lives here:

* **Overlap guard (B6)** — a *bounded* existence probe against InfluxDB.
  Bounded matters: an unbounded aggregate over ``network_metrics`` was
  measured at 25–28 s, the bounded ``LIMIT 1`` probe at 0.026 s
  (2026-07-29).
* **Job model (B7)** — existing ``type='ingest'`` with
  ``params.kind='pcap-import'``. No new CHECK value, no migration.
* **Delivery (B8)** — a busy or unreachable worker never loses a job: it
  stays ``queued`` and the dispatch loop retries it.
* **Reports (B9)** — partial progress payloads are translated into guarded
  job updates; absent fields mean "no change", never "set to null".
* **Orphan recovery (B10)** — a worker restart mid-import leaves a job
  ``running`` that nobody is working on. The loop detects that against
  ``GET /health`` and re-queues it, or fails it once recovery attempts are
  exhausted.
* **Cleanup (B12)** — a completed import deletes its upload; a failed or
  cancelled one archives it for diagnosis under a bounded retention.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from loguru import logger

from otalon_api.api.schemas.pcap_import import PcapImportReport
from otalon_api.domain.operations import JobType, OperationsJob, OperationsJobUpdate
from otalon_api.domain.pcap_import import CaptureTimeRange
from otalon_api.repositories.influx_repo import InfluxRepository
from otalon_api.services.operations_jobs_service import OperationsJobsService
from otalon_api.services.pcap_import_worker_client import (
    PcapImportWorkerClient,
    WorkerBusy,
    WorkerRejected,
    WorkerUnavailable,
)
from otalon_api.services.pcap_upload_service import StoredUpload

JOB_KIND = "pcap-import"
JOB_TYPE: JobType = "ingest"
ARCHIVE_DIR_NAME = "failed"
MAX_RECOVERY_ATTEMPTS = 3
_ORPHAN_LOG_MARKER = "orphan-recovery"
_CANCEL_REQUEST = "cancel-request"
_CANCEL_ATTEMPT = "cancel-reconciliation"
_CANCEL_BLOCKED = "Cancellation needs reconciliation; worker settlement is unverified."
_TERMINAL_STATES = frozenset({"completed", "failed", "cancelled", "rejected"})


@dataclass(frozen=True)
class OverlapConflict:
    """An existing measurement range that the capture would overwrite."""

    measurement: str
    time_start: datetime
    time_end: datetime


@dataclass(frozen=True)
class PcapImportConfig:
    """Deployment-tunable knobs of the import pipeline."""

    import_dir: Path
    measurement: str = "network_metrics"
    dispatch_interval_s: float = 5.0
    orphan_grace_s: float = 120.0
    archive_keep: int = 20


class PcapImportService:
    """Owns import jobs and reconciles them with the single-slot worker."""

    def __init__(
        self,
        jobs_service: OperationsJobsService,
        influx_repo: InfluxRepository,
        worker: PcapImportWorkerClient,
        config: PcapImportConfig,
    ) -> None:
        """Wire the service to the shared job store, Influx and the worker."""
        self._jobs = jobs_service
        self._influx = influx_repo
        self._worker = worker
        self._config = config
        self._dispatch_lock = asyncio.Lock()

    @property
    def config(self) -> PcapImportConfig:
        """Return the active import configuration."""
        return self._config

    # ── B6: overlap guard ────────────────────────────────────────

    async def find_overlap(self, time_range: CaptureTimeRange) -> OverlapConflict | None:
        """Probe InfluxDB for measurements inside the capture's window.

        Args:
            time_range: The window the capture covers.

        Returns:
            An :class:`OverlapConflict` naming the conflicting range, or
            ``None`` when the window is free.
        """
        exists = await asyncio.to_thread(
            self._influx.has_rows_between,
            self._config.measurement,
            time_range.time_start.astimezone(timezone.utc).isoformat(),
            time_range.time_end.astimezone(timezone.utc).isoformat(),
        )
        if not exists:
            return None
        return OverlapConflict(
            measurement=self._config.measurement,
            time_start=time_range.time_start,
            time_end=time_range.time_end,
        )

    # ── B7: job creation ─────────────────────────────────────────

    async def create_job(
        self,
        upload: StoredUpload,
        time_range: CaptureTimeRange | None,
        *,
        force: bool,
        actor: str = "operator",
    ) -> OperationsJob:
        """Record the import as an ``ingest`` job with ``kind=pcap-import``.

        Args:
            upload: The stored capture file.
            time_range: The detected packet-time window, when readable.
            force: Whether the overlap check was explicitly overridden.
            actor: Audit actor for the job row.

        Returns:
            The created :class:`OperationsJob` in state ``queued``.
        """
        params: dict[str, Any] = {
            "kind": JOB_KIND,
            "filename": upload.filename,
            "size_bytes": upload.size_bytes,
            "sha256": upload.sha256,
            "original_filename": upload.original_filename,
            "time_start": time_range.time_start.isoformat() if time_range else None,
            "time_end": time_range.time_end.isoformat() if time_range else None,
            "force": force,
        }
        title = f"PCAP-Import {upload.original_filename or upload.filename}"
        return await self._jobs.record_job(
            type_=JOB_TYPE,
            title=title,
            trigger="operator",
            params=params,
            actor=actor,
            can_cancel=True,
            idempotency_key=upload.sha256,
        )

    # ── B8: delivery ─────────────────────────────────────────────

    async def deliver(self, job: OperationsJob) -> bool:
        """Attempt to hand one queued job to the worker.

        A busy or unreachable worker is **not** an error: the job simply
        stays ``queued`` and the dispatch loop tries again.

        Args:
            job: The queued import job.

        Returns:
            ``True`` when the worker accepted the job.
        """
        async with self._dispatch_lock:
            return await self._deliver_locked(job)

    async def _deliver_locked(self, job: OperationsJob) -> bool:
        """Deliver under the transport lock without recursive acquisition."""
        current = await self._jobs.get_job(job.id)
        if current is None or not is_import_job(current) or current.state != "queued":
            return False
        job = current
        params = job.params or {}
        file_path = self.file_path_of(job)
        if file_path is None:
            await self._jobs.update_job(
                job.id,
                OperationsJobUpdate(
                    state="failed",
                    error="Upload file is missing from the import directory",
                    ended_at=datetime.now(timezone.utc),
                    can_cancel=False,
                    can_retry=True,
                ),
                allowed_from={"queued"},
            )
            return False
        try:
            await self._worker.deliver(
                job.display_id,
                str(file_path),
                time_start=_parse_dt(params.get("time_start")),
                time_end=_parse_dt(params.get("time_end")),
                original_filename=params.get("original_filename"),
                force=bool(params.get("force")),
            )
        except WorkerBusy as exc:
            logger.debug("pcap-import: worker busy with {}, keeping {} queued", exc.running_display_id, job.display_id)
            return False
        except WorkerUnavailable as exc:
            logger.warning("pcap-import: worker unreachable, keeping {} queued ({})", job.display_id, exc)
            return False
        except WorkerRejected as exc:
            await self._jobs.update_job(
                job.id,
                OperationsJobUpdate(
                    state="failed",
                    error=f"Worker rejected the import: {exc.detail}",
                    ended_at=datetime.now(timezone.utc),
                    can_cancel=False,
                    can_retry=True,
                ),
                allowed_from={"queued"},
            )
            return False
        await self._jobs.update_job(
            job.id,
            OperationsJobUpdate(
                state="running",
                phase_current=1,
                phase_total=3,
                phase_label="Übergeben",
                latest_event="Import an den Worker übergeben",
            ),
            allowed_from={"queued"},
        )
        logger.info("pcap-import: delivered {} to the worker", job.display_id)
        return True

    async def dispatch_pending(self) -> int:
        """Deliver queued jobs until the worker is busy or none are left.

        Returns:
            The number of jobs the worker accepted in this pass.
        """
        delivered = 0
        async with self._dispatch_lock:
            for job in await self.list_jobs(state="queued"):
                if not await self._deliver_locked(job):
                    break
                delivered += 1
        return delivered

    # ── B9: report channel ───────────────────────────────────────

    async def apply_report(self, display_id: str, report: PcapImportReport) -> OperationsJob | None:
        """Translate a worker report into a guarded job update.

        Args:
            display_id: The job the worker is reporting on.
            report: The partial progress/outcome payload.

        Returns:
            The updated job, or ``None`` when no import job carries that
            display id.
        """
        job = await self._jobs.get_job_by_display_id(display_id)
        if job is None or not is_import_job(job):
            return None
        if job.state in _TERMINAL_STATES:
            return job
        if report.state in ("completed", "failed", "cancelled"):
            return await self._apply_terminal(job, report)
        data = _present(report, ("state", "phase_current", "phase_total", "phase_label", "latest_event"))
        allowed = {"queued", "running"}
        if report.state == "cancelling":
            data["can_retry"] = False
        updated = await self._jobs.update_job(job.id, OperationsJobUpdate(**data), allowed_from=allowed)
        if updated is None and report.state != "running":
            # Separate SQL guards keep late progress from overwriting blocked evidence.
            data.pop("latest_event", None)
            updated = await self._jobs.update_job(job.id, OperationsJobUpdate(**data), allowed_from={"cancelling"})
        return updated or await self._jobs.get_job(job.id)

    async def _apply_terminal(
        self, job: OperationsJob, report: PcapImportReport, *, finished_at: datetime | None = None
    ) -> OperationsJob | None:
        """Drive a job to its terminal state and clean up its upload."""
        data = _present(report, ("phase_current", "phase_total", "phase_label", "latest_event", "error"))
        if report.result is not None:
            data["result"] = json.dumps(report.result, default=str)
        if job.error == _CANCEL_BLOCKED and report.error is None:
            data["error"] = _cancel_previous_error(job)
        if job.latest_event == _CANCEL_BLOCKED and report.latest_event is None:
            data["latest_event"] = None
        data["ended_at"] = finished_at or datetime.now(timezone.utc)
        if report.state == "completed":
            data.update(state="completed", can_cancel=False, can_retry=False)
            if report.result is None and job.result is None:
                data["result"] = "{}"
            finished = await self._jobs.update_job(
                job.id, OperationsJobUpdate(**data), allowed_from={"queued", "running", "cancelling"}
            )
            # Deliberately NOT offloaded: invalidate_data_extent_cache is a
            # pure in-memory dict pop, so a to_thread hop would cost more
            # than the call itself. The invariant is documented on the
            # method and pinned by a test (audit QUA-09).
            if finished is not None:
                self._influx.invalidate_data_extent_cache(self._config.measurement)
        elif report.state == "failed":
            data.update(state="failed", can_cancel=False, can_retry=True, error=report.error or "Import failed")
            finished = await self._jobs.update_job(
                job.id, OperationsJobUpdate(**data), allowed_from={"queued", "running", "cancelling"}
            )
        else:
            await self._jobs.update_job(
                job.id, OperationsJobUpdate(**data), allowed_from={"queued", "running", "cancelling"}
            )
            finished = await self._jobs.cancel_job(job.id, stops_immediately=True, actor="worker")
        if finished is not None:
            await self.cleanup_upload(finished, finished.state)
        return finished or await self._jobs.get_job(job.id)

    # ── B10: orphan recovery ─────────────────────────────────────

    async def reap_orphans(self) -> int:
        """Reconcile cancellation settlement and recover running-only orphans.

        A worker restart loses its in-memory slot; the job would otherwise
        stay ``running`` forever. Jobs younger than the configured grace
        period are left alone so a freshly delivered job is never mistaken
        for an orphan.

        Returns:
            The number of cancellations settled or orphans recovered this pass.
        """
        async with self._dispatch_lock:
            settled = await self._reconcile_cancelling_locked()
            return settled + await self._reap_running_locked()

    async def _reap_running_locked(self) -> int:
        """Retain the legacy running-only health/recovery budget under coordination."""
        running = await self.list_jobs(state="running")
        if not running:
            return 0
        health = await self._worker.health()
        if health is None:
            return 0
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=self._config.orphan_grace_s)
        recovered = 0
        for job in running:
            current = await self.get_job(job.display_id)
            if current is None or current.state != "running":
                continue
            job = current
            if health.busy and health.display_id == job.display_id:
                continue
            if _started_at(job) > cutoff:
                continue
            await self._recover_orphan(job)
            recovered += 1
        return recovered

    async def _reconcile_cancelling_locked(self) -> int:
        """Spend at most three persisted exact-status attempts after request grace."""
        settled = 0
        for candidate in await self.list_jobs(state="cancelling"):
            job = await self.get_job(candidate.display_id)
            if job is None or job.state != "cancelling":
                continue
            requested, attempts = _cancel_episode(job)
            now = datetime.now(timezone.utc)
            if requested is None:
                await self._jobs.update_job(
                    job.id,
                    OperationsJobUpdate(
                        can_retry=False,
                        log_append=[{"event": _CANCEL_REQUEST, "requested_at": now.isoformat()}],
                    ),
                    allowed_from={"cancelling"},
                )
                continue
            if attempts >= MAX_RECOVERY_ATTEMPTS:
                if job.latest_event != _CANCEL_BLOCKED:
                    await self._mark_cancel_unverified(job)
                continue
            if (now - requested).total_seconds() < self._config.orphan_grace_s:
                continue
            job = await self._jobs.update_job(
                job.id,
                OperationsJobUpdate(
                    can_retry=False,
                    log_append=[{"event": _CANCEL_ATTEMPT, "attempt": attempts + 1, "requested_at": now.isoformat()}],
                ),
                allowed_from={"cancelling"},
            )
            if job is None:
                continue
            snapshot = await self._worker.status()
            current = await self.get_job(job.display_id)
            if current is None or current.state != "cancelling":
                continue
            if (
                snapshot is not None
                and snapshot.display_id == job.display_id
                and snapshot.state in ("completed", "failed", "cancelled")
                and snapshot.finished_at is not None
            ):
                report = PcapImportReport.model_validate(
                    snapshot.model_dump(
                        include={"state", "phase_current", "phase_total", "latest_event", "error", "result"}
                    )
                )
                finished = await self._apply_terminal(current, report, finished_at=snapshot.finished_at)
                if finished is not None and finished.state in _TERMINAL_STATES:
                    settled += 1
            elif attempts + 1 == MAX_RECOVERY_ATTEMPTS:
                await self._mark_cancel_unverified(current)
        return settled

    async def _mark_cancel_unverified(self, job: OperationsJob) -> None:
        """Persist exhaustion even when restart interrupted the last status call."""
        await self._jobs.update_job(
            job.id,
            OperationsJobUpdate(
                error=_CANCEL_BLOCKED,
                latest_event=_CANCEL_BLOCKED,
                can_retry=False,
                log_append=[{"event": "cancel-unverified", "previous_error": job.error}],
            ),
            allowed_from={"cancelling"},
        )

    async def _recover_orphan(self, job: OperationsJob) -> None:
        """Re-queue an orphaned job, or fail it once attempts run out."""
        attempts = _recovery_attempts(job) + 1
        if attempts > MAX_RECOVERY_ATTEMPTS or self.file_path_of(job) is None:
            await self._jobs.update_job(
                job.id,
                OperationsJobUpdate(
                    state="failed",
                    error=(
                        f"Import worker stopped processing this job and recovery was "
                        f"abandoned after {attempts - 1} attempt(s)"
                    ),
                    ended_at=datetime.now(timezone.utc),
                    can_cancel=False,
                    can_retry=True,
                ),
                allowed_from={"running"},
            )
            logger.warning("pcap-import: gave up on orphaned job {}", job.display_id)
            return
        await self._jobs.update_job(
            job.id,
            OperationsJobUpdate(
                state="queued",
                latest_event="Worker war nicht mehr zuständig — erneut eingereiht",
                log_append=[{"event": _ORPHAN_LOG_MARKER, "attempt": attempts}],
            ),
            allowed_from={"running"},
        )
        logger.info("pcap-import: re-queued orphaned job {} (attempt {})", job.display_id, attempts)

    # ── B12: upload cleanup ──────────────────────────────────────

    async def cleanup_upload(self, job: OperationsJob, terminal_state: str) -> None:
        """Delete a successful import's upload, archive an unsuccessful one.

        A completed import has become measurements in InfluxDB, so the raw
        upload is redundant and is removed. A failed or cancelled import
        keeps its file — under a bounded archive — because the operator
        needs it to diagnose or retry.

        Args:
            job: The terminal import job.
            terminal_state: The state the job reached.
        """
        path = self.file_path_of(job)
        if path is None:
            return
        if terminal_state == "completed":
            await asyncio.to_thread(path.unlink, True)
            logger.info("pcap-import: removed upload of completed job {}", job.display_id)
            return
        await asyncio.to_thread(self._archive, path)
        logger.info("pcap-import: archived upload of {} job {}", terminal_state, job.display_id)

    def _archive(self, path: Path) -> None:
        """Move *path* into the bounded archive directory."""
        archive_dir = self._config.import_dir / ARCHIVE_DIR_NAME
        archive_dir.mkdir(parents=True, exist_ok=True)
        try:
            path.replace(archive_dir / path.name)
        except OSError:
            logger.opt(exception=True).warning("pcap-import: could not archive {}", path)
            return
        self._prune_archive(archive_dir)

    def _prune_archive(self, archive_dir: Path) -> None:
        """Keep only the newest ``archive_keep`` files in the archive."""
        entries = sorted((p for p in archive_dir.iterdir() if p.is_file()), key=lambda p: p.stat().st_mtime)
        for stale in entries[: max(0, len(entries) - self._config.archive_keep)]:
            stale.unlink(missing_ok=True)

    # ── shared helpers ───────────────────────────────────────────

    def file_path_of(self, job: OperationsJob) -> Path | None:
        """Return the stored upload path of *job*, or ``None`` when gone.

        The filename is read back from ``params`` and reduced to its base
        name before it is joined, so a doctored row can never escape the
        import directory.
        """
        filename = str((job.params or {}).get("filename") or "")
        if not filename:
            return None
        candidate = self._config.import_dir / Path(filename).name
        return candidate if candidate.is_file() else None

    async def list_jobs(self, state: str | None = None, limit: int = 1000) -> list[OperationsJob]:
        """Return import jobs, newest first, optionally filtered by state."""
        return await self._jobs.list_jobs(state=state, type_=JOB_TYPE, limit=limit, kind=JOB_KIND)

    async def get_job(self, display_id: str) -> OperationsJob | None:
        """Return one import job by display id, or ``None``."""
        job = await self._jobs.get_job_by_display_id(display_id)
        return job if job is not None and is_import_job(job) else None

    async def cancel_job(self, display_id: str) -> OperationsJob | None:
        """Request an identity-bound cooperative stop without claiming settlement."""
        async with self._dispatch_lock:
            job = await self.get_job(display_id)
            if job is None or job.state in _TERMINAL_STATES or not job.can_cancel:
                return job
            if job.state == "queued":
                guarded = await self._jobs.update_job(
                    job.id, OperationsJobUpdate(state="cancelling", can_retry=False), allowed_from={"queued"}
                )
                if guarded is None:
                    return await self.get_job(display_id)
                finished = await self._jobs.cancel_job(job.id, stops_immediately=True, actor="operator")
                if finished is not None:
                    await self.cleanup_upload(finished, "cancelled")
                return finished or await self.get_job(display_id)
            _, attempts = _cancel_episode(job)
            if job.state == "cancelling" and attempts < MAX_RECOVERY_ATTEMPTS:
                return job
            if job.state == "running":
                job = await self._jobs.cancel_job(job.id, stops_immediately=False, actor="operator")
                if job is None:
                    return await self.get_job(display_id)
            data: dict[str, Any] = {
                "can_retry": False,
                "log_append": [{"event": _CANCEL_REQUEST, "requested_at": datetime.now(timezone.utc).isoformat()}],
            }
            if job.error == _CANCEL_BLOCKED:
                data["error"] = _cancel_previous_error(job)
            if job.latest_event == _CANCEL_BLOCKED:
                data["latest_event"] = "Cancellation reconciliation requested"
            guarded = await self._jobs.update_job(job.id, OperationsJobUpdate(**data), allowed_from={"cancelling"})
            if guarded is None:
                return await self.get_job(display_id)
            try:
                accepted = await self._worker.cancel(display_id)
            except WorkerUnavailable:
                accepted = False
            await self._jobs.update_job(
                job.id,
                OperationsJobUpdate(log_append=[{"event": "cancel-delivery", "accepted": accepted}]),
                allowed_from={"cancelling"},
            )
            return await self.get_job(display_id)

    async def run_dispatch_loop(self) -> None:
        """Reconcile queued and orphaned jobs on a fixed cadence.

        Runs for the lifetime of the application; cancellation ends it.
        Individual failures are logged and never break the loop, so a
        transient Influx/PG hiccup cannot silently stop delivery.
        """
        while True:
            try:
                await asyncio.sleep(self._config.dispatch_interval_s)
                await self.reap_orphans()
                await self.dispatch_pending()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.opt(exception=True).warning("pcap-import: dispatch pass failed — continuing")


def is_import_job(job: OperationsJob) -> bool:
    """Return whether *job* is a PCAP import job."""
    return job.type == JOB_TYPE and str((job.params or {}).get("kind")) == JOB_KIND


def _present(report: PcapImportReport, names: tuple[str, ...]) -> dict[str, Any]:
    """Return the subset of *names* the worker actually reported."""
    data = report.model_dump(exclude_none=True)
    return {name: data[name] for name in names if name in data}


def _parse_dt(value: Any) -> datetime | None:
    """Parse an ISO-8601 string from ``params`` into a datetime."""
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _started_at(job: OperationsJob) -> datetime:
    """Return the job's start time as an aware UTC datetime."""
    started = job.started_at
    if started.tzinfo is None:
        return started.replace(tzinfo=timezone.utc)
    return started.astimezone(timezone.utc)


def _recovery_attempts(job: OperationsJob) -> int:
    """Count how often this job has already been recovered from an orphan."""
    return sum(1 for entry in job.log or [] if isinstance(entry, dict) and entry.get("event") == _ORPHAN_LOG_MARKER)


def _cancel_episode(job: OperationsJob) -> tuple[datetime | None, int]:
    """Read the last persisted request and its attempt count across restarts."""
    attempts = 0
    for entry in reversed(job.log):
        if not isinstance(entry, dict):
            continue
        if entry.get("event") == _CANCEL_ATTEMPT:
            attempts += 1
        if entry.get("event") == _CANCEL_REQUEST:
            requested = _parse_dt(entry.get("requested_at"))
            if requested is not None and requested.tzinfo is not None:
                return requested.astimezone(timezone.utc), attempts
            return None, attempts
    return None, attempts


def _cancel_previous_error(job: OperationsJob) -> str | None:
    """Recover real error evidence shadowed by the reconciliation diagnosis."""
    for entry in reversed(job.log):
        if isinstance(entry, dict) and entry.get("event") == "cancel-unverified":
            value = entry.get("previous_error")
            return value if isinstance(value, str) and value != _CANCEL_BLOCKED else None
    return None
