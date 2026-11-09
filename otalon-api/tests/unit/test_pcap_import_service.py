"""Service-level tests for PCAP import ownership (UI-078 Wave B, B13).

These cover the parts of the contract that are invisible at the router
boundary but decide whether a job survives real operations:

* a **busy** worker and an **unreachable** worker both leave the job
  ``queued`` — no job is lost because the worker was unavailable;
* a worker that restarted mid-import leaves an orphaned ``running`` job,
  which the reconciler re-queues and eventually fails;
* the report channel translates partial payloads without nulling fields
  and applies the B12 cleanup decision (delete on success, archive on
  failure).
"""

from __future__ import annotations

import shutil
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

import pytest

from otalon_api.api.schemas.pcap_import import PcapImportReport
from otalon_api.domain.pcap_import import CaptureTimeRange
from otalon_api.services.pcap_import_service import (
    ARCHIVE_DIR_NAME,
    MAX_RECOVERY_ATTEMPTS,
    PcapImportConfig,
    PcapImportService,
)
from otalon_api.services.pcap_import_worker_client import (
    WorkerBusy,
    WorkerHealth,
    WorkerRejected,
    WorkerUnavailable,
)
from otalon_api.services.pcap_upload_service import StoredUpload
from tests.helpers.pcap_fixtures import FakeJobsService

pytestmark = pytest.mark.unit


class _FakeInflux:
    """Influx stand-in returning a canned overlap verdict."""

    def __init__(self, overlapping: bool = False) -> None:
        """Record the canned answer and the probes issued."""
        self.overlapping = overlapping
        self.calls: list[tuple[str, str, str]] = []
        self.invalidated: list[str | None] = []

    def has_rows_between(self, measurement: str, start: str, stop: str) -> bool:
        """Return the canned verdict and record the probe."""
        self.calls.append((measurement, start, stop))
        return self.overlapping

    def invalidate_data_extent_cache(self, measurement: str | None = None) -> None:
        """Record that the cached extent was dropped."""
        self.invalidated.append(measurement)


class _FakeWorker:
    """Worker client stand-in with scriptable delivery and health."""

    def __init__(self, error: Exception | None = None, health: WorkerHealth | None = None) -> None:
        """Configure the delivery error and the health snapshot."""
        self.error = error
        self.health_result = health
        self.delivered: list[str] = []
        self.cancelled: list[str] = []

    async def deliver(self, display_id: str, file_path: str, **_: Any) -> dict[str, Any]:
        """Record the attempt and honour the scripted error."""
        self.delivered.append(display_id)
        if self.error is not None:
            raise self.error
        return {"display_id": display_id, "state": "running"}

    async def cancel(self, display_id: str) -> bool:
        """Record a cancellation request."""
        self.cancelled.append(display_id)
        return True

    async def health(self) -> WorkerHealth | None:
        """Return the canned health snapshot."""
        return self.health_result


@pytest.fixture()
def import_dir() -> Iterator[Path]:
    """Provide an isolated import directory removed after the test."""
    path = Path(tempfile.mkdtemp(prefix="pcap-import-svc-"))
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def _build(
    import_dir: Path,
    worker: _FakeWorker,
    influx: _FakeInflux | None = None,
    **config: Any,
) -> tuple[PcapImportService, FakeJobsService]:
    """Assemble a service over fake collaborators."""
    jobs = FakeJobsService()
    options: dict[str, Any] = {"orphan_grace_s": 0.0}
    options.update(config)
    service = PcapImportService(
        jobs_service=jobs,  # type: ignore[arg-type]
        influx_repo=influx or _FakeInflux(),  # type: ignore[arg-type]
        worker=worker,  # type: ignore[arg-type]
        config=PcapImportConfig(import_dir=import_dir, **options),
    )
    return service, jobs


def _seed_upload(jobs: FakeJobsService, import_dir: Path, state: str = "queued", **params: Any) -> Any:
    """Seed a job whose upload file actually exists on disk."""
    name = params.pop("filename", "capture.pcap")
    (import_dir / name).write_bytes(b"\xd4\xc3\xb2\xa1payload")
    return jobs.seed(state=state, params={"kind": "pcap-import", "filename": name, **params})


class TestDeliveryResilience:
    """B8 — no job is lost because the worker was unavailable."""

    async def test_busy_worker_keeps_job_queued(self, import_dir: Path) -> None:
        """A worker ``409`` leaves the job pending for a later pass."""
        worker = _FakeWorker(error=WorkerBusy("J-99"))
        service, jobs = _build(import_dir, worker)
        job = _seed_upload(jobs, import_dir)
        assert await service.deliver(job) is False
        assert jobs.jobs[job.id].state == "queued"

    async def test_unreachable_worker_keeps_job_queued(self, import_dir: Path) -> None:
        """A transport failure leaves the job pending, not failed."""
        worker = _FakeWorker(error=WorkerUnavailable("ConnectError"))
        service, jobs = _build(import_dir, worker)
        job = _seed_upload(jobs, import_dir)
        assert await service.deliver(job) is False
        assert jobs.jobs[job.id].state == "queued"

    async def test_queued_job_is_delivered_once_the_worker_frees_up(self, import_dir: Path) -> None:
        """The dispatch loop retries a previously refused job."""
        worker = _FakeWorker(error=WorkerBusy("J-99"))
        service, jobs = _build(import_dir, worker)
        job = _seed_upload(jobs, import_dir)
        assert await service.dispatch_pending() == 0
        worker.error = None
        assert await service.dispatch_pending() == 1
        assert jobs.jobs[job.id].state == "running"
        assert worker.delivered == [job.display_id, job.display_id]

    async def test_permanent_rejection_fails_the_job(self, import_dir: Path) -> None:
        """A ``422`` is a payload defect, not a retryable condition."""
        worker = _FakeWorker(error=WorkerRejected(422, {"detail": "bad payload"}))
        service, jobs = _build(import_dir, worker)
        job = _seed_upload(jobs, import_dir)
        assert await service.deliver(job) is False
        assert jobs.jobs[job.id].state == "failed"

    async def test_missing_upload_fails_the_job(self, import_dir: Path) -> None:
        """A job whose file vanished cannot be delivered and fails loudly."""
        worker = _FakeWorker()
        service, jobs = _build(import_dir, worker)
        job = jobs.seed(params={"kind": "pcap-import", "filename": "gone.pcap"})
        assert await service.deliver(job) is False
        assert jobs.jobs[job.id].state == "failed"
        assert worker.delivered == []

    async def test_dispatch_stops_at_the_first_refusal(self, import_dir: Path) -> None:
        """The single-slot worker is not hammered with the whole backlog."""
        worker = _FakeWorker(error=WorkerBusy("J-99"))
        service, jobs = _build(import_dir, worker)
        _seed_upload(jobs, import_dir, filename="a.pcap")
        _seed_upload(jobs, import_dir, filename="b.pcap")
        assert await service.dispatch_pending() == 0
        assert len(worker.delivered) == 1


class TestOrphanRecovery:
    """B10 — a job never hangs forever after a worker restart."""

    async def test_orphaned_running_job_is_requeued(self, import_dir: Path) -> None:
        """An idle worker plus a running job means the job was orphaned."""
        worker = _FakeWorker(health=WorkerHealth(busy=False, state="idle", display_id=None))
        service, jobs = _build(import_dir, worker)
        job = _seed_upload(jobs, import_dir, state="running")
        assert await service.reap_orphans() == 1
        assert jobs.jobs[job.id].state == "queued"

    async def test_job_the_worker_is_actually_running_is_left_alone(self, import_dir: Path) -> None:
        """A genuinely running import is not disturbed."""
        service, jobs = _build(import_dir, _FakeWorker())
        job = _seed_upload(jobs, import_dir, state="running")
        service._worker.health_result = WorkerHealth(  # type: ignore[attr-defined]
            busy=True, state="running", display_id=job.display_id
        )
        assert await service.reap_orphans() == 0
        assert jobs.jobs[job.id].state == "running"

    async def test_freshly_delivered_job_is_protected_by_the_grace_period(self, import_dir: Path) -> None:
        """A job younger than the grace period is never called orphaned."""
        worker = _FakeWorker(health=WorkerHealth(busy=False, state="idle", display_id=None))
        service, jobs = _build(import_dir, worker, orphan_grace_s=600.0)
        job = _seed_upload(jobs, import_dir, state="running")
        assert await service.reap_orphans() == 0
        assert jobs.jobs[job.id].state == "running"

    async def test_unreachable_worker_does_not_declare_orphans(self, import_dir: Path) -> None:
        """Without a health answer nothing is concluded about the job."""
        worker = _FakeWorker(health=None)
        service, jobs = _build(import_dir, worker)
        job = _seed_upload(jobs, import_dir, state="running")
        assert await service.reap_orphans() == 0
        assert jobs.jobs[job.id].state == "running"

    async def test_repeated_orphaning_eventually_fails_the_job(self, import_dir: Path) -> None:
        """Recovery is bounded so a poisoned job cannot loop forever."""
        worker = _FakeWorker(health=WorkerHealth(busy=False, state="idle", display_id=None))
        service, jobs = _build(import_dir, worker)
        job = _seed_upload(jobs, import_dir, state="running")
        for _ in range(MAX_RECOVERY_ATTEMPTS):
            jobs.jobs[job.id] = jobs.jobs[job.id].model_copy(
                update={"state": "running", "started_at": datetime.now(timezone.utc) - timedelta(hours=1)}
            )
            await service.reap_orphans()
        jobs.jobs[job.id] = jobs.jobs[job.id].model_copy(update={"state": "running"})
        await service.reap_orphans()
        assert jobs.jobs[job.id].state == "failed"
        assert "recovery was abandoned" in (jobs.jobs[job.id].error or "")


class TestReportApplication:
    """B9 — partial reports advance a job without nulling its record."""

    async def test_progress_report_does_not_null_absent_fields(self, import_dir: Path) -> None:
        """An omitted field means "no change", never "set to null"."""
        service, jobs = _build(import_dir, _FakeWorker())
        job = _seed_upload(jobs, import_dir, state="running")
        jobs.jobs[job.id] = jobs.jobs[job.id].model_copy(update={"phase_total": 3, "phase_label": "Netcap++ liest"})
        updated = await service.apply_report(job.display_id, PcapImportReport(phase_current=2))
        assert updated is not None
        assert updated.phase_current == 2
        assert updated.phase_total == 3
        assert updated.phase_label == "Netcap++ liest"

    async def test_completion_records_result_and_deletes_the_upload(self, import_dir: Path) -> None:
        """B12: a successful import removes its now-redundant upload."""
        influx = _FakeInflux()
        service, jobs = _build(import_dir, _FakeWorker(), influx)
        job = _seed_upload(jobs, import_dir, state="running")
        report = PcapImportReport(
            state="completed",
            result={"records_processed": 12345, "points_written": 987},
        )
        updated = await service.apply_report(job.display_id, report)
        assert updated is not None and updated.state == "completed"
        assert "987" in (updated.result or "")
        assert not (import_dir / "capture.pcap").exists()
        assert influx.invalidated, "a completed import must drop the cached data extent"

    async def test_failure_archives_the_upload_for_diagnosis(self, import_dir: Path) -> None:
        """B12: a failed import keeps its file under the bounded archive."""
        service, jobs = _build(import_dir, _FakeWorker())
        job = _seed_upload(jobs, import_dir, state="running")
        updated = await service.apply_report(
            job.display_id, PcapImportReport(state="failed", error="RuntimeError: netcap died")
        )
        assert updated is not None and updated.state == "failed"
        assert updated.error == "RuntimeError: netcap died"
        assert (import_dir / ARCHIVE_DIR_NAME / "capture.pcap").is_file()

    async def test_archive_retention_is_bounded(self, import_dir: Path) -> None:
        """The archive keeps only the configured number of files."""
        service, jobs = _build(import_dir, _FakeWorker(), archive_keep=2)
        for index in range(4):
            job = _seed_upload(jobs, import_dir, state="running", filename=f"c{index}.pcap")
            await service.apply_report(job.display_id, PcapImportReport(state="failed", error="x"))
        archived = list((import_dir / ARCHIVE_DIR_NAME).iterdir())
        assert len(archived) == 2

    async def test_report_for_a_foreign_job_is_ignored(self, import_dir: Path) -> None:
        """A non-import job is never driven by the import report channel."""
        service, jobs = _build(import_dir, _FakeWorker())
        job = jobs.seed(type="backup", params={"kind": "backup"}, state="running")
        assert await service.apply_report(job.display_id, PcapImportReport(state="completed")) is None
        assert jobs.jobs[job.id].state == "running"


class TestOverlapProbe:
    """B6 — the overlap check is a bounded existence probe."""

    async def test_free_window_yields_no_conflict(self, import_dir: Path) -> None:
        """An empty window imports without objection."""
        service, _jobs = _build(import_dir, _FakeWorker(), _FakeInflux(overlapping=False))
        window = CaptureTimeRange(
            time_start=datetime(2026, 6, 1, 10, 0, tzinfo=timezone.utc),
            time_end=datetime(2026, 6, 1, 10, 15, tzinfo=timezone.utc),
            packet_count=1,
        )
        assert await service.find_overlap(window) is None

    async def test_occupied_window_names_the_conflicting_range(self, import_dir: Path) -> None:
        """A conflict carries the exact range the caller asked about."""
        influx = _FakeInflux(overlapping=True)
        service, _jobs = _build(import_dir, _FakeWorker(), influx)
        window = CaptureTimeRange(
            time_start=datetime(2026, 6, 1, 10, 0, tzinfo=timezone.utc),
            time_end=datetime(2026, 6, 1, 10, 15, tzinfo=timezone.utc),
            packet_count=1,
        )
        conflict = await service.find_overlap(window)
        assert conflict is not None
        assert conflict.time_start == window.time_start
        assert conflict.time_end == window.time_end
        assert len(influx.calls) == 1


class TestJobCreation:
    """B7 — the job row stays inside the existing CHECK vocabulary."""

    async def test_created_job_uses_ingest_type_and_kind_param(self, import_dir: Path) -> None:
        """``type`` stays ``ingest``; the kind lives in ``params``."""
        service, _jobs = _build(import_dir, _FakeWorker())
        upload = StoredUpload(
            path=import_dir / "x.pcap",
            filename="x.pcap",
            size_bytes=64,
            sha256="a" * 64,
            original_filename="kunde.pcap",
        )
        window = CaptureTimeRange(
            time_start=datetime(2026, 6, 1, 10, 0, tzinfo=timezone.utc),
            time_end=datetime(2026, 6, 1, 10, 15, tzinfo=timezone.utc),
            packet_count=2,
        )
        job = await service.create_job(upload, window, force=False)
        assert job.type == "ingest"
        assert job.params["kind"] == "pcap-import"
        assert job.params["sha256"] == "a" * 64
        assert job.idempotency_key == "a" * 64
        assert job.can_cancel is True
