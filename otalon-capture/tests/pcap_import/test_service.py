"""Tests for the single-slot behaviour of the PCAP import worker (A2/A5/A6).

Covers the three guarantees the worker must hold:

* a second push while an import runs is refused as busy,
* a failing import ends as ``failed`` and the worker accepts the next job,
* a cancelled import ends as ``cancelled`` and returns the worker to ready.
"""

from __future__ import annotations

from typing import Any, Dict

import pytest

from pcap_import.models import ImportRequest, ImportState
from pcap_import.service import ImportService, NoActiveImportError, WorkerBusyError

from .conftest import ClientFactory, ControllableRunner, RecordingReporter, make_job

pytestmark = pytest.mark.unit

IDLE_TIMEOUT_S = 5.0


def _wait_idle(service: ImportService) -> None:
    """Block until the worker finished its current job, failing on timeout."""

    assert service.wait_for_idle(timeout=IDLE_TIMEOUT_S), "worker did not return to idle"


class TestBusyRefusal:
    """A2 — exactly one import at a time, no internal queue."""

    def test_second_push_is_refused_with_409(
        self, make_client: ClientFactory, blocking_runner: ControllableRunner, reporter: RecordingReporter
    ) -> None:
        client, service = make_client(blocking_runner, reporter)

        first = client.post("/import", json=make_job("job-1"))
        assert first.status_code == 202
        assert first.json()["display_id"] == "job-1"
        assert blocking_runner.started.wait(timeout=IDLE_TIMEOUT_S)

        second = client.post("/import", json=make_job("job-2"))
        assert second.status_code == 409
        assert second.json()["detail"]["running_display_id"] == "job-1"

        blocking_runner.release.set()
        _wait_idle(service)

        assert [job.display_id for job in blocking_runner.calls] == ["job-1"]

    def test_refused_job_is_not_queued_internally(
        self, make_client: ClientFactory, blocking_runner: ControllableRunner, reporter: RecordingReporter
    ) -> None:
        client, service = make_client(blocking_runner, reporter)

        client.post("/import", json=make_job("job-1"))
        assert blocking_runner.started.wait(timeout=IDLE_TIMEOUT_S)
        client.post("/import", json=make_job("job-2"))

        blocking_runner.release.set()
        _wait_idle(service)

        assert service.status.state is ImportState.COMPLETED
        assert service.status.display_id == "job-1"
        assert len(blocking_runner.calls) == 1

    def test_health_reports_busy_then_ready(
        self, make_client: ClientFactory, blocking_runner: ControllableRunner, reporter: RecordingReporter
    ) -> None:
        client, service = make_client(blocking_runner, reporter)

        assert client.get("/health").json() == {
            "status": "ok",
            "busy": False,
            "state": "idle",
            "display_id": None,
        }

        client.post("/import", json=make_job("job-1"))
        assert blocking_runner.started.wait(timeout=IDLE_TIMEOUT_S)
        busy = client.get("/health").json()
        assert busy["busy"] is True
        assert busy["state"] == "running"
        assert busy["display_id"] == "job-1"

        blocking_runner.release.set()
        _wait_idle(service)
        assert client.get("/health").json()["busy"] is False


class TestFailureIsolation:
    """A5 — a failing import must not kill the worker."""

    def test_failed_import_reports_failed_and_worker_accepts_next(
        self, make_client: ClientFactory, reporter: RecordingReporter
    ) -> None:
        def explode(_job: ImportRequest) -> Dict[str, Any]:
            raise FileNotFoundError("Capture file not found: /import/missing.pcap")

        runner = ControllableRunner(behaviour=explode)
        client, service = make_client(runner, reporter)

        assert client.post("/import", json=make_job("job-bad")).status_code == 202
        _wait_idle(service)

        failed = service.status
        assert failed.state is ImportState.FAILED
        assert failed.error is not None
        assert "FileNotFoundError" in failed.error
        assert "missing.pcap" in failed.error

        runner._behaviour = None
        assert client.post("/import", json=make_job("job-good")).status_code == 202
        _wait_idle(service)
        assert service.status.state is ImportState.COMPLETED
        assert service.status.display_id == "job-good"

    def test_failure_is_reported_as_terminal_state(
        self, make_client: ClientFactory, reporter: RecordingReporter
    ) -> None:
        def explode(_job: ImportRequest) -> Dict[str, Any]:
            raise RuntimeError("influx unavailable")

        client, service = make_client(ControllableRunner(behaviour=explode), reporter)
        client.post("/import", json=make_job("job-bad"))
        _wait_idle(service)

        assert reporter.states()[-1] == ImportState.FAILED.value
        _, terminal = reporter.updates[-1]
        assert terminal.error is not None
        assert "influx unavailable" in terminal.error

    def test_reporting_outage_does_not_break_the_import(self, make_client: ClientFactory) -> None:
        client, service = make_client(ControllableRunner(), RecordingReporter(fail=True))

        assert client.post("/import", json=make_job("job-1")).status_code == 202
        _wait_idle(service)

        assert service.status.state is ImportState.COMPLETED
        assert client.get("/health").json()["busy"] is False


class TestCancellation:
    """A6 — a running import is cancellable and frees the worker."""

    def test_cancel_returns_worker_to_ready(
        self, make_client: ClientFactory, blocking_runner: ControllableRunner, reporter: RecordingReporter
    ) -> None:
        client, service = make_client(blocking_runner, reporter)

        client.post("/import", json=make_job("job-1"))
        assert blocking_runner.started.wait(timeout=IDLE_TIMEOUT_S)

        cancelled = client.post("/import/cancel")
        assert cancelled.status_code == 202
        assert cancelled.json()["display_id"] == "job-1"

        _wait_idle(service)
        assert blocking_runner.cancel_seen.is_set()
        assert service.status.state is ImportState.CANCELLED
        assert client.get("/health").json()["busy"] is False

        assert client.post("/import", json=make_job("job-2")).status_code == 202
        blocking_runner.release.set()
        _wait_idle(service)

    def test_cancel_while_idle_is_refused(self, make_client: ClientFactory, reporter: RecordingReporter) -> None:
        client, _service = make_client(ControllableRunner(), reporter)

        response = client.post("/import/cancel")
        assert response.status_code == 409
        assert response.json()["detail"]["message"] == "No import is currently running."

    def test_cancel_reaches_a_terminal_state(
        self, make_client: ClientFactory, blocking_runner: ControllableRunner, reporter: RecordingReporter
    ) -> None:
        client, service = make_client(blocking_runner, reporter)
        client.post("/import", json=make_job("job-1"))
        assert blocking_runner.started.wait(timeout=IDLE_TIMEOUT_S)
        client.post("/import/cancel")
        _wait_idle(service)

        assert reporter.states()[-1] == ImportState.CANCELLED.value
        assert service.status.finished_at is not None


class TestServiceApi:
    """Direct service-level assertions independent of the HTTP layer."""

    def test_submit_raises_worker_busy(self, blocking_runner: ControllableRunner) -> None:
        service = ImportService(runner=blocking_runner)
        service.submit(ImportRequest(display_id="job-1", file_path="/import/a.pcap"))
        assert blocking_runner.started.wait(timeout=IDLE_TIMEOUT_S)

        with pytest.raises(WorkerBusyError) as excinfo:
            service.submit(ImportRequest(display_id="job-2", file_path="/import/b.pcap"))
        assert excinfo.value.display_id == "job-1"

        blocking_runner.release.set()
        _wait_idle(service)

    def test_cancel_without_job_raises(self) -> None:
        service = ImportService(runner=ControllableRunner())
        with pytest.raises(NoActiveImportError):
            service.cancel()

    def test_completed_status_carries_result(self, make_client: ClientFactory, reporter: RecordingReporter) -> None:
        def succeed(job: ImportRequest) -> Dict[str, Any]:
            return {
                "records_processed": 7,
                "points_written": 5,
                "file_path": job.file_path,
            }

        client, service = make_client(ControllableRunner(behaviour=succeed), reporter)
        client.post("/import", json=make_job("job-1", "/import/x.pcap"))
        _wait_idle(service)

        status = client.get("/status").json()
        assert status["state"] == "completed"
        assert status["result"] == {
            "records_processed": 7,
            "points_written": 5,
            "file_path": "/import/x.pcap",
        }
