"""Producer identity and settlement contract for training import cancellation."""

from __future__ import annotations

import threading
from typing import Any, Dict, Iterator, Optional, Tuple

import pytest
from fastapi.testclient import TestClient

from pcap_import.api import create_app
from pcap_import.models import ImportPhase, ImportRequest, ImportState
from pcap_import.runner import ImportCancelled, ProgressCallback
from pcap_import.service import ImportService, NoActiveImportError, WorkerBusyError

from .conftest import TEST_OPERATOR_KEY, RecordingReporter, make_job

pytestmark = pytest.mark.unit

IDLE_TIMEOUT_S = 5.0
AUTH = {"X-API-Key": TEST_OPERATOR_KEY}


class HeldRunner:
    """Hold synthetic final writes until explicit release, even after cancel."""

    def __init__(self) -> None:
        self.started = threading.Event()
        self.release = threading.Event()
        self.cancel_event = threading.Event()
        self.calls: list[ImportRequest] = []
        self.threads: list[threading.Thread] = []
        self.writes: list[int] = []
        self.progress: Optional[ProgressCallback] = None
        self.error: Optional[Exception] = None

    def run(self, job: ImportRequest, progress: ProgressCallback, cancel_event: threading.Event) -> Dict[str, Any]:
        """Expose this generation's event and retain custody through release."""

        self.calls.append(job)
        self.threads.append(threading.current_thread())
        self.cancel_event = cancel_event
        self.progress = progress
        self.writes.append(375)
        progress(ImportPhase.READING, "synthetic: held before final write")
        self.started.set()
        self.release.wait()
        self.writes.append(1000)
        if self.error is not None:
            raise self.error
        if cancel_event.is_set():
            raise ImportCancelled("synthetic: settled after final write")
        return {
            "records_processed": 2,
            "points_written": 2,
            "file_path": job.file_path,
            "time_start": "1970-01-01T00:00:00.375000+00:00",
            "time_end": "1970-01-01T00:00:01+00:00",
        }


Harness = Tuple[TestClient, ImportService, HeldRunner, RecordingReporter]


@pytest.fixture
def held_import(monkeypatch: pytest.MonkeyPatch) -> Iterator[Harness]:
    """Use the actual app/service and always release and join every runner."""

    monkeypatch.setenv("ADMIN_API_KEY", TEST_OPERATOR_KEY)
    runner = HeldRunner()
    reporter = RecordingReporter()
    service = ImportService(runner, reporter)
    with TestClient(create_app(service)) as client:
        try:
            yield client, service, runner, reporter
        finally:
            runner.release.set()
            for thread in runner.threads:
                thread.join(timeout=IDLE_TIMEOUT_S)
                assert not thread.is_alive(), "held runner did not join"
            assert service.wait_for_idle(timeout=IDLE_TIMEOUT_S)


def _start(harness: Harness, display_id: str = "job-A") -> None:
    """Accept one synthetic job and wait for its held runner."""

    client, service, runner, _reporter = harness
    response = client.post("/import", json=make_job(display_id), headers=AUTH)
    assert response.status_code == 202
    assert response.json()["display_id"] == display_id
    assert runner.started.wait(timeout=IDLE_TIMEOUT_S)
    assert service.status.state is ImportState.RUNNING
    assert runner.writes[-1] == 375


def _release_and_join(harness: Harness) -> None:
    """Settle the actual runner thread rather than infer stop from status."""

    _client, service, runner, _reporter = harness
    runner.release.set()
    for thread in runner.threads:
        thread.join(timeout=IDLE_TIMEOUT_S)
        assert not thread.is_alive(), "held runner did not join"
    assert service.wait_for_idle(timeout=IDLE_TIMEOUT_S)


def test_mismatched_http_cancel_does_not_mutate_active_slot(held_import: Harness) -> None:
    client, service, runner, reporter = held_import
    _start(held_import)
    before = service.status
    updates = list(reporter.updates)
    event = runner.cancel_event

    response = client.post("/import/cancel", json={"display_id": "job-stale"}, headers=AUTH)

    assert response.status_code == 409
    assert response.json() == {
        "detail": {
            "message": "Expected display_id does not match the current import.",
            "running_display_id": "job-A",
        }
    }
    assert not event.is_set()
    assert runner.cancel_event is event
    assert service.status == before
    assert reporter.updates == updates
    assert service.busy
    assert runner.writes == [375]


def test_active_missing_http_identity_never_infers_current_job(held_import: Harness) -> None:
    client, service, runner, reporter = held_import
    _start(held_import)
    before = service.status
    updates = list(reporter.updates)

    response = client.post("/import/cancel", headers=AUTH)

    assert response.status_code == 409
    assert response.json() == {
        "detail": {
            "message": "Expected display_id is required for cancellation.",
            "running_display_id": "job-A",
        }
    }
    assert not runner.cancel_event.is_set()
    assert service.status == before
    assert reporter.updates == updates
    assert runner.writes == [375]


@pytest.mark.parametrize(
    "body",
    [{}, {"display_id": ""}, {"display_id": "x" * 129}, {"display_id": None}, {"display_id": 7}, []],
)
def test_malformed_expected_identity_is_422_without_mutation(held_import: Harness, body: Any) -> None:
    client, service, runner, reporter = held_import
    _start(held_import)
    before = service.status
    updates = list(reporter.updates)

    response = client.post("/import/cancel", json=body, headers=AUTH)

    assert response.status_code == 422
    assert not runner.cancel_event.is_set()
    assert service.status == before
    assert reporter.updates == updates
    assert runner.writes == [375]


def test_invalid_json_cancel_is_422_without_mutation(held_import: Harness) -> None:
    client, service, runner, reporter = held_import
    _start(held_import)
    before = service.status
    updates = list(reporter.updates)

    response = client.post("/import/cancel", content="{", headers={**AUTH, "Content-Type": "application/json"})

    assert response.status_code == 422
    assert not runner.cancel_event.is_set()
    assert service.status == before
    assert reporter.updates == updates


@pytest.mark.parametrize("display_id", ["job-A", "x" * 128])
def test_matching_repeat_holds_busy_until_real_settlement(held_import: Harness, display_id: str) -> None:
    client, service, runner, reporter = held_import
    _start(held_import, display_id)
    started_at = service.status.started_at
    assert started_at is not None
    event = runner.cancel_event

    response = client.post("/import/cancel", json={"display_id": display_id}, headers=AUTH)

    assert response.status_code == 202
    assert response.json() == {"display_id": display_id, "state": "cancelling"}
    assert event.is_set()
    cancelling = service.status
    assert cancelling.state is ImportState.CANCELLING
    assert cancelling.started_at == started_at
    assert cancelling.finished_at is None
    assert cancelling.error is None
    assert cancelling.result is None
    assert service.busy
    assert runner.threads[-1].is_alive()
    assert runner.writes == [375]
    assert reporter.states() == ["running", "cancelling"]
    assert reporter.updates[-1][0] == display_id
    assert reporter.updates[-1][1].model_dump(mode="json", exclude_none=True) == {
        "state": "cancelling",
        "latest_event": "Abbruch angefordert",
    }

    repeat = client.post("/import/cancel", json={"display_id": display_id}, headers=AUTH)

    assert repeat.status_code == 202
    assert repeat.json() == {"display_id": display_id, "state": "cancelling"}
    assert service.status == cancelling
    assert runner.cancel_event is event
    assert reporter.states() == ["running", "cancelling"]
    assert service.busy
    assert not service.wait_for_idle(timeout=0.0)
    status = client.get("/status", headers=AUTH)
    assert status.status_code == 200
    assert status.json() == cancelling.model_dump(mode="json")
    assert service.status == cancelling
    assert client.get("/health").json() == {
        "status": "ok",
        "busy": True,
        "state": "cancelling",
        "display_id": display_id,
    }
    refused = client.post("/import", json=make_job("job-next"), headers=AUTH)
    assert refused.status_code == 409
    assert refused.json()["detail"]["running_display_id"] == display_id
    assert [job.display_id for job in runner.calls] == [display_id]

    _release_and_join(held_import)

    terminal = service.status
    assert terminal.state is ImportState.CANCELLED
    assert terminal.display_id == display_id
    assert terminal.started_at == started_at
    assert terminal.finished_at is not None
    assert terminal.finished_at >= started_at
    assert terminal.latest_event == "synthetic: settled after final write"
    assert terminal.result is None
    assert terminal.error is None
    assert runner.writes == [375, 1000]
    assert not service.busy
    assert reporter.states() == ["running", "cancelling", "cancelled"]
    assert reporter.updates[-1][1].model_dump(mode="json", exclude_none=True) == {
        "state": "cancelled",
        "phase_current": 3,
        "phase_total": 3,
        "phase_label": "Abgeschlossen",
        "latest_event": "synthetic: settled after final write",
    }
    status = client.get("/status", headers=AUTH)
    assert status.status_code == 200
    assert status.json() == terminal.model_dump(mode="json")
    assert service.status == terminal
    assert client.get("/health").json() == {
        "status": "ok",
        "busy": False,
        "state": "cancelled",
        "display_id": None,
    }


def test_service_active_missing_identity_refuses_without_mutation(held_import: Harness) -> None:
    _client, service, runner, reporter = held_import
    _start(held_import)
    before = service.status
    updates = list(reporter.updates)

    with pytest.raises(RuntimeError, match="Expected display_id is required for cancellation"):
        service.cancel()

    assert not runner.cancel_event.is_set()
    assert service.status == before
    assert reporter.updates == updates


def test_service_matching_repeat_retains_slot_and_event(held_import: Harness) -> None:
    _client, service, runner, reporter = held_import
    _start(held_import)
    event = runner.cancel_event

    assert service.cancel("job-A") == "job-A"
    before = service.status
    updates = list(reporter.updates)
    assert service.cancel("job-A") == "job-A"
    assert service.status == before
    assert service.status.state is ImportState.CANCELLING
    assert service.busy
    assert runner.cancel_event is event
    assert event.is_set()
    assert reporter.updates == updates
    with pytest.raises(WorkerBusyError):
        service.submit(ImportRequest(**make_job("job-next")))
    assert [job.display_id for job in runner.calls] == ["job-A"]


def test_stale_a_cannot_cancel_newer_b_under_slot_lock(held_import: Harness) -> None:
    client, service, runner, reporter = held_import
    _start(held_import)
    old_event = runner.cancel_event
    old_progress = runner.progress
    assert old_progress is not None
    _release_and_join(held_import)
    assert service.status.state is ImportState.COMPLETED
    runner.started.clear()
    runner.release.clear()
    _start(held_import, "job-B")
    before = service.status
    updates = list(reporter.updates)
    event = runner.cancel_event

    with pytest.raises(RuntimeError, match="Expected display_id does not match the current import"):
        service.cancel("job-A")

    with service._lock:
        assert service._cancel_event is event
        assert not service._cancel_event.is_set()
        assert service._status == before
    assert not old_event.is_set()
    assert reporter.updates == updates
    response = client.post("/import/cancel", json={"display_id": "job-A"}, headers=AUTH)
    assert response.status_code == 409
    assert response.json()["detail"]["running_display_id"] == "job-B"
    old_progress(ImportPhase.WRITING, "stale A progress")
    assert service.status == before
    assert reporter.updates == updates
    assert runner.cancel_event is event
    assert not event.is_set()
    assert service.busy
    assert runner.threads[-1].is_alive()
    assert [job.display_id for job in runner.calls] == ["job-A", "job-B"]


@pytest.mark.parametrize("body", [None, {"display_id": "job-stale"}])
def test_idle_cancel_preserves_existing_refusal(held_import: Harness, body: Any) -> None:
    client, service, runner, reporter = held_import
    before = service.status

    response = client.post("/import/cancel", json=body, headers=AUTH)

    assert response.status_code == 409
    assert response.json() == {"detail": {"message": "No import is currently running."}}
    with pytest.raises(NoActiveImportError, match="No import is currently running"):
        service.cancel()
    assert service.status == before
    assert not runner.cancel_event.is_set()
    assert runner.calls == []
    assert reporter.updates == []


@pytest.mark.parametrize("headers", [{}, {"X-API-Key": "wrong-synthetic-key"}])
def test_auth_refusal_precedes_active_cancellation(held_import: Harness, headers: Dict[str, str]) -> None:
    client, service, runner, reporter = held_import
    _start(held_import)
    before = service.status
    updates = list(reporter.updates)

    response = client.post("/import/cancel", json={"display_id": "job-A"}, headers=headers)

    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid or missing API key"}
    assert client.post("/import/cancel", headers=headers).status_code == 401
    assert client.get("/status", headers=headers).status_code == 401
    assert not runner.cancel_event.is_set()
    assert service.status == before
    assert reporter.updates == updates
    assert client.get("/health").status_code == 200


def test_unconfigured_auth_refuses_without_mutation(held_import: Harness, monkeypatch: pytest.MonkeyPatch) -> None:
    client, service, runner, reporter = held_import
    _start(held_import)
    before = service.status
    updates = list(reporter.updates)
    monkeypatch.delenv("ADMIN_API_KEY", raising=False)
    monkeypatch.delenv("OTALON_API_ALLOWED_KEYS", raising=False)

    response = client.post("/import/cancel", json={"display_id": "job-A"}, headers=AUTH)

    assert response.status_code == 503
    assert response.json() == {"detail": "API key authentication unavailable"}
    assert client.post("/import/cancel", headers=AUTH).status_code == 503
    assert client.get("/status", headers=AUTH).status_code == 503
    assert not runner.cancel_event.is_set()
    assert service.status == before
    assert reporter.updates == updates
    assert client.get("/health").status_code == 200


def test_completed_result_and_status_are_not_rewritten_by_late_cancel(held_import: Harness) -> None:
    client, service, runner, reporter = held_import
    _start(held_import)
    started_at = service.status.started_at
    assert started_at is not None
    _release_and_join(held_import)
    terminal = service.status
    updates = list(reporter.updates)

    assert terminal.state is ImportState.COMPLETED
    assert terminal.started_at == started_at
    assert terminal.finished_at is not None
    assert terminal.finished_at >= started_at
    assert runner.writes == [375, 1000]
    assert terminal.result == {
        "records_processed": 2,
        "points_written": 2,
        "file_path": "/import/capture.pcap",
        "time_start": "1970-01-01T00:00:00.375000+00:00",
        "time_end": "1970-01-01T00:00:01+00:00",
    }
    assert terminal.error is None
    response = client.post("/import/cancel", json={"display_id": "job-A"}, headers=AUTH)
    assert response.status_code == 409
    assert response.json() == {"detail": {"message": "No import is currently running."}}
    assert not runner.cancel_event.is_set()
    assert service.status == terminal
    assert reporter.updates == updates
    assert reporter.states() == ["running", "completed"]
    status = client.get("/status", headers=AUTH)
    assert status.status_code == 200
    assert status.json() == terminal.model_dump(mode="json")
    assert service.status == terminal


def test_failed_outcome_and_status_are_not_rewritten_by_late_cancel(held_import: Harness) -> None:
    client, service, runner, reporter = held_import
    _start(held_import)
    started_at = service.status.started_at
    assert started_at is not None
    runner.error = ValueError("synthetic final write failure")
    _release_and_join(held_import)
    terminal = service.status
    updates = list(reporter.updates)

    assert terminal.state is ImportState.FAILED
    assert terminal.started_at == started_at
    assert terminal.finished_at is not None
    assert terminal.finished_at >= started_at
    assert terminal.result is None
    assert terminal.error == "ValueError: synthetic final write failure"
    assert runner.writes == [375, 1000]
    response = client.post("/import/cancel", json={"display_id": "job-A"}, headers=AUTH)
    assert response.status_code == 409
    assert response.json() == {"detail": {"message": "No import is currently running."}}
    assert not runner.cancel_event.is_set()
    assert service.status == terminal
    assert reporter.updates == updates
    assert reporter.states() == ["running", "failed"]
    status = client.get("/status", headers=AUTH)
    assert status.status_code == 200
    assert status.json() == terminal.model_dump(mode="json")
    assert service.status == terminal
