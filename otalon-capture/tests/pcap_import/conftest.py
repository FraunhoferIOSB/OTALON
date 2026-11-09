"""Shared fixtures and test doubles for the PCAP import worker tests."""

from __future__ import annotations

import threading
from typing import Any, Callable, Dict, Iterator, List, Optional, Protocol, Tuple

import pytest
from fastapi.testclient import TestClient

from pcap_import.api import create_app
from pcap_import.models import ImportPhase, ImportRequest, JobUpdate
from pcap_import.runner import ImportCancelled
from pcap_import.service import ImportService


class RecordingReporter:
    """Reporter double that records every delivered update in order."""

    def __init__(self, fail: bool = False) -> None:
        self.updates: List[Tuple[str, JobUpdate]] = []
        self._fail = fail
        self._lock = threading.Lock()

    def report(self, display_id: str, update: JobUpdate) -> bool:
        if self._fail:
            raise RuntimeError("reporter exploded")
        with self._lock:
            self.updates.append((display_id, update))
        return True

    def states(self) -> List[str]:
        """Return the state values of all updates that carried one."""

        with self._lock:
            return [update.state.value for _, update in self.updates if update.state is not None]


class ControllableRunner:
    """Runner double whose execution the test steers explicitly.

    The runner blocks on ``release`` so a test can hold the worker in the
    running state, then finishes with a configurable behaviour.
    """

    def __init__(
        self,
        behaviour: Optional[Callable[[ImportRequest], Dict[str, Any]]] = None,
        block: bool = False,
    ) -> None:
        self.release = threading.Event()
        self.started = threading.Event()
        self.calls: List[ImportRequest] = []
        self.cancel_seen = threading.Event()
        self._behaviour = behaviour
        self._block = block

    def run(
        self,
        job: ImportRequest,
        progress: Callable[[ImportPhase, str], None],
        cancel_event: threading.Event,
    ) -> Dict[str, Any]:
        self.calls.append(job)
        self.started.set()
        progress(ImportPhase.VALIDATING, "test: validating")
        if self._block:
            while not self.release.wait(0.02):
                if cancel_event.is_set():
                    self.cancel_seen.set()
                    raise _cancelled(job)
        if cancel_event.is_set():
            self.cancel_seen.set()
            raise _cancelled(job)
        if self._behaviour is not None:
            return self._behaviour(job)
        return {"records_processed": 1, "points_written": 1, "file_path": job.file_path}


def _cancelled(job: ImportRequest) -> ImportCancelled:
    """Build the cancellation error the real runner raises."""

    return ImportCancelled(f"Import of {job.file_path} was cancelled.")


@pytest.fixture
def reporter() -> RecordingReporter:
    """Return a reporter double capturing all job updates."""

    return RecordingReporter()


@pytest.fixture
def blocking_runner() -> ControllableRunner:
    """Return a runner that blocks until explicitly released."""

    return ControllableRunner(block=True)


class ClientFactory(Protocol):
    """Callable building a test client and its service from a runner double."""

    def __call__(self, runner: Any, reporter_double: Any = None) -> Tuple[TestClient, ImportService]:
        """Return a client bound to a fresh service using ``runner``."""
        ...


TEST_OPERATOR_KEY = "test-operator-key"
"""Operator credential the import-worker test client presents.

``/import`` and ``/status`` require the suite ``X-API-Key`` operator key
(audit CAP-02). These tests exercise worker behaviour, not the auth gate —
which has its own suite — so the client carries a valid key by default.
"""


@pytest.fixture
def make_client(monkeypatch: pytest.MonkeyPatch) -> Iterator[ClientFactory]:
    """Return a factory building a TestClient over a service and its runner."""

    monkeypatch.setenv("ADMIN_API_KEY", TEST_OPERATOR_KEY)
    clients: List[TestClient] = []

    def factory(runner: Any, reporter_double: Any = None) -> Tuple[TestClient, ImportService]:
        service = ImportService(runner=runner, reporter=reporter_double)
        client = TestClient(create_app(service))
        client.headers.update({"X-API-Key": TEST_OPERATOR_KEY})
        clients.append(client)
        return client, service

    yield factory

    for client in clients:
        client.close()


def make_job(display_id: str = "job-1", file_path: str = "/import/capture.pcap") -> Dict[str, Any]:
    """Build a minimal valid ``POST /import`` payload."""

    return {"display_id": display_id, "file_path": file_path}
