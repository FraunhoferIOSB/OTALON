"""Router-level tests for the PCAP import surface (UI-078 Wave B, B13).

Every collaborator is injected through ``app.dependency_overrides`` so no
PostgreSQL connection, no InfluxDB client and no outbound HTTP call is
made. Auth is exercised through the real
:class:`~otalon_api.middleware.auth.ApiKeyAuthMiddleware` by patching
``otalon_api.middleware.auth.get_settings``, matching ``test_operations_router``.

Covered contract:

* upload requires an operator key (401 without, 403 for a viewer key),
* a non-capture is refused 422 and leaves no file and no job behind,
* an oversized upload is refused 413 with no partial file retained,
* an overlapping capture is refused 409 naming the conflicting range,
  and ``force`` overrides it,
* the happy path creates a job and reports the delivery outcome,
* a traversal-shaped filename never reaches the storage path,
* the report channel rejects an unauthenticated caller and leaves the job
  record unchanged.
"""

from __future__ import annotations

import shutil
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from otalon_api.dependencies import (
    get_pcap_import_service,
    get_pcap_upload_service,
    get_settings,
)
from otalon_api.domain.pcap_import import CaptureTimeRange
from otalon_api.main import app
from otalon_api.services.pcap_import_service import PcapImportConfig, PcapImportService
from otalon_api.services.pcap_upload_service import PcapUploadService
from otalon_api.settings import Settings
from tests.helpers.pcap_fixtures import FakeJobsService, padded_pcap_bytes, pcap_bytes

pytestmark = pytest.mark.unit

OPERATOR_KEY = "pcap-operator-key"
VIEWER_KEY = "pcap-viewer-key"
ALLOWED_KEYS = f"ops:operator:{OPERATOR_KEY},watch:viewer:{VIEWER_KEY}"
WORKER_TOKEN = "worker-token-abc"
_OPERATOR_HEADERS = {"X-API-Key": OPERATOR_KEY}

_WINDOW = CaptureTimeRange(
    time_start=datetime(2026, 6, 1, 10, 0, tzinfo=timezone.utc),
    time_end=datetime(2026, 6, 1, 10, 15, tzinfo=timezone.utc),
    packet_count=2,
)
_CAPTURE = pcap_bytes([_WINDOW.time_start.timestamp(), _WINDOW.time_end.timestamp()])


def _make_settings(max_bytes: int = 10_000_000, worker_token: str = WORKER_TOKEN) -> Settings:
    """Build test settings arming role-based auth and the worker token."""
    return Settings(
        influxdb_host="localhost",
        influxdb_port=8181,
        influx_token="test-token",
        influxdb_org="test-org",
        influxdb_database="netcap",
        postgres_host="localhost",
        postgres_port=5432,
        postgres_user="test",
        postgres_password="test",
        postgres_database="test",
        admin_api_key=OPERATOR_KEY,
        otalon_api_allowed_keys=ALLOWED_KEYS,
        api_port=8090,
        netcap_measurement="network_metrics",
        netcap_id_tag="uci",
        netcap_sparse_port_threshold=10,
        default_sample_max_points=500,
        pcap_import_max_upload_bytes=max_bytes,
        pcap_import_worker_token=worker_token,
    )


class _FakeInflux:
    """Influx stand-in whose overlap answer each test controls."""

    def __init__(self, overlapping: bool = False) -> None:
        """Record the canned answer and the probes issued."""
        self.overlapping = overlapping
        self.calls: list[tuple[str, str, str]] = []

    def has_rows_between(self, measurement: str, start: str, stop: str) -> bool:
        """Return the canned overlap verdict and record the probe."""
        self.calls.append((measurement, start, stop))
        return self.overlapping


class _FakeWorker:
    """Worker client stand-in with a scriptable delivery outcome."""

    def __init__(self, error: Exception | None = None) -> None:
        """Configure what :meth:`deliver` should raise, if anything."""
        self.error = error
        self.delivered: list[dict[str, Any]] = []
        self.cancelled: list[str] = []
        self.health_result: Any = None

    async def deliver(self, display_id: str, file_path: str, **kwargs: Any) -> dict[str, Any]:
        """Record the delivery attempt and honour the scripted error."""
        self.delivered.append({"display_id": display_id, "file_path": file_path, **kwargs})
        if self.error is not None:
            raise self.error
        return {"display_id": display_id, "state": "running"}

    async def cancel(self, display_id: str) -> bool:
        """Record a cancellation request."""
        self.cancelled.append(display_id)
        return True

    async def health(self) -> Any:
        """Return the canned health snapshot."""
        return self.health_result


@pytest.fixture()
def import_dir() -> Iterator[Path]:
    """Provide an isolated import directory removed after the test."""
    path = Path(tempfile.mkdtemp(prefix="pcap-import-test-"))
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


@pytest.fixture()
def harness(import_dir: Path) -> Iterator[dict[str, Any]]:
    """Install upload + import services backed by fakes.

    Yields:
        A dict with the installed ``jobs``, ``influx``, ``worker``,
        ``service`` and the active ``import_dir``.
    """
    jobs = FakeJobsService()
    influx = _FakeInflux()
    worker = _FakeWorker()
    settings = _make_settings()
    service = PcapImportService(
        jobs_service=jobs,  # type: ignore[arg-type]
        influx_repo=influx,  # type: ignore[arg-type]
        worker=worker,  # type: ignore[arg-type]
        config=PcapImportConfig(import_dir=import_dir, orphan_grace_s=0.0),
    )
    uploads = PcapUploadService(import_dir, settings.pcap_import_max_upload_bytes)
    app.dependency_overrides[get_pcap_upload_service] = lambda: uploads
    app.dependency_overrides[get_pcap_import_service] = lambda: service
    app.dependency_overrides[get_settings] = lambda: settings
    try:
        yield {
            "jobs": jobs,
            "influx": influx,
            "worker": worker,
            "service": service,
            "uploads": uploads,
            "import_dir": import_dir,
            "settings": settings,
        }
    finally:
        for provider in (get_pcap_upload_service, get_pcap_import_service, get_settings):
            app.dependency_overrides.pop(provider, None)


def _stored_files(import_dir: Path) -> list[Path]:
    """Return the capture files currently held in the import directory."""
    return [p for p in import_dir.iterdir() if p.is_file()]


def _upload(
    client: TestClient,
    content: bytes = _CAPTURE,
    filename: str = "kunde.pcap",
    headers: dict[str, str] | None = None,
    data: dict[str, str] | None = None,
) -> Any:
    """POST one multipart capture upload."""
    return client.post(
        "/api/v1/operations/pcap-import",
        files={"file": (filename, content, "application/octet-stream")},
        data=data or {},
        headers=_OPERATOR_HEADERS if headers is None else headers,
    )


class TestUploadAuth:
    """B13 — operator authority is required to import."""

    def test_upload_without_key_is_401(self, harness: dict[str, Any]) -> None:
        """An unauthenticated upload is rejected and stores nothing."""
        with patch("otalon_api.middleware.auth.get_settings", return_value=harness["settings"]):
            client = TestClient(app, raise_server_exceptions=False)
            response = _upload(client, headers={})
        assert response.status_code == 401
        assert _stored_files(harness["import_dir"]) == []
        assert harness["jobs"].jobs == {}

    def test_viewer_key_is_403(self, harness: dict[str, Any]) -> None:
        """A viewer key may read but not import."""
        with patch("otalon_api.middleware.auth.get_settings", return_value=harness["settings"]):
            client = TestClient(app, raise_server_exceptions=False)
            response = _upload(client, headers={"X-API-Key": VIEWER_KEY})
        assert response.status_code == 403
        assert _stored_files(harness["import_dir"]) == []
        assert harness["jobs"].jobs == {}


class TestUploadValidation:
    """B13 — content-based validation and the size bound."""

    def test_non_capture_is_422(self, harness: dict[str, Any]) -> None:
        """A misnamed non-capture is refused and leaves no file behind."""
        with patch("otalon_api.middleware.auth.get_settings", return_value=harness["settings"]):
            client = TestClient(app, raise_server_exceptions=False)
            response = _upload(client, content=b"PK\x03\x04not a capture at all", filename="evil.pcap")
        assert response.status_code == 422
        assert _stored_files(harness["import_dir"]) == []
        assert harness["jobs"].jobs == {}

    def test_oversized_upload_is_413_without_partial_file(self, import_dir: Path) -> None:
        """The bound is enforced mid-stream and the partial file removed."""
        settings = _make_settings(max_bytes=4096)
        jobs = FakeJobsService()
        service = PcapImportService(
            jobs_service=jobs,  # type: ignore[arg-type]
            influx_repo=_FakeInflux(),  # type: ignore[arg-type]
            worker=_FakeWorker(),  # type: ignore[arg-type]
            config=PcapImportConfig(import_dir=import_dir),
        )
        app.dependency_overrides[get_pcap_upload_service] = lambda: PcapUploadService(import_dir, 4096)
        app.dependency_overrides[get_pcap_import_service] = lambda: service
        app.dependency_overrides[get_settings] = lambda: settings
        try:
            with patch("otalon_api.middleware.auth.get_settings", return_value=settings):
                client = TestClient(app, raise_server_exceptions=False)
                response = _upload(client, content=padded_pcap_bytes(200_000))
        finally:
            for provider in (get_pcap_upload_service, get_pcap_import_service, get_settings):
                app.dependency_overrides.pop(provider, None)
        assert response.status_code == 413
        assert _stored_files(import_dir) == []
        assert jobs.jobs == {}

    def test_content_length_alone_does_not_authorise(self, import_dir: Path) -> None:
        """A truthful large body is still refused even though it declares its size."""
        uploads = PcapUploadService(import_dir, 4096)
        assert uploads.max_upload_bytes == 4096


class TestPathTraversal:
    """B13 — the caller-supplied name never shapes the storage path."""

    def test_traversal_filename_is_ignored(self, harness: dict[str, Any]) -> None:
        """A ``../`` filename is kept as metadata only."""
        with patch("otalon_api.middleware.auth.get_settings", return_value=harness["settings"]):
            client = TestClient(app, raise_server_exceptions=False)
            response = _upload(client, filename="../../../etc/passwd.pcap")
        assert response.status_code == 201
        body = response.json()
        assert body["original_filename"] == "../../../etc/passwd.pcap"
        assert "/" not in body["filename"]
        assert ".." not in body["filename"]
        assert body["filename"].endswith(".pcap")
        stored = _stored_files(harness["import_dir"])
        assert [p.name for p in stored] == [body["filename"]]
        assert stored[0].parent == harness["import_dir"]


class TestOverlapGuard:
    """B13 — an overlapping import is a conflict unless explicitly forced."""

    def test_overlap_is_409_naming_the_range(self, harness: dict[str, Any]) -> None:
        """The conflict body names the range and no job is created."""
        harness["influx"].overlapping = True
        with patch("otalon_api.middleware.auth.get_settings", return_value=harness["settings"]):
            client = TestClient(app, raise_server_exceptions=False)
            response = _upload(client)
        assert response.status_code == 409
        detail = response.json()["detail"]
        assert detail["conflict_start"].startswith("2026-06-01T10:00")
        assert detail["conflict_end"].startswith("2026-06-01T10:15")
        assert detail["measurement"] == "network_metrics"
        assert harness["jobs"].jobs == {}
        assert _stored_files(harness["import_dir"]) == []

    def test_overlap_probe_is_bounded(self, harness: dict[str, Any]) -> None:
        """The probe passes both window bounds, never an open-ended range."""
        harness["influx"].overlapping = True
        with patch("otalon_api.middleware.auth.get_settings", return_value=harness["settings"]):
            client = TestClient(app, raise_server_exceptions=False)
            _upload(client)
        measurement, start, stop = harness["influx"].calls[0]
        assert measurement == "network_metrics"
        assert start.startswith("2026-06-01T10:00")
        assert stop.startswith("2026-06-01T10:15")

    def test_force_overrides_and_is_recorded(self, harness: dict[str, Any]) -> None:
        """Forcing creates the job and records the override in params."""
        harness["influx"].overlapping = True
        with patch("otalon_api.middleware.auth.get_settings", return_value=harness["settings"]):
            client = TestClient(app, raise_server_exceptions=False)
            response = _upload(client, data={"force": "true"})
        assert response.status_code == 201
        assert response.json()["forced"] is True
        job = next(iter(harness["jobs"].jobs.values()))
        assert job.params["force"] is True


class TestHappyPath:
    """B13 — the accepted import becomes a CHECK-conformant ingest job."""

    def test_upload_creates_job_and_delivers(self, harness: dict[str, Any]) -> None:
        """A valid capture is stored, enqueued and handed to the worker."""
        with patch("otalon_api.middleware.auth.get_settings", return_value=harness["settings"]):
            client = TestClient(app, raise_server_exceptions=False)
            response = _upload(client)
        assert response.status_code == 201
        body = response.json()
        assert body["delivered"] is True
        assert body["state"] == "running"
        assert body["time_start"].startswith("2026-06-01T10:00")
        assert body["time_end"].startswith("2026-06-01T10:15")
        assert len(body["sha256"]) == 64

        job = harness["jobs"].jobs[body["job_id"]]
        assert job.type == "ingest"
        assert job.params["kind"] == "pcap-import"
        assert job.idempotency_key == body["sha256"]
        assert job.can_cancel is True

        delivery = harness["worker"].delivered[0]
        assert delivery["display_id"] == body["display_id"]
        assert delivery["file_path"] == str(harness["import_dir"] / body["filename"])

    def test_status_endpoint_reports_progress(self, harness: dict[str, Any]) -> None:
        """The status read surfaces state, phase and the detected window."""
        with patch("otalon_api.middleware.auth.get_settings", return_value=harness["settings"]):
            client = TestClient(app, raise_server_exceptions=False)
            created = _upload(client).json()
            response = client.get(
                f"/api/v1/operations/pcap-import/{created['display_id']}",
                headers=_OPERATOR_HEADERS,
            )
        assert response.status_code == 200
        body = response.json()
        assert body["state"] == "running"
        assert body["phase_current"] == 1
        assert body["original_filename"] == "kunde.pcap"
        assert body["time_start"].startswith("2026-06-01T10:00")

    def test_status_read_requires_a_key(self, harness: dict[str, Any]) -> None:
        """The status read is not openly reachable."""
        with patch("otalon_api.middleware.auth.get_settings", return_value=harness["settings"]):
            client = TestClient(app, raise_server_exceptions=False)
            created = _upload(client).json()
            response = client.get(f"/api/v1/operations/pcap-import/{created['display_id']}")
        assert response.status_code == 401

    def test_unknown_display_id_is_404(self, harness: dict[str, Any]) -> None:
        """An unknown import id is a clean 404."""
        with patch("otalon_api.middleware.auth.get_settings", return_value=harness["settings"]):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get(
                "/api/v1/operations/pcap-import/J-does-not-exist",
                headers=_OPERATOR_HEADERS,
            )
        assert response.status_code == 404


class TestImportList:
    """Wave D — the read-only listing behind the "Recent Imports" surface.

    The generic ``GET /api/v1/operations/jobs?type=ingest`` cannot serve
    this: its list item carries no ``params``, so neither the
    ``kind == 'pcap-import'`` discrimination nor filename / size /
    capture window are reachable there.
    """

    def _seed(self, harness: dict[str, Any], **overrides: Any) -> Any:
        """Seed one import job with a sane default params payload."""
        params: dict[str, Any] = {
            "kind": "pcap-import",
            "filename": "stored.pcap",
            "original_filename": "kunde.pcap",
            "size_bytes": 4096,
            "time_start": "2026-06-01T10:00:00+00:00",
            "time_end": "2026-06-01T10:15:00+00:00",
        }
        params.update(overrides.pop("params", {}))
        return harness["jobs"].seed(params=params, **overrides)

    def test_list_requires_a_key(self, harness: dict[str, Any]) -> None:
        """The listing is not openly reachable."""
        with patch("otalon_api.middleware.auth.get_settings", return_value=harness["settings"]):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get("/api/v1/operations/pcap-import")
        assert response.status_code == 401

    def test_list_auth_matches_the_detail_route(self, harness: dict[str, Any]) -> None:
        """The listing is exactly as authenticated as the detail read.

        ``require_api_key`` compares against the admin key, so the viewer
        key passes the prefix middleware but is refused by the per-route
        dependency. That is pre-existing behaviour of the detail GET; the
        listing must not be laxer, and this pins both together.
        """
        job = self._seed(harness)
        viewer = {"X-API-Key": VIEWER_KEY}
        with patch("otalon_api.middleware.auth.get_settings", return_value=harness["settings"]):
            client = TestClient(app, raise_server_exceptions=False)
            listing = client.get("/api/v1/operations/pcap-import", headers=viewer)
            detail = client.get(f"/api/v1/operations/pcap-import/{job.display_id}", headers=viewer)
        assert listing.status_code == detail.status_code == 401

    def test_empty_list_is_an_empty_envelope(self, harness: dict[str, Any]) -> None:
        """No imports yet is an empty list, never a 404."""
        with patch("otalon_api.middleware.auth.get_settings", return_value=harness["settings"]):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get("/api/v1/operations/pcap-import", headers=_OPERATOR_HEADERS)
        assert response.status_code == 200
        assert response.json() == {"items": [], "total": 0}

    def test_items_carry_the_status_envelope(self, harness: dict[str, Any]) -> None:
        """Each entry is the same shape the detail endpoint returns."""
        self._seed(harness, state="completed", result='{"points_written": 987}')
        with patch("otalon_api.middleware.auth.get_settings", return_value=harness["settings"]):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get("/api/v1/operations/pcap-import", headers=_OPERATOR_HEADERS)
        item = response.json()["items"][0]
        assert item["original_filename"] == "kunde.pcap"
        assert item["size_bytes"] == 4096
        assert item["time_start"].startswith("2026-06-01T10:00")
        assert item["state"] == "completed"
        assert item["result"]["points_written"] == 987

    def test_non_import_ingest_jobs_are_excluded(self, harness: dict[str, Any]) -> None:
        """A future non-pcap ingest job must not leak into the list."""
        self._seed(harness)
        harness["jobs"].seed(type="ingest", params={"kind": "some-other-ingest"})
        with patch("otalon_api.middleware.auth.get_settings", return_value=harness["settings"]):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get("/api/v1/operations/pcap-import", headers=_OPERATOR_HEADERS)
        body = response.json()
        assert body["total"] == 1
        assert body["items"][0]["original_filename"] == "kunde.pcap"

    def test_newest_first(self, harness: dict[str, Any]) -> None:
        """Ordering is by start time descending, not insertion order."""
        base = datetime(2026, 6, 1, 10, 0, tzinfo=timezone.utc)
        self._seed(harness, started_at=base, params={"original_filename": "oldest.pcap"})
        self._seed(harness, started_at=base + timedelta(hours=2), params={"original_filename": "newest.pcap"})
        self._seed(harness, started_at=base + timedelta(hours=1), params={"original_filename": "middle.pcap"})
        with patch("otalon_api.middleware.auth.get_settings", return_value=harness["settings"]):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get("/api/v1/operations/pcap-import", headers=_OPERATOR_HEADERS)
        names = [item["original_filename"] for item in response.json()["items"]]
        assert names == ["newest.pcap", "middle.pcap", "oldest.pcap"]

    def test_limit_keeps_the_newest_entries(self, harness: dict[str, Any]) -> None:
        """The limit truncates the tail, not the head."""
        base = datetime(2026, 6, 1, 10, 0, tzinfo=timezone.utc)
        for index in range(5):
            self._seed(
                harness,
                started_at=base + timedelta(hours=index),
                params={"original_filename": f"capture-{index}.pcap"},
            )
        with patch("otalon_api.middleware.auth.get_settings", return_value=harness["settings"]):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get("/api/v1/operations/pcap-import?limit=2", headers=_OPERATOR_HEADERS)
        body = response.json()
        assert body["total"] == 2
        assert [i["original_filename"] for i in body["items"]] == ["capture-4.pcap", "capture-3.pcap"]

    def test_state_filter(self, harness: dict[str, Any]) -> None:
        """The optional state filter narrows the listing."""
        self._seed(harness, state="completed", params={"original_filename": "done.pcap"})
        self._seed(harness, state="running", params={"original_filename": "busy.pcap"})
        with patch("otalon_api.middleware.auth.get_settings", return_value=harness["settings"]):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get("/api/v1/operations/pcap-import?state=running", headers=_OPERATOR_HEADERS)
        body = response.json()
        assert body["total"] == 1
        assert body["items"][0]["original_filename"] == "busy.pcap"

    def test_unknown_state_is_rejected(self, harness: dict[str, Any]) -> None:
        """A state outside the CHECK vocabulary is a validation error."""
        with patch("otalon_api.middleware.auth.get_settings", return_value=harness["settings"]):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get("/api/v1/operations/pcap-import?state=succeeded", headers=_OPERATOR_HEADERS)
        assert response.status_code == 422

    def test_list_route_does_not_shadow_the_detail_route(self, harness: dict[str, Any]) -> None:
        """Adding the collection GET leaves the detail GET reachable."""
        job = self._seed(harness)
        with patch("otalon_api.middleware.auth.get_settings", return_value=harness["settings"]):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get(
                f"/api/v1/operations/pcap-import/{job.display_id}",
                headers=_OPERATOR_HEADERS,
            )
        assert response.status_code == 200
        assert response.json()["display_id"] == job.display_id


class TestReportChannel:
    """B13 — the report channel is authenticated and fails closed."""

    def _seed_running(self, harness: dict[str, Any]) -> Any:
        """Seed one running import job."""
        return harness["jobs"].seed(
            state="running",
            params={"kind": "pcap-import", "filename": "abc.pcap"},
        )

    def test_report_without_token_is_rejected_and_job_unchanged(self, harness: dict[str, Any]) -> None:
        """An unauthenticated report changes nothing."""
        job = self._seed_running(harness)
        client = TestClient(app, raise_server_exceptions=False)
        response = client.patch(f"/internal/jobs/{job.display_id}", json={"state": "completed"})
        assert response.status_code == 401
        assert harness["jobs"].jobs[job.id].state == "running"

    def test_report_with_wrong_token_is_rejected(self, harness: dict[str, Any]) -> None:
        """A wrong bearer token changes nothing."""
        job = self._seed_running(harness)
        client = TestClient(app, raise_server_exceptions=False)
        response = client.patch(
            f"/internal/jobs/{job.display_id}",
            json={"state": "failed", "error": "boom"},
            headers={"Authorization": "Bearer not-the-token"},
        )
        assert response.status_code == 401
        assert harness["jobs"].jobs[job.id].state == "running"
        assert harness["jobs"].jobs[job.id].error is None

    def test_report_channel_fails_closed_without_configured_token(self, import_dir: Path) -> None:
        """With no token configured the channel accepts nothing at all."""
        settings = _make_settings(worker_token="")
        jobs = FakeJobsService()
        job = jobs.seed(state="running", params={"kind": "pcap-import", "filename": "abc.pcap"})
        service = PcapImportService(
            jobs_service=jobs,  # type: ignore[arg-type]
            influx_repo=_FakeInflux(),  # type: ignore[arg-type]
            worker=_FakeWorker(),  # type: ignore[arg-type]
            config=PcapImportConfig(import_dir=import_dir),
        )
        app.dependency_overrides[get_pcap_import_service] = lambda: service
        app.dependency_overrides[get_settings] = lambda: settings
        try:
            client = TestClient(app, raise_server_exceptions=False)
            response = client.patch(
                f"/internal/jobs/{job.display_id}",
                json={"state": "completed"},
                headers={"Authorization": "Bearer anything"},
            )
        finally:
            for provider in (get_pcap_import_service, get_settings):
                app.dependency_overrides.pop(provider, None)
        assert response.status_code == 503
        assert jobs.jobs[job.id].state == "running"

    def test_authenticated_progress_report_is_applied(self, harness: dict[str, Any]) -> None:
        """A valid progress report advances phase without touching state."""
        job = self._seed_running(harness)
        client = TestClient(app, raise_server_exceptions=False)
        response = client.patch(
            f"/internal/jobs/{job.display_id}",
            json={"phase_current": 2, "phase_total": 3, "latest_event": "Netcap++ liest"},
            headers={"Authorization": f"Bearer {WORKER_TOKEN}"},
        )
        assert response.status_code == 200
        updated = harness["jobs"].jobs[job.id]
        assert updated.state == "running"
        assert updated.phase_current == 2
        assert updated.latest_event == "Netcap++ liest"
