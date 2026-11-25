"""Constructed persisted-identity counterexamples for SUITE-070 B3b1.

The repository's SQL seam is synthetic, not evidence of live persistence.
Router, upload, import owner and record/create entry points are production code.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from otalon_api.api.schemas.pcap_import import PcapImportReport
from otalon_api.dependencies import get_pcap_import_service, get_pcap_upload_service, get_settings
from otalon_api.domain.operations import OperationsJob, OperationsJobCreate
from otalon_api.main import app
from otalon_api.repositories.operations_jobs_repo import OperationsJobsRepository
from otalon_api.services.operations_jobs_service import OperationsJobsService
from otalon_api.services.pcap_import_service import PcapImportConfig, PcapImportService
from otalon_api.services.pcap_import_worker_client import WorkerBusy, WorkerRejected, WorkerUnavailable
from otalon_api.services.pcap_upload_service import PcapUploadService, StoredUpload
from tests.helpers.pcap_fixtures import FakeJobsService, pcap_bytes
from tests.unit.test_pcap_import_router import _CAPTURE, _WINDOW, _make_settings, _upload
from tests.unit.test_pcap_import_service import _FakeInflux, _FakeWorker

pytestmark = pytest.mark.unit

_STATES = ("queued", "running", "cancelling", "completed", "failed", "cancelled", "rejected")
_FIELDS = {
    "display_id",
    "job_id",
    "state",
    "filename",
    "original_filename",
    "size_bytes",
    "sha256",
    "time_start",
    "time_end",
    "forced",
    "delivered",
}


@pytest.fixture()
def identity(tmp_path: Path) -> Iterator[dict[str, Any]]:
    """Use the real create SQL with an explicit synthetic returned-row seam."""
    jobs = FakeJobsService()
    worker = _FakeWorker()
    settings = _make_settings()
    owner = PcapImportService(jobs, _FakeInflux(), worker, PcapImportConfig(import_dir=tmp_path))  # type: ignore[arg-type]
    pg = MagicMock()

    def execute(sql: str, params: dict[str, Any]) -> list[dict[str, Any]]:
        assert "INSERT INTO operations_jobs" in sql
        assert "ON CONFLICT (idempotency_key) DO UPDATE" in sql
        assert "SET idempotency_key = EXCLUDED.idempotency_key" in sql
        key = params["idempotency_key"]
        existing = next((job for job in jobs.jobs.values() if job.idempotency_key == key), None)
        if existing is None:
            existing = jobs.seed(**{**params, "params": json.loads(params["params"])})
        return [existing.model_dump()]

    pg._execute_query.side_effect = execute
    bus = MagicMock()
    bus.publish = AsyncMock()
    records = OperationsJobsService(pg, bus)
    jobs.record_job = records.record_job  # type: ignore[method-assign]
    uploads = PcapUploadService(tmp_path, 4096)
    previous = app.dependency_overrides.copy()
    app.dependency_overrides[get_pcap_import_service] = lambda: owner
    app.dependency_overrides[get_pcap_upload_service] = lambda: uploads
    app.dependency_overrides[get_settings] = lambda: settings
    try:
        with patch("otalon_api.middleware.auth.get_settings", return_value=settings):
            yield {
                "jobs": jobs,
                "worker": worker,
                "owner": owner,
                "root": tmp_path,
                "client": TestClient(app),
                "uploads": uploads,
                "pg": pg,
            }
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(previous)


def _original(identity: dict[str, Any], state: str, force: bool = False) -> OperationsJob:
    """Seed original immutable metadata and owned synthetic bytes."""
    root: Path = identity["root"]
    (root / "original.pcap").write_bytes(_CAPTURE)
    return identity["jobs"].seed(
        state=state,
        idempotency_key=hashlib.sha256(_CAPTURE).hexdigest(),
        params={
            "kind": "pcap-import",
            "filename": "original.pcap",
            "original_filename": "first-name.pcap",
            "size_bytes": len(_CAPTURE),
            "sha256": hashlib.sha256(_CAPTURE).hexdigest(),
            "time_start": _WINDOW.time_start.isoformat(),
            "time_end": _WINDOW.time_end.isoformat(),
            "force": force,
        },
    )


@pytest.mark.parametrize("state", _STATES)
@pytest.mark.parametrize("original_force", (False, True))
def test_sha_reuse_projects_original_row_and_discards_only_redundant_file(
    identity: dict[str, Any], state: str, original_force: bool
) -> None:
    """An incoming force/name cannot change the SHA-owning row or its input."""
    job = _original(identity, state, original_force)
    response = _upload(identity["client"], filename="second-name.pcap", data={"force": str(not original_force).lower()})
    assert response.status_code == 201
    body = response.json()
    assert set(body) == _FIELDS
    assert body == {
        "display_id": job.display_id,
        "job_id": job.id,
        "state": "running" if state == "queued" else state,
        "filename": job.params["filename"],
        "original_filename": job.params["original_filename"],
        "size_bytes": job.params["size_bytes"],
        "sha256": job.params["sha256"],
        "time_start": _WINDOW.time_start.isoformat().replace("+00:00", "Z"),
        "time_end": _WINDOW.time_end.isoformat().replace("+00:00", "Z"),
        "forced": original_force,
        "delivered": state == "queued",
    }
    assert len(identity["jobs"].jobs) == 1
    assert identity["jobs"].jobs[job.id].params == job.params
    assert sorted(path.name for path in identity["root"].iterdir()) == ["original.pcap"]
    assert (identity["root"] / "original.pcap").read_bytes() == _CAPTURE
    assert identity["worker"].delivered == ([job.display_id] if state == "queued" else [])


@pytest.mark.parametrize("state", _STATES[1:])
def test_historical_reuse_without_input_is_not_failed_or_redelivered(identity: dict[str, Any], state: str) -> None:
    """Cleaned or archived historical input is not a new delivery defect."""
    job = _original(identity, state)
    (identity["root"] / "original.pcap").unlink()
    response = _upload(identity["client"], data={"force": "true"})
    assert response.status_code == 201
    assert response.json()["state"] == state
    assert response.json()["filename"] == "original.pcap"
    assert response.json()["delivered"] is False
    assert identity["jobs"].jobs[job.id].state == state
    assert identity["jobs"].jobs[job.id].error is None
    assert identity["worker"].delivered == []
    assert list(identity["root"].iterdir()) == []


def test_matching_storage_name_never_discards_original_input(identity: dict[str, Any]) -> None:
    """The defensive same-name branch must not unlink the owning file."""
    job = _original(identity, "completed")
    upload = StoredUpload(
        path=identity["root"] / "original.pcap",
        filename="original.pcap",
        size_bytes=len(_CAPTURE),
        sha256=job.params["sha256"],
        original_filename="first-name.pcap",
    )
    with patch.object(identity["uploads"], "store", AsyncMock(return_value=upload)):
        response = _upload(identity["client"])
    assert response.status_code == 201
    assert response.json()["state"] == "completed"
    assert response.json()["delivered"] is False
    assert upload.path.read_bytes() == _CAPTURE
    assert identity["worker"].delivered == []


@pytest.mark.parametrize("state", _STATES[1:])
@pytest.mark.parametrize("input_exists", (False, True))
async def test_delivery_rereads_current_owning_state(identity: dict[str, Any], state: str, input_exists: bool) -> None:
    """A stale queued snapshot is not permission to deliver or fail history."""
    queued = _original(identity, "queued")
    current = queued.model_copy(update={"state": state})
    identity["jobs"].jobs[queued.id] = current
    if not input_exists:
        (identity["root"] / "original.pcap").unlink()
    assert await identity["owner"].deliver(queued) is False
    assert identity["jobs"].jobs[queued.id] == current
    assert identity["worker"].delivered == []


@pytest.mark.parametrize("foreign", ({"type": "backup"}, {"params": {"kind": "other"}}, None))
async def test_delivery_refuses_foreign_or_absent_owning_row(identity: dict[str, Any], foreign: Any) -> None:
    """The persisted type/kind and existence are part of the delivery guard."""
    stale = _original(identity, "queued")
    if foreign is None:
        identity["jobs"].jobs.pop(stale.id)
    else:
        identity["jobs"].jobs[stale.id] = stale.model_copy(update=foreign)
    before = dict(identity["jobs"].jobs)
    assert await identity["owner"].deliver(stale) is False
    assert identity["jobs"].jobs == before
    assert identity["worker"].delivered == []
    assert (identity["root"] / "original.pcap").read_bytes() == _CAPTURE


async def test_delivery_uses_reread_owning_params_not_stale_metadata(identity: dict[str, Any]) -> None:
    """Current queued metadata, not the caller's snapshot, supplies delivery."""
    stale = _original(identity, "queued")
    current_params = {**stale.params, "original_filename": "persisted-name.pcap", "force": True}
    current = stale.model_copy(update={"params": current_params})
    identity["jobs"].jobs[stale.id] = current
    with patch.object(identity["worker"], "deliver", AsyncMock(return_value={})) as delivery:
        assert await identity["owner"].deliver(stale) is True
    delivery.assert_awaited_once_with(
        current.display_id,
        str(identity["root"] / "original.pcap"),
        time_start=_WINDOW.time_start,
        time_end=_WINDOW.time_end,
        original_filename="persisted-name.pcap",
        force=True,
    )
    assert identity["jobs"].jobs[stale.id].params == current_params


@pytest.mark.parametrize("error", (WorkerBusy("J-other"), WorkerUnavailable("synthetic transport failure")))
def test_genuine_queued_reuse_busy_or_unreachable_remains_queued(identity: dict[str, Any], error: Exception) -> None:
    """Only an actual acceptance in this request sets delivered=true."""
    job = _original(identity, "queued")
    identity["worker"].error = error
    response = _upload(identity["client"])
    assert response.status_code == 201
    assert response.json()["state"] == "queued"
    assert response.json()["delivered"] is False
    assert identity["worker"].delivered == [job.display_id]
    assert identity["jobs"].jobs[job.id].params == job.params
    assert sorted(path.name for path in identity["root"].iterdir()) == ["original.pcap"]


def test_genuine_missing_queued_input_still_fails(identity: dict[str, Any]) -> None:
    """A queued row with no original input fails rather than borrowing the duplicate."""
    job = _original(identity, "queued")
    (identity["root"] / "original.pcap").unlink()
    response = _upload(identity["client"])
    assert response.status_code == 201
    assert response.json()["state"] == "failed"
    assert response.json()["delivered"] is False
    assert identity["jobs"].jobs[job.id].error == "Upload file is missing from the import directory"
    assert identity["worker"].delivered == []
    assert list(identity["root"].iterdir()) == []


@pytest.mark.parametrize("terminal", ("completed", "failed", "cancelled"))
@pytest.mark.parametrize("reused", (False, True))
def test_terminal_report_during_acceptance_is_not_overwritten_or_projected_running(
    identity: dict[str, Any], terminal: str, reused: bool
) -> None:
    """Real report mapping/cleanup wins over the guarded post-delivery update."""
    if reused:
        _original(identity, "queued")

    async def settle(display_id: str, file_path: str, **kwargs: Any) -> dict[str, Any]:
        report = PcapImportReport(state=terminal, result={"points_written": 7}, error="synthetic outcome")
        finished = await identity["owner"].apply_report(display_id, report)
        assert finished is not None and finished.state == terminal
        return {"display_id": display_id, "state": "running"}

    with patch.object(identity["worker"], "deliver", AsyncMock(side_effect=settle)) as delivery:
        response = _upload(identity["client"])
    assert response.status_code == 201
    assert response.json()["state"] == terminal
    assert response.json()["delivered"] is True
    assert delivery.await_count == 1
    job = identity["jobs"].jobs[response.json()["job_id"]]
    assert job.state == terminal
    assert not (identity["root"] / job.params["filename"]).exists()
    if terminal == "completed":
        assert json.loads(job.result or "{}")["points_written"] == 7
        assert list(identity["root"].iterdir()) == []
    else:
        assert (identity["root"] / "failed" / job.params["filename"]).read_bytes() == _CAPTURE


def test_permanent_delivery_refusal_projects_persisted_failed_state(identity: dict[str, Any]) -> None:
    """A false delivery result must not conceal the real failed state."""
    identity["worker"].error = WorkerRejected(422, {"detail": "synthetic invalid payload"})
    response = _upload(identity["client"])
    assert response.status_code == 201
    assert response.json()["state"] == "failed"
    assert response.json()["delivered"] is False


def test_distinct_bytes_same_declared_filename_create_distinct_jobs(identity: dict[str, Any]) -> None:
    """Identity is SHA, not the filename; no timestamps are shifted."""
    second_bytes = pcap_bytes([_WINDOW.time_start.timestamp(), _WINDOW.time_end.timestamp()], payload_size=8)
    first = _upload(identity["client"], filename="same.pcap")
    second = _upload(identity["client"], filename="same.pcap", content=second_bytes)
    assert first.status_code == second.status_code == 201
    a, b = first.json(), second.json()
    assert a["job_id"] != b["job_id"]
    assert a["filename"] != b["filename"]
    assert a["sha256"] == hashlib.sha256(_CAPTURE).hexdigest()
    assert b["sha256"] == hashlib.sha256(second_bytes).hexdigest()
    assert a["time_start"] == b["time_start"]
    assert a["time_end"] == b["time_end"]
    assert (identity["root"] / a["filename"]).read_bytes() == _CAPTURE
    assert (identity["root"] / b["filename"]).read_bytes() == second_bytes


def test_create_returns_original_row_without_replacing_params() -> None:
    """Inspect actual emitted conflict SQL and actual returned-row conversion."""
    jobs = FakeJobsService()
    original = jobs.seed(state="completed", idempotency_key="a" * 64, params={"filename": "original.pcap"})
    pg = MagicMock()
    pg._execute_query.return_value = [original.model_dump()]
    result = OperationsJobsRepository(pg).create(
        OperationsJobCreate(
            type="ingest",
            title="new",
            trigger="operator",
            params={"filename": "new.pcap"},
            idempotency_key="a" * 64,
        )
    )
    sql, params = pg._execute_query.call_args.args
    conflict = sql.split("ON CONFLICT (idempotency_key) DO UPDATE", 1)[1].split("RETURNING", 1)[0]
    assert conflict.strip() == "SET idempotency_key = EXCLUDED.idempotency_key"
    assert json.loads(params["params"]) == {"filename": "new.pcap"}
    assert result == original
