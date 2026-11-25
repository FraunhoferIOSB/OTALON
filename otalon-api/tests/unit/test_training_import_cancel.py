"""B3b2 cancellation counterexamples with production routes/service/SQL.

The PostgreSQL returned-row seam, event bus, audit sink and HTTP transport are
synthetic unit dependencies, not live persistence or HTTPS acceptance.
"""

from __future__ import annotations

import asyncio
import json
import threading
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from otalon_api.api.schemas.pcap_import import PcapImportReport
from otalon_api.dependencies import get_operations_jobs_service, get_pcap_import_service, get_settings
from otalon_api.domain.operations import OperationsJob
from otalon_api.main import app
from otalon_api.services.operations_jobs_service import OperationsJobsService
from otalon_api.services.pcap_import_service import PcapImportConfig, PcapImportService
from otalon_api.services.pcap_import_worker_client import PcapImportWorkerClient, WorkerUnavailable
from tests.helpers.pcap_fixtures import FakeJobsService, pcap_bytes
from tests.unit.test_pcap_import_router import OPERATOR_KEY, VIEWER_KEY, WORKER_TOKEN, _make_settings

pytestmark = pytest.mark.unit


class RowStore:
    """Execute the production repository's emitted guards on synthetic rows."""

    def __init__(self) -> None:
        self.seed_store = FakeJobsService()
        self.rows = self.seed_store.jobs
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.lock = threading.Lock()

    def execute(self, sql: str, params: dict[str, Any]) -> list[dict[str, Any]]:
        """Reject unknown SQL and respect actual WHERE state/cancel guards."""
        with self.lock:
            self.calls.append((sql, dict(params)))
            if "SELECT * FROM operations_jobs" in sql:
                rows = list(self.rows.values())
                if "id" in params:
                    rows = [row for row in rows if row.id == params["id"]]
                if "display_id" in params:
                    rows = [row for row in rows if row.display_id == params["display_id"]]
                for field in ("state", "type", "actor"):
                    if field in params:
                        rows = [row for row in rows if getattr(row, field) == params[field]]
                if "kind" in params:
                    assert "params->>'kind' = %(kind)s" in sql
                    rows = [row for row in rows if row.params.get("kind") == params["kind"]]
                rows.sort(key=lambda row: row.started_at, reverse=True)
                return [row.model_dump() for row in rows[: params.get("limit", 1000)]]
            assert "UPDATE operations_jobs" in sql and "RETURNING *" in sql
            row = self.rows.get(params["id"])
            if row is None:
                return []
            where = sql.split("WHERE", 1)[1]
            if "allowed" in params:
                assert "state = ANY(%(allowed)s)" in where
                allowed = set(params["allowed"])
            else:
                allowed = {state for state in ("queued", "running", "cancelling") if f"'{state}'" in where}
            if row.state not in allowed or ("can_cancel = true" in where and not row.can_cancel):
                return []
            data = {key: value for key, value in params.items() if key not in {"id", "allowed", "log_append"}}
            if "state" not in data and "allowed" not in params:
                data["state"] = next(
                    state
                    for state in ("completed", "failed", "cancelled", "cancelling")
                    if f"state = '{state}'" in sql.split("WHERE", 1)[0]
                )
                if data["state"] != "cancelling":
                    data.update(
                        ended_at=row.ended_at or datetime.now(timezone.utc),
                        can_cancel=False,
                        can_retry=data["state"] != "completed",
                    )
                if "COALESCE(%(result)s, result)" in sql and data.get("result") is None:
                    data.pop("result", None)
                if "COALESCE(%(error)s, error)" in sql and data.get("error") is None:
                    data.pop("error", None)
            if params.get("log_append") is not None:
                entries = json.loads(params["log_append"])
                data["log"] = [*row.log, *(entries if isinstance(entries, list) else [entries])]
            updated = OperationsJob.model_validate({**row.model_dump(), **data})
            self.rows[row.id] = updated
            return [updated.model_dump()]


@pytest.fixture()
def cancellation(tmp_path: Path) -> Iterator[dict[str, Any]]:
    """Inject the real owner/facade/repository over declared unit seams."""
    store = RowStore()
    pg = MagicMock()
    pg._execute_query.side_effect = store.execute
    bus = MagicMock()
    bus.publish = AsyncMock()
    jobs = OperationsJobsService(pg, bus)
    jobs._audit.append = MagicMock()
    influx = MagicMock()
    worker = PcapImportWorkerClient("http://worker.invalid", timeout=1.0, api_key="synthetic-key")
    worker.deliver = AsyncMock(return_value={})  # type: ignore[method-assign]
    worker.cancel = AsyncMock(return_value=True)  # type: ignore[method-assign]
    worker.health = AsyncMock(return_value=None)  # type: ignore[method-assign]
    owner = PcapImportService(jobs, influx, worker, PcapImportConfig(import_dir=tmp_path, orphan_grace_s=0))
    settings = _make_settings()
    previous = app.dependency_overrides.copy()
    app.dependency_overrides[get_operations_jobs_service] = lambda: jobs
    app.dependency_overrides[get_pcap_import_service] = lambda: owner
    app.dependency_overrides[get_settings] = lambda: settings
    try:
        with (
            patch("otalon_api.middleware.auth.get_settings", return_value=settings),
            patch("otalon_api.api.v1.operations.get_pcap_import_service", return_value=owner) as resolve,
        ):
            yield dict(
                store=store,
                jobs=jobs,
                owner=owner,
                worker=worker,
                root=tmp_path,
                influx=influx,
                client=TestClient(app),
                resolve=resolve,
            )
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(previous)


def seed(cancellation: dict[str, Any], state: str = "running", **overrides: Any) -> OperationsJob:
    """Create only owned synthetic bytes, with a distinct path per identity."""
    store: RowStore = cancellation["store"]
    job = store.seed_store.seed(state=state, **overrides)
    name = f"{job.display_id}.pcap"
    (cancellation["root"] / name).write_bytes(pcap_bytes([1700000000]))
    job = job.model_copy(update={"params": {**job.params, "filename": name}})
    store.rows[job.id] = job
    return job


def cancel_url(job: OperationsJob, generic: bool) -> str:
    """Return the existing trigger's exact URL."""
    segment = f"jobs/{job.id}" if generic else f"pcap-import/{job.display_id}"
    return f"/api/v1/operations/{segment}/cancel"


@pytest.mark.parametrize("generic", (False, True))
@pytest.mark.parametrize("key,code", ((None, 401), ("wrong", 401), (VIEWER_KEY, 403), (OPERATOR_KEY, 200)))
def test_both_cancel_routes_auth_and_actual_cooperative_state(
    cancellation: dict[str, Any], generic: bool, key: str | None, code: int
) -> None:
    """Generic cancel must not expose false terminal settlement to the UI."""
    job = seed(cancellation)
    response = cancellation["client"].post(cancel_url(job, generic), headers={"X-API-Key": key} if key else {})
    assert response.status_code == code
    current = cancellation["store"].rows[job.id]
    assert current.state == ("cancelling" if code == 200 else "running")
    assert current.ended_at is None
    assert (cancellation["root"] / job.params["filename"]).is_file()
    if code == 200:
        body = response.json()["job"] if generic else response.json()
        assert body["state"] == current.state
        assert current.can_retry is False
        cancellation["worker"].cancel.assert_awaited_once_with(job.display_id)
        assert cancellation["jobs"]._audit.append.call_count == 1
    else:
        cancellation["worker"].cancel.assert_not_awaited()


@pytest.mark.parametrize("generic", (False, True))
def test_repeat_cancel_is_nonterminal_and_preserves_input(cancellation: dict[str, Any], generic: bool) -> None:
    """A repeated action is not a second immediate-cancel transition."""
    job = seed(cancellation)
    for _ in range(3):
        response = cancellation["client"].post(cancel_url(job, generic), headers={"X-API-Key": OPERATOR_KEY})
        assert response.status_code == 200
        assert cancellation["store"].rows[job.id].state == "cancelling"
    assert cancellation["worker"].cancel.await_count == 1
    assert (cancellation["root"] / job.params["filename"]).is_file()


@pytest.mark.parametrize("outcome", (True, False, WorkerUnavailable("synthetic outage")))
async def test_cancel_persists_before_http_and_terminal_callback_wins(
    cancellation: dict[str, Any], outcome: bool | Exception
) -> None:
    """Synchronous reporting must never wait on the transport lock."""
    job = seed(cancellation)

    async def stop(display_id: str) -> bool:
        current = cancellation["store"].rows[job.id]
        assert current.state == "cancelling" and not current.can_retry
        assert any(entry.get("event") == "cancel-request" for entry in current.log)
        await cancellation["owner"].apply_report(
            display_id, PcapImportReport(state="completed", result={"points_written": 9})
        )
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    cancellation["worker"].cancel.side_effect = stop
    result = await cancellation["owner"].cancel_job(job.display_id)
    assert result.state == "completed"
    assert json.loads(result.result)["points_written"] == 9
    assert not (cancellation["root"] / job.params["filename"]).exists()


@pytest.mark.parametrize("outcome", (False, WorkerUnavailable("synthetic outage")))
async def test_false_or_unavailable_cancel_retains_barrier_and_evidence(
    cancellation: dict[str, Any], outcome: bool | Exception
) -> None:
    """No worker acceptance is stop proof, and failure evidence is row-local."""
    job = seed(cancellation)
    newer = seed(cancellation)
    if isinstance(outcome, Exception):
        cancellation["worker"].cancel.side_effect = outcome
    else:
        cancellation["worker"].cancel.return_value = outcome
    result = await cancellation["owner"].cancel_job(job.display_id)
    assert result.state == "cancelling" and not result.can_retry
    assert any(entry.get("event") == "cancel-delivery" and entry.get("accepted") is False for entry in result.log)
    assert cancellation["store"].rows[newer.id] == newer
    assert (cancellation["root"] / newer.params["filename"]).is_file()


@respx.mock
async def test_stale_a_cancel_cannot_stop_b_or_cleanup_either_input(cancellation: dict[str, Any]) -> None:
    """Real API client preserves the producer's exact-ID 409 refusal."""
    a = seed(cancellation)
    b = seed(cancellation)
    worker = PcapImportWorkerClient("http://worker.invalid", api_key="synthetic-key")
    owner = PcapImportService(cancellation["jobs"], cancellation["influx"], worker, cancellation["owner"].config)
    stopped = False

    def locked_slot(request: httpx.Request) -> httpx.Response:
        nonlocal stopped
        expected = json.loads(request.content)["display_id"]
        if expected != b.display_id:
            return httpx.Response(409, json={"detail": {"running_display_id": b.display_id}})
        stopped = True
        return httpx.Response(202, json={"display_id": b.display_id, "state": "cancelling"})

    route = respx.post("http://worker.invalid/import/cancel").mock(side_effect=locked_slot)
    result = await owner.cancel_job(a.display_id)
    assert result.state == "cancelling" and result.ended_at is None
    assert stopped is False and route.call_count == 1
    assert cancellation["store"].rows[b.id] == b
    for job in (a, b):
        assert (cancellation["root"] / job.params["filename"]).is_file()
    assert any(entry.get("event") == "cancel-delivery" and entry.get("accepted") is False for entry in result.log)


@pytest.mark.parametrize("generic", (False, True))
def test_noncancellable_job_remains_noop(cancellation: dict[str, Any], generic: bool) -> None:
    """Existing can-cancel refusal is retained on both triggers."""
    job = seed(cancellation, can_cancel=False)
    response = cancellation["client"].post(cancel_url(job, generic), headers={"X-API-Key": OPERATOR_KEY})
    assert response.status_code == 200
    assert cancellation["store"].rows[job.id] == job
    cancellation["worker"].cancel.assert_not_awaited()


async def test_shared_lock_serializes_queued_dispatch_and_cancel(cancellation: dict[str, Any]) -> None:
    """Cancel waits for in-flight delivery, then rereads the running owner."""
    job = seed(cancellation, "queued")
    entered, release = asyncio.Event(), asyncio.Event()

    async def deliver(*args: Any, **kwargs: Any) -> dict[str, Any]:
        entered.set()
        await release.wait()
        return {}

    cancellation["worker"].deliver.side_effect = deliver
    dispatch = asyncio.create_task(cancellation["owner"].dispatch_pending())
    await entered.wait()
    stop = asyncio.create_task(cancellation["owner"].cancel_job(job.display_id))
    await asyncio.sleep(0)
    try:
        assert not stop.done()
    finally:
        release.set()
        await dispatch
        result = await stop
    assert result.state == "cancelling"
    cancellation["worker"].cancel.assert_awaited_once_with(job.display_id)


async def test_immediate_delivery_uses_same_lock_without_recursive_dispatch(cancellation: dict[str, Any]) -> None:
    """Immediate and background delivery cannot both submit one queued owner."""
    job = seed(cancellation, "queued")
    entered, release = asyncio.Event(), asyncio.Event()

    async def deliver(*args: Any, **kwargs: Any) -> dict[str, Any]:
        entered.set()
        await release.wait()
        return {}

    cancellation["worker"].deliver.side_effect = deliver
    immediate = asyncio.create_task(cancellation["owner"].deliver(job))
    await entered.wait()
    queued = asyncio.create_task(cancellation["owner"].dispatch_pending())
    await asyncio.sleep(0)
    try:
        assert cancellation["worker"].deliver.await_count == 1
    finally:
        release.set()
        await asyncio.gather(immediate, queued)
    assert cancellation["worker"].deliver.await_count == 1


async def test_queued_cancel_wins_and_stale_delivery_cannot_clean_newer(cancellation: dict[str, Any]) -> None:
    """Queued-only cancellation cleans only its successful guarded transition."""
    job = seed(cancellation, "queued")
    newer = seed(cancellation, "queued")
    result = await cancellation["owner"].cancel_job(job.display_id)
    assert result.state == "cancelled" and result.ended_at is not None
    assert not (cancellation["root"] / job.params["filename"]).exists()
    assert (cancellation["root"] / "failed" / job.params["filename"]).is_file()
    assert await cancellation["owner"].deliver(job) is False
    assert cancellation["store"].rows[newer.id] == newer
    cancellation["worker"].cancel.assert_not_awaited()


@pytest.mark.parametrize("state", ("completed", "failed", "cancelled", "rejected"))
@pytest.mark.parametrize("generic", (False, True))
def test_terminal_cancel_is_unchanged_noop(cancellation: dict[str, Any], state: str, generic: bool) -> None:
    """No-op responses keep original result and do not initialize the worker."""
    job = seed(cancellation, state, result='{"points_written":7}')
    response = cancellation["client"].post(cancel_url(job, generic), headers={"X-API-Key": OPERATOR_KEY})
    assert response.status_code == 200
    assert cancellation["store"].rows[job.id] == job
    cancellation["worker"].cancel.assert_not_awaited()


@pytest.mark.parametrize("overrides", ({"type": "backup"}, {"params": {"kind": "other"}}))
def test_generic_other_kinds_keep_existing_cancel_audit_without_owner(
    cancellation: dict[str, Any], overrides: dict[str, Any]
) -> None:
    """Unrelated jobs must not initialize capture credentials or runtime."""
    job = seed(cancellation, **overrides)
    cancellation["resolve"].side_effect = AssertionError("unrelated job resolved import owner")
    response = cancellation["client"].post(cancel_url(job, True), headers={"X-API-Key": OPERATOR_KEY})
    assert response.status_code == 200
    assert response.json()["job"]["state"] == ("cancelling" if job.type == "backup" else "cancelled")
    assert cancellation["jobs"]._audit.append.call_count == 1


@pytest.mark.parametrize("generic", (False, True))
def test_missing_cancel_is_404(cancellation: dict[str, Any], generic: bool) -> None:
    """Both existing routes retain their missing-owner response."""
    job = seed(cancellation)
    cancellation["store"].rows.clear()
    response = cancellation["client"].post(cancel_url(job, generic), headers={"X-API-Key": OPERATOR_KEY})
    assert response.status_code == 404


@pytest.mark.parametrize("token,code", ((None, 401), ("wrong", 401), (WORKER_TOKEN, 200)))
def test_actual_cancelling_report_and_late_running_guard(
    cancellation: dict[str, Any], token: str | None, code: int
) -> None:
    """Producer JobUpdate cancelling is additive; delayed running cannot regress it."""
    job = seed(cancellation)
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    response = cancellation["client"].patch(
        f"/internal/jobs/{job.display_id}", json={"state": "cancelling"}, headers=headers
    )
    assert response.status_code == code
    if code == 200:
        late = cancellation["client"].patch(
            f"/internal/jobs/{job.display_id}",
            json={"state": "running", "phase_current": 2},
            headers=headers,
        )
        assert late.status_code == 200
        assert cancellation["store"].rows[job.id].state == "cancelling"
    else:
        assert cancellation["store"].rows[job.id] == job


@pytest.mark.parametrize("terminal", ("completed", "failed", "cancelled"))
async def test_late_reports_never_revive_terminal_or_cleanup_new_input(
    cancellation: dict[str, Any], terminal: str
) -> None:
    """Only an actual terminal write owns cleanup; duplicate reports are no-op."""
    job = seed(cancellation, "cancelling")
    owner = cancellation["owner"]
    settled = await owner.apply_report(
        job.display_id, PcapImportReport(state=terminal, result={"points_written": 4}, error="real failure")
    )
    assert settled.state == terminal
    newer = seed(cancellation)
    for report in (
        PcapImportReport(state="running"),
        PcapImportReport(state="cancelling"),
        PcapImportReport(phase_current=1),
        PcapImportReport(state="completed", result={"points_written": 0}),
    ):
        assert await owner.apply_report(job.display_id, report) == settled
    assert cancellation["store"].rows[newer.id] == newer
    assert (cancellation["root"] / newer.params["filename"]).is_file()
