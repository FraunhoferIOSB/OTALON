"""Bounded report-loss reconciliation through real owner and repository SQL.

Clock, rows and HTTP are declared synthetic dependencies; no live worker or DB.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import patch

import pytest
import respx

from otalon_api.api.schemas.pcap_import import PcapImportReport
from otalon_api.services.pcap_import_service import PcapImportConfig, PcapImportService
from tests.unit.test_training_import_cancel import cancellation as _cancellation, seed
from tests.unit.test_training_worker_status import BASE, status_body

cancellation = _cancellation
pytestmark = pytest.mark.unit
DIAGNOSIS = "Cancellation needs reconciliation; worker settlement is unverified."


@pytest.mark.parametrize("state", ("completed", "failed", "cancelled"))
@respx.mock
async def test_matching_authenticated_terminal_readback_preserves_outcome(
    cancellation: dict[str, Any], state: str
) -> None:
    """Actual terminal results, including unknown counts, beat cancel intent."""
    job = seed(cancellation)
    await cancellation["owner"].cancel_job(job.display_id)
    body = status_body(state, job.display_id)
    body["result"] = {"points_written": 7, "records_processed": None}
    body["error"] = "actual worker failure" if state == "failed" else None
    route = respx.get(f"{BASE}/status").respond(200, json=body)
    await cancellation["owner"].reap_orphans()
    current = cancellation["store"].rows[job.id]
    assert current.state == state
    assert current.ended_at == datetime(2026, 6, 1, 10, 1, tzinfo=timezone.utc)
    assert json.loads(current.result)["points_written"] == 7
    assert json.loads(current.result)["records_processed"] is None
    assert route.calls[0].request.headers["X-API-Key"] == "synthetic-key"
    assert not (cancellation["root"] / job.params["filename"]).exists()
    if state != "completed":
        assert (cancellation["root"] / "failed" / job.params["filename"]).is_file()
    if state == "failed":
        assert current.error == "actual worker failure"


@pytest.mark.parametrize(
    "body",
    (
        None,
        {"state": "unknown"},
        status_body("idle", None),
        status_body("completed", "J-newer"),
        {**status_body(), "display_id": None},
        {**status_body(), "finished_at": None},
        {**status_body("running"), "finished_at": None},
        {**status_body("cancelling"), "finished_at": None},
    ),
)
@respx.mock
async def test_inconclusive_status_exhausts_three_attempts_and_restart_stays_blocked(
    cancellation: dict[str, Any], body: Any
) -> None:
    """Missing/reset/newer/active snapshots never prove stop or release input."""
    job = seed(cancellation)
    newer = seed(cancellation)
    await cancellation["owner"].cancel_job(job.display_id)
    route = respx.get(f"{BASE}/status").respond(200, json=body)
    for _ in range(3):
        await cancellation["owner"].reap_orphans()
    current = cancellation["store"].rows[job.id]
    assert route.call_count == 3
    assert current.state == "cancelling" and not current.can_retry and current.ended_at is None
    assert current.error == current.latest_event == DIAGNOSIS
    attempts = [entry for entry in current.log if entry.get("event") == "cancel-reconciliation"]
    assert [entry["attempt"] for entry in attempts] == [1, 2, 3]
    restarted = PcapImportService(
        cancellation["jobs"], cancellation["influx"], cancellation["worker"], cancellation["owner"].config
    )
    for _ in range(4):
        await restarted.reap_orphans()
        assert await restarted.dispatch_pending() == 0
    assert route.call_count == 3
    assert cancellation["store"].rows[newer.id] == newer
    assert (cancellation["root"] / job.params["filename"]).is_file()
    assert (cancellation["root"] / newer.params["filename"]).is_file()
    cancellation["worker"].deliver.assert_not_awaited()


@respx.mock
async def test_grace_uses_recent_cancel_request_not_old_job_start(cancellation: dict[str, Any]) -> None:
    """An old running job gets the full configured grace after cancellation."""
    owner = PcapImportService(
        cancellation["jobs"],
        cancellation["influx"],
        cancellation["worker"],
        PcapImportConfig(import_dir=cancellation["root"], orphan_grace_s=120),
    )
    old = datetime(2026, 1, 1, tzinfo=timezone.utc)
    now = datetime(2026, 6, 1, tzinfo=timezone.utc)
    job = seed(cancellation, started_at=old)
    route = respx.get(f"{BASE}/status").respond(200, json=status_body("idle", None))
    with patch("otalon_api.services.pcap_import_service.datetime") as clock:
        clock.now.return_value = now
        clock.fromisoformat.side_effect = datetime.fromisoformat
        await owner.cancel_job(job.display_id)
        for age in (0, 119):
            clock.now.return_value = now + timedelta(seconds=age)
            await owner.reap_orphans()
            assert route.call_count == 0
        clock.now.return_value = now + timedelta(seconds=120)
        await owner.reap_orphans()
    assert route.call_count == 1
    assert cancellation["store"].rows[job.id].state == "cancelling"


@respx.mock
async def test_explicit_same_id_retry_resets_only_bounded_episode_and_late_report_settles(
    cancellation: dict[str, Any],
) -> None:
    """Blocked retry keeps history and never cancels a newer worker identity."""
    job = seed(cancellation)
    owner = cancellation["owner"]
    await owner.cancel_job(job.display_id)
    route = respx.get(f"{BASE}/status").respond(200, json=status_body("running", "J-newer"))
    for _ in range(3):
        await owner.reap_orphans()
    history = list(cancellation["store"].rows[job.id].log)
    cancellation["worker"].cancel.return_value = False
    await owner.cancel_job(job.display_id)
    assert cancellation["worker"].cancel.call_args.args == (job.display_id,)
    for _ in range(5):
        await owner.reap_orphans()
    current = cancellation["store"].rows[job.id]
    assert route.call_count == 6 and current.error == DIAGNOSIS
    assert current.log[: len(history)] == history
    finished = await owner.apply_report(
        job.display_id, PcapImportReport(state="completed", result={"points_written": 11})
    )
    assert finished.state == "completed" and finished.error is None and finished.latest_event != DIAGNOSIS
    assert json.loads(finished.result)["points_written"] == 11
    await owner.reap_orphans()
    assert route.call_count == 6


@respx.mock
async def test_exhaustion_does_not_erase_real_error_on_settlement(cancellation: dict[str, Any]) -> None:
    """Clear only the reconciliation diagnosis, not unrelated failure evidence."""
    job = seed(cancellation, error="original real error")
    owner = cancellation["owner"]
    await owner.cancel_job(job.display_id)
    respx.get(f"{BASE}/status").respond(200, json=status_body("idle", None))
    for _ in range(3):
        await owner.reap_orphans()
    result = await owner.apply_report(job.display_id, PcapImportReport(state="cancelled"))
    assert result.state == "cancelled" and result.error == "original real error"


@pytest.mark.parametrize("code", (401, 403, 503))
@respx.mock
async def test_status_http_refusal_spends_only_three_attempts(cancellation: dict[str, Any], code: int) -> None:
    """Auth failure is unknown, never a reason for cleanup or redispatch."""
    job = seed(cancellation)
    await cancellation["owner"].cancel_job(job.display_id)
    route = respx.get(f"{BASE}/status").respond(code, json={"detail": "refused"})
    for _ in range(5):
        await cancellation["owner"].reap_orphans()
    assert route.call_count == 3
    current = cancellation["store"].rows[job.id]
    assert current.state == "cancelling" and current.error == DIAGNOSIS
    assert (cancellation["root"] / job.params["filename"]).is_file()


@respx.mock
async def test_restart_after_third_attempt_before_diagnosis_does_not_poll_again(cancellation: dict[str, Any]) -> None:
    """Attempt persistence precedes HTTP, covering a process interruption."""
    job = seed(cancellation)
    await cancellation["owner"].cancel_job(job.display_id)
    current = cancellation["store"].rows[job.id]
    cancellation["store"].rows[job.id] = current.model_copy(
        update={"log": [*current.log, *({"event": "cancel-reconciliation", "attempt": i} for i in (1, 2, 3))]}
    )
    route = respx.get(f"{BASE}/status").respond(200, json=status_body("completed", job.display_id))
    restarted = PcapImportService(
        cancellation["jobs"], cancellation["influx"], cancellation["worker"], cancellation["owner"].config
    )
    await restarted.reap_orphans()
    assert route.call_count == 0
    current = cancellation["store"].rows[job.id]
    assert current.state == "cancelling" and current.latest_event == current.error == DIAGNOSIS
