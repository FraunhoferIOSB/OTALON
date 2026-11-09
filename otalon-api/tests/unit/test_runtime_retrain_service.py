"""Unit tests for :class:`RuntimeRetrainService`.

Covers window validation, atomic DB-backed single-flight (audit B-01),
bounds snapshot ORDERING (only after a successful reservation), status
mapping of all five job states, the reaper, and the guarantee that the
runtime path performs NO env/compose/docker calls (audit F7/F8).
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any, Coroutine, TypeVar

import pytest

from otalon_api.domain.operations import OperationsJob
from otalon_api.services.runtime_retrain_service import (
    RuntimeRetrainBusy,
    RuntimeRetrainCooldown,
    RuntimeRetrainService,
    RuntimeRetrainValidationError,
    validate_window,
)
from otalon_api.settings import Settings

_T = TypeVar("_T")

_NON_TERMINAL = {"queued", "running", "publishing"}


def _run(coro: Coroutine[Any, Any, _T]) -> _T:
    """Run an async coroutine from a synchronous test."""
    return asyncio.run(coro)


class _FakePostgresRepo:
    """In-memory stand-in modelling the atomic single-flight semantics.

    Also raises loudly if any env/compose/docker attribute is accessed, so
    a test proves the runtime path never touches those collaborators.
    """

    def __init__(self) -> None:
        self.rows: list[dict] = []
        self.notifies: list[str] = []
        self.snapshot_calls: list[tuple[str, str]] = []
        self.forbidden_calls: list[str] = []
        self.reserved_operation_ids: list[int | None] = []
        self.closed = False

    # -- forbidden collaborators (F8): any access is a failure ------------
    def update_training_keys(self, *a: Any, **k: Any) -> None:
        self.forbidden_calls.append("update_training_keys")
        raise AssertionError("env/compose mutation is forbidden on the runtime path")

    def run_action(self, *a: Any, **k: Any) -> None:
        self.forbidden_calls.append("run_action")
        raise AssertionError("docker compose recreate is forbidden on the runtime path")

    # -- bounds snapshot --------------------------------------------------
    def snapshot_bounds_to_history(self, module: str, reason: str) -> int:
        self.snapshot_calls.append((module, reason))
        return 3

    # -- generic SQL emulation -------------------------------------------
    def _has_non_terminal(self) -> bool:
        return any(r["state"] in _NON_TERMINAL for r in self.rows)

    def _execute_query(self, sql: str, params: dict | None = None) -> list[dict]:
        if "finished_at" in sql and "terminal" not in sql:
            terminal = [r for r in self.rows if r.get("state") in {"succeeded", "failed"} and r.get("finished_at")]
            terminal.sort(key=lambda row: row["finished_at"], reverse=True)
            return [{"finished_at": terminal[0]["finished_at"]}] if terminal else []
        if "ORDER BY requested_at DESC" in sql:
            if self.rows:
                return [dict(self.rows[-1])]
            return []
        return []

    def _execute_update(self, sql: str, params: dict | None = None) -> int:
        params = params or {}
        if "pg_notify" in sql:
            self.notifies.append(str(params.get("payload")))
            return 0
        if "CREATE TABLE" in sql or "CREATE INDEX" in sql:
            return 0
        if "INSERT INTO retrain_jobs" in sql and "WHERE NOT EXISTS" in sql:
            # Atomic single-flight: only insert when no non-terminal row.
            if self._has_non_terminal():
                return 0
            self.reserved_operation_ids.append(params.get("operations_job_id"))
            self.rows.append(
                {
                    "job_ref": params["job_ref"],
                    "scope": params["scope"],
                    "state": "queued",
                    "window_start": params["window_start"],
                    "window_stop": params["window_stop"],
                    "mitre_file": params.get("mitre_file"),
                    "requested_by": params.get("requested_by"),
                    "requested_at": params["requested_at"],
                    "started_at": None,
                    "finished_at": None,
                    "detail": params["detail"],
                    "error": None,
                    "history_snapshot_rows": params.get("history_snapshot_rows", 0),
                    "operations_job_id": params.get("operations_job_id"),
                    "heartbeat_at": None,
                }
            )
            return 1
        if "SET history_snapshot_rows" in sql:
            for r in self.rows:
                if r["job_ref"] == params["job_ref"]:
                    r["history_snapshot_rows"] = params["rows"]
            return 1
        if "WHERE job_ref" in sql and "state = 'queued'" in sql and "finished_at" in sql:
            for row in self.rows:
                if row["job_ref"] == params["job_ref"] and row["state"] == "queued":
                    row["state"] = "rejected" if "state = 'rejected'" in sql else "failed"
                    row["worker_id"] = None
                    row["error"] = params.get("error")
                    return 1
            return 0
        if "UPDATE retrain_jobs" in sql and "SET state = 'failed'" in sql:
            cutoff = params["cutoff"]
            reaped = 0
            for r in self.rows:
                age = r.get("heartbeat_at") or r["requested_at"]
                if r["state"] in {"queued", "running", "publishing"} and age < cutoff:
                    hb = r.get("heartbeat_at")
                    if hb is None or hb < cutoff:
                        r["state"] = "failed"
                        r["worker_id"] = None
                        r["error"] = "heartbeat timeout: worker appears dead"
                        reaped += 1
            return reaped
        return 0


class _FakeOperationsRepo:
    """Capture canonical projections without a database connection."""

    def __init__(self) -> None:
        self.created: list[Any] = []
        self.failed: list[tuple[int, str]] = []

    def create(self, payload: Any) -> OperationsJob:
        self.created.append(payload)
        return OperationsJob(
            id=len(self.created),
            display_id=f"J-{len(self.created)}",
            type=payload.type,
            title=payload.title,
            trigger=payload.trigger,
            state="queued",
            actor=payload.actor,
            started_at=datetime.now(tz=timezone.utc),
            params=payload.params,
        )

    def fail(self, job_id: int, error: str) -> None:
        self.failed.append((job_id, error))


@pytest.fixture()
def repo() -> _FakePostgresRepo:
    return _FakePostgresRepo()


@pytest.fixture()
def service(repo: _FakePostgresRepo) -> RuntimeRetrainService:
    return RuntimeRetrainService(
        settings=Settings(),
        postgres_repo=repo,
        stale_timeout_s=10.0,
    )


def test_validate_window_rejects_inverted_window() -> None:
    """start >= stop is rejected before any side-effect."""
    with pytest.raises(RuntimeRetrainValidationError):
        validate_window("2026-05-08 12:30:00", "2026-05-08 12:15:00")


def test_validate_window_rejects_non_iso() -> None:
    """Non ISO-8601 timestamps are rejected."""
    with pytest.raises(RuntimeRetrainValidationError):
        validate_window("not-a-date", "2026-05-08 12:15:00")


def test_validate_window_accepts_browser_minute_precision() -> None:
    """Minute precision from datetime-local passes; seconds stay optional."""
    validate_window("2026-07-06T16:00", "2026-07-06T19:00")
    validate_window("2026-07-06 16:00:00", "2026-07-06 19:00:00")


def test_start_accepts_browser_minute_precision_and_normalizes_to_utc(
    service: RuntimeRetrainService, repo: _FakePostgresRepo
) -> None:
    """A datetime-local window without seconds reaches retrain start as UTC.

    Reproduces the exact browser serialization shape (``YYYY-MM-DDTHH:MM``)
    and asserts it is not rejected before interval normalization and that the
    reserved retrain carries the Europe/Berlin -> UTC normalized interval.
    """
    status = _run(
        service.start(
            window_start="2026-07-06T16:00",
            window_stop="2026-07-06T19:00",
        )
    )
    assert status.state == "queued"
    # The normalized UTC interval reached retrain start (one reserved row).
    assert status.intervals == [("2026-07-06T14:00:00+00:00", "2026-07-06T17:00:00+00:00")]
    assert len(repo.rows) == 1
    assert repo.rows[0]["state"] == "queued"


def test_start_still_rejects_dst_gap_with_minute_precision(service: RuntimeRetrainService) -> None:
    """DST rejection survives the minute-precision relaxation."""
    with pytest.raises(RuntimeRetrainValidationError):
        _run(service.start(window_start="2026-03-29T02:30", window_stop="2026-03-29T03:30"))


def test_start_boundaries_snapshots_bounds_and_emits_notify(
    service: RuntimeRetrainService, repo: _FakePostgresRepo
) -> None:
    """A bounds run reserves, snapshots bounds, records rows and NOTIFYs."""
    status = _run(
        service.start(
            window_start="2026-05-08 12:15:00",
            window_stop="2026-05-08 12:30:00",
        )
    )

    assert status.scope == "bounds"
    assert status.state == "queued"
    assert status.history_snapshot_rows == 3
    assert len(repo.snapshot_calls) == 1
    assert len(repo.notifies) == 1
    assert repo.rows[0]["history_snapshot_rows"] == 3


def test_classifier_start_skips_snapshot(service: RuntimeRetrainService, repo: _FakePostgresRepo) -> None:
    """The classifier scope does not snapshot bounds."""
    status = _run(
        service.start_classifier(
            window_start="2026-05-08 12:15:00",
            window_stop="2026-05-08 12:30:00",
            mitre_file="/labels/mitre.json",
        )
    )
    assert status.scope == "ml"
    assert repo.snapshot_calls == []
    assert len(repo.notifies) == 1


def test_start_classifier_requires_mitre_file(service: RuntimeRetrainService) -> None:
    """Empty mitre_file is rejected before touching the DB."""
    with pytest.raises(RuntimeRetrainValidationError, match="mitre_file"):
        _run(
            service.start_classifier(
                window_start="2026-05-08 12:15:00",
                window_stop="2026-05-08 12:30:00",
                mitre_file="",
            )
        )


def test_second_start_is_rejected_while_job_queued(service: RuntimeRetrainService, repo: _FakePostgresRepo) -> None:
    """DB-backed single-flight returns RuntimeRetrainBusy."""
    _run(
        service.start(
            window_start="2026-05-08 12:15:00",
            window_stop="2026-05-08 12:30:00",
        )
    )
    with pytest.raises(RuntimeRetrainBusy):
        _run(
            service.start(
                window_start="2026-05-08 13:00:00",
                window_stop="2026-05-08 13:15:00",
            )
        )
    # Exactly one row reserved; the rejected request left no extra row.
    assert len(repo.rows) == 1


def test_busy_start_fails_provisional_operations_row() -> None:
    """Rejected starts leave one terminal canonical provisional row."""
    repo = _FakePostgresRepo()
    operations = _FakeOperationsRepo()
    service = RuntimeRetrainService(Settings(), repo, operations_repo=operations)
    _run(service.start("2026-05-08 12:15:00", "2026-05-08 12:30:00"))
    with pytest.raises(RuntimeRetrainBusy):
        _run(service.start("2026-05-08 13:00:00", "2026-05-08 13:15:00", requested_by="operator"))
    assert len(operations.created) == 2
    assert operations.failed == [(2, "runtime retrain already in progress")]


def test_accepted_start_creates_one_linked_operation_with_actor_and_params() -> None:
    """An accepted bounds start creates exactly one canonical operation.

    The single created row must carry the actor and the retrain params,
    and its id must be threaded into the reservation as the canonical
    link (operations_job_id) so worker projection can find it.
    """
    repo = _FakePostgresRepo()
    operations = _FakeOperationsRepo()
    service = RuntimeRetrainService(Settings(), repo, operations_repo=operations)

    status = _run(service.start("2026-05-08 12:15:00", "2026-05-08 12:30:00", requested_by="operator"))

    assert status.state == "queued"
    assert len(operations.created) == 1
    assert operations.failed == []
    payload = operations.created[0]
    assert payload.type == "training"
    assert payload.actor == "operator"
    assert payload.params["retrain_job_ref"] == status.job_ref
    assert payload.params["scope"] == "bounds"
    assert payload.params["window_start"] == "2026-05-08 12:15:00"
    assert payload.idempotency_key == f"retrain:{status.job_ref}"
    # The reserved retrain row links back to the single canonical operation.
    # The fake assigns id = len(created) = 1 to the created OperationsJob.
    assert repo.rows[0]["operations_job_id"] == 1
    assert repo.reserved_operation_ids == [1]


class _ReservationBoom(RuntimeError):
    """Stand-in for a non-unique DB failure during reservation."""


def _raise_on_reserve(repo: _FakePostgresRepo) -> None:
    """Make the reservation INSERT raise a non-'busy' database error."""
    original = repo._execute_update

    def _boom(sql: str, params: dict | None = None) -> int:
        if "INSERT INTO retrain_jobs" in sql and "WHERE NOT EXISTS" in sql:
            raise _ReservationBoom("connection reset during reservation")
        return original(sql, params)

    repo._execute_update = _boom  # type: ignore[method-assign]


def test_reservation_exception_fails_provisional_operation_and_reraises() -> None:
    """A bounds reservation DB error terminalizes the provisional row.

    The non-'busy' exception must propagate, the single provisional
    canonical row must be failed with a bounded error naming the
    exception type, and no orphan queued retrain row or NOTIFY may leak.
    """
    repo = _FakePostgresRepo()
    operations = _FakeOperationsRepo()
    service = RuntimeRetrainService(Settings(), repo, operations_repo=operations)
    _raise_on_reserve(repo)

    with pytest.raises(_ReservationBoom):
        _run(service.start("2026-05-08 12:15:00", "2026-05-08 12:30:00", requested_by="operator"))

    assert len(operations.created) == 1
    assert operations.failed == [(1, "reservation failed: _ReservationBoom")]
    assert repo.rows == []  # no orphan queued retrain row
    assert repo.notifies == []  # never notified
    assert repo.snapshot_calls == []  # never snapshotted after a failed reservation


def test_classifier_reservation_exception_fails_provisional_and_reraises() -> None:
    """A classifier reservation DB error terminalizes the provisional row."""
    repo = _FakePostgresRepo()
    operations = _FakeOperationsRepo()
    service = RuntimeRetrainService(Settings(), repo, operations_repo=operations)
    _raise_on_reserve(repo)

    with pytest.raises(_ReservationBoom):
        _run(
            service.start_classifier(
                "2026-05-08 12:15:00",
                "2026-05-08 12:30:00",
                mitre_file="/labels/mitre.json",
                requested_by="operator",
            )
        )

    assert len(operations.created) == 1
    assert operations.failed == [(1, "reservation failed: _ReservationBoom")]
    assert repo.rows == []
    assert repo.notifies == []


def test_rejected_second_start_takes_no_snapshot(service: RuntimeRetrainService, repo: _FakePostgresRepo) -> None:
    """A 409'd start must not write a misleading bounds snapshot (B-01)."""
    _run(service.start(window_start="2026-05-08 12:15:00", window_stop="2026-05-08 12:30:00"))
    assert len(repo.snapshot_calls) == 1
    with pytest.raises(RuntimeRetrainBusy):
        _run(service.start(window_start="2026-05-08 13:00:00", window_stop="2026-05-08 13:15:00"))
    # Still exactly one snapshot — the rejected reservation snapshotted nothing.
    assert len(repo.snapshot_calls) == 1


def test_classifier_shares_single_flight_with_bounds(
    service: RuntimeRetrainService,
) -> None:
    """A classifier start is rejected while a bounds job is non-terminal."""
    _run(service.start(window_start="2026-05-08 12:15:00", window_stop="2026-05-08 12:30:00"))
    with pytest.raises(RuntimeRetrainBusy):
        _run(
            service.start_classifier(
                window_start="2026-05-08 13:00:00",
                window_stop="2026-05-08 13:15:00",
                mitre_file="/labels/mitre.json",
            )
        )


@pytest.mark.parametrize(
    "raw_state,raw_scope,expect_state,expect_scope,expect_busy",
    [
        ("queued", "bounds_frequency", "queued", "bounds", True),
        ("running", "bounds_frequency", "running", "bounds", True),
        ("publishing", "classifier", "publishing", "ml", True),
        ("succeeded", "classifier", "succeeded", "ml", False),
        ("failed", "bounds_frequency", "failed", "bounds", False),
    ],
)
def test_status_maps_all_five_states(
    service: RuntimeRetrainService,
    repo: _FakePostgresRepo,
    raw_state: str,
    raw_scope: str,
    expect_state: str,
    expect_scope: str,
    expect_busy: bool,
) -> None:
    """Every persisted job state maps onto the public status shape."""
    repo.rows.append(
        {
            "job_ref": "j1",
            "scope": raw_scope,
            "state": raw_state,
            "window_start": "2026-05-08 12:00:00",
            "window_stop": "2026-05-08 12:30:00",
            "mitre_file": None,
            "requested_at": datetime.now(tz=timezone.utc),
            "started_at": None,
            "finished_at": None,
            "detail": "d",
            "error": None,
            "history_snapshot_rows": 0,
            "heartbeat_at": datetime.now(tz=timezone.utc),
        }
    )
    status = service.get_status()
    assert status.state == expect_state
    assert status.scope == expect_scope
    assert status.busy is expect_busy


def test_idle_status_when_no_jobs(service: RuntimeRetrainService) -> None:
    """With no rows the status is idle and not busy."""
    status = service.get_status()
    assert status.state == "idle"
    assert status.busy is False


def test_reaper_marks_stale_running_job_failed(service: RuntimeRetrainService, repo: _FakePostgresRepo) -> None:
    """A running job with a stale heartbeat is reaped to failed on status."""
    stale = datetime.now(tz=timezone.utc) - timedelta(seconds=120)
    repo.rows.append(
        {
            "job_ref": "j-stale",
            "scope": "bounds_frequency",
            "state": "running",
            "window_start": "2026-05-08 12:00:00",
            "window_stop": "2026-05-08 12:30:00",
            "mitre_file": None,
            "requested_at": stale,
            "started_at": stale,
            "finished_at": None,
            "detail": "training",
            "error": None,
            "history_snapshot_rows": 0,
            "heartbeat_at": stale,
        }
    )
    status = service.get_status()
    assert status.state == "failed"
    assert status.error is not None
    # Lock released: a fresh start now succeeds.
    ok = _run(service.start(window_start="2026-05-08 14:00:00", window_stop="2026-05-08 14:30:00"))
    assert ok.state == "queued"


def test_reaper_marks_stale_queued_job_failed_and_releases_reservation(
    service: RuntimeRetrainService, repo: _FakePostgresRepo
) -> None:
    """A queued row with no heartbeat ages from requested_at and is reusable."""
    stale = datetime.now(tz=timezone.utc) - timedelta(seconds=120)
    repo.rows.append(
        {
            "job_ref": "queued-stale",
            "scope": "bounds_frequency",
            "state": "queued",
            "window_start": "2026-05-08 12:00:00",
            "window_stop": "2026-05-08 12:30:00",
            "mitre_file": None,
            "requested_at": stale,
            "started_at": None,
            "finished_at": None,
            "detail": "queued",
            "error": None,
            "history_snapshot_rows": 0,
            "heartbeat_at": None,
        }
    )
    status = service.get_status()
    assert status.state == "failed"
    assert repo.rows[0]["worker_id"] is None
    fresh = _run(service.start(window_start="2026-05-08 15:00:00", window_stop="2026-05-08 15:30:00"))
    assert fresh.state == "queued"


def test_snapshot_failure_fails_reserved_job_without_notify(
    service: RuntimeRetrainService, repo: _FakePostgresRepo
) -> None:
    """Snapshot failure closes the reservation and leaves NOTIFY untouched."""

    def fail_snapshot(module: str, reason: str) -> int:
        raise RuntimeError("snapshot database unavailable")

    repo.snapshot_bounds_to_history = fail_snapshot
    with pytest.raises(RuntimeError, match="snapshot failed"):
        _run(service.start(window_start="2026-05-08 16:00:00", window_stop="2026-05-08 16:30:00"))
    assert repo.rows[0]["state"] == "failed"
    assert repo.rows[0]["worker_id"] is None
    assert repo.notifies == []
    repo.snapshot_bounds_to_history = lambda module, reason: 3
    assert _run(service.start(window_start="2026-05-08 17:00:00", window_stop="2026-05-08 17:30:00")).state == "queued"


def test_runtime_path_never_calls_env_or_compose(service: RuntimeRetrainService, repo: _FakePostgresRepo) -> None:
    """Start performs NO env/compose/docker collaborator calls (F8)."""
    _run(service.start(window_start="2026-05-08 12:15:00", window_stop="2026-05-08 12:30:00"))
    (
        _run(
            service.start_classifier(
                window_start="2026-05-08 12:15:00",
                window_stop="2026-05-08 12:30:00",
                mitre_file="/labels/mitre.json",
            )
        )
        if not repo._has_non_terminal()
        else None
    )
    assert repo.forbidden_calls == []


def test_terminal_retrain_inside_cooldown_is_rejected(service: RuntimeRetrainService, repo: _FakePostgresRepo) -> None:
    """A terminal job blocks a new start during configured cooldown."""
    repo.rows.append(
        {
            "job_ref": "finished",
            "scope": "bounds_frequency",
            "state": "succeeded",
            "window_start": "2026-05-08 10:00:00",
            "window_stop": "2026-05-08 10:30:00",
            "finished_at": datetime.now(tz=timezone.utc),
            "requested_at": datetime.now(tz=timezone.utc),
        }
    )
    with pytest.raises(RuntimeRetrainCooldown):
        _run(service.start(window_start="2026-05-08 18:00:00", window_stop="2026-05-08 18:30:00"))
    assert len(repo.rows) == 2
    assert repo.rows[-1]["state"] == "rejected"
    assert repo.rows[-1]["error"] is None
