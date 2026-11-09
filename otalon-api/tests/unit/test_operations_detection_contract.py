"""Direct HTTP-contract tests for the Wave-D detection & bounds surfaces.

These exercise the real FastAPI routers (``otalon_api.api.v1.operations`` and
``otalon_api.api.v1.baselines``) through :class:`fastapi.testclient.TestClient`
with the repository/service dependencies overridden by in-memory fakes.
They assert the exact acceptance criteria of the approved Wave-D specs:

* readiness returns three modules, an untrained module is not ``ready``,
  and a module with a running training job is ``training``;
* bound-review reads are filterable by module + state;
* expand widens only and rejects a missing-feature subset; replace is a
  distinct advanced operation; create initialises;
* the legacy expand/replace/create endpoints require a non-empty reason
  (422) and write exactly one ``operations_audit`` row carrying the actor,
  target and prior snapshot; the one-click correction apply contract needs
  no typed confirmation and treats reason as optional;
* the classifier artifact manifest lists current + rollback, and is empty
  when the model directory is absent;
* baseline activate/delete each write exactly one ``config`` audit row and
  the active baseline cannot be deleted.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterator, cast
from unittest.mock import patch
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from otalon_api.dependencies import (
    get_detection_readiness_service,
    get_operations_jobs_service,
    get_postgres_repo,
)
from otalon_api.domain.operations import OperationsAuditAppend
from otalon_api.domain.operations.job import OperationsJob
from otalon_api.main import app
from otalon_api.services.baseline_service import BaselineConflict, BaselineNotFound
from otalon_api.settings import Settings

_ADMIN_KEY = "test-secret"


def _auth_settings() -> Settings:
    """Settings with an admin key so the protected operations prefix is reachable."""
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
        admin_api_key=_ADMIN_KEY,
        api_port=8090,
        netcap_measurement="network_metrics",
        netcap_id_tag="uci",
        netcap_sparse_port_threshold=10,
        default_sample_max_points=500,
    )


_HEADERS = {"X-API-Key": _ADMIN_KEY}


class _FakeJobsService:
    """Captures audit appends and serves a controllable running-jobs list."""

    def __init__(self) -> None:
        self.audit_rows: list[OperationsAuditAppend] = []
        self.running_jobs: list[Any] = []
        self.recorded: list[OperationsJob] = []
        self.started: list[int] = []
        self.completed: list[tuple[int, str | None]] = []
        self.failed: list[tuple[int, str]] = []
        self._next_id = 1

    async def append_audit(self, entry: OperationsAuditAppend) -> None:
        self.audit_rows.append(entry)

    async def list_jobs(self, **_kwargs: Any) -> list[Any]:
        return self.running_jobs

    async def record_job(
        self,
        type_: str,
        title: str,
        trigger: str,
        params: dict[str, Any],
        actor: str,
        *,
        can_cancel: bool = False,
    ) -> OperationsJob:
        job = OperationsJob(
            id=self._next_id,
            display_id=f"job-{self._next_id}",
            type=cast(Any, type_),
            title=title,
            state="running",
            trigger=trigger,
            actor=actor,
            started_at=datetime(2026, 7, 20, tzinfo=timezone.utc),
            params=params,
            can_cancel=can_cancel,
        )
        self._next_id += 1
        self.recorded.append(job)
        return job

    async def start_job(self, job_id: int) -> OperationsJob:
        self.started.append(job_id)
        base = self.recorded[-1]
        started = base.model_copy(update={"state": "running"})
        self.recorded[-1] = started
        return started

    async def complete_job(self, job_id: int, result: str | None = None) -> OperationsJob:
        self.completed.append((job_id, result))
        base = self.recorded[-1]
        return base.model_copy(update={"state": "completed", "result": result})

    async def fail_job(self, job_id: int, error: str) -> OperationsJob:
        self.failed.append((job_id, error))
        base = self.recorded[-1]
        return base.model_copy(update={"state": "failed", "error": error})


class _RunningJob:
    def __init__(self, modules: list[str]) -> None:
        self.params = {"modules": modules}


class _FakePostgres:
    """In-memory bounds store implementing the correction contract."""

    def __init__(self) -> None:
        self.bounds: dict[tuple[str, str], dict[str, Any]] = {}
        self.history: list[dict[str, Any]] = []
        self.on_lock: Any = None
        self.notifications: list[dict[str, Any]] = []

    def seed(self, module: str, series: str, lower: dict[str, Any], upper: dict[str, Any]) -> None:
        self.bounds[(module, series)] = {
            "lower_bounds": dict(lower),
            "upper_bounds": dict(upper),
        }

    def query_bounds(self, module: str, series_id: str | None = None) -> list[dict[str, Any]]:
        existing = self.bounds.get((module, series_id or ""))
        if existing is None:
            return []
        return [
            {
                "module": module,
                "series_id": series_id,
                "lower_bounds": dict(existing["lower_bounds"]),
                "upper_bounds": dict(existing["upper_bounds"]),
            }
        ]

    def preview_bounds_correction(
        self,
        module: str,
        series_id: str,
        action: str,
        lower_bounds: dict[str, Any],
        upper_bounds: dict[str, Any],
        before: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        from otalon_common import calculate_bounds_correction

        existing = self.bounds.get((module, series_id))
        old_lower = dict(existing["lower_bounds"]) if existing else None
        old_upper = dict(existing["upper_bounds"]) if existing else None
        required = (
            set(old_lower or {}) | set(old_upper or {})
            if action in {"expand", "replace"} and existing is not None
            else None
        )
        correction = calculate_bounds_correction(
            action,
            old_lower,
            old_upper,
            lower_bounds,
            upper_bounds,
            required_features=required,
        )
        return {
            "module": module,
            "series_id": series_id,
            "action": action,
            "prior": {"lower_bounds": old_lower, "upper_bounds": old_upper},
            "lower_bounds": correction.lower,
            "upper_bounds": correction.upper,
        }

    def correct_bounds(
        self,
        module: str,
        series_id: str,
        action: str,
        lower_bounds: dict[str, Any],
        upper_bounds: dict[str, Any],
        reason: str,
        actor: str,
        before: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        reason = reason or ""
        from otalon_common import calculate_bounds_correction

        from otalon_api.repositories.postgres_repo import BoundsCorrectionConflict

        # Real seam: a competing writer may commit between preview and this
        # locked read. The hook runs exactly at the FOR UPDATE point so the
        # snapshot compare below sees the concurrently mutated state.
        if self.on_lock is not None:
            self.on_lock()
        existing = self.bounds.get((module, series_id))
        old_lower = dict(existing["lower_bounds"]) if existing else None
        old_upper = dict(existing["upper_bounds"]) if existing else None
        if before is not None and before != {
            "lower_bounds": old_lower or {},
            "upper_bounds": old_upper or {},
        }:
            raise BoundsCorrectionConflict("bounds changed since preview; correction rejected as stale")
        required = (
            set(old_lower or {}) | set(old_upper or {})
            if action in {"expand", "replace"} and existing is not None
            else None
        )
        correction = calculate_bounds_correction(
            action,
            old_lower,
            old_upper,
            lower_bounds,
            upper_bounds,
            required_features=required,
        )
        self.bounds[(module, series_id)] = {
            "lower_bounds": correction.lower,
            "upper_bounds": correction.upper,
        }
        history_id = uuid4().hex
        self.history.append(
            {
                "id": history_id,
                "module": module,
                "series_id": series_id,
                "action": action,
                "actor": actor,
                "reason": reason,
                "old_lower": old_lower,
                "old_upper": old_upper,
            }
        )
        self.notifications.append(
            {
                "channel": "cyberclas_bounds_invalidation",
                "payload": {"module": module, "series_id": series_id},
            }
        )
        return {
            "history_id": history_id,
            "module": module,
            "series_id": series_id,
            "action": action,
            "lower_bounds": correction.lower,
            "upper_bounds": correction.upper,
            "prior": {"lower_bounds": old_lower, "upper_bounds": old_upper},
        }


class _FakeReadiness:
    """Serves deterministic readiness/bounds/artifacts for the router."""

    def __init__(self) -> None:
        self.artifact_items: list[dict[str, Any]] = []
        self.bounds_calls: list[dict[str, Any]] = []
        self.suggestion_calls: list[dict[str, Any]] = []

    def readiness(self, running_modules: set[str]) -> list[dict[str, Any]]:
        out = []
        for module, has_bounds in (
            ("conn", True),
            ("mac_traffic", True),
            ("proto_traffic", False),
        ):
            training = module in running_modules
            if training:
                state = "training"
            elif not has_bounds:
                state = "untrained"
            else:
                state = "ready"
            out.append(
                {
                    "module": module,
                    "state": state,
                    "detection_mode": "active" if has_bounds else "observe-only",
                    "bounds_series_count": 3 if has_bounds else 0,
                    "no_bounds_count": 0 if has_bounds else 5,
                    "no_bounds_event_count": 0 if has_bounds else 5,
                    "no_bounds_series_count": 0 if has_bounds else 2,
                    "frequency_profile_count": 3 if has_bounds else 0,
                    "last_training": (datetime(2026, 7, 17, tzinfo=timezone.utc) if has_bounds else None),
                    "schema_version": "bounds-v1",
                    "schema_compatible": True,
                }
            )
        return out

    def live_poll_interval_seconds(self) -> int:
        """Return deterministic cadence metadata for readiness response tests."""
        return 5

    def bounds(
        self,
        module: str | None,
        state: str | None,
        since: Any,
        query: str | None,
        until: Any = None,
    ) -> list[dict[str, Any]]:
        self.bounds_calls.append(
            {
                "module": module,
                "state": state,
                "since": since,
                "until": until,
                "query": query,
            }
        )
        rows = [
            {
                "module": "conn",
                "series_id": "uci-1",
                "feature": "packet_count",
                "state": "NoBounds",
                "lower": 0,
                "upper": 100,
                "violation_count": 0,
                "last_event": None,
            },
            {
                "module": "mac_traffic",
                "series_id": "mac-1",
                "feature": "out_total_volume",
                "state": "BoundViolation",
                "lower": 1,
                "upper": 50,
                "violation_count": 4,
                "last_event": None,
            },
        ]
        if module:
            rows = [r for r in rows if r["module"] == module]
        if state:
            rows = [r for r in rows if r["state"] == state]
        if query:
            rows = [r for r in rows if query.lower() in str(r["series_id"]).lower()]
        return rows

    def artifacts(self) -> list[dict[str, Any]]:
        return self.artifact_items

    def suggest_bounds(
        self,
        module: str,
        series_id: str,
        action: str,
        window_start: datetime,
        window_end: datetime,
    ) -> dict[str, Any]:
        self.suggestion_calls.append(
            {
                "module": module,
                "series_id": series_id,
                "action": action,
                "from": window_start,
                "to": window_end,
            }
        )
        if series_id == "empty":
            return {
                "module": module,
                "series_id": series_id,
                "action": action,
                "status": "unavailable",
                "window_from": window_start,
                "window_to": window_end,
                "evidence_count": 0,
                "current": {"lower_bounds": {"a": 5}, "upper_bounds": {"a": 10}},
                "proposed": {"lower_bounds": {"a": 5}, "upper_bounds": {"a": 10}},
                "rationale": {
                    "a": {
                        "evidence_count": 0,
                        "lower_rationale": "No numeric values observed in strict [from, to)",
                        "upper_rationale": "No numeric values observed in strict [from, to)",
                    }
                },
                "message": "No usable feature values in [from, to)",
            }
        lower = 1 if action == "expand" else 2
        upper = 20 if action == "expand" else 18
        current = (
            {"lower_bounds": {}, "upper_bounds": {}}
            if action == "create"
            else {
                "lower_bounds": {"a": 5},
                "upper_bounds": {"a": 10},
            }
        )
        return {
            "module": module,
            "series_id": series_id,
            "action": action,
            "status": "available",
            "window_from": window_start,
            "window_to": window_end,
            "evidence_count": 3,
            "current": current,
            "proposed": {"lower_bounds": {"a": lower}, "upper_bounds": {"a": upper}},
            "rationale": {
                "a": {
                    "evidence_count": 3,
                    "lower_rationale": "Observed minimum 1 in strict [from, to)",
                    "upper_rationale": "Observed maximum 20 in strict [from, to)",
                }
            },
            "message": "Observed feature evidence supports this proposal",
        }


class _FakeBaselineService:
    """In-memory baseline lifecycle with active-delete protection."""

    def __init__(self) -> None:
        self.active_id = uuid4()
        self.spare_id = uuid4()
        self.items = {
            self.active_id: {
                "id": str(self.active_id),
                "name": "Active",
                "is_active": True,
            },
            self.spare_id: {
                "id": str(self.spare_id),
                "name": "Spare",
                "is_active": False,
            },
        }

    def list(self) -> list[dict[str, Any]]:
        return list(self.items.values())

    def create(self, **kwargs: Any) -> dict[str, Any]:
        new_id = uuid4()
        row = {"id": str(new_id), "name": kwargs["name"], "is_active": False}
        self.items[new_id] = row
        return row

    def activate(self, baseline_id: UUID, user: Any = None) -> dict[str, Any]:
        if baseline_id not in self.items:
            raise BaselineNotFound()
        for row in self.items.values():
            row["is_active"] = False
        self.items[baseline_id]["is_active"] = True
        return self.items[baseline_id]

    def delete(self, baseline_id: UUID) -> None:
        if baseline_id not in self.items:
            raise BaselineNotFound()
        if self.items[baseline_id]["is_active"]:
            raise BaselineConflict("active baseline cannot be deleted")
        del self.items[baseline_id]


@pytest.fixture()
def jobs() -> _FakeJobsService:
    return _FakeJobsService()


@pytest.fixture()
def postgres() -> _FakePostgres:
    return _FakePostgres()


@pytest.fixture()
def readiness() -> _FakeReadiness:
    return _FakeReadiness()


@pytest.fixture()
def baseline() -> _FakeBaselineService:
    return _FakeBaselineService()


@pytest.fixture()
def client(
    jobs: _FakeJobsService,
    postgres: _FakePostgres,
    readiness: _FakeReadiness,
    baseline: _FakeBaselineService,
) -> Iterator[TestClient]:
    app.dependency_overrides[get_operations_jobs_service] = lambda: jobs
    app.dependency_overrides[get_postgres_repo] = lambda: postgres
    app.dependency_overrides[get_detection_readiness_service] = lambda: readiness
    previous_baseline = getattr(app.state, "baseline_service", None)
    app.state.baseline_service = baseline
    with patch("otalon_api.middleware.auth.get_settings", return_value=_auth_settings()):
        try:
            yield TestClient(app, headers=_HEADERS, raise_server_exceptions=False)
        finally:
            for dep in (
                get_operations_jobs_service,
                get_postgres_repo,
                get_detection_readiness_service,
            ):
                app.dependency_overrides.pop(dep, None)
            app.state.baseline_service = previous_baseline


# --- readiness -------------------------------------------------------------


def test_readiness_returns_three_modules_untrained_not_ready(client: TestClient, readiness: _FakeReadiness) -> None:
    resp = client.get("/api/v1/operations/detection/readiness", headers=_HEADERS)
    assert resp.status_code == 200, resp.text
    modules = resp.json()["modules"]
    assert {m["module"] for m in modules} == {"conn", "mac_traffic", "proto_traffic"}
    proto = next(m for m in modules if m["module"] == "proto_traffic")
    assert proto["state"] == "untrained"
    assert proto["state"] != "ready"


def test_readiness_reports_training_when_job_running(client: TestClient, jobs: _FakeJobsService) -> None:
    jobs.running_jobs = [_RunningJob(["conn"])]
    resp = client.get("/api/v1/operations/detection/readiness", headers=_HEADERS)
    conn = next(m for m in resp.json()["modules"] if m["module"] == "conn")
    assert conn["state"] == "training"


def test_readiness_labels_raw_and_unique_no_bounds_counts(
    client: TestClient,
) -> None:
    """Readiness distinguishes raw event volume from affected series."""
    response = client.get("/api/v1/operations/detection/readiness", headers=_HEADERS)
    proto = next(item for item in response.json()["modules"] if item["module"] == "proto_traffic")
    assert proto["no_bounds_event_count"] == 5
    assert proto["no_bounds_series_count"] == 2


# --- bound review read -----------------------------------------------------


def test_bounds_forwards_strict_from_to_window(client: TestClient, readiness: _FakeReadiness) -> None:
    """The route forwards ``from`` as the window start and ``to`` as the strict upper bound."""
    resp = client.get(
        "/api/v1/operations/bounds",
        params={"from": "2026-07-04T00:00:00Z", "to": "2026-07-09T00:00:00Z"},
        headers=_HEADERS,
    )
    assert resp.status_code == 200, resp.text
    call = readiness.bounds_calls[-1]
    assert call["since"] == datetime(2026, 7, 4, tzinfo=timezone.utc)
    assert call["until"] == datetime(2026, 7, 9, tzinfo=timezone.utc)


def test_bounds_legacy_since_maps_to_window_start(client: TestClient, readiness: _FakeReadiness) -> None:
    """Legacy ``since`` still drives the window start when ``from`` is absent."""
    resp = client.get(
        "/api/v1/operations/bounds",
        params={"since": "2026-07-01T00:00:00Z"},
        headers=_HEADERS,
    )
    assert resp.status_code == 200, resp.text
    call = readiness.bounds_calls[-1]
    assert call["since"] == datetime(2026, 7, 1, tzinfo=timezone.utc)
    assert call["until"] is None


def test_bounds_filter_by_module_and_state(client: TestClient) -> None:
    resp = client.get(
        "/api/v1/operations/bounds",
        params={"module": "conn", "state": "NoBounds"},
        headers=_HEADERS,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["module"] == "conn"
    assert body["items"][0]["state"] == "NoBounds"


def test_bound_suggestion_forwards_strict_window_and_does_not_mutate(
    client: TestClient,
    readiness: _FakeReadiness,
    postgres: _FakePostgres,
    jobs: _FakeJobsService,
) -> None:
    response = client.post(
        "/api/v1/operations/bounds/suggestion",
        json={
            "module": "conn",
            "series_id": "uci-1",
            "action": "expand",
            "from": "2026-07-04T00:00:00Z",
            "to": "2026-07-09T00:00:00Z",
        },
        headers=_HEADERS,
    )
    assert response.status_code == 200, response.text
    call = readiness.suggestion_calls[-1]
    assert call["from"] == datetime(2026, 7, 4, tzinfo=timezone.utc)
    assert call["to"] == datetime(2026, 7, 9, tzinfo=timezone.utc)
    assert response.json()["status"] == "available"
    assert postgres.history == []
    assert jobs.recorded == []
    assert jobs.audit_rows == []


def test_bound_suggestion_accepts_create_and_forwards_exactly_without_mutation(
    client: TestClient,
    readiness: _FakeReadiness,
    postgres: _FakePostgres,
    jobs: _FakeJobsService,
) -> None:
    payload = {
        "module": "proto_traffic",
        "series_id": "proto-hash",
        "action": "create",
        "from": "2026-07-04T01:02:03Z",
        "to": "2026-07-09T04:05:06Z",
    }
    response = client.post("/api/v1/operations/bounds/suggestion", json=payload, headers=_HEADERS)
    assert response.status_code == 200, response.text
    assert readiness.suggestion_calls[-1] == {
        "module": "proto_traffic",
        "series_id": "proto-hash",
        "action": "create",
        "from": datetime(2026, 7, 4, 1, 2, 3, tzinfo=timezone.utc),
        "to": datetime(2026, 7, 9, 4, 5, 6, tzinfo=timezone.utc),
    }
    assert response.json()["current"] == {"lower_bounds": {}, "upper_bounds": {}}
    assert postgres.history == []
    assert jobs.recorded == []
    assert jobs.audit_rows == []


def test_bound_suggestion_action_changes_full_envelope_semantics(client: TestClient, readiness: _FakeReadiness) -> None:
    payload = {
        "module": "conn",
        "series_id": "uci-1",
        "from": "2026-07-04T00:00:00Z",
        "to": "2026-07-09T00:00:00Z",
    }
    expand = client.post(
        "/api/v1/operations/bounds/suggestion",
        json={**payload, "action": "expand"},
        headers=_HEADERS,
    )
    replace = client.post(
        "/api/v1/operations/bounds/suggestion",
        json={**payload, "action": "replace"},
        headers=_HEADERS,
    )
    assert expand.status_code == replace.status_code == 200
    assert expand.json()["proposed"] != replace.json()["proposed"]
    assert [call["action"] for call in readiness.suggestion_calls[-2:]] == [
        "expand",
        "replace",
    ]


def test_bound_suggestion_truthfully_reports_insufficient_data(
    client: TestClient,
) -> None:
    response = client.post(
        "/api/v1/operations/bounds/suggestion",
        json={
            "module": "conn",
            "series_id": "empty",
            "action": "replace",
            "from": "2026-07-04T00:00:00Z",
            "to": "2026-07-09T00:00:00Z",
        },
        headers=_HEADERS,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "unavailable"
    assert body["evidence_count"] == 0


def test_bound_suggestion_rejects_unknown_module(client: TestClient) -> None:
    response = client.post(
        "/api/v1/operations/bounds/suggestion",
        json={
            "module": "unknown",
            "series_id": "uci-1",
            "action": "replace",
            "from": "2026-07-04T00:00:00Z",
            "to": "2026-07-09T00:00:00Z",
        },
        headers=_HEADERS,
    )
    assert response.status_code == 422


# --- bound correction ------------------------------------------------------


def test_expand_widens_only_and_audits_one_row(
    client: TestClient, postgres: _FakePostgres, jobs: _FakeJobsService
) -> None:
    postgres.seed("conn", "uci-1", {"a": 5, "b": 5}, {"a": 10, "b": 10})
    resp = client.post(
        "/api/v1/operations/bounds/uci-1/expand",
        json={
            "module": "conn",
            "lower_bounds": {"a": 1, "b": 6},
            "upper_bounds": {"a": 8, "b": 20},
            "reason": "widen after false positive",
        },
        headers=_HEADERS,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    # widen-only: lower is the min, upper is the max; never narrower.
    assert body["lower_bounds"]["a"] == 1
    assert body["lower_bounds"]["b"] == 5
    assert body["upper_bounds"]["a"] == 10
    assert body["upper_bounds"]["b"] == 20
    # prior snapshot preserved.
    assert body["prior"]["lower_bounds"] == {"a": 5, "b": 5}
    # exactly one operations_audit row, with actor + target + reason.
    assert len(jobs.audit_rows) == 1
    entry = jobs.audit_rows[0]
    assert entry.category == "bounds"
    assert entry.actor == "operator"
    assert entry.target == "conn:uci-1"
    assert entry.reason == "widen after false positive"
    # bounds_history recorded with actor.
    assert len(postgres.history) == 1
    assert postgres.history[0]["actor"] == "operator"
    assert postgres.notifications == [
        {
            "channel": "cyberclas_bounds_invalidation",
            "payload": {"module": "conn", "series_id": "uci-1"},
        }
    ]


def test_expand_rejects_missing_feature_subset(
    client: TestClient, postgres: _FakePostgres, jobs: _FakeJobsService
) -> None:
    postgres.seed("conn", "uci-1", {"a": 5, "b": 5}, {"a": 10, "b": 10})
    resp = client.post(
        "/api/v1/operations/bounds/uci-1/expand",
        json={
            "module": "conn",
            "lower_bounds": {"a": 1},
            "upper_bounds": {"a": 20},
            "reason": "partial",
        },
        headers=_HEADERS,
    )
    assert resp.status_code == 422
    assert "b" in resp.text
    # nothing persisted or audited on rejection.
    assert postgres.history == []
    assert jobs.audit_rows == []


def test_correction_requires_non_empty_reason(client: TestClient, jobs: _FakeJobsService) -> None:
    resp = client.post(
        "/api/v1/operations/bounds/uci-1/expand",
        json={
            "module": "conn",
            "lower_bounds": {"a": 1},
            "upper_bounds": {"a": 2},
            "reason": "",
        },
        headers=_HEADERS,
    )
    assert resp.status_code == 422
    assert jobs.audit_rows == []


def test_replace_overwrites_and_is_distinct_advanced(
    client: TestClient, postgres: _FakePostgres, jobs: _FakeJobsService
) -> None:
    postgres.seed("conn", "uci-1", {"a": 5}, {"a": 10})
    resp = client.post(
        "/api/v1/operations/bounds/uci-1/replace",
        json={
            "module": "conn",
            "lower_bounds": {"a": 1},
            "upper_bounds": {"a": 3},
            "reason": "full overwrite",
        },
        headers=_HEADERS,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["action"] == "replace"
    assert body["lower_bounds"] == {"a": 1}
    assert body["upper_bounds"] == {"a": 3}
    assert postgres.history[0]["action"] == "replace"
    assert len(jobs.audit_rows) == 1
    assert len(postgres.notifications) == 1
    assert postgres.notifications[0]["payload"] == {
        "module": "conn",
        "series_id": "uci-1",
    }


def test_expand_series_with_slashes_uses_body_series_id(
    client: TestClient, postgres: _FakePostgres, jobs: _FakeJobsService
) -> None:
    """A slash-bearing series id is resolved from the authoritative body field.

    Real UCIs contain ``/`` (e.g. ``aa:bb/cc:dd//Ethernet``) which cannot be
    carried cleanly in an ASGI path segment across every client, so the body
    ``series_id`` is authoritative. The path segment is an opaque placeholder.
    """
    raw_series = "aa:bb/cc:dd//Ethernet:LLDP"
    postgres.seed("conn", raw_series, {"a": 5}, {"a": 10})
    resp = client.post(
        "/api/v1/operations/bounds/placeholder/expand",
        json={
            "module": "conn",
            "series_id": raw_series,
            "lower_bounds": {"a": 1},
            "upper_bounds": {"a": 20},
            "reason": "slash id",
        },
        headers=_HEADERS,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["series_id"] == raw_series
    assert ("conn", raw_series) in postgres.bounds
    assert jobs.audit_rows[0].target == f"conn:{raw_series}"


def test_create_initialises_new_series(client: TestClient, postgres: _FakePostgres, jobs: _FakeJobsService) -> None:
    resp = client.post(
        "/api/v1/operations/bounds/new-series/create",
        json={
            "module": "conn",
            "lower_bounds": {"a": 0},
            "upper_bounds": {"a": 100},
            "reason": "initialise NoBounds series",
        },
        headers=_HEADERS,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["action"] == "create"
    assert body["prior"] == {"lower_bounds": None, "upper_bounds": None}
    assert ("conn", "new-series") in postgres.bounds
    assert len(jobs.audit_rows) == 1


# --- artifact manifest -----------------------------------------------------


def test_artifacts_lists_current_and_rollback(client: TestClient, readiness: _FakeReadiness) -> None:
    readiness.artifact_items = [
        {"artifact": "current.joblib", "status": "production"},
        {"artifact": "rollback.joblib", "status": "rollback"},
    ]
    resp = client.get("/api/v1/operations/detection/artifacts", headers=_HEADERS)
    assert resp.status_code == 200, resp.text
    items = resp.json()["items"]
    statuses = {i["status"] for i in items}
    assert "production" in statuses
    assert "rollback" in statuses


def test_artifacts_absent_returns_empty(client: TestClient) -> None:
    resp = client.get("/api/v1/operations/detection/artifacts", headers=_HEADERS)
    assert resp.status_code == 200
    assert resp.json()["items"] == []


# --- baselines lifecycle ---------------------------------------------------


def test_baseline_activate_writes_one_config_audit_row(
    client: TestClient, baseline: _FakeBaselineService, jobs: _FakeJobsService
) -> None:
    resp = client.post(f"/api/v1/baselines/{baseline.spare_id}/activate")
    assert resp.status_code == 200, resp.text
    assert resp.json()["is_active"] is True
    assert len(jobs.audit_rows) == 1
    assert jobs.audit_rows[0].category == "config"
    assert jobs.audit_rows[0].action == "activate_baseline"


def test_active_baseline_cannot_be_deleted(
    client: TestClient, baseline: _FakeBaselineService, jobs: _FakeJobsService
) -> None:
    resp = client.request("DELETE", f"/api/v1/baselines/{baseline.active_id}")
    assert resp.status_code == 409
    # active baseline still present, no audit row for the blocked delete.
    assert baseline.active_id in baseline.items
    assert jobs.audit_rows == []


def test_spare_baseline_delete_writes_one_config_audit_row(
    client: TestClient, baseline: _FakeBaselineService, jobs: _FakeJobsService
) -> None:
    resp = client.request("DELETE", f"/api/v1/baselines/{baseline.spare_id}")
    assert resp.status_code == 204
    assert baseline.spare_id not in baseline.items
    assert len(jobs.audit_rows) == 1
    assert jobs.audit_rows[0].category == "config"
    assert jobs.audit_rows[0].action == "delete_baseline"


def test_baseline_create_returns_201(client: TestClient, baseline: _FakeBaselineService) -> None:
    resp = client.post(
        "/api/v1/baselines",
        json={
            "name": "Nightly",
            "start_ts": "2026-07-01T00:00:00Z",
            "end_ts": "2026-07-02T00:00:00Z",
        },
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["name"] == "Nightly"


# --- bound-review correction preview / guarded apply -----------------------


def test_bounds_correction_preview_is_non_mutating(
    client: TestClient, postgres: _FakePostgres, jobs: _FakeJobsService
) -> None:
    """The preview computes before/after without writing bounds, jobs or audit."""
    postgres.seed("conn", "uci-1", {"a": 5}, {"a": 10})
    resp = client.post(
        "/api/v1/operations/bounds/uci-1/correction/preview",
        json={
            "module": "conn",
            "action": "expand",
            "before": {"lower_bounds": {"a": 5}, "upper_bounds": {"a": 10}},
            "after": {"lower_bounds": {"a": 1}, "upper_bounds": {"a": 20}},
            "reason": "widen for legitimate burst",
        },
        headers=_HEADERS,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["prior"] == {"lower_bounds": {"a": 5}, "upper_bounds": {"a": 10}}
    assert body["lower_bounds"]["a"] <= 5 and body["upper_bounds"]["a"] >= 10
    # No mutation, no job, no audit on preview.
    assert postgres.bounds[("conn", "uci-1")] == {
        "lower_bounds": {"a": 5},
        "upper_bounds": {"a": 10},
    }
    assert postgres.history == []
    assert jobs.recorded == []
    assert jobs.audit_rows == []


def test_bounds_correction_apply_needs_no_confirmation_and_reason_is_optional(
    client: TestClient, postgres: _FakePostgres, jobs: _FakeJobsService
) -> None:
    """One-click apply carries no confirmation phrase; reason may be empty.

    A validated envelope with a matching before snapshot mutates, links one
    canonical job and appends exactly one audit row even when reason is
    omitted entirely.
    """
    postgres.seed("conn", "uci-1", {"a": 5}, {"a": 10})
    resp = client.post(
        "/api/v1/operations/bounds/uci-1/correction/apply",
        json={
            "module": "conn",
            "action": "expand",
            "before": {"lower_bounds": {"a": 5}, "upper_bounds": {"a": 10}},
            "after": {"lower_bounds": {"a": 1}, "upper_bounds": {"a": 20}},
        },
        headers=_HEADERS,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["job"]["state"] == "completed"
    assert body["correction"]["history_id"]
    assert jobs.started == [jobs.recorded[0].id]
    assert len(jobs.recorded) == 1
    assert jobs.completed and jobs.completed[0][0] == jobs.recorded[0].id
    assert len(jobs.audit_rows) == 1
    assert jobs.audit_rows[0].category == "bounds"
    assert jobs.audit_rows[0].reason == ""
    assert postgres.history[0]["reason"] == ""
    assert postgres.notifications == [
        {
            "channel": "cyberclas_bounds_invalidation",
            "payload": {"module": "conn", "series_id": "uci-1"},
        }
    ]
    # Persisted mutation reflects the expanded envelope.
    assert postgres.bounds[("conn", "uci-1")]["upper_bounds"]["a"] >= 20


def test_bounds_correction_apply_internal_validation_failure_mutates_nothing(
    client: TestClient, postgres: _FakePostgres, jobs: _FakeJobsService
) -> None:
    """A failing internal non-mutating validation writes no job/audit/mutation."""
    postgres.seed("conn", "uci-1", {"a": 5, "b": 5}, {"a": 10, "b": 10})
    resp = client.post(
        "/api/v1/operations/bounds/uci-1/correction/apply",
        json={
            "module": "conn",
            "action": "expand",
            "before": {
                "lower_bounds": {"a": 5, "b": 5},
                "upper_bounds": {"a": 10, "b": 10},
            },
            # Missing feature "b" is an invalid expand subset.
            "after": {"lower_bounds": {"a": 1}, "upper_bounds": {"a": 20}},
            "reason": "partial",
        },
        headers=_HEADERS,
    )
    assert resp.status_code == 422
    assert postgres.history == []
    assert jobs.recorded == []
    assert jobs.audit_rows == []
    assert postgres.notifications == []
    assert postgres.bounds[("conn", "uci-1")] == {
        "lower_bounds": {"a": 5, "b": 5},
        "upper_bounds": {"a": 10, "b": 10},
    }


def test_bounds_correction_apply_stale_before_conflicts_at_locked_seam(
    client: TestClient, postgres: _FakePostgres, jobs: _FakeJobsService
) -> None:
    """A concurrent mutation at the locked apply seam rejects the stale before.

    The competing writer commits between the client's preview and the locked
    apply read. The stale ``before`` snapshot must fail as a conflict-safe
    409, leave the newer bounds untouched, create no correction audit, and
    mark the already-created canonical job failed rather than completed.
    """
    postgres.seed("conn", "uci-1", {"a": 5}, {"a": 10})

    def concurrent_writer() -> None:
        # Another operator/retrain publication widened the bound first.
        postgres.bounds[("conn", "uci-1")] = {
            "lower_bounds": {"a": 2},
            "upper_bounds": {"a": 30},
        }

    postgres.on_lock = concurrent_writer

    resp = client.post(
        "/api/v1/operations/bounds/uci-1/correction/apply",
        json={
            "module": "conn",
            "action": "expand",
            # Snapshot the client previewed, now stale.
            "before": {"lower_bounds": {"a": 5}, "upper_bounds": {"a": 10}},
            "after": {"lower_bounds": {"a": 1}, "upper_bounds": {"a": 20}},
            "reason": "widen for legitimate burst",
        },
        headers=_HEADERS,
    )

    assert resp.status_code == 409, resp.text
    # Newer producer bounds survive untouched.
    assert postgres.bounds[("conn", "uci-1")] == {
        "lower_bounds": {"a": 2},
        "upper_bounds": {"a": 30},
    }
    # No successful correction history, no success audit row.
    assert postgres.history == []
    assert jobs.audit_rows == []
    assert postgres.notifications == []
    assert postgres.notifications == []
    # The provisional canonical job is failed, not completed.
    assert jobs.failed and jobs.failed[0][0] == jobs.recorded[0].id
    assert jobs.completed == []


def test_bounds_correction_apply_matching_before_applies_exactly_once(
    client: TestClient, postgres: _FakePostgres, jobs: _FakeJobsService
) -> None:
    """A matching before snapshot applies the correction exactly once."""
    postgres.seed("conn", "uci-1", {"a": 5}, {"a": 10})
    resp = client.post(
        "/api/v1/operations/bounds/uci-1/correction/apply",
        json={
            "module": "conn",
            "action": "expand",
            "before": {"lower_bounds": {"a": 5}, "upper_bounds": {"a": 10}},
            "after": {"lower_bounds": {"a": 1}, "upper_bounds": {"a": 20}},
            "reason": "widen for legitimate burst",
        },
        headers=_HEADERS,
    )
    assert resp.status_code == 200, resp.text
    assert len(postgres.history) == 1
    assert jobs.completed and jobs.failed == []
    assert postgres.bounds[("conn", "uci-1")]["upper_bounds"]["a"] >= 20
