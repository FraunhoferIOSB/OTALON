"""Focused tests for health incident correlation, offloading and routes."""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from otalon_api.dependencies import get_health_incident_service
from otalon_api.main import app
from otalon_api.services.health_incident_service import HealthIncidentService
from otalon_api.settings import Settings


def _row(status: str = "active", **overrides: Any) -> dict[str, Any]:
    """Build a representative persisted incident row."""
    row: dict[str, Any] = {
        "id": uuid4(),
        "service": "Network Traffic Recorder",
        "owning_service": "otalon-capture",
        "probe_target": "Network Traffic Recorder",
        "category": "probe_timeout",
        "cause": "health probe timeout",
        "status": status,
        "first_seen": datetime.now(timezone.utc),
        "last_seen": datetime.now(timezone.utc),
        "recovered_at": None,
        "sample_count": 1,
        "failure_count": 1,
        "consecutive_successes": 0,
        "latency_budget_ms": 3000.0,
        "worst_latency_ms": 4200.0,
        "samples": [],
    }
    row.update(overrides)
    return row


def _core_service(running: bool, detail: str, latency: float = 100.0) -> dict[str, Any]:
    """Build a canonical core probe result."""
    return {
        "name": "Network Traffic Recorder",
        "running": running,
        "detail": detail,
        "timestamp": 1.0,
        "latency_ms": latency,
        "latency_budget_ms": 3000.0,
        "classification": "core",
    }


# ---------------------------------------------------------------------------
# Service correlation
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_first_failure_opens_incident() -> None:
    """A first failed core probe upserts a new incident."""
    repository = MagicMock()
    repository.active.return_value = None
    repository.upsert_sample.side_effect = lambda sample, now: _row()
    repository.list.return_value = [_row()]
    repository.unacknowledged.return_value = [_row()]
    service = HealthIncidentService(repository)

    result = service.record({"services": [_core_service(False, "probe timeout after 4200 ms", 4200.0)]})

    repository.upsert_sample.assert_called_once()
    assert result["active_incidents"][0]["status"] == "active"


@pytest.mark.unit
def test_repeated_failure_updates_same_incident() -> None:
    """A repeated failure while active updates the existing incident."""
    repository = MagicMock()
    repository.active.return_value = _row()
    repository.upsert_sample.side_effect = lambda sample, now: _row(sample_count=2, failure_count=2)
    repository.list.return_value = [_row(sample_count=2, failure_count=2)]
    repository.unacknowledged.return_value = [_row(sample_count=2, failure_count=2)]
    service = HealthIncidentService(repository)

    service.record({"services": [_core_service(False, "probe timeout after 4300 ms", 4300.0)]})

    repository.upsert_sample.assert_called_once()


@pytest.mark.unit
def test_intermediate_success_keeps_active_incident() -> None:
    """One in-budget sample does not clear active evidence."""
    repository = MagicMock()
    repository.active.return_value = _row()
    repository.upsert_sample.side_effect = lambda sample, now: _row()
    repository.list.return_value = [_row()]
    repository.unacknowledged.return_value = [_row()]
    service = HealthIncidentService(repository)

    result = service.record({"services": [_core_service(True, "ok in 100 ms")], "overall_status": "healthy"})

    repository.upsert_sample.assert_called_once()
    assert result["active_incidents"][0]["status"] == "active"
    # Degraded latch: an active incident keeps the aggregate degraded.
    assert result["active_incidents"], "expected the active incident to survive one success"


@pytest.mark.unit
def test_intermittent_success_latches_overall_degraded() -> None:
    """An active incident forces REST/SSE overall_status back to degraded."""
    repository = MagicMock()
    repository.active.return_value = _row()
    repository.upsert_sample.side_effect = lambda sample, now: _row()
    repository.list.return_value = [_row()]
    repository.unacknowledged.return_value = [_row()]
    service = HealthIncidentService(repository)

    payload = {"services": [_core_service(True, "ok in 100 ms")], "overall_status": "healthy"}
    service.record(payload)

    assert payload["overall_status"] == "degraded"


@pytest.mark.unit
def test_two_success_recovers_incident() -> None:
    """Two consecutive in-budget samples transition the incident to recovered."""
    repository = MagicMock()
    repository.active.return_value = _row(consecutive_successes=1)
    repository.upsert_sample.side_effect = lambda sample, now: _row(
        status="recovered", recovered_at=datetime.now(timezone.utc)
    )
    repository.list.return_value = []  # no active rows after recovery
    repository.unacknowledged.return_value = [_row(status="recovered", recovered_at=datetime.now(timezone.utc))]
    service = HealthIncidentService(repository)

    result = service.record({"services": [_core_service(True, "ok in 90 ms")], "overall_status": "healthy"})

    assert not result["active_incidents"]
    assert result["recent_incidents"][0]["status"] == "recovered"


@pytest.mark.unit
def test_failure_after_recovery_opens_new_incident() -> None:
    """After recovery, a new failure opens a fresh incident (no active row)."""
    repository = MagicMock()
    repository.active.return_value = None  # recovered row is not 'active'
    repository.upsert_sample.side_effect = lambda sample, now: _row()
    repository.list.return_value = [_row()]
    repository.unacknowledged.return_value = [_row()]
    service = HealthIncidentService(repository)

    service.record({"services": [_core_service(False, "probe timeout after 5000 ms", 5000.0)]})

    repository.upsert_sample.assert_called_once()
    # Because active() returned None the correlation path inserts a new row.


@pytest.mark.unit
def test_optional_service_is_excluded() -> None:
    """Optional probes do not create incident evidence."""
    repository = MagicMock()
    repository.list.return_value = []
    repository.unacknowledged.return_value = []
    service = HealthIncidentService(repository)

    service.record(
        {"services": [{"name": "OTALON-AI", "running": False, "detail": "probe timeout", "classification": "optional"}]}
    )

    repository.upsert_sample.assert_not_called()


@pytest.mark.unit
def test_healthy_core_without_active_incident_is_not_recorded() -> None:
    """A healthy core probe with no active incident does not upsert."""
    repository = MagicMock()
    repository.active.return_value = None
    repository.list.return_value = []
    repository.unacknowledged.return_value = []
    service = HealthIncidentService(repository)

    service.record({"services": [_core_service(True, "ok in 80 ms")]})

    repository.upsert_sample.assert_not_called()


@pytest.mark.unit
def test_recent_window_excludes_stale_recovery() -> None:
    """A recovery older than 15 minutes is not surfaced as recent."""
    repository = MagicMock()
    stale = _row(status="recovered", recovered_at=datetime.now(timezone.utc) - timedelta(minutes=30))
    repository.list.return_value = []
    repository.unacknowledged.return_value = [stale]
    service = HealthIncidentService(repository)

    summaries = service.summaries()

    assert not summaries["recent_incidents"]
    # Still an unacknowledged reminder even though it dropped out of the 15-min ring.
    assert summaries["unacknowledged_incidents"]


@pytest.mark.unit
def test_acknowledged_active_stays_health_visible_but_not_unacknowledged() -> None:
    """Acknowledged active incidents preserve health latch without Overview affordance.

    ``active_incidents`` (the latch input) comes from the status-scoped active
    query and is UNFILTERED by acknowledgement, so the header stays truthful; an
    acknowledged incident is absent from the unacknowledged projection because
    the dedicated ``unacknowledged`` query excludes it.
    """
    repository = MagicMock()
    acked = _row(acknowledged_at=datetime.now(timezone.utc), acknowledged_by="alice")
    repository.list.return_value = [acked]  # status='active' query returns it (ack-agnostic)
    repository.unacknowledged.return_value = []  # excluded from the unack projection

    summaries = HealthIncidentService(repository).summaries()

    assert summaries["active_incidents"]
    assert not summaries["unacknowledged_incidents"]


@pytest.mark.unit
def test_unacknowledged_recovered_remains_visible_until_acknowledged() -> None:
    """Recovered incidents remain in the unacknowledged projection until explicit acknowledgement."""
    repository = MagicMock()
    recovered = _row(status="recovered", recovered_at=datetime.now(timezone.utc))
    repository.list.return_value = []  # no active rows
    repository.unacknowledged.return_value = [recovered]

    summaries = HealthIncidentService(repository).summaries()

    assert summaries["recent_incidents"]
    assert summaries["unacknowledged_incidents"]


@pytest.mark.unit
def test_unacknowledged_projection_is_independent_of_50_row_history_page() -> None:
    """An unacknowledged reminder survives 50 newer incidents (CAPTURE 45).

    The unacknowledged projection MUST come from the dedicated ``unacknowledged``
    query, not the 50-row history page: if it derived from ``list(limit=50)``,
    50 newer acknowledged incidents would truncate a still-valid reminder off
    Overview. Here ``list`` (history page) is saturated with 50 newer rows that
    do NOT include the older reminder, while the dedicated query still returns
    it — the projection must reflect the dedicated query.
    """
    repository = MagicMock()
    older_unacked = _row(status="recovered", recovered_at=datetime.now(timezone.utc) - timedelta(minutes=1))
    # History page: 50 newer, acknowledged rows — the reminder is NOT on it.
    repository.list.return_value = [
        _row(status="recovered", acknowledged_at=datetime.now(timezone.utc)) for _ in range(50)
    ]
    repository.unacknowledged.return_value = [older_unacked]

    summaries = HealthIncidentService(repository).summaries()

    ids = {i["id"] for i in summaries["unacknowledged_incidents"]}
    assert str(older_unacked["id"]) in ids, "reminder must survive independently of the 50-row history page"


@pytest.mark.unit
def test_sample_carries_owning_service_and_probe_target() -> None:
    """The recorder sample records its owning service and probe target."""
    sample = HealthIncidentService._sample(_core_service(False, "probe timeout after 4200 ms", 4200.0))

    assert sample["owning_service"] == "otalon-capture"
    assert sample["probe_target"] == "Network Traffic Recorder"
    assert sample["category"] == "probe_timeout"


@pytest.mark.unit
def test_summary_exposes_backend_owned_evidence_fields() -> None:
    """Summaries expose owning service, probe target and system deep-link id."""
    summary = HealthIncidentService._summary(_row())

    assert summary["owning_service"] == "otalon-capture"
    assert summary["system_service_id"] == "otalon-capture"
    assert summary["evidence_type"] == "operational_health"
    assert isinstance(summary["id"], str)


@pytest.mark.unit
def test_running_but_over_budget_sample_is_failure_evidence() -> None:
    """A running probe above budget cannot advance recovery."""
    repository = MagicMock()
    repository.active.return_value = _row(consecutive_successes=1)
    repository.upsert_sample.side_effect = lambda sample, now: _row()
    repository.list.return_value = [_row()]
    repository.unacknowledged.return_value = [_row()]
    service = HealthIncidentService(repository)

    service.record({"services": [_core_service(True, "slow", 4200.0)]})

    sample = repository.upsert_sample.call_args.args[0]
    assert sample["in_budget"] is False
    assert sample["cause"] == "health probe failed"


# ---------------------------------------------------------------------------
# Async offloading / event-loop responsiveness
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_record_async_keeps_event_loop_responsive() -> None:
    """A blocking repository call must not freeze the event loop."""

    class _BlockingRepo:
        def active(self, service: str) -> dict[str, Any] | None:
            time.sleep(0.3)  # simulate a slow synchronous DB call
            return None

        def upsert_sample(self, sample: dict[str, Any], now: datetime) -> dict[str, Any]:
            return _row()

        def prune(self, now: datetime | None = None) -> None:
            return None

        def list(self, status: str | None = None, service: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
            return []

        def unacknowledged(self) -> list[dict[str, Any]]:
            return []

    service = HealthIncidentService(_BlockingRepo())  # type: ignore[arg-type]

    async def _scenario() -> int:
        ticks = 0

        async def _heartbeat() -> None:
            nonlocal ticks
            for _ in range(20):
                await asyncio.sleep(0.02)
                ticks += 1

        beat = asyncio.create_task(_heartbeat())
        await service.record_async({"services": [_core_service(False, "probe timeout after 4200 ms", 4200.0)]})
        await beat
        return ticks

    ticks = asyncio.run(_scenario())
    # If record_async blocked the loop the heartbeat could not have ticked.
    assert ticks >= 10


@pytest.mark.unit
def test_async_helpers_delegate_to_sync() -> None:
    """The async wrappers return the same result as the sync methods."""
    repository = MagicMock()
    repository.list.return_value = [_row()]
    repository.unacknowledged.return_value = [_row()]
    repository.get.return_value = _row()
    service = HealthIncidentService(repository)

    listed = asyncio.run(service.list_async())
    detail = asyncio.run(service.detail_async(listed[0]["id"] and uuid4()))
    summaries = asyncio.run(service.summaries_async())

    assert listed[0]["service"] == "Network Traffic Recorder"
    assert detail is not None
    assert "active_incidents" in summaries


# ---------------------------------------------------------------------------
# Emitter
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_emitter_records_once_and_publishes_additive_summaries() -> None:
    """The health emitter records each cycle once and merges summaries."""
    from otalon_api.services import emitters

    bus = MagicMock()
    published: list[dict[str, Any]] = []

    async def _publish(topic: str, data: dict[str, Any]) -> None:
        published.append({"topic": topic, "data": data})
        raise asyncio.CancelledError

    bus.publish.side_effect = _publish

    health = MagicMock()

    async def _check_all() -> dict[str, Any]:
        return {"services": [], "overall_status": "healthy"}

    health.check_all.side_effect = _check_all

    incident = MagicMock()

    async def _record(payload: dict[str, Any]) -> dict[str, Any]:
        return {"active_incidents": [_row()], "recent_incidents": []}

    incident.record_async.side_effect = _record

    with patch.object(emitters, "HEALTH_INTERVAL_S", 0):
        asyncio.run(emitters.health_emitter(bus, health, incident))

    incident.record_async.assert_called_once()
    assert published[0]["data"]["active_incidents"]
    assert "overall_status" in published[0]["data"]


# ---------------------------------------------------------------------------
# Routes / REST contract
# ---------------------------------------------------------------------------


def _settings(api_key: str = "test-secret") -> Settings:
    """Return minimal settings with an operator API key configured."""
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
        admin_api_key=api_key,
        api_port=8090,
        netcap_measurement="network_metrics",
        netcap_id_tag="uci",
        netcap_sparse_port_threshold=10,
        default_sample_max_points=500,
    )


@pytest.fixture()
def incident_override():
    """Install a mock incident service via dependency_overrides."""
    service = MagicMock()
    app.dependency_overrides[get_health_incident_service] = lambda: service
    try:
        yield service
    finally:
        app.dependency_overrides.pop(get_health_incident_service, None)


@pytest.mark.unit
def test_health_incidents_requires_operator_key() -> None:
    """The incident history route rejects unauthenticated requests."""
    with patch("otalon_api.middleware.auth.get_settings", return_value=_settings()):
        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/api/v1/operations/health-incidents")
        assert response.status_code == 401


@pytest.mark.unit
def test_health_incident_detail_requires_operator_key() -> None:
    """The incident detail route rejects unauthenticated requests."""
    with patch("otalon_api.middleware.auth.get_settings", return_value=_settings()):
        client = TestClient(app, raise_server_exceptions=False)
        response = client.get(f"/api/v1/operations/health-incidents/{uuid4()}")
        assert response.status_code == 401


@pytest.mark.unit
def test_health_incidents_list_returns_bounded_history(incident_override: MagicMock) -> None:
    """An authenticated list returns items and retention metadata."""

    async def _list(status: Any, service: Any, limit: int) -> list[dict[str, Any]]:
        return [HealthIncidentService._summary(_row())]

    incident_override.list_async.side_effect = _list
    with patch("otalon_api.middleware.auth.get_settings", return_value=_settings()):
        client = TestClient(app, raise_server_exceptions=False)
        response = client.get(
            "/api/v1/operations/health-incidents?status=active",
            headers={"X-API-Key": "test-secret"},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["retention"] == {"max_incidents": 50, "max_days": 7}
        assert body["items"][0]["service"] == "Network Traffic Recorder"


@pytest.mark.unit
def test_health_incidents_list_rejects_bad_status(incident_override: MagicMock) -> None:
    """An invalid status filter is a 422 client error."""
    with patch("otalon_api.middleware.auth.get_settings", return_value=_settings()):
        client = TestClient(app, raise_server_exceptions=False)
        response = client.get(
            "/api/v1/operations/health-incidents?status=bogus",
            headers={"X-API-Key": "test-secret"},
        )
        assert response.status_code == 422


@pytest.mark.unit
def test_health_incident_detail_404_for_bad_uuid(incident_override: MagicMock) -> None:
    """A malformed incident id yields a 404, not a 500."""
    with patch("otalon_api.middleware.auth.get_settings", return_value=_settings()):
        client = TestClient(app, raise_server_exceptions=False)
        response = client.get(
            "/api/v1/operations/health-incidents/not-a-uuid",
            headers={"X-API-Key": "test-secret"},
        )
        assert response.status_code == 404


@pytest.mark.unit
def test_health_incident_detail_404_when_missing(incident_override: MagicMock) -> None:
    """A valid but unknown incident id yields a 404."""

    async def _detail(incident_id: Any) -> None:
        return None

    incident_override.detail_async.side_effect = _detail
    with patch("otalon_api.middleware.auth.get_settings", return_value=_settings()):
        client = TestClient(app, raise_server_exceptions=False)
        response = client.get(
            f"/api/v1/operations/health-incidents/{uuid4()}",
            headers={"X-API-Key": "test-secret"},
        )
        assert response.status_code == 404


@pytest.mark.unit
def test_acknowledge_route_passes_authenticated_actor(incident_override: MagicMock) -> None:
    """Operator key identity is persisted as acknowledgement actor."""
    result = HealthIncidentService._summary(_row(acknowledged_at=datetime.now(timezone.utc)))

    async def _ack(incident_id: Any, actor: str) -> dict[str, Any]:
        assert actor == "alice"
        return result

    incident_override.acknowledge_async.side_effect = _ack
    with patch(
        "otalon_api.middleware.auth.get_settings",
        return_value=Settings(**{**_settings().model_dump(), "otalon_api_allowed_keys": "alice:operator:test-secret"}),
    ):
        client = TestClient(app, raise_server_exceptions=False)
        response = client.post(
            f"/api/v1/operations/health-incidents/{uuid4()}/acknowledge", headers={"X-API-Key": "test-secret"}
        )
    assert response.status_code == 200
