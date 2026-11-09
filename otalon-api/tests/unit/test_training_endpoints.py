"""Endpoint smoke tests for :mod:`otalon_api.api.v1.training`.

Targets the runtime retrain REST surfaces:

- ``POST /api/v1/training/retrain-boundaries``
- ``POST /api/v1/training/retrain-classifier``
- ``GET  /api/v1/training/retrain-boundaries/status``

Both go through the same :class:`ApiKeyAuthMiddleware` as the admin
surface. Auth is not configured in this test environment, so the
middleware lets requests through unauthenticated and we focus on payload
+ status-code behaviour.

The orchestrator is swapped out for a stub via FastAPI's
``dependency_overrides`` so no real PostgreSQL access occurs.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest
from fastapi.testclient import TestClient

from otalon_api.dependencies import get_runtime_retrain_service
from otalon_api.main import app
from otalon_api.services.runtime_retrain_service import (
    RetrainStatus,
    RuntimeRetrainBusy,
    RuntimeRetrainCooldown,
    RuntimeRetrainValidationError,
)
from otalon_api.settings import Settings


class _FakeService:
    """Minimal stand-in for :class:`RuntimeRetrainService`."""

    def __init__(self) -> None:
        self._status = RetrainStatus(state="idle", detail="orchestrator initialised")
        self._busy_on_start = False
        self._invalid_on_start = False
        self._cooldown_on_start = False
        self.start_calls: list[dict[str, str]] = []
        self.classifier_calls: list[dict[str, str]] = []
        self.last_intervals: list[tuple[str, str]] | None = None

    def get_status(self) -> RetrainStatus:
        return self._status

    async def start(
        self,
        window_start: str,
        window_stop: str,
        *,
        intervals: list[tuple[str, str]] | None = None,
        requested_by: str | None = None,
    ) -> RetrainStatus:
        self.start_calls.append({"window_start": window_start, "window_stop": window_stop})
        self.last_intervals = intervals
        if self._busy_on_start:
            raise RuntimeRetrainBusy("boundary retrain already in progress")
        if self._invalid_on_start:
            raise RuntimeRetrainValidationError("window_start must be ISO-8601 …")
        if self._cooldown_on_start:
            raise RuntimeRetrainCooldown("runtime retrain cooldown active", 42)
        self._status = RetrainStatus(
            state="queued",
            detail="boundary retrain queued",
            job_ref="job-abc-123",
            scope="bounds",
            started_at=datetime(2026, 5, 8, 12, 0, 0, tzinfo=timezone.utc),
            window_start=window_start,
            window_stop=window_stop,
        )
        return self._status

    async def start_classifier(
        self,
        window_start: str,
        window_stop: str,
        mitre_file: str,
        *,
        intervals: list[tuple[str, str]] | None = None,
        requested_by: str | None = None,
    ) -> RetrainStatus:
        self.last_intervals = intervals
        self.classifier_calls.append(
            {
                "window_start": window_start,
                "window_stop": window_stop,
                "mitre_file": mitre_file,
                "requested_by": requested_by or "",
            }
        )
        if self._busy_on_start:
            raise RuntimeRetrainBusy("classifier retrain already in progress")
        if self._invalid_on_start:
            raise RuntimeRetrainValidationError("window_start must be ISO-8601 …")
        self._status = RetrainStatus(
            state="queued",
            detail="classifier retrain queued",
            job_ref="job-ml-123",
            scope="ml",
            started_at=datetime(2026, 5, 8, 12, 0, 0, tzinfo=timezone.utc),
            window_start=window_start,
            window_stop=window_stop,
            mitre_file=mitre_file,
        )
        return self._status


@pytest.fixture()
def fake_service() -> _FakeService:
    return _FakeService()


@pytest.fixture()
def client(fake_service: _FakeService, monkeypatch: pytest.MonkeyPatch) -> Any:
    app.dependency_overrides[get_runtime_retrain_service] = lambda: fake_service
    test_key = "test-suite-key-do-not-use-in-prod"
    monkeypatch.setattr("otalon_api.middleware.auth.get_settings", lambda: Settings(admin_api_key=test_key))
    try:
        yield TestClient(app, headers={"X-API-Key": test_key})
    finally:
        app.dependency_overrides.pop(get_runtime_retrain_service, None)


def test_start_retrain_success_returns_initial_snapshot(client: TestClient, fake_service: _FakeService) -> None:
    """POST returns 200 and forwards the window verbatim to the service."""
    body = {
        "window_start": "2026-05-08 12:15:00",
        "window_stop": "2026-05-08 12:30:00",
    }
    response = client.post("/api/v1/training/retrain-boundaries", json=body)
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["state"] == "queued"
    assert payload["job_ref"] == "job-abc-123"
    assert payload["window_start"] == body["window_start"]
    assert payload["window_stop"] == body["window_stop"]
    assert payload["busy"] is True
    assert fake_service.start_calls == [body]


def test_start_retrain_409_when_busy(client: TestClient, fake_service: _FakeService) -> None:
    """Single-flight: a busy orchestrator yields HTTP 409."""
    fake_service._busy_on_start = True
    body = {
        "window_start": "2026-05-08 12:15:00",
        "window_stop": "2026-05-08 12:30:00",
    }
    response = client.post("/api/v1/training/retrain-boundaries", json=body)
    assert response.status_code == 409
    detail = response.json().get("detail", "")
    assert "already in progress" in detail


def test_start_retrain_429_contains_retry_after(client: TestClient, fake_service: _FakeService) -> None:
    """Cooldown rejection exposes seconds in JSON and the standard header."""
    fake_service._cooldown_on_start = True
    response = client.post(
        "/api/v1/training/retrain-boundaries",
        json={"window_start": "2026-05-08 12:15:00", "window_stop": "2026-05-08 12:30:00"},
    )
    assert response.status_code == 429
    assert response.json()["detail"]["retry_after"] == 42
    assert response.headers["retry-after"] == "42"


def test_start_retrain_400_on_invalid_window(client: TestClient, fake_service: _FakeService) -> None:
    """A validation error from the service surfaces as 400."""
    fake_service._invalid_on_start = True
    body = {
        "window_start": "garbage",
        "window_stop": "also-garbage",
    }
    response = client.post("/api/v1/training/retrain-boundaries", json=body)
    assert response.status_code == 400


def test_get_status_returns_current_snapshot(client: TestClient, fake_service: _FakeService) -> None:
    """GET returns the current orchestrator status (no side effects)."""
    response = client.get("/api/v1/training/retrain-boundaries/status")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["state"] == "idle"
    assert payload["busy"] is False
    assert "initialised" in payload["detail"]
    assert fake_service.start_calls == []


# ---------------------------------------------------------------------------
# Classifier retrain endpoint (ML-training decoupling)
# ---------------------------------------------------------------------------


def test_start_retrain_classifier_success_returns_initial_snapshot_with_ml_scope(
    client: TestClient, fake_service: _FakeService
) -> None:
    """POST returns 200, forwards window + MITRE file, surfaces scope='ml'."""
    body = {
        "window_start": "2026-05-08 12:15:00",
        "window_stop": "2026-05-08 12:30:00",
        "mitre_file": "/app/models/mitre_techniques_log.json",
    }
    response = client.post("/api/v1/training/retrain-classifier", json=body)
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["state"] == "queued"
    assert payload["scope"] == "ml"
    assert payload["job_ref"] == "job-ml-123"
    assert payload["window_start"] == body["window_start"]
    assert payload["window_stop"] == body["window_stop"]
    assert payload["mitre_file"] == body["mitre_file"]
    assert payload["busy"] is True
    assert fake_service.classifier_calls == [{**body, "requested_by": "operator"}]


def test_start_retrain_classifier_409_when_busy(client: TestClient, fake_service: _FakeService) -> None:
    """A busy orchestrator (bounds OR ML in flight) yields HTTP 409.

    Shares the single-flight lock with the bounds endpoint — see
    ``.dev/concepts/ml-training-decoupling.md``.
    """
    fake_service._busy_on_start = True
    body = {
        "window_start": "2026-05-08 12:15:00",
        "window_stop": "2026-05-08 12:30:00",
        "mitre_file": "/app/models/mitre_techniques_log.json",
    }
    response = client.post("/api/v1/training/retrain-classifier", json=body)
    assert response.status_code == 409
    detail = response.json().get("detail", "")
    assert "already in progress" in detail


def test_start_retrain_classifier_400_on_invalid_payload(client: TestClient, fake_service: _FakeService) -> None:
    """A validation error from the service surfaces as 400."""
    fake_service._invalid_on_start = True
    body = {
        "window_start": "garbage",
        "window_stop": "also-garbage",
        "mitre_file": "/app/models/mitre_techniques_log.json",
    }
    response = client.post("/api/v1/training/retrain-classifier", json=body)
    assert response.status_code == 400


def test_start_retrain_classifier_requires_mitre_file(client: TestClient, fake_service: _FakeService) -> None:
    """Missing ``mitre_file`` is rejected by Pydantic before the orchestrator
    is reached."""
    body = {
        "window_start": "2026-05-08 12:15:00",
        "window_stop": "2026-05-08 12:30:00",
    }
    response = client.post("/api/v1/training/retrain-classifier", json=body)
    assert response.status_code == 422
    assert fake_service.classifier_calls == [], (
        "the orchestrator must not be called when the request body is " "schema-invalid"
    )


def test_get_status_reports_scope_after_classifier_run(client: TestClient, fake_service: _FakeService) -> None:
    """After a classifier start, GET .../status reports ``scope='ml'``."""
    body = {
        "window_start": "2026-05-08 12:15:00",
        "window_stop": "2026-05-08 12:30:00",
        "mitre_file": "/app/models/mitre_techniques_log.json",
    }
    client.post("/api/v1/training/retrain-classifier", json=body)
    response = client.get("/api/v1/training/retrain-boundaries/status")
    assert response.status_code == 200
    payload = response.json()
    assert payload["scope"] == "ml"
    assert payload["mitre_file"] == body["mitre_file"]
    assert payload["busy"] is True


def test_boundary_route_forwards_multi_interval_contract(client: TestClient, fake_service: _FakeService) -> None:
    """The bounds route forwards the canonical multi-interval list to the service."""
    body = {
        "intervals": [
            ["2026-05-08 12:00:00", "2026-05-08 12:15:00"],
            ["2026-05-08 12:30:00", "2026-05-08 12:45:00"],
        ]
    }
    response = client.post("/api/v1/training/retrain-boundaries", json=body)
    assert response.status_code == 200, response.text
    assert fake_service.last_intervals == [
        ("2026-05-08 12:00:00", "2026-05-08 12:15:00"),
        ("2026-05-08 12:30:00", "2026-05-08 12:45:00"),
    ]


def test_classifier_route_forwards_multi_interval_contract(client: TestClient, fake_service: _FakeService) -> None:
    """The classifier route forwards intervals while remaining window-compatible."""
    body = {
        "intervals": [["2026-04-18 22:00:00", "2026-04-19 17:00:00"]],
        "mitre_file": "/app/models/mitre_techniques_log.json",
    }
    response = client.post("/api/v1/training/retrain-classifier", json=body)
    assert response.status_code == 200, response.text
    assert fake_service.last_intervals == [("2026-04-18 22:00:00", "2026-04-19 17:00:00")]


# ---------------------------------------------------------------------------
# Regression tests for API-026: missing time window → 400, not 500
# ---------------------------------------------------------------------------


def test_start_retrain_400_with_empty_body(client: TestClient) -> None:
    """Missing window on retrain-boundaries returns 400, not 500."""
    response = client.post("/api/v1/training/retrain-boundaries", json={})
    assert response.status_code == 400
    detail = response.json().get("detail", "")
    assert "intervals or window_start/window_stop is required" in detail


def test_start_retrain_classifier_400_without_window(client: TestClient) -> None:
    """Missing window on retrain-classifier returns 400, not 500."""
    response = client.post(
        "/api/v1/training/retrain-classifier",
        json={"mitre_file": "/app/models/mitre_techniques_log.json"},
    )
    assert response.status_code == 400
    detail = response.json().get("detail", "")
    assert "intervals or window_start/window_stop is required" in detail
