"""Tests for the outbound job reporter (A4).

The worker never writes PostgreSQL — it reports over HTTP. Because the owner
endpoint arrives in a later wave, an unreachable target must be a bounded,
logged retry rather than a crash.
"""

from __future__ import annotations

from typing import Any, List
from urllib import error

import pytest

from pcap_import.models import ImportState, JobUpdate
from pcap_import.reporter import HttpJobReporter, NullJobReporter, create_reporter
from pcap_import.settings import ReporterConfig

pytestmark = pytest.mark.unit


class FakeResponse:
    """Context-manager double mimicking ``urlopen``'s return value."""

    def __init__(self, status: int) -> None:
        self.status = status

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *_exc: Any) -> None:
        return None


@pytest.fixture
def config() -> ReporterConfig:
    """Reporter configuration with retries fast enough for a unit test."""

    return ReporterConfig(
        base_url="http://api:8090",
        token="worker-token",
        max_attempts=3,
        retry_backoff_s=0.0,
    )


class TestReporterSelection:
    """An unconfigured owner URL must not produce a broken HTTP reporter."""

    def test_empty_base_url_yields_null_reporter(self) -> None:
        assert isinstance(create_reporter(ReporterConfig()), NullJobReporter)

    def test_configured_base_url_yields_http_reporter(self, config: ReporterConfig) -> None:
        assert isinstance(create_reporter(config), HttpJobReporter)

    def test_null_reporter_accepts_updates(self) -> None:
        assert NullJobReporter().report("job-1", JobUpdate(state=ImportState.COMPLETED)) is True


class TestHttpReporter:
    """Delivery, authentication and bounded retry behaviour."""

    def test_successful_patch_reports_true(self, config: ReporterConfig, monkeypatch: pytest.MonkeyPatch) -> None:
        seen: List[Any] = []

        def fake_urlopen(request_obj: Any, timeout: float = 0.0) -> FakeResponse:
            seen.append(request_obj)
            return FakeResponse(200)

        monkeypatch.setattr("pcap_import.reporter.request.urlopen", fake_urlopen)

        assert HttpJobReporter(config).report("job-1", JobUpdate(state=ImportState.RUNNING)) is True
        assert len(seen) == 1
        assert seen[0].get_method() == "PATCH"
        assert seen[0].full_url == "http://api:8090/internal/jobs/job-1"
        assert seen[0].headers["Authorization"] == "Bearer worker-token"

    def test_unreachable_owner_is_retried_then_given_up(
        self, config: ReporterConfig, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        attempts: List[int] = []

        def fake_urlopen(_request_obj: Any, timeout: float = 0.0) -> FakeResponse:
            attempts.append(1)
            raise error.URLError("connection refused")

        monkeypatch.setattr("pcap_import.reporter.request.urlopen", fake_urlopen)

        assert HttpJobReporter(config).report("job-1", JobUpdate(state=ImportState.FAILED)) is False
        assert len(attempts) == int(config.max_attempts)

    def test_retry_stops_at_first_success(self, config: ReporterConfig, monkeypatch: pytest.MonkeyPatch) -> None:
        attempts: List[int] = []

        def fake_urlopen(_request_obj: Any, timeout: float = 0.0) -> FakeResponse:
            attempts.append(1)
            if len(attempts) == 1:
                raise error.URLError("not up yet")
            return FakeResponse(204)

        monkeypatch.setattr("pcap_import.reporter.request.urlopen", fake_urlopen)

        assert HttpJobReporter(config).report("job-1", JobUpdate(state=ImportState.COMPLETED)) is True
        assert len(attempts) == 2

    def test_http_error_is_not_fatal(self, config: ReporterConfig, monkeypatch: pytest.MonkeyPatch) -> None:
        def fake_urlopen(_request_obj: Any, timeout: float = 0.0) -> FakeResponse:
            raise error.HTTPError("http://api:8090", 404, "Not Found", {}, None)  # type: ignore[arg-type]

        monkeypatch.setattr("pcap_import.reporter.request.urlopen", fake_urlopen)

        assert HttpJobReporter(config).report("job-1", JobUpdate(state=ImportState.RUNNING)) is False

    def test_payload_omits_unset_fields(self, config: ReporterConfig, monkeypatch: pytest.MonkeyPatch) -> None:
        bodies: List[bytes] = []

        def fake_urlopen(request_obj: Any, timeout: float = 0.0) -> FakeResponse:
            bodies.append(request_obj.data)
            return FakeResponse(200)

        monkeypatch.setattr("pcap_import.reporter.request.urlopen", fake_urlopen)

        HttpJobReporter(config).report("job-1", JobUpdate(latest_event="reading"))

        import json

        payload = json.loads(bodies[0])
        assert payload == {"latest_event": "reading"}

    def test_missing_token_sends_no_authorization_header(self, monkeypatch: pytest.MonkeyPatch) -> None:
        seen: List[Any] = []

        def fake_urlopen(request_obj: Any, timeout: float = 0.0) -> FakeResponse:
            seen.append(request_obj)
            return FakeResponse(200)

        monkeypatch.setattr("pcap_import.reporter.request.urlopen", fake_urlopen)
        reporter = HttpJobReporter(ReporterConfig(base_url="http://api:8090", max_attempts=1))

        reporter.report("job-1", JobUpdate(state=ImportState.RUNNING))

        assert "Authorization" not in seen[0].headers
