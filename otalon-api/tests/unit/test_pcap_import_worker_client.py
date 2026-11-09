"""Tests for the import-worker client contract (UI-078 Wave B, B8).

The worker shipped by Wave A (``otalon-capture``, commit ``d4c522d``) has
one slot and no queue. This module pins the three outcomes the api must
distinguish — accepted, busy, unreachable — plus the permanent rejection,
against ``respx``-mocked transports rather than a live worker.
"""

from __future__ import annotations

from datetime import datetime, timezone

import httpx
import pytest
import respx

from otalon_api import dependencies
from otalon_api.services.pcap_import_worker_client import (
    PcapImportWorkerClient,
    WorkerBusy,
    WorkerRejected,
    WorkerUnavailable,
)
from otalon_api.settings import Settings

pytestmark = pytest.mark.unit

_BASE = "http://netcap-pcap-import:9092"
_API_KEY = "synthetic-worker-api-key"


def _client(api_key: str | None = _API_KEY) -> PcapImportWorkerClient:
    """Return a client pointed at the mocked worker base URL."""
    return PcapImportWorkerClient(_BASE, timeout=1.0, api_key=api_key)


class TestDelivery:
    """``POST /import`` — the three outcomes that matter."""

    @respx.mock
    async def test_accepted_delivery_returns_the_body(self) -> None:
        """A ``202`` means the import is running asynchronously."""
        route = respx.post(f"{_BASE}/import").mock(
            return_value=httpx.Response(202, json={"display_id": "J-1", "state": "running"})
        )
        body = await _client().deliver(
            "J-1",
            "/import/abc.pcap",
            time_start=datetime(2026, 6, 1, 10, 0, tzinfo=timezone.utc),
            time_end=datetime(2026, 6, 1, 10, 15, tzinfo=timezone.utc),
            original_filename="kunde.pcap",
        )
        assert body["state"] == "running"
        sent = route.calls[0].request
        assert sent.headers["X-API-Key"] == _API_KEY
        assert b'"display_id":"J-1"' in sent.content.replace(b" ", b"")
        assert b"/import/abc.pcap" in sent.content
        assert _API_KEY.encode() not in sent.content

    @respx.mock
    async def test_busy_worker_raises_worker_busy_with_the_running_id(self) -> None:
        """A ``409`` names the job currently occupying the slot."""
        respx.post(f"{_BASE}/import").mock(
            return_value=httpx.Response(
                409,
                json={"detail": {"message": "Worker is busy.", "running_display_id": "J-9"}},
            )
        )
        with pytest.raises(WorkerBusy) as excinfo:
            await _client().deliver("J-1", "/import/abc.pcap")
        assert excinfo.value.running_display_id == "J-9"

    @respx.mock
    async def test_validation_failure_raises_worker_rejected(self) -> None:
        """A ``422`` is a permanent payload defect, not a busy signal."""
        respx.post(f"{_BASE}/import").mock(return_value=httpx.Response(422, json={"detail": "bad file_path"}))
        with pytest.raises(WorkerRejected) as excinfo:
            await _client().deliver("J-1", "relative/path.pcap")
        assert excinfo.value.status_code == 422

    @respx.mock
    async def test_missing_credential_is_rejected_by_worker(self) -> None:
        """A missing key remains missing and the worker's auth rejection surfaces."""
        route = respx.post(f"{_BASE}/import").mock(return_value=httpx.Response(401, json={"detail": "unauthorized"}))
        with pytest.raises(WorkerRejected) as excinfo:
            await _client(api_key=None).deliver("J-1", "/import/abc.pcap")
        assert excinfo.value.status_code == 401
        assert "X-API-Key" not in route.calls[0].request.headers

    @respx.mock
    async def test_wrong_credential_is_rejected_by_worker(self) -> None:
        """An invalid key does not bypass the worker's existing auth policy."""
        route = respx.post(f"{_BASE}/import").mock(return_value=httpx.Response(403, json={"detail": "forbidden"}))
        with pytest.raises(WorkerRejected) as excinfo:
            await _client("synthetic-wrong-worker-key").deliver("J-1", "/import/abc.pcap")
        assert excinfo.value.status_code == 403
        assert route.calls[0].request.headers["X-API-Key"] == "synthetic-wrong-worker-key"

    @respx.mock
    async def test_transport_failure_raises_worker_unavailable(self) -> None:
        """An unreachable worker is distinguishable from a rejection."""
        respx.post(f"{_BASE}/import").mock(side_effect=httpx.ConnectError("no route"))
        with pytest.raises(WorkerUnavailable):
            await _client().deliver("J-1", "/import/abc.pcap")

    @respx.mock
    async def test_optional_fields_are_omitted_when_unknown(self) -> None:
        """An unreadable capture window is left out, not sent as null."""
        route = respx.post(f"{_BASE}/import").mock(return_value=httpx.Response(202, json={}))
        await _client().deliver("J-1", "/import/abc.pcap")
        content = route.calls[0].request.content
        assert b"time_start" not in content
        assert b"original_filename" not in content


class TestHealth:
    """``GET /health`` — the orphan-detection signal."""

    @respx.mock
    async def test_health_reports_the_busy_slot(self) -> None:
        """A busy worker names the job it is processing."""
        respx.get(f"{_BASE}/health").mock(
            return_value=httpx.Response(
                200, json={"status": "ok", "busy": True, "state": "running", "display_id": "J-7"}
            )
        )
        health = await _client().health()
        assert health is not None
        assert health.busy is True
        assert health.display_id == "J-7"

    @respx.mock
    async def test_health_of_an_unreachable_worker_is_none(self) -> None:
        """No answer means "unknown", never "idle"."""
        respx.get(f"{_BASE}/health").mock(side_effect=httpx.ConnectError("down"))
        assert await _client().health() is None


class TestCancel:
    """``POST /import/cancel`` — best-effort abort."""

    @respx.mock
    async def test_cancel_accepted(self) -> None:
        """A ``202`` confirms the worker is stopping."""
        route = respx.post(f"{_BASE}/import/cancel").mock(
            return_value=httpx.Response(202, json={"display_id": "J-1", "state": "cancelling"})
        )
        assert await _client().cancel("J-1") is True
        sent = route.calls[0].request
        assert sent.headers["X-API-Key"] == _API_KEY
        assert b'"display_id":"J-1"' in sent.content.replace(b" ", b"")
        assert _API_KEY.encode() not in sent.content

    @respx.mock
    async def test_cancel_when_idle_is_not_an_error(self) -> None:
        """A ``409`` (nothing running) is reported as "not cancelled"."""
        respx.post(f"{_BASE}/import/cancel").mock(return_value=httpx.Response(409, json={"detail": "idle"}))
        assert await _client().cancel("J-1") is False

    @respx.mock
    async def test_cancel_survives_an_unreachable_worker(self) -> None:
        """An unreachable worker does not break the cancel path."""
        respx.post(f"{_BASE}/import/cancel").mock(side_effect=httpx.ConnectError("down"))
        assert await _client().cancel("J-1") is False


@pytest.mark.asyncio
async def test_worker_client_factory_uses_admin_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """The worker client receives the configured API-to-capture credential."""
    settings = Settings(
        admin_api_key="synthetic-factory-worker-key",
        pcap_import_worker_token="synthetic-report-channel-token",
        pcap_import_worker_host="netcap-pcap-import",
        _env_file=None,
    )
    monkeypatch.setattr(dependencies, "get_settings", lambda: settings)
    dependencies.get_pcap_import_worker_client.cache_clear()
    try:
        with respx.mock:
            route = respx.post(f"{_BASE}/import").mock(return_value=httpx.Response(202, json={}))
            client = dependencies.get_pcap_import_worker_client()
            await client.deliver("J-1", "/import/abc.pcap")
        sent = route.calls[0].request
        assert sent.headers["X-API-Key"] == "synthetic-factory-worker-key"
        assert b"synthetic-factory-worker-key" not in sent.content
    finally:
        dependencies.get_pcap_import_worker_client.cache_clear()
