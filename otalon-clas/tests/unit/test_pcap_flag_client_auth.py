"""Tests for the PCAP flag client's operator-credential handling (CLAS-059).

The recorder's ``POST /anomalies/flag`` route is gated on the suite
``X-API-Key`` operator credential (``require_operator_api_key``). The client
used to post without that header, so every flag request answered HTTP 401 and
no PCAP evidence was pinned to an alarm.

The credential is read from ``ADMIN_API_KEY`` at call time. The dummy value
below is a test fixture only; the real key never appears in code, logs or
fixtures.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from loguru import logger

from otalon_clas.common.pcap_flag_client import PcapFlagClient

pytestmark = pytest.mark.unit

DUMMY_KEY = "unit-test-dummy-key"
"""Placeholder credential; asserts header propagation, not secrecy."""

START = datetime(2026, 10, 29, 12, 0, tzinfo=UTC)
END = datetime(2026, 10, 29, 12, 1, tzinfo=UTC)


class _FakeResponse:
    """Minimal stand-in for :class:`httpx.Response`."""

    def __init__(self, status_code: int = 200, body: dict[str, Any] | None = None) -> None:
        self.status_code = status_code
        self._body = body or {}
        self.text = ""

    def json(self) -> dict[str, Any]:
        return self._body


@pytest.fixture()
def recorded_posts(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Capture ``httpx.post`` calls instead of performing network IO."""

    calls: list[dict[str, Any]] = []

    def _post(url: str, **kwargs: Any) -> _FakeResponse:
        calls.append({"url": url, **kwargs})
        return _FakeResponse(body={"chunk_ids": ["chunk-1"]})

    monkeypatch.setattr(httpx, "post", _post)
    return calls


def test_flag_alarm_sends_admin_api_key_header(
    monkeypatch: pytest.MonkeyPatch,
    recorded_posts: list[dict[str, Any]],
) -> None:
    """A configured credential is sent as ``X-API-Key``; 200 yields chunk IDs."""

    monkeypatch.setenv("ADMIN_API_KEY", DUMMY_KEY)
    client = PcapFlagClient(base_url="http://recorder:9090")

    chunk_ids = client.flag_alarm(START, END, {"alarm_id": "alarm-1"})

    assert chunk_ids == ["chunk-1"]
    assert len(recorded_posts) == 1
    assert recorded_posts[0]["headers"] == {"X-API-Key": DUMMY_KEY}
    assert recorded_posts[0]["url"] == "http://recorder:9090/anomalies/flag"


def test_flag_anomaly_sends_admin_api_key_header(
    monkeypatch: pytest.MonkeyPatch,
    recorded_posts: list[dict[str, Any]],
) -> None:
    """The legacy per-sample path authenticates the same way."""

    monkeypatch.setenv("ADMIN_API_KEY", DUMMY_KEY)
    client = PcapFlagClient(base_url="http://recorder:9090")

    client.flag_anomaly({"start_ts": START.isoformat(), "end_ts": END.isoformat()})

    assert len(recorded_posts) == 1
    assert recorded_posts[0]["headers"] == {"X-API-Key": DUMMY_KEY}


def test_flag_alarm_skips_request_without_credential(
    monkeypatch: pytest.MonkeyPatch,
    recorded_posts: list[dict[str, Any]],
) -> None:
    """Without ``ADMIN_API_KEY`` no unauthenticated request is attempted."""

    monkeypatch.delenv("ADMIN_API_KEY", raising=False)
    warnings: list[str] = []
    sink_id = logger.add(lambda message: warnings.append(str(message)), level="WARNING")
    try:
        client = PcapFlagClient(base_url="http://recorder:9090")
        chunk_ids = client.flag_alarm(START, END, {"alarm_id": "alarm-1"})
    finally:
        logger.remove(sink_id)

    assert chunk_ids == []
    assert recorded_posts == []
    assert any("ADMIN_API_KEY" in warning for warning in warnings)


def test_401_is_logged_and_yields_no_chunks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A rejected request stays fire-and-forget: no raise, empty result."""

    monkeypatch.setenv("ADMIN_API_KEY", DUMMY_KEY)

    def _unauthorized(url: str, **kwargs: Any) -> _FakeResponse:
        return _FakeResponse(status_code=401)

    monkeypatch.setattr(httpx, "post", _unauthorized)
    client = PcapFlagClient(base_url="http://recorder:9090")

    assert client.flag_alarm(START, END, {"alarm_id": "alarm-1"}) == []
