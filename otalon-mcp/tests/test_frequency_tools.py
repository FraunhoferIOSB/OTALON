"""Tests for chat-triggered rhythm-profile corrections."""

from __future__ import annotations

import json
from typing import Any

import httpx

from otalon_mcp.tools import frequency as frequency_tools


def _install(monkeypatch: Any, handler: Any) -> None:
    transport = httpx.MockTransport(handler)

    class Client(httpx.Client):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            kwargs["transport"] = transport
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(frequency_tools.httpx, "Client", Client)
    frequency_tools.init("http://api.test:8090", "key")


def test_preview_then_apply_uses_snapshot_and_optional_reason(monkeypatch: Any) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path.endswith("/preview"):
            return httpx.Response(
                200, json={"before_snapshot": {"tolerance_factor_override": None, "absence_factor_override": 2.0}}
            )
        body = json.loads(request.content)
        assert body["before_snapshot"]["absence_factor_override"] == 2.0
        assert body["reason"] == ""
        return httpx.Response(200, json={"history_id": "one", "notified": True})

    _install(monkeypatch, handler)
    result = frequency_tools.correct_rhythm_profile("a/b", tolerance_factor_override=1.5)
    assert result["ok"] is True
    assert [request.url.path.rsplit("/", 1)[-1] for request in requests] == ["preview", "apply"]
    # Path segment must survive Starlette's route-matching decode, so the
    # tool double-encodes it (mirrors the UI's `seriesPathSegment()`); the
    # body-carried `series_id` stays authoritative for the actual value.
    assert requests[0].url.path == "/api/v1/frequency/a%2Fb/override/preview"


def test_stale_snapshot_surfaces_409(monkeypatch: Any) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/preview"):
            return httpx.Response(200, json={"before_snapshot": {}})
        return httpx.Response(409, json={"detail": "frequency profile changed since preview"})

    _install(monkeypatch, handler)
    result = frequency_tools.correct_rhythm_profile("series", absence_factor_override=3.0)
    assert result == {
        "ok": False,
        "status": 409,
        "error": "stale rhythm profile snapshot (409): frequency profile changed since preview",
    }
