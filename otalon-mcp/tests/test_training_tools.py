"""Tests for the runtime-retrain MCP proxy tools.

Covers the ``runtime-retraining-control-plane`` change: the three
proxy tools ``training.retrain_boundaries``, ``training.retrain_classifier``
and ``training.get_retrain_status`` and the corresponding spec scenarios:

- The MCP layer rejects an invalid window BEFORE any HTTP call to
  otalon-api (no side-effect can possibly be triggered); the
  classifier tool additionally rejects an empty ``mitre_file`` locally.
- A valid request is proxied verbatim to the matching
  ``POST /api/v1/training/...`` endpoint and the api's response is
  surfaced back to the caller (with a chat-friendly hint).
- A 409 from the api is surfaced as ``{"ok": False, "status": "busy"}``
  so the chat agent can present the single-flight result without
  treating it as a network failure.
- The status proxy maps a successful api response into the same shape.
  The runtime path performs NO container restart; the terminal job
  state is ``succeeded`` or ``failed``.

A real otalon-api is not required: ``httpx.Client`` is monkey-
patched to a :class:`httpx.MockTransport` that records the outbound
request and returns scripted responses.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

# Make ``src/`` importable like the other mcp tests do.
from otalon_mcp.tools import training as training_tools


@pytest.fixture(autouse=True)
def _init_training_tool() -> None:
    """Reset the module-level state before every test."""
    training_tools.init(api_url="http://api.test:8090", api_key="test-key", timeout=5.0)


def _install_mock_transport(
    monkeypatch: pytest.MonkeyPatch,
    handler: "callable[[httpx.Request], httpx.Response]",
    captured: list[httpx.Request] | None = None,
) -> None:
    """Replace ``httpx.Client`` inside ``tools.training`` with one that uses a MockTransport."""

    def _wrapped(request: httpx.Request) -> httpx.Response:
        if captured is not None:
            captured.append(request)
        return handler(request)

    transport = httpx.MockTransport(_wrapped)

    class _Client(httpx.Client):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            kwargs["transport"] = transport
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(training_tools.httpx, "Client", _Client)


def _confirm_boundaries() -> str:
    """Issue a confirmation nonce for proxy-focused tests."""
    result = training_tools.retrain_boundaries(
        window_start="2026-05-08 12:15:00",
        window_stop="2026-05-08 12:30:00",
    )
    assert result["requires"] == "confirm"
    return str(result["nonce"])


# ---------------------------------------------------------------------------
# Window validation — happens BEFORE any network call.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "start,stop,expected_token",
    [
        ("garbage", "2026-05-08 12:30:00", "ISO-8601"),
        ("2026-05-08 12:15:00", "", "must be a non-empty"),
        ("", "2026-05-08 12:30:00", "must be a non-empty"),
        ("2026-05-08 12:30:00", "2026-05-08 12:15:00", "strictly less"),
    ],
)
def test_retrain_boundaries_rejects_invalid_window_locally(
    monkeypatch: pytest.MonkeyPatch,
    start: str,
    stop: str,
    expected_token: str,
) -> None:
    """A bad window MUST NOT touch the api at all."""

    def _fail_if_called(_request: httpx.Request) -> httpx.Response:
        raise AssertionError("api MUST NOT be called for an invalid window")

    _install_mock_transport(monkeypatch, _fail_if_called)

    result = training_tools.retrain_boundaries(window_start=start, window_stop=stop)
    assert result["ok"] is False
    assert expected_token in result["error"]


# ---------------------------------------------------------------------------
# Happy path: proxy to api.
# ---------------------------------------------------------------------------


def test_retrain_boundaries_proxies_valid_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A valid window is forwarded verbatim and the api response surfaces."""
    captured: list[httpx.Request] = []

    def _handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/api/v1/training/retrain-boundaries"
        body = json.loads(request.content.decode("utf-8"))
        assert body == {
            "window_start": "2026-05-08 12:15:00",
            "window_stop": "2026-05-08 12:30:00",
        }
        assert request.headers.get("X-API-Key") == "test-key"
        # Runtime path: a queued job is returned (no env-mutation state).
        return httpx.Response(
            200,
            json={
                "state": "queued",
                "detail": "boundary retrain queued",
                "job_ref": "job-abc-123",
                "started_at": "2026-05-08T12:00:00+00:00",
                "window_start": body["window_start"],
                "window_stop": body["window_stop"],
                "history_snapshot_rows": 0,
                "finished_at": None,
                "error": None,
            },
        )

    _install_mock_transport(monkeypatch, _handler, captured)

    confirmation = training_tools.retrain_boundaries(
        window_start="2026-05-08 12:15:00",
        window_stop="2026-05-08 12:30:00",
    )
    assert confirmation["ok"] is False
    assert confirmation["requires"] == "confirm"
    assert len(captured) == 0

    result = training_tools.retrain_boundaries(
        window_start="2026-05-08 12:15:00",
        window_stop="2026-05-08 12:30:00",
        nonce=confirmation["nonce"],
    )

    assert len(captured) == 1
    assert result["ok"] is True
    assert result["state"] == "queued"
    assert result["job_ref"] == "job-abc-123"
    assert result["window_start"] == "2026-05-08 12:15:00"
    assert result["window_stop"] == "2026-05-08 12:30:00"
    # Chat-friendly hint is present so the LLM surfaces the in-process
    # (no container restart) behaviour + the snapshot guarantee to the
    # operator.
    hint = result["hint"].lower()
    assert "in-process" in hint and "without restarting" in hint
    assert "bounds_history" in result["hint"]


def test_retrain_boundaries_proxies_multiple_intervals(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Chat can forward one logical retrain with multiple intervals."""
    captured: list[httpx.Request] = []

    def _handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode("utf-8"))
        assert body["intervals"] == [
            ["2026-07-06 16:00:00", "2026-07-06 17:00:00"],
            ["2026-07-06 18:00:00", "2026-07-06 19:00:00"],
        ]
        return httpx.Response(200, json={"state": "queued", "job_ref": "job-multi", "intervals": body["intervals"]})

    _install_mock_transport(monkeypatch, _handler, captured)
    intervals = [
        ["2026-07-06 16:00:00", "2026-07-06 17:00:00"],
        ["2026-07-06 18:00:00", "2026-07-06 19:00:00"],
    ]
    confirmation = training_tools.retrain_boundaries(
        window_start=intervals[0][0],
        window_stop=intervals[-1][1],
        intervals=intervals,
    )
    result = training_tools.retrain_boundaries(
        window_start=intervals[0][0],
        window_stop=intervals[-1][1],
        intervals=intervals,
        nonce=confirmation["nonce"],
    )

    assert result["ok"] is True
    assert result["intervals"] == intervals
    assert len(captured) == 1


# ---------------------------------------------------------------------------
# Single-flight: 409 surfaces as a structured busy error.
# ---------------------------------------------------------------------------


def test_retrain_boundaries_surfaces_409_busy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the api returns 409 the tool yields a structured busy error."""

    def _handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            409,
            json={"detail": "boundary retrain already in progress (state=running)"},
        )

    _install_mock_transport(monkeypatch, _handler)
    nonce = _confirm_boundaries()

    result = training_tools.retrain_boundaries(
        window_start="2026-05-08 12:15:00",
        window_stop="2026-05-08 12:30:00",
        nonce=nonce,
    )
    assert result["ok"] is False
    assert result["status"] == "busy"
    assert "already in progress" in result["error"]


# ---------------------------------------------------------------------------
# Network failure → structured ``api unreachable``.
# ---------------------------------------------------------------------------


def test_retrain_boundaries_handles_network_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Transport-level failures yield a structured ok=False, never raise."""

    def _handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    _install_mock_transport(monkeypatch, _handler)
    nonce = _confirm_boundaries()

    result = training_tools.retrain_boundaries(
        window_start="2026-05-08 12:15:00",
        window_stop="2026-05-08 12:30:00",
        nonce=nonce,
    )
    assert result["ok"] is False
    assert "unreachable" in result["error"]


def test_retrain_boundaries_expired_nonce_reissues_without_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Expired confirmation cannot reach the API and gets replaced."""
    captured: list[httpx.Request] = []
    _install_mock_transport(monkeypatch, lambda _: pytest.fail("API must not be called"), captured)
    monkeypatch.setenv("OTALON_MCP_CONFIRM_NONCE_TTL", "1")
    first = _confirm_boundaries()
    training_tools._state["confirm_nonce_expires_at"] = 0.0

    result = training_tools.retrain_boundaries(
        window_start="2026-05-08 12:15:00",
        window_stop="2026-05-08 12:30:00",
        nonce=first,
    )

    assert result["ok"] is False
    assert result["requires"] == "confirm"
    assert result["nonce"] != first
    assert captured == []


# ---------------------------------------------------------------------------
# get_retrain_status proxy.
# ---------------------------------------------------------------------------


def test_get_retrain_status_proxies_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GET /status returns the api payload verbatim under ok=True."""
    captured: list[httpx.Request] = []

    def _handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == "/api/v1/training/retrain-boundaries/status"
        assert request.headers.get("X-API-Key") == "test-key"
        # Runtime path: the terminal job state is 'succeeded'|'failed'
        # (there is no container restart and no 'live' mode-restore step).
        return httpx.Response(
            200,
            json={
                "state": "succeeded",
                "detail": "training and publication complete",
                "job_ref": "job-abc-123",
                "started_at": "2026-05-08T12:00:00+00:00",
                "finished_at": "2026-05-08T12:08:00+00:00",
                "window_start": "2026-05-08 12:15:00",
                "window_stop": "2026-05-08 12:30:00",
                "history_snapshot_rows": 47,
                "error": None,
            },
        )

    _install_mock_transport(monkeypatch, _handler, captured)

    result = training_tools.get_retrain_status()
    assert len(captured) == 1
    assert result["ok"] is True
    assert result["state"] == "succeeded"
    assert result["history_snapshot_rows"] == 47


# ---------------------------------------------------------------------------
# retrain_classifier — mirrors the boundaries suite (audit F10 / task 8.7).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "start,stop,expected_token",
    [
        ("garbage", "2026-05-08 12:30:00", "ISO-8601"),
        ("2026-05-08 12:30:00", "2026-05-08 12:15:00", "strictly less"),
    ],
)
def test_retrain_classifier_rejects_invalid_window_locally(
    monkeypatch: pytest.MonkeyPatch,
    start: str,
    stop: str,
    expected_token: str,
) -> None:
    """A bad window MUST NOT touch the api at all (classifier path)."""

    def _fail_if_called(_request: httpx.Request) -> httpx.Response:
        raise AssertionError("api MUST NOT be called for an invalid window")

    _install_mock_transport(monkeypatch, _fail_if_called)

    result = training_tools.retrain_classifier(
        window_start=start,
        window_stop=stop,
        mitre_file="/labels/mitre.json",
    )
    assert result["ok"] is False
    assert expected_token in result["error"]


def test_retrain_classifier_requires_mitre_file_locally(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An empty mitre_file is rejected before any network call."""

    def _fail_if_called(_request: httpx.Request) -> httpx.Response:
        raise AssertionError("api MUST NOT be called when mitre_file is empty")

    _install_mock_transport(monkeypatch, _fail_if_called)

    result = training_tools.retrain_classifier(
        window_start="2026-05-08 12:15:00",
        window_stop="2026-05-08 12:30:00",
        mitre_file="   ",
    )
    assert result["ok"] is False
    assert "mitre_file" in result["error"]


def test_retrain_classifier_proxies_valid_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A valid classifier request is forwarded and the api response surfaces."""
    captured: list[httpx.Request] = []

    def _handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/api/v1/training/retrain-classifier"
        body = json.loads(request.content.decode("utf-8"))
        assert body == {
            "window_start": "2026-05-08 12:15:00",
            "window_stop": "2026-05-08 12:30:00",
            "mitre_file": "/labels/mitre.json",
        }
        assert request.headers.get("X-API-Key") == "test-key"
        return httpx.Response(
            200,
            json={
                "state": "queued",
                "detail": "classifier retrain queued",
                "job_ref": "job-ml-123",
                "scope": "ml",
                "started_at": None,
                "window_start": body["window_start"],
                "window_stop": body["window_stop"],
                "mitre_file": body["mitre_file"],
            },
        )

    _install_mock_transport(monkeypatch, _handler, captured)

    result = training_tools.retrain_classifier(
        window_start="2026-05-08 12:15:00",
        window_stop="2026-05-08 12:30:00",
        mitre_file="/labels/mitre.json",
    )

    assert len(captured) == 1
    assert result["ok"] is True
    assert result["scope"] == "ml"
    assert result["job_ref"] == "job-ml-123"
    assert result["mitre_file"] == "/labels/mitre.json"


def test_retrain_classifier_proxies_multiple_intervals(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Classifier retraining forwards the same multi-interval contract."""
    intervals = [
        ["2026-04-18 22:00:00", "2026-04-19 01:00:00"],
        ["2026-04-19 12:00:00", "2026-04-19 17:00:00"],
    ]

    def _handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode("utf-8"))
        assert body["intervals"] == intervals
        return httpx.Response(
            200,
            json={"state": "queued", "job_ref": "job-clf-multi", "scope": "ml", "intervals": intervals},
        )

    _install_mock_transport(monkeypatch, _handler)
    result = training_tools.retrain_classifier(
        window_start=intervals[0][0],
        window_stop=intervals[-1][1],
        intervals=intervals,
        mitre_file="/labels/mitre.json",
    )

    assert result["ok"] is True
    assert result["intervals"] == intervals


def test_retrain_classifier_surfaces_409_busy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A 409 (shared single-flight) surfaces as a structured busy error."""

    def _handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            409,
            json={"detail": "runtime retrain already in progress"},
        )

    _install_mock_transport(monkeypatch, _handler)

    result = training_tools.retrain_classifier(
        window_start="2026-05-08 12:15:00",
        window_stop="2026-05-08 12:30:00",
        mitre_file="/labels/mitre.json",
    )
    assert result["ok"] is False
    assert result["status"] == "busy"
    assert "already in progress" in result["error"]
