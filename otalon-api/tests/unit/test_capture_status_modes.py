"""Bounded producer-to-API status projection, without acquisition or live services."""

from __future__ import annotations

import ast
import json
from dataclasses import asdict, fields
from pathlib import Path
from types import SimpleNamespace
from typing import Any, get_args
from unittest.mock import MagicMock

import httpx
import pytest
import respx
from capture_runtime import CaptureIntent, CaptureSnapshot, ReasonCode
from desktop_ingest.main import Status
from fastapi import FastAPI
from fastapi.testclient import TestClient
from loguru import logger
from pcap_recorder.api import CaptureStatusProvider, CaptureStatusResponse, PcapService, create_app
from pcap_recorder.main import RuntimeState
from pydantic import ValidationError

from otalon_api.api.schemas.operations import CaptureStatus
from otalon_api.api.v1.operations import router
from otalon_api.dependencies import get_capture_status_service
from otalon_api.middleware.auth import ApiKeyAuthMiddleware
from otalon_api.services.capture_status_service import CaptureStatusResult, CaptureStatusService
from otalon_api.settings import Settings

pytestmark = pytest.mark.unit

_UPSTREAM = "http://a5b-recorder:9090/status"
_ROUTE = "/api/v1/operations/capture-status"
_KEY = "constructed-a5b-operator"
_LEGACY = {"interface": None, "link_up": None, "recording": None, "drops_24h_pct": None, "overflows": None}
_ADDITIVE = {
    "capture_type": None,
    "backend": None,
    "source_state": "degraded",
    "reason_code": None,
    "retry_attempt": None,
    "retry_limit": None,
    "retry_in_seconds": None,
    "retry_exhausted": None,
    "observation_age_seconds": None,
}
_DEFAULT = {**_LEGACY, **_ADDITIVE}
_DEGRADED = {**_DEFAULT, "reason_code": "upstream_unavailable"}


def _settings(recorder_key: str = "") -> SimpleNamespace:
    return SimpleNamespace(
        pcap_recorder_host="a5b-recorder",
        pcap_recorder_port=9090,
        pcap_recorder_timeout_s=1.25,
        pcap_recorder_api_key=recorder_key,
    )


def _client(service: CaptureStatusService, monkeypatch: pytest.MonkeyPatch, key: str = _KEY) -> TestClient:
    settings = Settings(_env_file=None, admin_api_key=key, otalon_api_allowed_keys="")
    monkeypatch.setattr("otalon_api.middleware.auth.get_settings", lambda: settings)
    app = FastAPI()
    app.include_router(router)
    app.add_middleware(ApiKeyAuthMiddleware)
    app.dependency_overrides[get_capture_status_service] = lambda: service
    return TestClient(app, headers={"X-API-Key": _KEY})


def _producer(provider: CaptureStatusProvider) -> tuple[TestClient, MagicMock]:
    service = MagicMock(spec=PcapService)
    return TestClient(create_app(service, status_provider=provider)), service


def _emitted(client: TestClient) -> dict[str, Any]:
    response = client.get("/status")
    assert response.status_code == 200
    assert set(response.json()) == set(_DEFAULT)
    return response.json()


def _assert_route(payload: dict[str, Any], monkeypatch: pytest.MonkeyPatch, producer: TestClient | None = None) -> None:
    with respx.mock(assert_all_called=True) as upstream:

        def forward(request: httpx.Request) -> httpx.Response:
            if producer is None:
                return httpx.Response(200, json=payload)
            emitted = producer.get("/status", headers=dict(request.headers))
            assert emitted.status_code == 200
            return httpx.Response(200, content=emitted.content)

        request = upstream.get(_UPSTREAM).mock(side_effect=forward)
        response = _client(CaptureStatusService(_settings()), monkeypatch).get(_ROUTE)
    assert response.status_code == 200
    assert response.json() == payload
    assert request.call_count == 1
    assert request.calls.last.request.method == "GET"


def test_complete_defaults_and_actual_serializer_contract() -> None:
    assert CaptureStatus().model_dump(mode="json") == _DEFAULT
    assert asdict(CaptureStatusResult(None, None, None, None, None)) == _DEFAULT
    assert asdict(CaptureStatusResult.degraded()) == _DEGRADED
    assert CaptureStatusResponse().model_dump(mode="json") == _DEFAULT
    assert set(CaptureStatus.model_fields) == set(CaptureStatusResponse.model_fields) == set(_DEFAULT)
    assert {field.name for field in fields(CaptureSnapshot)} == set(_ADDITIVE)
    assert {field.name for field in fields(CaptureStatusResult)} == set(_DEFAULT)
    schema = CaptureStatus.model_json_schema()["properties"]
    assert schema["source_state"]["default"] == "degraded"
    for name in set(_DEFAULT) - {"source_state"}:
        assert schema[name]["default"] is None


@pytest.mark.parametrize("backend,recording", [("native", False), ("wsl", None)])
def test_real_none_producers_keep_local_and_remote_truth_distinct(
    backend: str, recording: bool | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger = MagicMock()
    state = RuntimeState(intent=CaptureIntent.NONE)
    provider = {
        "native": CaptureStatusProvider(state, snapshot=lambda: state.snapshot),
        "wsl": Status(ledger, intent=CaptureIntent.NONE),
    }[backend]
    producer, service = _producer(provider)
    expected = {
        **_DEFAULT,
        "recording": recording,
        "capture_type": "NONE",
        "backend": backend,
        "source_state": "disabled",
        "reason_code": "none_selected",
        "retry_attempt": 0,
        "retry_limit": 5,
        "retry_exhausted": False,
    }
    assert _emitted(producer) == expected
    _assert_route(expected, monkeypatch, producer)
    assert ledger.mock_calls == []
    assert service.mock_calls == []
    assert state.recorder is None
    assert state.acquisition is None


_NATIVE_CASES = [
    ("waiting", None, 0, None, False, False),
    ("recording", None, 1, None, False, True),
    ("degraded", "dependency_unavailable", 1, None, False, True),
    ("blocked", "privilege_denied", 1, None, False, True),
    ("waiting", "source_absent", 1, 2, False, False),
    ("waiting", "source_absent", 2, 4, False, False),
    ("degraded", "source_absent", 3, 8, False, False),
    ("degraded", "source_absent", 4, 16, False, False),
    ("waiting", "retry_exhausted", 5, None, True, False),
    ("degraded", "retry_exhausted", 5, None, True, False),
]


@pytest.mark.parametrize("source,reason,attempt,delay,exhausted,running", _NATIVE_CASES)
def test_real_native_live_owner_snapshots_are_not_reinterpreted(
    source: str,
    reason: str | None,
    attempt: int,
    delay: int | None,
    exhausted: bool,
    running: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = CaptureSnapshot("LIVE", "native", source, reason, attempt, 5, delay, exhausted)
    state = RuntimeState(intent=CaptureIntent.LIVE)
    recorder = MagicMock(interface="constructed0", is_running=running)
    state.recorder = recorder
    state.acquisition = SimpleNamespace(snapshot=snapshot)
    monkeypatch.setattr("pcap_recorder.api._read_link_up", lambda _: False)
    producer, service = _producer(CaptureStatusProvider(state, snapshot=lambda: state.snapshot))
    expected = {
        **_LEGACY,
        "interface": "constructed0",
        "link_up": False,
        "recording": running,
        **CaptureStatusResponse(**asdict(snapshot)).model_dump(mode="json", include=set(_ADDITIVE)),
    }
    assert _emitted(producer) == expected
    _assert_route(expected, monkeypatch, producer)
    assert recorder.mock_calls == []
    assert service.mock_calls == []
    assert state.acquisition.snapshot is snapshot


@pytest.mark.parametrize(
    "observation,age,usable,processor_state,collector_state,expected_state,expected_reason",
    [
        (True, 0.25, True, "recording", "waiting", "recording", None),
        (False, 1.5, True, "waiting", "waiting", "waiting", None),
        (None, 7.0, True, "recording", "degraded", "degraded", "collector_stale"),
        (None, None, True, "waiting", "waiting", "waiting", "collector_stale"),
        (True, 0.5, False, "blocked", "waiting", "blocked", "custody_invalid"),
        (None, 8.0, False, "blocked", "degraded", "blocked", "custody_invalid"),
        (None, 9.0, False, "degraded", "waiting", "degraded", "dependency_unavailable"),
        (None, 10.0, True, "recording", "degraded", "degraded", "retry_exhausted"),
    ],
    ids=[
        "fresh-true",
        "fresh-false",
        "stale",
        "restarted",
        "blocked-fresh",
        "blocked-stale",
        "processor-retry",
        "collector-exhausted",
    ],
)
def test_real_wsl_status_preserves_nullable_observation_and_owner_precedence(
    observation: bool | None,
    age: float | None,
    usable: bool,
    processor_state: str,
    collector_state: str,
    expected_state: str,
    expected_reason: str | None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger = MagicMock()
    ledger.observation.return_value = (
        None if observation is None else {"interface": "constructed-guid", "recording": observation}
    )
    ledger.observation_age_seconds.return_value = age
    processor_reason = {"blocked": "custody_invalid", "degraded": "dependency_unavailable"}.get(processor_state)
    processor = SimpleNamespace(
        usable=usable,
        snapshot=CaptureSnapshot("LIVE", "wsl", processor_state, processor_reason, 2, 5, 4, False),
    )
    collector_reason = "retry_exhausted" if age == 10.0 else "collector_stale"
    collector = SimpleNamespace(
        snapshot=CaptureSnapshot("LIVE", "wsl", collector_state, collector_reason, 5, 5, None, age == 10.0)
    )
    provider = Status(ledger, intent=CaptureIntent.LIVE, processor=lambda: processor, collector=lambda: collector)
    producer, service = _producer(provider)
    emitted = _emitted(producer)
    assert emitted["source_state"] == expected_state
    assert emitted["reason_code"] == expected_reason
    assert emitted["recording"] is observation
    assert emitted["interface"] == (None if observation is None else "constructed-guid")
    assert emitted["link_up"] is None
    assert emitted["capture_type"] == "LIVE"
    assert emitted["backend"] == "wsl"
    assert emitted["observation_age_seconds"] == age
    selected = collector if observation is None and usable and processor_state != "blocked" else processor
    assert emitted["retry_attempt"] == selected.snapshot.retry_attempt
    assert emitted["retry_limit"] == 5
    assert emitted["retry_in_seconds"] == selected.snapshot.retry_in_seconds
    assert emitted["retry_exhausted"] is selected.snapshot.retry_exhausted
    assert emitted["drops_24h_pct"] is None
    assert emitted["overflows"] is None
    _assert_route(emitted, monkeypatch, producer)
    assert ledger.mock_calls == [("observation", (), {}), ("observation_age_seconds", (), {})] * 2
    assert service.mock_calls == []


@pytest.mark.parametrize("recording", [False, True, None])
def test_real_legacy_provider_additives_stay_unknown(recording: bool | None, monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {
        **_LEGACY,
        "interface": "legacy0",
        "link_up": True,
        "recording": recording,
        "drops_24h_pct": 2,
        "overflows": 0,
    }
    with respx.mock(assert_all_called=True) as upstream:
        upstream.get(_UPSTREAM).respond(200, json=payload)
        response = _client(CaptureStatusService(_settings()), monkeypatch).get(_ROUTE)
    assert response.status_code == 200
    assert response.json() == {**payload, **_ADDITIVE}


_INVALID = [
    ("capture_type", "PCAP"),
    ("capture_type", "live"),
    ("capture_type", True),
    ("capture_type", []),
    ("backend", "AUTO"),
    ("backend", "Native"),
    ("backend", 1),
    ("backend", {}),
    ("source_state", "current"),
    ("source_state", None),
    ("source_state", True),
    ("source_state", []),
    ("reason_code", "raw constructed-secret /private/path tcpdump -i eth0"),
    ("reason_code", []),
    ("reason_code", 1),
    ("retry_attempt", True),
    ("retry_attempt", "1"),
    ("retry_attempt", 1.0),
    ("retry_attempt", -1),
    ("retry_attempt", 6),
    ("retry_limit", True),
    ("retry_limit", "5"),
    ("retry_limit", 5.0),
    ("retry_limit", 4),
    ("retry_limit", 6),
    ("retry_in_seconds", True),
    ("retry_in_seconds", "2"),
    ("retry_in_seconds", -0.1),
    ("retry_in_seconds", 16.01),
    ("retry_in_seconds", float("inf")),
    ("retry_in_seconds", float("-inf")),
    ("retry_in_seconds", float("nan")),
    ("retry_exhausted", "false"),
    ("retry_exhausted", 0),
    ("retry_exhausted", 1),
    ("retry_exhausted", []),
    ("observation_age_seconds", True),
    ("observation_age_seconds", "6"),
    ("observation_age_seconds", -0.1),
    ("observation_age_seconds", float("inf")),
    ("observation_age_seconds", float("-inf")),
    ("observation_age_seconds", float("nan")),
    ("retry_in_seconds", 10**400),
    ("observation_age_seconds", 10**400),
]


@pytest.mark.parametrize("field,value", _INVALID, ids=[f"{field}-{index}" for index, (field, _) in enumerate(_INVALID)])
async def test_external_mapping_rejects_invalid_additives_without_coercion(
    field: str, value: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = {**_DEFAULT, field: value}
    expected = {**_DEFAULT, field: "degraded" if field == "source_state" else None}
    with respx.mock(assert_all_called=True) as upstream:
        upstream.get(_UPSTREAM).respond(200, content=json.dumps(payload), headers={"Content-Type": "application/json"})
        service = CaptureStatusService(_settings())
        assert asdict(await service.get_status()) == expected
        response = _client(service, monkeypatch).get(_ROUTE)
    assert response.status_code == 200
    assert response.json() == expected


@pytest.mark.parametrize("field,value", _INVALID, ids=[f"{field}-{index}" for index, (field, _) in enumerate(_INVALID)])
def test_api_schema_rejects_invalid_additives_before_numeric_coercion(field: str, value: Any) -> None:
    with pytest.raises(ValidationError):
        CaptureStatus.model_validate({field: value})


@pytest.mark.parametrize("reason", [None, *get_args(ReasonCode)])
def test_all_actual_reason_domains_round_trip(reason: str | None, monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {
        **_DEFAULT,
        "capture_type": "LIVE",
        "backend": "wsl",
        "source_state": "degraded",
        "reason_code": reason,
        "retry_attempt": 5,
        "retry_limit": 5,
        "retry_in_seconds": 16,
        "retry_exhausted": True,
        "observation_age_seconds": 123456.75,
    }
    _assert_route(payload, monkeypatch)


@pytest.mark.parametrize(
    "field,value",
    [
        ("retry_attempt", 0),
        ("retry_in_seconds", 0),
        ("retry_in_seconds", 0.5),
        ("observation_age_seconds", 0),
        ("retry_exhausted", False),
    ],
)
def test_valid_zero_and_fractional_additives_are_preserved(
    field: str, value: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    _assert_route({**_DEFAULT, field: value}, monkeypatch)


@pytest.mark.parametrize("body", [{}, _LEGACY, {**_LEGACY, "capture_type": "LIVE"}])
async def test_missing_fields_have_unknown_defaults(body: dict[str, Any]) -> None:
    with respx.mock(assert_all_called=True) as upstream:
        upstream.get(_UPSTREAM).respond(200, json=body)
        status = await CaptureStatusService(_settings()).get_status()
    assert asdict(status) == {**_DEFAULT, **body}


def test_unknown_upstream_fields_and_diagnostics_are_not_projected(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {
        **_DEFAULT,
        "reason_code": "constructed-secret /private/path tcpdump -i eth0",
        "command": "tcpdump -i eth0",
        "path": "/private/path",
        "secret": "constructed-secret",
        "error": "raw exception",
    }
    with respx.mock(assert_all_called=True) as upstream:
        upstream.get(_UPSTREAM).respond(200, json=payload)
        response = _client(CaptureStatusService(_settings()), monkeypatch).get(_ROUTE)
    assert response.status_code == 200
    assert response.json() == _DEFAULT


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(code, json={"detail": "constructed-secret /private/path command"})
        for code in (204, 301, 401, 403, 404, 500, 503)
    ]
    + [httpx.Response(200, text="not-json constructed-secret")],
)
def test_non_success_upstream_is_degraded(response: httpx.Response, monkeypatch: pytest.MonkeyPatch) -> None:
    with respx.mock(assert_all_called=True) as upstream:
        upstream.get(_UPSTREAM).mock(return_value=response)
        result = _client(CaptureStatusService(_settings()), monkeypatch).get(_ROUTE)
    assert result.status_code == 200
    assert result.json() == _DEGRADED


@pytest.mark.parametrize("body", [None, [], [1], "recording", 42, True])
def test_nonobject_json_is_degraded(body: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    with respx.mock(assert_all_called=True) as upstream:
        upstream.get(_UPSTREAM).respond(200, content=json.dumps(body))
        response = _client(CaptureStatusService(_settings()), monkeypatch).get(_ROUTE)
    assert response.status_code == 200
    assert response.json() == _DEGRADED


@pytest.mark.parametrize(
    "error", [httpx.ReadTimeout, httpx.ConnectTimeout, httpx.ConnectError, httpx.RemoteProtocolError]
)
def test_transport_fallback_does_not_leak_raw_errors(
    error: type[httpx.TransportError], monkeypatch: pytest.MonkeyPatch
) -> None:
    messages: list[str] = []
    sink = logger.add(lambda message: messages.append(str(message)), level="DEBUG")
    try:
        with respx.mock(assert_all_called=True) as upstream:
            upstream.get(_UPSTREAM).mock(side_effect=error("constructed-secret /private/path tcpdump -i eth0"))
            response = _client(CaptureStatusService(_settings()), monkeypatch).get(_ROUTE)
        assert response.status_code == 200
        assert response.json() == _DEGRADED
        for text in [response.text, *messages]:
            for forbidden in ("constructed-secret", "/private/path", "tcpdump -i"):
                assert forbidden not in text
    finally:
        logger.remove(sink)


@pytest.mark.parametrize(
    "key,header,expected", [(_KEY, None, 401), (_KEY, "wrong-a5b-key", 401), ("", None, 503), ("", _KEY, 503)]
)
def test_auth_fail_closed_reaches_existing_real_middleware(
    key: str, header: str | None, expected: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    with respx.mock(assert_all_called=False) as upstream:
        outbound = upstream.get(_UPSTREAM).respond(200, json=_DEFAULT)
        client = _client(CaptureStatusService(_settings()), monkeypatch, key)
        client.headers.clear()
        response = client.get(_ROUTE, headers={} if header is None else {"X-API-Key": header})
    assert response.status_code == expected
    assert response.json() == {
        "detail": "API key authentication unavailable" if expected == 503 else "Invalid or missing API key"
    }
    assert outbound.call_count == 0


@pytest.mark.parametrize("recorder_key", ["", "constructed-a5b-recorder-key"])
def test_repeated_get_forwarding_timeout_and_nonmutation(recorder_key: str, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _settings(recorder_key)
    service = CaptureStatusService(settings)
    client = _client(service, monkeypatch)
    state = RuntimeState(intent=CaptureIntent.NONE)
    producer, evidence = _producer(CaptureStatusProvider(state, snapshot=lambda: state.snapshot))
    payload = _emitted(producer)
    forbidden = MagicMock(side_effect=AssertionError("source control or secret lookup on GET"))
    monkeypatch.setattr("capture_settings_base.OperatorAuthSettings.from_env", forbidden)
    monkeypatch.setattr("capture_runtime.resolve_capture_intent", forbidden)
    monkeypatch.setattr(Path, "read_text", forbidden)
    monkeypatch.setattr("subprocess.run", forbidden)
    monkeypatch.setattr("subprocess.Popen", forbidden)
    with respx.mock(assert_all_called=True) as upstream:

        def forward(request: httpx.Request) -> httpx.Response:
            assert request.method == "GET"
            assert request.url == _UPSTREAM
            assert request.content == b""
            assert request.extensions["timeout"] == {"connect": 1.25, "read": 1.25, "write": 1.25, "pool": 1.25}
            assert request.headers.get("X-API-Key") == (recorder_key or None)
            assert _KEY not in request.headers.values()
            emitted = producer.get("/status", headers=dict(request.headers))
            assert emitted.status_code == 200
            return httpx.Response(200, content=emitted.content)

        outbound = upstream.get(_UPSTREAM).mock(side_effect=forward)
        for _ in range(3):
            response = client.get(_ROUTE)
            assert response.status_code == 200
            assert response.json() == payload
            assert _KEY not in response.text
            assert "constructed-a5b-recorder-key" not in response.text
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            assert client.request(method, _ROUTE).status_code == 405
        assert outbound.call_count == 3
    assert vars(settings) == vars(_settings(recorder_key))
    forbidden.assert_not_called()
    assert evidence.mock_calls == []
    assert state.recorder is None
    assert state.acquisition is None


def test_production_api_projection_does_not_import_capture_image_modules() -> None:
    root = Path(__file__).resolve().parents[2] / "src" / "otalon_api"
    for relative in ("services/capture_status_service.py", "api/schemas/operations.py", "api/v1/operations.py"):
        tree = ast.parse((root / relative).read_text())
        for node in ast.walk(tree):
            modules = [alias.name for alias in node.names] if isinstance(node, ast.Import) else []
            if isinstance(node, ast.ImportFrom):
                modules.append(node.module or "")
            assert all(
                module.split(".")[0] not in {"capture_runtime", "pcap_recorder", "desktop_ingest"} for module in modules
            )
