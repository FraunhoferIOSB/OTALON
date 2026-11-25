"""A5a producer-only status contracts; no live capture or publication proof."""

from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient

from capture_runtime import CaptureBackend, CaptureIntent, CaptureSnapshot, SourceState
from desktop_ingest import ledger as ledger_module
from desktop_ingest import main as desktop_main
from desktop_ingest import processor_lifecycle
from desktop_ingest.ledger import Ledger
from pcap_recorder import api, lifecycle
from pcap_recorder import main as recorder_main
from tests.test_capture_lifecycle import Recorder, _settings

LEGACY = dict.fromkeys(("interface", "link_up", "recording", "drops_24h_pct", "overflows"))
UNKNOWN = asdict(CaptureSnapshot())
SOURCE = "disposable-public-source-value-00000001"
OPERATOR = "disposable-public-operator-value"


def forbidden(*args, **kwargs):
    raise AssertionError("status touched source control, credentials, discovery or custody mutation")


def client(provider):
    return TestClient(api.create_app(api.PcapService(Mock(), Mock()), provider))


def disabled(backend, recording):
    return dict(
        LEGACY,
        recording=recording,
        **asdict(
            CaptureSnapshot(CaptureIntent.NONE, backend, SourceState.DISABLED, "none_selected", 0, 5, None, False, None)
        ),
    )


def test_status_serializes_complete_nullable_contract():
    response = client(SimpleNamespace(get_status=api.CaptureStatusResponse)).get("/status")
    assert response.status_code == 200
    assert response.json() == dict(LEGACY, **UNKNOWN)
    assert len(response.json()) == 14


@pytest.mark.parametrize(
    "field,value",
    [
        ("capture_type", "PCAP"),
        ("capture_type", "live"),
        ("backend", "AUTO"),
        ("source_state", None),
        ("source_state", "healthy"),
        ("reason_code", "raw_exception"),
        ("retry_attempt", True),
        ("retry_attempt", -1),
        ("retry_attempt", 6),
        ("retry_attempt", 1.0),
        ("retry_attempt", "1"),
        ("retry_limit", True),
        ("retry_limit", 4),
        ("retry_limit", 6),
        ("retry_limit", 5.0),
        ("retry_limit", "5"),
        ("retry_in_seconds", True),
        ("retry_in_seconds", -0.1),
        ("retry_in_seconds", 16.01),
        ("retry_in_seconds", float("nan")),
        ("retry_in_seconds", float("inf")),
        ("retry_in_seconds", float("-inf")),
        ("retry_in_seconds", "2"),
        ("retry_exhausted", 1),
        ("retry_exhausted", "false"),
        ("observation_age_seconds", False),
        ("observation_age_seconds", -1),
        ("observation_age_seconds", float("nan")),
        ("observation_age_seconds", float("inf")),
        ("observation_age_seconds", float("-inf")),
        ("observation_age_seconds", "3"),
    ],
)
def test_status_rejects_invalid_additive_values_before_json(field, value):
    with pytest.raises(ValueError):
        api.CaptureStatusResponse(**{field: value})


@pytest.mark.parametrize("attempt", range(6))
@pytest.mark.parametrize("delay", [None, 0, 2.5, 16])
def test_status_roundtrips_shared_snapshot_domains(attempt, delay):
    snapshot = CaptureSnapshot(
        CaptureIntent.LIVE, CaptureBackend.NATIVE, SourceState.WAITING, "source_absent", attempt, 5, delay, False, 0
    )
    result = api.CaptureStatusResponse(**asdict(snapshot)).model_dump(mode="json")
    assert result == dict(LEGACY, **asdict(snapshot))
    assert type(result["retry_attempt"]) is int
    assert type(result["retry_limit"]) is int
    assert type(result["retry_exhausted"]) is bool


def test_native_none_does_not_inspect_recorder_or_source(monkeypatch):
    state = recorder_main.RuntimeState(intent=CaptureIntent.NONE)
    state.recorder = SimpleNamespace(interface="unused", is_running=True)
    state.acquisition = SimpleNamespace(snapshot=forbidden)
    monkeypatch.setattr(api, "_read_link_up", forbidden)
    provider = api.CaptureStatusProvider(state, snapshot=lambda: state.snapshot)
    before = dict(vars(state))
    for _ in range(3):
        assert client(provider).get("/status").json() == disabled(CaptureBackend.NATIVE, False)
    assert vars(state) == before


@pytest.mark.asyncio
@pytest.mark.parametrize("intent", [CaptureIntent.NONE, CaptureIntent.LIVE])
async def test_native_service_selects_intent_before_rest_and_before_acquisition(monkeypatch, tmp_path, intent):
    monkeypatch.setenv("CAPTURE_TYPE", "LIVE" if intent is CaptureIntent.NONE else "NONE")
    monkeypatch.setattr(lifecycle, "AcquisitionPair", forbidden)
    monkeypatch.setattr(recorder_main, "CaptureLossMonitor", forbidden)
    monkeypatch.setattr(api, "_read_link_up", forbidden)
    state = recorder_main.RuntimeState()
    responses = []

    async def serve(app, host, port, runtime):
        runtime.uvicorn_server = SimpleNamespace(started=False, should_exit=False)
        with TestClient(app) as rest:
            for _ in range(3):
                responses.append(rest.get("/status").json())
            assert rest.get("/health").json() == {"status": "ok"}
        assert runtime.acquisition is None

    monkeypatch.setattr(recorder_main, "_run_uvicorn", serve)
    await recorder_main._run_service(_settings(tmp_path, intent), intent, state)
    expected = disabled(CaptureBackend.NATIVE, False)
    if intent is CaptureIntent.LIVE:
        expected = dict(
            LEGACY,
            recording=False,
            **asdict(
                CaptureSnapshot(CaptureIntent.LIVE, CaptureBackend.NATIVE, SourceState.WAITING, None, 0, 5, None, False)
            ),
        )
    assert responses == [expected] * 3
    assert state.acquisition is None
    assert state.ringbuffer_task is None
    assert state.capture_stats_task is None


@pytest.mark.parametrize(
    "source_state,reason,attempt,delay,exhausted,running",
    [
        (SourceState.WAITING, None, 0, None, False, False),
        (SourceState.WAITING, "source_absent", 1, 2, False, False),
        (SourceState.RECORDING, None, 1, None, False, True),
        (SourceState.DEGRADED, "source_absent", 2, 4, False, True),
        (SourceState.BLOCKED, "privilege_denied", 1, None, False, True),
        (SourceState.BLOCKED, "dependency_unavailable", 1, None, False, False),
        (SourceState.WAITING, "retry_exhausted", 5, None, True, False),
        (SourceState.DEGRADED, "retry_exhausted", 5, None, True, False),
    ],
)
def test_native_projects_actual_pair_snapshot_not_pid_or_carrier(
    monkeypatch, tmp_path, source_state, reason, attempt, delay, exhausted, running
):
    owner = lifecycle.AcquisitionPair(_settings(tmp_path).pcap)
    owner._attempts = attempt
    owner._status(source_state, reason, exhausted=exhausted)
    monkeypatch.setattr(lifecycle, "time", SimpleNamespace(monotonic=lambda: 10.0))
    owner._retry_at = None if delay is None else 10.0 + delay
    for method in ("start", "stop", "_read_snapshot"):
        monkeypatch.setattr(owner, method, forbidden)
    monkeypatch.setattr(lifecycle, "_interface_exists", forbidden)
    monkeypatch.setattr(api, "_read_link_up", lambda _: True)
    recorder = Recorder(_settings(tmp_path).pcap)
    recorder.is_running = running
    recorder.start = recorder.stop = forbidden
    state = recorder_main.RuntimeState(intent=CaptureIntent.LIVE)
    state.recorder, state.acquisition = recorder, owner
    before = dict(vars(owner))
    rest = client(api.CaptureStatusProvider(state, snapshot=lambda: state.snapshot))
    for _ in range(3):
        response = rest.get("/status")
        assert response.status_code == 200
        assert response.json() == dict(
            LEGACY, interface="fake0", link_up=True, recording=running, **asdict(owner.snapshot)
        )
    assert vars(owner) == before
    assert rest.get("/health").json() == {"status": "ok"}


@pytest.mark.parametrize("running", [False, True])
def test_legacy_native_provider_does_not_infer_intent_or_acquisition(monkeypatch, tmp_path, running):
    monkeypatch.setenv("CAPTURE_TYPE", "NONE")
    monkeypatch.setattr(api, "_read_link_up", lambda _: None)
    recorder = Recorder(_settings(tmp_path).pcap)
    recorder.is_running = running
    response = client(api.CaptureStatusProvider(recorder)).get("/status")
    assert response.json() == dict(LEGACY, interface="fake0", recording=running, **UNKNOWN)


@pytest.mark.parametrize("populated", [False, True])
def test_wsl_none_never_reads_observation_key_processor_or_custody(tmp_path, monkeypatch, populated):
    root = tmp_path / "custody"
    if populated:
        writer = Ledger(root)
        writer.register_run("owned", None)
        writer.observe({"interface": "fixture", "recording": True})
        writer.close()
    view = Ledger.open_existing_readonly(root)
    before = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}
    monkeypatch.setenv("CAPTURE_TYPE", "LIVE")
    for method in ("observation", "observation_age_seconds"):
        monkeypatch.setattr(view, method, forbidden)
    for method in ("_snapshot_existing", "_read_existing"):
        monkeypatch.setattr(Ledger, method, forbidden)
    monkeypatch.setattr(processor_lifecycle.ProcessorOwner, "__init__", forbidden)
    monkeypatch.setattr(processor_lifecycle.CollectorFreshness, "__init__", forbidden)
    monkeypatch.setattr(Path, "read_text", forbidden)
    app = desktop_main.build_app(None, view, None, None, intent=CaptureIntent.NONE, source_key_file=tmp_path / "unused")
    rest = TestClient(app)
    for _ in range(3):
        assert rest.get("/status").json() == disabled(CaptureBackend.WSL, None)
        assert rest.get("/health").json() == {"status": "ok"}
    assert {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()} == before
    assert root.exists() is populated
    assert getattr(view, "db", None) is None
    assert getattr(view, "_scratch", None) is None
    view.close()


@pytest.fixture
def wsl(tmp_path, monkeypatch):
    clock = SimpleNamespace(now=10.0)
    monkeypatch.setattr(ledger_module, "time", SimpleNamespace(monotonic=lambda: clock.now, time=lambda: 0.0))
    monkeypatch.setattr(processor_lifecycle, "monotonic", lambda: clock.now)
    ledger = Ledger(tmp_path / "live")
    app = desktop_main.build_app(None, ledger, SOURCE, OPERATOR, intent=CaptureIntent.LIVE)
    owner, collector = app.state.processor, app.state.collector
    for target, methods in ((owner, ("run", "_work", "_close")), (collector, ("run", "stop"))):
        for method in methods:
            monkeypatch.setattr(target, method, forbidden)
    yield ledger, owner, collector, clock, TestClient(app)
    ledger.close()


@pytest.mark.parametrize(
    "recording,age,usable,ever,blocked,expected_state,expected_recording,reason",
    [
        (True, 0.0, True, True, False, "recording", True, None),
        (True, 5.999, True, True, False, "recording", True, None),
        (False, 1.0, True, True, False, "degraded", False, None),
        (True, 6.0, True, True, False, "degraded", None, "collector_stale"),
        (True, 7.0, True, False, False, "waiting", None, "collector_stale"),
        (None, 0.0, True, False, False, "waiting", None, "collector_stale"),
        (True, 1.0, False, False, False, "waiting", True, "dependency_unavailable"),
        (True, 1.0, False, True, False, "degraded", True, "dependency_unavailable"),
        (True, 1.0, False, True, True, "blocked", True, "checkpoint_incompatible"),
        (True, 7.0, False, True, True, "blocked", None, "checkpoint_incompatible"),
    ],
)
def test_wsl_live_actual_owner_fresh_stop_stale_and_failure_mapping(
    wsl, recording, age, usable, ever, blocked, expected_state, expected_recording, reason
):
    ledger, owner, collector, clock, rest = wsl
    if recording is not None:
        ledger.observe({"interface": "fixture", "recording": recording})
    clock.now += age
    owner.usable, owner.ever_usable = usable, ever
    owner.processor_state = "blocked" if blocked else "usable" if usable else "degraded" if ever else "waiting"
    owner.reason = "checkpoint_incompatible" if blocked else None if usable else "dependency_unavailable"
    owner.attempts = 1
    collector.ever_present = ever
    before = list(ledger.db.iterdump()), dict(vars(owner)), dict(vars(collector))
    for _ in range(3):
        response = rest.get("/status")
        assert response.status_code == 200
        body = response.json()
        assert set(body) == set(LEGACY) | set(UNKNOWN)
        assert body["capture_type"] == "LIVE"
        assert body["backend"] == "wsl"
        assert body["source_state"] == expected_state
        assert body["recording"] is expected_recording
        assert body["interface"] == ("fixture" if expected_recording is not None else None)
        assert body["reason_code"] == reason
        assert body["observation_age_seconds"] == ledger.observation_age_seconds()
        assert body["link_up"] is body["drops_24h_pct"] is body["overflows"] is None
        for leaked in (
            SOURCE,
            OPERATOR,
            "checkpoint configuration",
            "tcpdump",
            "/sys/",
            str(ledger.root),
            "-w",
            "token",
        ):
            assert leaked not in response.text
    assert (list(ledger.db.iterdump()), vars(owner), vars(collector)) == before


@pytest.mark.parametrize("usable,blocked", [(True, False), (False, False), (False, True)])
def test_wsl_retry_precedence_uses_collector_only_when_processor_usable(wsl, usable, blocked):
    ledger, owner, collector, clock, rest = wsl
    owner.usable = usable
    owner.ever_usable = True
    owner.processor_state = "blocked" if blocked else "usable" if usable else "degraded"
    owner.reason = "privilege_denied" if blocked else "dependency_unavailable"
    owner.attempts, owner.retry_at = 2, None if blocked else clock.now + 4
    collector.ever_present = True
    collector.attempts, collector.retry_exhausted = 5, True
    body = rest.get("/status").json()
    assert body["recording"] is None
    assert body["source_state"] == ("blocked" if blocked else "degraded")
    assert body["retry_attempt"] == (5 if usable else 2)
    assert body["retry_limit"] == 5
    assert body["retry_in_seconds"] == (None if usable or blocked else 4)
    assert body["retry_exhausted"] is usable
    assert body["reason_code"] == (
        "collector_stale" if usable else "privilege_denied" if blocked else "dependency_unavailable"
    )


def test_wsl_collector_countdown_and_current_age_do_not_freeze(wsl):
    ledger, owner, collector, clock, rest = wsl
    ledger.observe({"interface": "fixture", "recording": True})
    owner.usable = owner.ever_usable = True
    owner.processor_state = "usable"
    collector.ever_present = True
    collector.attempts, collector.retry_at = 3, clock.now + 14
    clock.now += 6
    first = rest.get("/status").json()
    clock.now += 2
    second = rest.get("/status").json()
    assert first["observation_age_seconds"] == 6
    assert second["observation_age_seconds"] == 8
    assert first["retry_in_seconds"] == 8
    assert second["retry_in_seconds"] == 6
    assert first["retry_attempt"] == second["retry_attempt"] == 3
    assert first["recording"] is second["recording"] is None


@pytest.mark.parametrize("fresh", [False, True])
def test_wsl_unusable_processor_exhaustion_precedes_collector_receipt(wsl, fresh):
    ledger, owner, collector, clock, rest = wsl
    if fresh:
        ledger.observe({"interface": "fixture", "recording": True})
    owner.ever_usable = True
    owner.processor_state = "degraded"
    owner.reason = "retry_exhausted"
    owner.attempts, owner.retry_exhausted = 5, True
    collector.attempts, collector.retry_at = 1, clock.now + 2
    body = rest.get("/status").json()
    assert body["source_state"] == "degraded"
    assert body["reason_code"] == "retry_exhausted"
    assert body["retry_attempt"] == 5
    assert body["retry_exhausted"] is True
    assert body["retry_in_seconds"] is None
    assert body["recording"] is (True if fresh else None)


def test_wsl_restart_never_resurrects_persisted_recording(tmp_path):
    root = tmp_path / "restarted"
    previous = Ledger(root)
    previous.observe({"interface": "fixture", "recording": True})
    previous.close()
    ledger = Ledger(root)
    try:
        app = desktop_main.build_app(None, ledger, SOURCE, OPERATOR, intent=CaptureIntent.LIVE)
        app.state.processor.usable = True
        app.state.processor.processor_state = "usable"
        body = TestClient(app).get("/status").json()
        assert body["capture_type"] == "LIVE"
        assert body["source_state"] == "waiting"
        assert body["reason_code"] == "collector_stale"
        assert body["recording"] is body["interface"] is body["observation_age_seconds"] is None
        assert ledger.db.execute("SELECT value FROM observations").fetchone() is not None
    finally:
        ledger.close()


def test_legacy_wsl_provider_keeps_observation_but_additive_unknown(monkeypatch):
    monkeypatch.setenv("CAPTURE_TYPE", "NONE")
    ledger = SimpleNamespace(observation=lambda: {"interface": "fixture", "recording": True})
    body = client(desktop_main.Status(ledger)).get("/status").json()
    assert body == dict(LEGACY, interface="fixture", recording=True, **UNKNOWN)
