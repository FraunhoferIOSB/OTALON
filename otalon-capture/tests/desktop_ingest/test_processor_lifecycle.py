"""A4b regression proofs with actual apps, local custody and dependency doubles."""

import asyncio
import errno
import importlib
import json
import ssl
import threading
from types import SimpleNamespace
from unittest.mock import Mock

import httpx
import pytest
from fastapi.testclient import TestClient
from loguru import logger
from urllib3.exceptions import MaxRetryError, NewConnectionError, ReadTimeoutError

from capture_runtime import SourceState
from desktop_ingest import ledger as ledger_module
from desktop_ingest import main
from desktop_ingest.ledger import Ledger

SOURCE = "constructed-source-key-for-unit-tests-0001"
OPERATOR = "constructed-operator-key-for-unit-tests"


class Clock:
    now = 100.0

    def __call__(self):
        return self.now


def lifecycle():
    return importlib.import_module("desktop_ingest.processor_lifecycle")


def unavailable():
    return NewConnectionError(None, "https://token:SECRET@dependency.invalid/private")


@pytest.fixture
def local(tmp_path, monkeypatch):
    clock = Clock()
    monkeypatch.setattr(ledger_module, "time", SimpleNamespace(monotonic=clock, time=lambda: 123.0))
    ledger = Ledger(tmp_path / "custody")
    yield ledger, clock
    ledger.close()


def app_owner(local, monkeypatch, factory):
    ledger, clock = local
    module = lifecycle()
    monkeypatch.setattr(module, "monotonic", clock)
    from desktop_ingest import pipeline

    monkeypatch.setattr(pipeline, "ContinuousPipeline", factory)
    app = main.build_app(None, ledger, SOURCE, OPERATOR)
    return app, app.state.processor


async def request(app, method, path, **kwargs):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://unit.test") as client:
        return await client.request(method, path, **kwargs)


@pytest.mark.asyncio
async def test_actual_lifespan_exact_processor_backoff_exhaustion_and_liveness(local, monkeypatch):
    calls, waits = [], []

    def factory(*args):
        calls.append(local[1]())
        raise unavailable()

    app, owner = app_owner(local, monkeypatch, factory)

    async def pause(delay):
        if delay is None:
            owner.stop_event.set()
        else:
            waits.append(delay)
            local[1].now += delay

    monkeypatch.setattr(owner, "_pause", pause)
    async with app.router.lifespan_context(app):
        await app.state.processor_task
        response = await request(app, "GET", "/health")
        assert response.status_code == 200 and response.json() == {"status": "ok"}
        assert owner.attempts == 5 and owner.retry_exhausted
        assert owner.processor_state == "waiting"
        assert owner.snapshot.source_state is SourceState.WAITING
        assert (
            await request(
                app,
                "POST",
                "/ingest/v1/observation",
                headers={"X-Source-Key": SOURCE},
                json={"interface": "fixture", "recording": True},
            )
        ).json() == {"observed": True}
    assert calls == [100, 102, 106, 114, 130]
    assert waits == [2, 4, 8, 16]
    assert app.state.processor_task.done() and app.state.collector_task.done()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    [
        PermissionError("SECRET"),
        OSError("SECRET"),
        ValueError("checkpoint configuration mismatch"),
        ValueError("checkpoint timestamp contract mismatch; legacy carry requires explicit reconciliation"),
        ValueError("custody bytes changed"),
        ValueError("point identity conflict"),
        ValueError("exact point not yet visible"),
        RuntimeError("SECRET"),
        httpx.HTTPStatusError("SECRET", request=httpx.Request("GET", "http://unit.test"), response=httpx.Response(401)),
    ],
)
async def test_auth_permission_checkpoint_custody_visibility_unknown_block_without_retry(local, monkeypatch, failure):
    calls = []

    class Pipeline:
        def process_one(self):
            raise failure

        def close(self):
            calls.append("close")

    app, owner = app_owner(local, monkeypatch, lambda *args: (calls.append("construct"), Pipeline())[1])

    async def idle(delay):
        assert delay is None, "blocked errors must never schedule retry"
        owner.stop_event.set()

    monkeypatch.setattr(owner, "_pause", idle)
    async with app.router.lifespan_context(app):
        await app.state.processor_task
        assert (await request(app, "GET", "/health")).json() == {"status": "ok"}
        assert owner.processor_state == "blocked" and owner.attempts == 1
        assert owner.error_class is not None and not owner.usable
        assert owner.snapshot.source_state is SourceState.BLOCKED
    assert calls == ["construct", "close"]


@pytest.mark.parametrize(
    "error,retry",
    [
        (unavailable(), True),
        (ReadTimeoutError(None, "/SECRET", "SECRET"), True),
        (MaxRetryError(None, "/SECRET", unavailable()), True),
        (MaxRetryError(None, "/SECRET", PermissionError("SECRET")), False),
        (ConnectionError("SECRET"), False),
        (TimeoutError("SECRET"), False),
    ],
)
def test_only_proved_transport_classes_are_retryable(error, retry):
    assert lifecycle().classify_failure(error)[0] is retry


@pytest.mark.asyncio
@pytest.mark.parametrize("stable", [59.999, 60.0])
async def test_stable_sixty_second_reset_but_short_flapping_keeps_budget(local, monkeypatch, stable):
    calls, closed, waits = [], [], []
    count = 0

    class Pipeline:
        def __init__(self, ident):
            self.ident = ident
            self.steps = 0

        def process_one(self):
            self.steps += 1
            if self.steps == 1:
                return False
            if self.steps == 2:
                local[1].now += stable
                return False
            raise unavailable()

        def close(self):
            closed.append(self.ident)

    def factory(*args):
        nonlocal count
        count += 1
        calls.append(local[1]())
        if count == 2:
            owner.stop_event.set()
        return Pipeline(count)

    app, owner = app_owner(local, monkeypatch, factory)

    async def pause(delay):
        assert delay is not None
        if delay >= 2:
            waits.append(delay)
            local[1].now += delay

    monkeypatch.setattr(owner, "_pause", pause)
    async with app.router.lifespan_context(app):
        await app.state.processor_task
    assert waits == ([] if stable == 60 else [2])
    assert owner.attempts == (1 if stable == 60 else 2)
    assert len(calls) == 2 and closed == [1, 2]


@pytest.mark.asyncio
@pytest.mark.parametrize("delay", [2, 4, 8, 16])
async def test_stop_interrupts_every_backoff_without_new_work_or_timers(local, monkeypatch, delay):
    entered = asyncio.Event()
    factory = Mock(side_effect=unavailable())
    app, owner = app_owner(local, monkeypatch, factory)
    real_pause = owner._pause

    async def pause(seconds):
        if seconds == delay:
            entered.set()
            await real_pause(seconds)
        else:
            local[1].now += seconds

    monkeypatch.setattr(owner, "_pause", pause)
    async with app.router.lifespan_context(app):
        await entered.wait()
        assert owner.snapshot.retry_in_seconds == delay
        before = factory.call_count
    assert factory.call_count == before
    assert owner._work_task is None
    assert app.state.processor_task.done() and app.state.collector_task.done()


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", ["construct", "process", "close"])
async def test_shutdown_joins_returned_thread_result_and_serializes_close(local, monkeypatch, stage):
    entered, release = threading.Event(), threading.Event()
    calls = []
    active = 0
    lock = threading.Lock()

    def work(name):
        nonlocal active
        with lock:
            active += 1
            assert active == 1, "concurrent thread work/close"
        calls.append(name)
        if name == stage:
            entered.set()
            assert release.wait(1.0)
        with lock:
            active -= 1

    class Pipeline:
        def process_one(self):
            work("process")
            owner.stop_event.set()
            return False

        def close(self):
            work("close")

    def factory(*args):
        work("construct")
        return Pipeline()

    app, owner = app_owner(local, monkeypatch, factory)
    context = app.router.lifespan_context(app)
    await context.__aenter__()
    try:
        assert await asyncio.to_thread(entered.wait, 1.0)
        stopping = asyncio.create_task(context.__aexit__(None, None, None))
        await asyncio.sleep(0)
        assert not stopping.done()
        release.set()
        await stopping
    finally:
        release.set()
    assert calls.count("construct") == calls.count("close") == 1
    assert calls.count("process") == (0 if stage == "construct" else 1)
    assert active == 0 and owner._work_task is None


@pytest.mark.asyncio
async def test_http_health_and_authenticated_ingress_never_wait_for_constructor(local, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    closed = []

    def factory(*args):
        entered.set()
        assert release.wait(1.0)
        return SimpleNamespace(process_one=lambda: False, close=lambda: closed.append(True))

    app, owner = app_owner(local, monkeypatch, factory)
    assert not entered.is_set(), "app construction initialized pipeline"
    async with app.router.lifespan_context(app):
        try:
            assert await asyncio.to_thread(entered.wait, 1.0)
            assert (await request(app, "GET", "/health")).status_code == 200
            result = await request(
                app,
                "POST",
                "/ingest/v1/observation",
                headers={"X-Source-Key": SOURCE},
                json={"interface": "fixture", "recording": False},
            )
            assert result.json() == {"observed": True}
            assert (await request(app, "GET", "/status")).json()["recording"] is False
            owner.stop_event.set()
        finally:
            release.set()
    assert closed == [True]


def test_observation_age_exact_cutoff_finite_and_restart_reset(local):
    ledger, clock = local
    assert ledger.observation_age_seconds() is None
    ledger.observe({"interface": "fixture", "recording": False})
    assert ledger.observation_age_seconds() == 0
    clock.now += 5.999
    assert ledger.observation()["recording"] is False
    assert ledger.observation_age_seconds() == pytest.approx(5.999)
    clock.now += 0.001
    assert ledger.observation() is None and ledger.observation_age_seconds() == pytest.approx(6)
    ledger.close()
    restarted = Ledger(ledger.root)
    try:
        assert restarted.observation() is None and restarted.observation_age_seconds() is None
        restarted.observe({"interface": "new", "recording": True})
        assert restarted.observation_age_seconds() == 0 and restarted.observation()["recording"] is True
        clock.now = float("nan")
        assert restarted.observation_age_seconds() is None and restarted.observation() is None
    finally:
        restarted.close()


@pytest.mark.asyncio
async def test_collector_five_local_checks_then_authenticated_new_observation_only(local, monkeypatch):
    lifecycle()
    app, processor = app_owner(local, monkeypatch, Mock(side_effect=unavailable()))
    collector = app.state.collector
    checks, exhausted = [], asyncio.Event()
    real_wait = collector._wait

    async def wait(delay):
        if delay is None:
            exhausted.set()
            await real_wait(delay)
        else:
            checks.append(delay)
            local[1].now += delay

    monkeypatch.setattr(collector, "_wait", wait)
    task = asyncio.create_task(collector.run())
    try:
        await exhausted.wait()
        assert checks == [2, 4, 8, 16] and collector.attempts == 5 and collector.retry_exhausted
        assert collector.snapshot.source_state is SourceState.WAITING
        old_seen = local[0].db.execute("SELECT * FROM observations").fetchall()
        response = await request(
            app,
            "POST",
            "/ingest/v1/observation",
            headers={"X-Source-Key": OPERATOR},
            json={"interface": "fixture", "recording": True},
        )
        assert response.status_code == 401
        assert local[0].db.execute("SELECT * FROM observations").fetchall() == old_seen
        assert not collector.changed.is_set() and not collector.present
        monkeypatch.setattr(collector, "_wait", real_wait)
        response = await request(
            app,
            "POST",
            "/ingest/v1/observation",
            headers={"X-Source-Key": SOURCE},
            json={"interface": "fixture", "recording": True},
        )
        assert response.json() == {"observed": True}
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        assert collector.present and collector.attempts == 5
        assert collector.snapshot.retry_exhausted is False
        assert processor.snapshot.source_state is not SourceState.RECORDING
        assert (await request(app, "GET", "/status")).json() == {
            "interface": "fixture",
            "link_up": None,
            "recording": True,
            "drops_24h_pct": None,
            "overflows": None,
        }
    finally:
        await collector.stop()
        await task
    assert local[0]._observation_listener is None


def test_logging_selects_only_used_fields_and_stdout_temporary_file(tmp_path, monkeypatch, capsys):
    path = tmp_path / "config.json"
    sink = tmp_path / "logs" / "capture.log"
    path.write_text(
        json.dumps(
            {
                "log": {"file": str(sink), "level": "INFO", "verbose": "$UNUSED_VERBOSE"},
                "capture": {"source": "$UNUSED_SOURCE"},
                "influx": {"token": "$UNUSED_KEY"},
            }
        )
    )
    main._configure_logging(path)
    module = lifecycle()
    owner = module.ProcessorOwner(None, SimpleNamespace(), lambda: None)
    try:
        owner._failure(unavailable())
        owner._schedule()
        console = capsys.readouterr().out
        persisted = sink.read_text()
        for output in (console, persisted):
            assert "first_failure" in output and "scheduled" in output
            assert "dependency_unavailable" in output and "NewConnectionError" in output
            assert "SECRET" not in output and "dependency.invalid" not in output
    finally:
        logger.remove()


def test_none_main_logging_before_readonly_and_no_metric_source_or_key_load(tmp_path, monkeypatch):
    calls = []
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps(
            {
                "log": {"file": str(tmp_path / "capture.log"), "level": "INFO"},
                "capture": {"source": "$UNUSED"},
                "influx": {"token": "$UNUSED"},
            }
        )
    )
    monkeypatch.setenv("CAPTURE_TYPE", "NONE")
    monkeypatch.setenv("NETCAP_CONFIG_FILE", str(config))
    monkeypatch.setenv("CONTINUOUS_ROOT", str(tmp_path / "absent"))
    monkeypatch.setattr(main, "load_settings", Mock(side_effect=AssertionError("NONE metric settings")))
    original = Ledger.open_existing_readonly

    def view(root):
        assert (tmp_path / "capture.log").exists()
        calls.append("view")
        return original(root)

    monkeypatch.setattr(Ledger, "open_existing_readonly", view)

    def serve(app, **kwargs):
        with TestClient(app) as client:
            assert client.get("/health").json() == {"status": "ok"}
            assert client.post("/ingest/v1/observation", content=b"bad").status_code == 503
            assert not hasattr(app.state, "processor")
        calls.append("serve")

    monkeypatch.setattr(main.uvicorn, "run", serve)
    try:
        main.main()
    finally:
        logger.remove()
    assert calls == ["view", "serve"] and not (tmp_path / "absent").exists()


@pytest.mark.asyncio
async def test_constructor_readiness_deadline_rejects_late_return_and_closes_once(local, monkeypatch):
    closed = []

    def factory(*args):
        local[1].now += 5
        return SimpleNamespace(
            process_one=Mock(side_effect=AssertionError("late owner processing")), close=lambda: closed.append(True)
        )

    app, owner = app_owner(local, monkeypatch, factory)

    async def pause(delay):
        assert delay is None
        owner.stop_event.set()

    monkeypatch.setattr(owner, "_pause", pause)
    async with app.router.lifespan_context(app):
        await app.state.processor_task
        assert owner.processor_state == "blocked" and owner.attempts == 1
        assert (await request(app, "GET", "/health")).status_code == 200
    assert closed == [True]


@pytest.mark.asyncio
async def test_owned_close_failure_blocks_without_retry_or_false_usable(local, monkeypatch):
    closed = []

    def close():
        closed.append(True)
        raise unavailable()

    app, owner = app_owner(
        local, monkeypatch, lambda *args: SimpleNamespace(process_one=Mock(side_effect=unavailable()), close=close)
    )

    async def pause(delay):
        assert delay is None
        owner.stop_event.set()

    monkeypatch.setattr(owner, "_pause", pause)
    async with app.router.lifespan_context(app):
        await app.state.processor_task
        assert owner.processor_state == "blocked" and not owner.usable
        assert not owner.retry_exhausted and owner.attempts == 1
    assert closed == [True]


@pytest.mark.asyncio
async def test_cancellation_during_constructor_retains_and_closes_returned_owner(local, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    closed = []

    def factory(*args):
        entered.set()
        assert release.wait(1)
        return SimpleNamespace(
            process_one=Mock(side_effect=AssertionError("cancelled processor")), close=lambda: closed.append(True)
        )

    app, owner = app_owner(local, monkeypatch, factory)
    async with app.router.lifespan_context(app):
        try:
            assert await asyncio.to_thread(entered.wait, 1)
            app.state.processor_task.cancel()
            await asyncio.sleep(0)
            assert not app.state.processor_task.done()
        finally:
            release.set()
        await app.state.processor_task
    assert closed == [True] and owner._work_task is None


@pytest.mark.asyncio
async def test_index_failure_never_retries_as_dependency_or_processes(local, monkeypatch):
    process, close = Mock(), Mock()
    app, owner = app_owner(local, monkeypatch, lambda *args: SimpleNamespace(process_one=process, close=close))
    owner.refresh_index = Mock(side_effect=unavailable())

    async def pause(delay):
        assert delay is None
        owner.stop_event.set()

    monkeypatch.setattr(owner, "_pause", pause)
    async with app.router.lifespan_context(app):
        await app.state.processor_task
        assert owner.processor_state == "blocked" and owner.reason == "custody_invalid"
    process.assert_not_called()
    close.assert_called_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("recording", [True, False])
async def test_fresh_collector_is_independent_and_stale_status_is_null(local, monkeypatch, recording):
    app, owner = app_owner(local, monkeypatch, Mock(side_effect=unavailable()))
    result = await request(
        app,
        "POST",
        "/ingest/v1/observation",
        headers={"X-Source-Key": SOURCE},
        json={"interface": "fixture", "recording": recording},
    )
    assert result.json() == {"observed": True}
    assert (await request(app, "GET", "/status")).json()["recording"] is recording
    assert owner.snapshot.source_state is SourceState.WAITING
    local[1].now += 6
    assert (await request(app, "GET", "/status")).json()["recording"] is None
    assert owner.snapshot.observation_age_seconds == 6
    assert owner.snapshot.source_state is not SourceState.RECORDING


@pytest.mark.asyncio
@pytest.mark.parametrize("delay", [2, 4, 8, 16])
async def test_collector_stop_interrupts_each_delay_and_removes_listener(local, monkeypatch, delay):
    app, owner = app_owner(local, monkeypatch, Mock(side_effect=unavailable()))
    collector = app.state.collector
    entered = asyncio.Event()
    real_wait = collector._wait

    async def wait(seconds):
        if seconds == delay:
            entered.set()
            await real_wait(seconds)
        else:
            local[1].now += seconds

    monkeypatch.setattr(collector, "_wait", wait)
    task = asyncio.create_task(collector.run())
    await entered.wait()
    before = collector.attempts
    await collector.stop()
    await task
    assert collector.attempts == before and collector.retry_at is None
    assert local[0]._observation_listener is None


def test_logging_missing_used_placeholder_fails_before_custody(tmp_path, monkeypatch):
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"log": {"file": "$A4B_MISSING_LOG", "level": "INFO"}}))
    monkeypatch.delenv("A4B_MISSING_LOG", raising=False)
    monkeypatch.setenv("CAPTURE_TYPE", "NONE")
    monkeypatch.setenv("NETCAP_CONFIG_FILE", str(config))
    view = Mock(side_effect=AssertionError("custody before logging"))
    monkeypatch.setattr(Ledger, "open_existing_readonly", view)
    with pytest.raises(Exception, match="A4B_MISSING_LOG"):
        main.main()
    view.assert_not_called()


def test_none_no_config_uses_configured_temporary_sink_without_adapter_load(tmp_path, monkeypatch, capsys):
    sink = tmp_path / "capture.log"
    monkeypatch.setenv("NETCAP_LOG_FILE", str(sink))
    try:
        main._configure_logging(None)
        logger.warning("Processor blocked reason=upstream_unavailable exception=Exception")
        assert "blocked" in capsys.readouterr().out and "blocked" in sink.read_text()
    finally:
        logger.remove()


@pytest.mark.asyncio
async def test_sixty_second_failed_call_is_not_stable_usable_reset(local, monkeypatch):
    count = 0
    closed = []

    class Pipeline:
        steps = 0

        def process_one(self):
            self.steps += 1
            if self.steps == 1:
                return False
            local[1].now += 60
            raise unavailable()

        def close(self):
            closed.append(True)

    def factory(*args):
        nonlocal count
        count += 1
        if count == 2:
            owner.stop_event.set()
        return Pipeline()

    app, owner = app_owner(local, monkeypatch, factory)
    waits = []

    async def pause(delay):
        if delay >= 2:
            waits.append(delay)
            local[1].now += delay

    monkeypatch.setattr(owner, "_pause", pause)
    async with app.router.lifespan_context(app):
        await app.state.processor_task
    assert waits == [2] and owner.attempts == 2 and closed == [True, True]


@pytest.mark.asyncio
@pytest.mark.parametrize("stable", [59.999, 60.0])
async def test_collector_continuous_fresh_reset_and_short_flapping(local, monkeypatch, stable):
    app, owner = app_owner(local, monkeypatch, Mock(side_effect=unavailable()))
    collector = app.state.collector
    collector.attempts = 5
    collector.retry_exhausted = True
    local[0].observe({"interface": "fixture", "recording": True})
    steps = 0

    async def wait(delay):
        nonlocal steps
        steps += 1
        if steps == 1:
            # Simulate successive accepted receipts throughout stable uptime.
            start = local[1]()
            while local[1]() < start + stable:
                local[1].now = min(start + stable, local[1]() + 3)
                local[0].observe({"interface": "fixture", "recording": False})
                await asyncio.sleep(0)
        elif steps == 2:
            local[1].now += 6
        else:
            await collector.stop()

    monkeypatch.setattr(collector, "_wait", wait)
    await collector.run()
    assert not collector.present
    assert collector.attempts == (1 if stable == 60 else 5)
    assert collector.retry_exhausted is (stable != 60)
    assert local[0].observation() is None


def test_warning_exception_class_is_allowlisted_not_attacker_named(tmp_path, capsys):
    sink = tmp_path / "capture.log"
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"log": {"file": str(sink), "level": "WARNING"}}))
    error_type = type("SECRET_TOKEN_CLASS", (Exception,), {})
    try:
        main._configure_logging(config)
        owner = lifecycle().ProcessorOwner(None, SimpleNamespace(), lambda: None)
        owner._failure(error_type("https://SECRET@private.invalid"))
        for output in (capsys.readouterr().out, sink.read_text()):
            assert "blocked" in output and "exception=Exception" in output
            assert "SECRET" not in output and "private.invalid" not in output
    finally:
        logger.remove()


@pytest.mark.parametrize("failure", ["missing", "short"])
def test_live_source_key_failure_is_precise_pre_http_nonzero_without_custody(tmp_path, monkeypatch, failure):
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"log": {"file": str(tmp_path / "capture.log"), "level": "INFO"}}))
    key = tmp_path / "source-key"
    if failure == "short":
        key.write_text("short")
    monkeypatch.setenv("CAPTURE_TYPE", "LIVE")
    monkeypatch.setenv("NETCAP_CONFIG_FILE", str(config))
    monkeypatch.setenv("CONTINUOUS_SOURCE_KEY_FILE", str(key))
    monkeypatch.setattr(Ledger, "__init__", Mock(side_effect=AssertionError("custody before config")))
    monkeypatch.setattr(main.uvicorn, "run", Mock(side_effect=AssertionError("HTTP before config")))
    try:
        with pytest.raises(ValueError, match="CONTINUOUS_SOURCE_KEY_FILE"):
            main.main()
    finally:
        logger.remove()


@pytest.mark.asyncio
async def test_short_flapping_exhausts_five_owned_instances_without_tail_flush(local, monkeypatch):
    instances, waits = [], []

    class Pipeline:
        steps = 0
        closes = 0

        def process_one(self):
            self.steps += 1
            if self.steps == 1:
                return False
            raise unavailable()

        def close(self):
            self.closes += 1

    def factory(*args):
        instance = Pipeline()
        instances.append(instance)
        return instance

    app, owner = app_owner(local, monkeypatch, factory)

    async def pause(delay):
        if delay is None:
            owner.stop_event.set()
        elif delay >= 2:
            waits.append(delay)
            local[1].now += delay

    monkeypatch.setattr(owner, "_pause", pause)
    async with app.router.lifespan_context(app):
        await app.state.processor_task
        assert owner.processor_state == "degraded" and owner.retry_exhausted
    assert waits == [2, 4, 8, 16] and len(instances) == 5
    assert all(instance.closes == 1 and instance.steps == 2 for instance in instances)
    assert local[0].load_checkpoint() is None and local[0].pending_batches() == []


@pytest.mark.asyncio
async def test_actual_exhaustion_warnings_stdout_and_file_are_bounded(local, monkeypatch, tmp_path, capsys):
    sink = tmp_path / "capture.log"
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"log": {"file": str(sink), "level": "WARNING"}}))
    app, owner = app_owner(local, monkeypatch, Mock(side_effect=unavailable()))

    async def pause(delay):
        if delay is None:
            owner.stop_event.set()
        else:
            local[1].now += delay

    monkeypatch.setattr(owner, "_pause", pause)
    try:
        main._configure_logging(config)
        await owner.run()
        for output in (capsys.readouterr().out, sink.read_text()):
            assert output.count("Processor first_failure") == 1
            assert output.count("Processor scheduled") == 4
            assert output.count("Processor exhausted") == 1
            assert output.count("Processor failure") == 4
            assert "SECRET" not in output and "dependency.invalid" not in output
    finally:
        logger.remove()


def test_stable_reset_and_blocked_warnings_reach_both_sinks(tmp_path, capsys, monkeypatch):
    sink = tmp_path / "capture.log"
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"log": {"file": str(sink), "level": "WARNING"}}))
    clock = Clock()
    monkeypatch.setattr(lifecycle(), "monotonic", clock)
    try:
        main._configure_logging(config)
        owner = lifecycle().ProcessorOwner(None, SimpleNamespace(), lambda: None)
        owner.attempts = 3
        owner.stable_since = 40
        owner.last_usable = 100
        owner._failure(unavailable())
        owner._failure(PermissionError("SECRET"))
        assert owner.attempts == 0 and owner.processor_state == "blocked"
        for output in (capsys.readouterr().out, sink.read_text()):
            assert output.count("Processor reset") == 1 and output.count("Processor blocked") == 1
            assert "privilege_denied" in output and "SECRET" not in output
    finally:
        logger.remove()


@pytest.mark.parametrize("cause", [PermissionError("SECRET"), ssl.SSLError("SECRET")])
def test_transport_wrapper_never_retries_permission_or_tls_refusal(cause):
    error = unavailable()
    error.__cause__ = cause
    assert lifecycle().classify_failure(MaxRetryError(None, "/SECRET", error))[0] is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "state",
    [
        {"version": 1},
        {"version": 2, "timestamp_contract": "native-window-start-ms-v1", "config": "different"},
    ],
)
async def test_real_pipeline_checkpoint_refusal_is_http_alive_without_retry(local, monkeypatch, state):
    from desktop_ingest.settings import ReliablePipelineSettings

    ledger, clock = local
    with ledger.db:
        ledger.db.execute("INSERT INTO checkpoint VALUES(1,?)", (json.dumps(state),))
    settings = ReliablePipelineSettings.model_validate(
        {
            "interval_ms": 1000,
            "influx": {
                "host": "http://127.0.0.1:1",
                "token": "constructed",
                "database": "test",
                "measurement_name": "network",
                "tags": [],
                "fields": {},
            },
            "write_options": {"batch_size": 1, "flush_interval": 1, "jitter_interval": 0, "precision": "ms"},
        }
    )
    monkeypatch.setattr(lifecycle(), "monotonic", clock)
    app = main.build_app(settings, ledger, SOURCE, OPERATOR)
    owner = app.state.processor

    async def pause(delay):
        assert delay is None
        owner.stop_event.set()

    monkeypatch.setattr(owner, "_pause", pause)
    async with app.router.lifespan_context(app):
        await app.state.processor_task
        assert owner.processor_state == "blocked" and owner.reason == "checkpoint_incompatible"
        assert owner.attempts == 1 and not owner.usable
        assert (await request(app, "GET", "/health")).json() == {"status": "ok"}
    assert ledger.load_checkpoint() == state


@pytest.mark.asyncio
async def test_new_fresh_receipt_after_unobserved_stale_gap_does_not_reset_collector(local, monkeypatch):
    app, owner = app_owner(local, monkeypatch, Mock(side_effect=unavailable()))
    collector = app.state.collector
    collector.attempts = 4
    local[0].observe({"interface": "fixture", "recording": True})
    steps = 0

    async def wait(delay):
        nonlocal steps
        steps += 1
        if steps == 1:
            local[1].now += 60
            local[0].observe({"interface": "fixture", "recording": True})
            await asyncio.sleep(0)
        else:
            await collector.stop()

    monkeypatch.setattr(collector, "_wait", wait)
    await collector.run()
    assert collector.attempts == 4


@pytest.mark.parametrize(
    "cause,retry",
    [
        (OSError(errno.ECONNREFUSED, "SECRET"), True),
        (OSError(errno.ETIMEDOUT, "SECRET"), True),
        (OSError(errno.EINVAL, "SECRET"), False),
        (OSError("SECRET"), False),
        (ValueError("SECRET"), False),
        (RuntimeError("SECRET"), False),
    ],
)
def test_dependency_transport_wrapping_does_not_hide_unknown_or_configuration_cause(cause, retry):
    error = unavailable()
    error.__cause__ = cause
    assert lifecycle().classify_failure(error)[0] is retry


@pytest.mark.asyncio
async def test_collector_exhaustion_logs_both_sinks_once_without_tick_flood(local, monkeypatch, tmp_path, capsys):
    app, owner = app_owner(local, monkeypatch, Mock(side_effect=unavailable()))
    collector = app.state.collector
    sink = tmp_path / "capture.log"
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"log": {"file": str(sink), "level": "WARNING"}}))

    async def wait(delay):
        if delay is None:
            await collector.stop()
        else:
            local[1].now += delay

    monkeypatch.setattr(collector, "_wait", wait)
    try:
        main._configure_logging(config)
        await collector.run()
        for output in (capsys.readouterr().out, sink.read_text()):
            assert output.count("Collector first_failure") == 1
            assert output.count("Collector scheduled") == 4
            assert output.count("Collector exhausted") == 1
    finally:
        logger.remove()
