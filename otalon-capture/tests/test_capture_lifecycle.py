"""Wave A2 source contracts. Process doubles are not built-image evidence."""

from __future__ import annotations

import asyncio
import importlib
import json
import os
import stat
import subprocess
import sys
import threading
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient

from capture_runtime import AdapterSnapshot, CaptureIntent, SourceState
from pcap_recorder import api
from pcap_recorder import main as recorder_main
from pcap_recorder.index import PcapIndex
from pcap_recorder.recorder import TcpdumpRecorder
from pcap_recorder.ringbuffer import RingbufferManager
from pcap_recorder.settings import PcapRecorderSettings


def _settings(tmp_path, intent=CaptureIntent.LIVE):
    return PcapRecorderSettings.model_validate(
        {
            "pcap": {
                "interface": "fake0" if intent is CaptureIntent.LIVE else "",
                "chunk_duration_sec": 30,
                "ringbuffer": {"directory": str(tmp_path / "buffer"), "max_total_size_mb": 1, "max_file_count": 1},
                "archive": {"directory": str(tmp_path / "archive")},
            },
            "api": {"host": "127.0.0.1", "port": 9090, "subprocess_timeout_s": 7},
            "log": {"level": "INFO", "file": str(tmp_path / "recorder.log")},
        }
    )


def _lifecycle():
    return importlib.import_module("pcap_recorder.lifecycle")


class Child:
    pid = 321

    def __init__(self):
        self.returncode = None
        self.terminated = 0
        self.killed = 0
        self.reaped = 0
        self.exited = asyncio.Event()

    def terminate(self):
        self.terminated += 1
        self.returncode = 0
        self.exited.set()

    def kill(self):
        self.killed += 1
        self.returncode = -9
        self.exited.set()

    async def wait(self):
        await self.exited.wait()
        self.reaped += 1
        return self.returncode


class Recorder:
    interface = "fake0"

    def __init__(self, config):
        self.is_running = False
        self.starts = 0
        self.stops = 0

    def start(self):
        self.starts += 1
        self.is_running = True

    def stop(self, timeout_s=5.0):
        self.stops += 1
        self.is_running = False


class Clock:
    def __init__(self):
        self.now = 10.0

    def __call__(self):
        return self.now


def _pair(monkeypatch, tmp_path):
    module = _lifecycle()
    child = Child()
    clock = Clock()
    settings = _settings(tmp_path)
    recorder = Recorder(settings.pcap)
    monkeypatch.setattr(module, "ADAPTER_SNAPSHOT_PATH", str(tmp_path / "state.json"))
    monkeypatch.setattr(module.time, "monotonic", clock)
    monkeypatch.setattr(module, "_interface_exists", lambda interface: interface == "fake0")
    monkeypatch.setattr(module, "TcpdumpRecorder", lambda config: recorder)
    calls = []

    async def spawn(*args):
        calls.append(args)
        return child

    monkeypatch.setattr(module.asyncio, "create_subprocess_exec", spawn)
    owner = module.AcquisitionPair(settings.pcap)

    async def step(delay):
        clock.now += delay

    monkeypatch.setattr(owner, "_pause", step)
    return module, owner, child, recorder, clock, calls


def _snapshot(module, owner, child, clock, **changes):
    payload = asdict(AdapterSnapshot(SourceState.RECORDING, owner.generation, child.pid, clock(), None))
    payload.update(changes)
    Path(module.ADAPTER_SNAPSHOT_PATH).write_text(json.dumps(payload), encoding="utf-8")


def test_docker_plain_boot_and_capability_free_read_copy():
    source = (Path(__file__).resolve().parents[1] / "Dockerfile").read_text()
    assert 'ENTRYPOINT ["python","-u","/app/entrypoint.py"]' in source
    copy = 'cp --no-preserve=xattr "$(readlink -f "$(command -v tcpdump)")" /usr/local/bin/tcpdump-read'
    assert copy in source
    assert source.index(copy) < source.index("RUN setcap cap_net_raw,cap_net_admin+eip")
    assert "chmod 0755 /usr/local/bin/tcpdump-read" in source
    assert "setcap cap_net_raw,cap_net_admin+eip /usr/local/bin/python3-cap" in source
    assert "--uid 10006 --gid 10006" in source
    assert "COPY otalon-capture/src/ /app/src/" in source
    assert "HEALTHCHECK --interval=30s --timeout=5s" in source
    bootstrap = (Path(__file__).resolve().parents[1] / "entrypoint.py").read_text()
    body = bootstrap[bootstrap.index("async def _run(self)") :]
    assert body.index("modules = _resolve_modules()") < body.index("intent = resolve_capture_intent()")
    assert body.index("intent = resolve_capture_intent()") < body.index("await self._start_module(module)")
    main_source = Path(recorder_main.__file__).read_text()
    body = main_source[main_source.index("def main()") :]
    assert body.index("from_json_for_intent") < body.index("_configure_logging(settings.log)")
    assert body.index("_configure_logging(settings.log)") < body.index("_run_service(settings, intent, runtime_state)")


@pytest.mark.asyncio
@pytest.mark.parametrize("intent", ["NONE", "PCAP", "invalid"])
async def test_worker_override_is_selected_before_boot_gate(monkeypatch, intent):
    import entrypoint

    monkeypatch.setenv("NETCAP_ENTRYPOINT_MODULES", "pcap_import.main")
    monkeypatch.setenv("CAPTURE_TYPE", intent)
    owner = entrypoint.EntryPoint([])
    child = Child()
    child.terminate()
    calls = []

    async def spawn(*args):
        calls.append(args)
        return child

    monkeypatch.setattr(entrypoint.asyncio, "create_subprocess_exec", spawn)
    monkeypatch.setattr(entrypoint.signal, "signal", lambda *args: None)
    assert await owner._run() == 0
    assert calls == [(entrypoint.sys.executable, "-u", "-m", "pcap_import.main")]


@pytest.mark.asyncio
@pytest.mark.parametrize("modules", [None, "otalon_capture.main"])
async def test_automatic_boot_gate_precedes_child_exec(monkeypatch, modules):
    import entrypoint

    if modules is None:
        monkeypatch.delenv("NETCAP_ENTRYPOINT_MODULES", raising=False)
    else:
        monkeypatch.setenv("NETCAP_ENTRYPOINT_MODULES", modules)
    monkeypatch.setenv("CAPTURE_TYPE", "PCAP")
    spawn = Mock(side_effect=AssertionError("child exec before intent gate"))
    monkeypatch.setattr(entrypoint.asyncio, "create_subprocess_exec", spawn)
    with pytest.raises(ValueError, match="CAPTURE_TYPE=PCAP is retired"):
        await entrypoint.EntryPoint([])._run()
    spawn.assert_not_called()
    assert entrypoint.DEFAULT_MODULES == ("pcap_recorder.main",)


@pytest.mark.asyncio
async def test_none_rest_tripwires_and_no_automatic_evidence_mutation(monkeypatch, tmp_path):
    from capture_settings_base import OperatorAuthSettings
    from otalon_capture.influxdb_writer import InfluxDBWriter
    from otalon_capture.netcap import Netcap
    from otalon_capture.pipeline import CapturePipeline
    from otalon_capture.settings import Settings

    def forbidden(*args, **kwargs):
        pytest.fail("NONE initialized acquisition/metric settings/credentials or automatic tick")

    for target in (TcpdumpRecorder, recorder_main.CaptureLossMonitor, CapturePipeline, Netcap, InfluxDBWriter):
        monkeypatch.setattr(target, "__init__", forbidden)
    monkeypatch.setattr(Settings, "from_json", forbidden)
    monkeypatch.setattr(OperatorAuthSettings, "from_env", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", forbidden)
    monkeypatch.setattr(recorder_main, "_ringbuffer_loop", forbidden)
    monkeypatch.setattr(recorder_main, "_capture_stats_loop", forbidden)
    settings = _settings(tmp_path, CaptureIntent.NONE)
    state = recorder_main.RuntimeState()
    observed = []

    async def serve(app, host, port, runtime):
        runtime.uvicorn_server = SimpleNamespace(started=True, should_exit=False)
        with TestClient(app) as client:
            observed.append(client.get("/health").json())
            observed.append(client.get("/status").json())

    monkeypatch.setattr(recorder_main, "_run_uvicorn", serve)
    await recorder_main._run_service(settings, CaptureIntent.NONE, state)
    assert observed[0] == {"status": "ok"}
    assert observed[1]["recording"] is False
    assert observed[1]["interface"] is None
    assert not (tmp_path / "buffer").exists()
    assert not (tmp_path / "archive").exists()
    assert state.recorder is None
    assert state.ringbuffer_task is None
    assert state.capture_stats_task is None


def test_none_main_uses_intent_loader_before_service(monkeypatch, tmp_path):
    settings = _settings(tmp_path, CaptureIntent.NONE)
    monkeypatch.setenv("CAPTURE_TYPE", "NONE")
    monkeypatch.setattr(recorder_main, "load_dotenv", lambda **kwargs: None)
    loader = Mock(return_value=settings)
    monkeypatch.setattr(PcapRecorderSettings, "from_json_for_intent", loader)
    monkeypatch.setattr(PcapRecorderSettings, "from_json", Mock(side_effect=AssertionError("legacy loader")))
    monkeypatch.setattr(recorder_main, "_configure_logging", lambda config: None)
    monkeypatch.setattr(recorder_main.signal, "signal", lambda *args: None)

    async def service(config, intent, state):
        assert config is settings
        assert intent is CaptureIntent.NONE

    monkeypatch.setattr(recorder_main, "_run_service", service, raising=False)
    recorder_main.main()
    assert loader.call_args.args[1] is CaptureIntent.NONE


@pytest.mark.asyncio
async def test_rest_started_is_observed_before_source_attempt(monkeypatch, tmp_path):
    module = _lifecycle()
    events = []
    serving = asyncio.Event()
    finish = asyncio.Event()
    state = recorder_main.RuntimeState()

    async def serve(app, host, port, runtime):
        runtime.uvicorn_server = SimpleNamespace(started=False, should_exit=False)
        events.append("http-created")
        serving.set()
        await asyncio.sleep(0)
        runtime.uvicorn_server.started = True
        events.append("http-started")
        await finish.wait()

    class Pair:
        recorder = None
        stopped = False

        def __init__(self, config):
            assert state.uvicorn_server.started

        async def run(self):
            events.append("source")
            finish.set()

        async def start(self):
            await self.run()
            return False

        async def stop(self):
            if not self.stopped:
                events.append("reaped")
                self.stopped = True

    monkeypatch.setattr(module, "AcquisitionPair", Pair)
    monkeypatch.setattr(recorder_main, "_run_uvicorn", serve)
    await recorder_main._run_service(_settings(tmp_path), CaptureIntent.LIVE, state)
    assert events == ["http-created", "http-started", "source", "reaped"]


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["return", "raise"])
async def test_http_serving_failure_never_starts_acquisition(monkeypatch, tmp_path, failure):
    module = _lifecycle()
    monkeypatch.setattr(module, "AcquisitionPair", Mock(side_effect=AssertionError("source before HTTP")))

    async def serve(*args):
        if failure == "raise":
            raise RuntimeError("synthetic HTTP failure")

    monkeypatch.setattr(recorder_main, "_run_uvicorn", serve)
    if failure == "raise":
        with pytest.raises(RuntimeError, match="synthetic HTTP failure"):
            await recorder_main._run_service(_settings(tmp_path), CaptureIntent.LIVE, recorder_main.RuntimeState())
    else:
        await recorder_main._run_service(_settings(tmp_path), CaptureIntent.LIVE, recorder_main.RuntimeState())


@pytest.mark.asyncio
async def test_absent_source_is_waiting_without_either_exec(monkeypatch, tmp_path):
    module, owner, child, recorder, clock, calls = _pair(monkeypatch, tmp_path)
    monkeypatch.setattr(module, "_interface_exists", lambda interface: False)
    assert await owner.start() is False
    assert owner.snapshot.source_state is SourceState.WAITING
    assert owner.snapshot.reason_code == "source_absent"
    assert calls == []
    assert recorder.starts == 0
    await owner.stop()


@pytest.mark.asyncio
async def test_pair_ready_only_with_current_generation_and_both_producers(monkeypatch, tmp_path):
    module, owner, child, recorder, clock, calls = _pair(monkeypatch, tmp_path)
    Path(module.ADAPTER_SNAPSHOT_PATH).write_text("old generation", encoding="utf-8")

    async def ready(delay):
        assert recorder.is_running
        assert not Path(module.ADAPTER_SNAPSHOT_PATH).exists()
        _snapshot(module, owner, child, clock)

    monkeypatch.setattr(owner, "_pause", ready)
    assert await owner.start() is True
    assert calls == [
        ("/usr/local/bin/python3-cap", "-u", "-m", "otalon_capture.main", "--_capture-generation", owner.generation)
    ]
    assert owner.snapshot.source_state is SourceState.RECORDING
    assert recorder.starts == 1
    await owner.stop()
    await owner.stop()
    assert child.terminated == 1
    assert child.reaped == 1
    assert recorder.stops == 1
    assert owner.adapter is None
    assert owner.recorder is None
    assert not Path(module.ADAPTER_SNAPSHOT_PATH).exists()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "changes",
    [
        {"generation": "wrong"},
        {"child_pid": 999},
        {"updated_monotonic": 4.0},
        {"updated_monotonic": 100.0},
        {"state": "waiting"},
    ],
)
async def test_unready_snapshot_times_out_and_reaps_pair(monkeypatch, tmp_path, changes):
    module, owner, child, recorder, clock, calls = _pair(monkeypatch, tmp_path)
    began = clock()

    async def unready(delay):
        clock.now += delay
        _snapshot(module, owner, child, clock, **changes)

    monkeypatch.setattr(owner, "_pause", unready)
    assert await owner.start() is False
    assert clock() - began == pytest.approx(5.0)
    assert child.reaped == 1
    assert recorder.stops == 1
    assert owner.snapshot.source_state is SourceState.BLOCKED


@pytest.mark.asyncio
@pytest.mark.parametrize("lost", ["adapter", "recorder", "heartbeat"])
async def test_lost_child_or_stale_readiness_reaps_sibling(monkeypatch, tmp_path, lost):
    module, owner, child, recorder, clock, calls = _pair(monkeypatch, tmp_path)

    async def ready(delay):
        _snapshot(module, owner, child, clock)

    monkeypatch.setattr(owner, "_pause", ready)
    assert await owner.start()
    if lost == "adapter":
        child.terminate()
    elif lost == "recorder":
        recorder.is_running = False
    else:
        clock.now += 6
    await owner.run()
    assert owner.snapshot.source_state is SourceState.DEGRADED
    assert child.reaped == 1
    assert recorder.stops == 1
    assert owner.adapter is None
    assert owner.recorder is None


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["spawn", "recorder"])
async def test_start_exception_is_blocked_and_cleans_partial_pair(monkeypatch, tmp_path, failure):
    module, owner, child, recorder, clock, calls = _pair(monkeypatch, tmp_path)
    if failure == "spawn":

        async def denied(*args):
            raise PermissionError("synthetic refusal")

        monkeypatch.setattr(module.asyncio, "create_subprocess_exec", denied)
    else:
        recorder.start = Mock(side_effect=RuntimeError("synthetic constructor failure"))
    assert await owner.start() is False
    assert owner.snapshot.source_state is SourceState.BLOCKED
    assert owner.recorder is None
    assert owner.adapter is None
    if failure == "recorder":
        assert child.reaped == 1


def test_exited_tcpdump_stop_reaps_without_stale_terminate(tmp_path):
    recorder = TcpdumpRecorder(_settings(tmp_path).pcap)
    child = Mock()
    child.poll.return_value = 1
    child.terminate.side_effect = ProcessLookupError("already gone")
    recorder._process = child
    recorder.stop()
    child.terminate.assert_not_called()
    child.wait.assert_called_once()
    assert recorder._process is None
    assert recorder._stderr_thread is None


def test_historical_text_uses_fixed_reader_and_preserves_output_timeout(monkeypatch, tmp_path):
    run = Mock(return_value=SimpleNamespace(returncode=0, stdout="decoded\n", stderr=""))
    monkeypatch.setattr(api.subprocess, "run", run)
    path = tmp_path / "20260213_120000.pcap"
    assert api._tcpdump_read_text(path, timeout_s=7) == "decoded\n"
    run.assert_called_once_with(
        ["/usr/local/bin/tcpdump-read", "-r", str(path), "-q", "-tttt", "-n"], capture_output=True, text=True, timeout=7
    )
    run.return_value = SimpleNamespace(returncode=1, stdout="partial", stderr="read error")
    assert api._tcpdump_read_text(path) == "partial\n--- stderr ---\nread error"
    run.side_effect = subprocess.TimeoutExpired("read", 7)
    with pytest.raises(RuntimeError, match="tcpdump timed out after 7s"):
        api._tcpdump_read_text(path, timeout_s=7)


def test_idle_index_ring_do_not_create_or_quarantine_but_explicit_pinning_works(tmp_path):
    settings = _settings(tmp_path, CaptureIntent.NONE)
    index_path = tmp_path / "buffer" / "pcap_index.json"
    index = PcapIndex(index_path, auto_write=False)
    ring = RingbufferManager(settings.pcap.ringbuffer, settings.pcap.archive, index, auto_write=False)
    assert not index_path.parent.exists()
    index_path.parent.mkdir()
    index_path.write_text("{bad", encoding="utf-8")
    with pytest.raises(ValueError, match="Corrupt retained PCAP index"):
        PcapIndex(index_path, auto_write=False)
    assert index_path.read_text() == "{bad"
    chunk = index_path.parent / "20260213_120000.pcap"
    chunk.write_bytes(b"owned synthetic bytes")
    meta = index.add_chunk(chunk)
    api.PcapService(index, ring).flag_anomaly(meta.start_ts, meta.end_ts, {"case": "synthetic"})
    assert meta.pinned
    assert meta.path == tmp_path / "archive" / chunk.name
    assert meta.path.read_bytes() == b"owned synthetic bytes"


@pytest.mark.parametrize("intent", ["NONE", "PCAP", "invalid"])
def test_direct_adapter_gate_before_metric_settings(monkeypatch, intent):
    from otalon_capture import main as adapter_main

    monkeypatch.setenv("CAPTURE_TYPE", intent)
    monkeypatch.setattr(adapter_main, "load_dotenv", lambda **kwargs: None)
    loader = Mock(side_effect=AssertionError("settings before adapter gate"))
    monkeypatch.setattr(adapter_main.Settings, "from_json", loader)
    with pytest.raises(ValueError, match="CAPTURE_TYPE"):
        adapter_main.main()
    loader.assert_not_called()


def test_adapter_readiness_follows_constructor_and_heartbeat_is_joined(monkeypatch, tmp_path):
    from otalon_capture import main as adapter_main

    monkeypatch.setenv("CAPTURE_TYPE", "LIVE")
    monkeypatch.setattr(adapter_main, "ADAPTER_SNAPSHOT_PATH", str(tmp_path / "adapter.json"))
    monkeypatch.setattr(sys, "argv", ["adapter", "--_capture-generation", "owned-generation"])
    monkeypatch.setattr(adapter_main, "load_dotenv", lambda **kwargs: None)
    settings = SimpleNamespace(
        log=None,
        influx=SimpleNamespace(
            host="http://synthetic.invalid", token=SimpleNamespace(get_secret_value=lambda: "synthetic")
        ),
    )
    monkeypatch.setattr(adapter_main.Settings, "from_json", lambda path: settings)
    monkeypatch.setattr(adapter_main, "configure_logger", lambda config: None)
    monkeypatch.setattr(adapter_main.signal, "signal", lambda *args: None)
    health = Mock(return_value=False)
    monkeypatch.setattr(adapter_main, "wait_for_influx_health", health)
    stop_calls = []

    class Pipeline:
        def __init__(self, config):
            assert not Path(adapter_main.ADAPTER_SNAPSHOT_PATH).exists()

        def run(self):
            snapshot = json.loads(Path(adapter_main.ADAPTER_SNAPSHOT_PATH).read_text())
            assert snapshot["state"] == "recording"
            assert snapshot["generation"] == "owned-generation"
            assert snapshot["child_pid"] == adapter_main.os.getpid()
            assert any(thread.name == "capture-adapter-heartbeat" for thread in threading.enumerate())

        def stop(self):
            stop_calls.append("stop")

    monkeypatch.setattr(adapter_main, "CapturePipeline", Pipeline)
    adapter_main.main()
    assert health.call_args.kwargs["max_wait_s"] == 2.0
    assert health.call_args.kwargs["timeout_s"] <= 2.0
    assert health.call_args.kwargs["stop_event"] is not None
    assert not any(thread.name == "capture-adapter-heartbeat" for thread in threading.enumerate())
    assert json.loads(Path(adapter_main.ADAPTER_SNAPSHOT_PATH).read_text())["state"] != "recording"
    assert stop_calls == ["stop"]


def test_failed_pipeline_constructor_releases_partial_reader_writer(monkeypatch):
    from otalon_capture import main as adapter_main

    reader = Mock()
    writer = Mock()

    class Pipeline:
        def __init__(self, settings):
            self._capture = reader
            self._writer = writer
            raise RuntimeError("synthetic partial constructor")

    monkeypatch.setattr(adapter_main, "CapturePipeline", Pipeline)
    with pytest.raises(RuntimeError, match="synthetic partial constructor"):
        adapter_main._construct_pipeline(None)
    reader.stop.assert_called_once()
    writer.close.assert_called_once()


def test_advisory_health_budget_uses_remaining_time_and_interruptible_wait(monkeypatch):
    from otalon_capture import helper

    clock = Clock()
    event = threading.Event()
    timeouts = []

    def unavailable(req, timeout):
        timeouts.append(timeout)
        clock.now += timeout
        raise helper.error.URLError("synthetic offline")

    monkeypatch.setattr(helper.time, "monotonic", clock)
    monkeypatch.setattr(helper.request, "urlopen", unavailable)
    monkeypatch.setattr(helper.time, "sleep", Mock(side_effect=AssertionError("uncancellable health wait")))
    began = clock()
    assert (
        helper.wait_for_influx_health("http://synthetic.invalid", timeout_s=5, max_wait_s=2, stop_event=event) is False
    )
    assert clock() - began == 2
    assert timeouts == [2]
    event.set()
    assert helper.wait_for_influx_health("http://synthetic.invalid", stop_event=event) is False
    assert timeouts == [2]


@pytest.mark.asyncio
async def test_stop_during_adapter_spawn_reaps_returned_child(monkeypatch, tmp_path):
    module, owner, child, recorder, clock, calls = _pair(monkeypatch, tmp_path)
    entered = asyncio.Event()
    release = asyncio.Event()

    async def spawn(*args):
        entered.set()
        await release.wait()
        return child

    monkeypatch.setattr(module.asyncio, "create_subprocess_exec", spawn)
    attempt = asyncio.create_task(owner.start())
    await entered.wait()
    stopping = asyncio.create_task(owner.stop())
    await asyncio.sleep(0)
    release.set()
    assert await attempt is False
    await stopping
    assert child.reaped == 1
    assert child.terminated == 1
    assert recorder.starts == 0
    assert owner.adapter is None


def test_snapshot_file_read_is_bounded(monkeypatch, tmp_path):
    module = _lifecycle()
    owner = module.AcquisitionPair(_settings(tmp_path).pcap)
    owner.adapter = SimpleNamespace(pid=321)
    handle = Mock()
    handle.read.return_value = b"x" * 4097
    handle.fileno.return_value = 123
    opened = Mock()
    opened.__enter__ = Mock(return_value=handle)
    opened.__exit__ = Mock(return_value=False)
    descriptor = Mock(return_value=123)
    monkeypatch.setattr(
        module,
        "os",
        SimpleNamespace(
            open=descriptor,
            fdopen=lambda *args: opened,
            fstat=lambda fd: SimpleNamespace(st_mode=stat.S_IFREG),
            O_RDONLY=os.O_RDONLY,
            O_NONBLOCK=os.O_NONBLOCK,
            O_NOFOLLOW=os.O_NOFOLLOW,
        ),
    )
    assert owner._read_snapshot() is None
    descriptor.assert_called_once_with(module.ADAPTER_SNAPSHOT_PATH, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    handle.read.assert_called_once_with(4097)


@pytest.mark.asyncio
async def test_shutdown_kill_fallback_and_total_budget(monkeypatch, tmp_path):
    module, owner, child, recorder, clock, calls = _pair(monkeypatch, tmp_path)
    owner.adapter = child
    owner.recorder = recorder
    child.terminate = Mock()
    waits = []

    async def wait():
        waits.append("wait")
        if len(waits) == 1:
            raise asyncio.TimeoutError
        assert child.killed == 1
        child.reaped += 1
        return -9

    child.wait = wait
    recorder.stop = Mock()
    original = asyncio.wait_for
    budgets = []

    async def bounded(awaitable, timeout):
        budgets.append(timeout)
        return await original(awaitable, timeout)

    monkeypatch.setattr(asyncio, "wait_for", bounded)
    state = recorder_main.RuntimeState()
    state.acquisition = owner
    finished = asyncio.Event()

    class Server:
        started = True

        @property
        def should_exit(self):
            return finished.is_set()

        @should_exit.setter
        def should_exit(self, value):
            if value:
                finished.set()

    state.uvicorn_server = Server()
    state.http_task = asyncio.create_task(finished.wait())
    state.ringbuffer_task = asyncio.create_task(asyncio.Event().wait())
    state.capture_stats_task = asyncio.create_task(asyncio.Event().wait())
    await state.stop()
    await state.stop()
    assert budgets == [8.0, 5.0, 1.0]
    assert child.killed == 1
    assert child.reaped == 1
    recorder.stop.assert_called_once_with(timeout_s=2.0)
    assert state.http_task.done()
    assert state.ringbuffer_task.cancelled()
    assert state.capture_stats_task.cancelled()


@pytest.mark.parametrize("stage", ["constructor", "run"])
def test_adapter_failure_publishes_nonready_and_leaves_no_heartbeat(monkeypatch, tmp_path, stage):
    from otalon_capture import main as adapter_main

    monkeypatch.setenv("CAPTURE_TYPE", "LIVE")
    monkeypatch.setattr(sys, "argv", ["adapter", "--_capture-generation", "failure-generation"])
    monkeypatch.setattr(adapter_main, "ADAPTER_SNAPSHOT_PATH", str(tmp_path / "failed.json"))
    monkeypatch.setattr(adapter_main, "load_dotenv", lambda **kwargs: None)
    monkeypatch.setattr(adapter_main, "configure_logger", lambda config: None)
    monkeypatch.setattr(adapter_main.signal, "signal", lambda *args: None)
    monkeypatch.setattr(
        adapter_main.Settings,
        "from_json",
        lambda path: SimpleNamespace(
            log=None,
            influx=SimpleNamespace(host="synthetic", token=SimpleNamespace(get_secret_value=lambda: "synthetic")),
        ),
    )
    monkeypatch.setattr(adapter_main, "wait_for_influx_health", lambda *args, **kwargs: False)
    stopped = []

    class Pipeline:
        def __init__(self, settings):
            if stage == "constructor":
                raise RuntimeError("synthetic constructor")

        def run(self):
            raise RuntimeError("synthetic run")

        def stop(self):
            stopped.append(True)

    monkeypatch.setattr(adapter_main, "CapturePipeline", Pipeline)
    with pytest.raises(RuntimeError, match=f"synthetic {stage}"):
        adapter_main.main()
    payload = json.loads(Path(adapter_main.ADAPTER_SNAPSHOT_PATH).read_text())
    assert payload["state"] == "blocked"
    assert payload["reason_code"] == "dependency_unavailable"
    assert not any(thread.name == "capture-adapter-heartbeat" for thread in threading.enumerate())
    assert stopped == ([] if stage == "constructor" else [True])


def test_none_retained_request_shapes_auth_pinning_and_decoder_errors(monkeypatch, tmp_path):
    settings = _settings(tmp_path, CaptureIntent.NONE)
    index = PcapIndex(tmp_path / "buffer" / "pcap_index.json")
    chunk = tmp_path / "buffer" / "20260213_120000.pcap"
    chunk.write_bytes(b"owned synthetic evidence")
    meta = index.add_chunk(chunk)
    ring = RingbufferManager(settings.pcap.ringbuffer, settings.pcap.archive, index, auto_write=False)
    state = recorder_main.RuntimeState()
    service = api.PcapService(index, ring, settings.api)
    client = TestClient(api.create_app(service, api.CaptureStatusProvider(state)))
    monkeypatch.delenv("OTALON_OPERATOR_KEY", raising=False)
    monkeypatch.delenv("ADMIN_API_KEY", raising=False)
    decoder = Mock(return_value=SimpleNamespace(returncode=0, stdout="synthetic decoded\n", stderr=""))
    monkeypatch.setattr(api.subprocess, "run", decoder)
    monkeypatch.setattr(api, "_build_privilege_dropper", lambda: None)
    params = {"start_ts": meta.start_ts.isoformat(), "end_ts": meta.end_ts.isoformat(), "format": "text"}
    assert client.get("/chunks", params=params).status_code == 503
    decoder.assert_not_called()
    monkeypatch.setenv("ADMIN_API_KEY", "synthetic-evidence-key")
    assert client.get("/chunks", params=params).status_code == 401
    client.headers["X-API-Key"] = "synthetic-evidence-key"
    for route in ("/chunks", f"/chunks/{chunk.name}"):
        response = client.get(route, params=params)
        assert response.status_code == 200
        assert response.text == "synthetic decoded\n"
        assert decoder.call_args.args[0] == ["/usr/local/bin/tcpdump-read", "-r", str(chunk), "-q", "-tttt", "-n"]
        assert decoder.call_args.kwargs["timeout"] == 7
    response = client.get(f"/chunks/{chunk.name}", params={"format": "detail", "tshark_args": "-q -z io,phs"})
    assert response.status_code == 200
    assert decoder.call_args.args[0] == ["tshark", "-r", str(chunk), "-q", "-z", "io,phs"]
    before = decoder.call_count
    assert (
        client.get(f"/chunks/{chunk.name}", params={"format": "detail", "tshark_args": "-r /other"}).status_code == 400
    )
    assert client.get(f"/chunks/{chunk.name}", params={"format": "invalid"}).status_code == 422
    assert client.get("/chunks/not-a-chunk", params={"format": "text"}).status_code == 422
    assert client.get("/chunks/20260101_000000.pcap", params={"format": "text"}).status_code == 404
    assert decoder.call_count == before
    decoder.side_effect = FileNotFoundError("synthetic missing decoder")
    assert client.get(f"/chunks/{chunk.name}", params={"format": "text"}).status_code == 500
    assert client.get(f"/chunks/{chunk.name}", params={"format": "detail"}).status_code == 500
    response = client.post(
        "/anomalies/flag",
        json={
            "start_ts": meta.start_ts.isoformat(),
            "end_ts": meta.end_ts.isoformat(),
            "labels": {"case": "synthetic"},
        },
    )
    assert response.status_code == 200
    assert response.json() == {"chunk_ids": [chunk.name]}
    assert meta.pinned
    assert meta.labels == {"case": "synthetic"}
    assert meta.path.read_bytes() == b"owned synthetic evidence"
    assert client.get("/status").json()["recording"] is False


@pytest.mark.asyncio
async def test_http_exit_after_acquisition_cleans_owned_tasks_and_pair(monkeypatch, tmp_path):
    module = _lifecycle()
    active = asyncio.Event()
    state = recorder_main.RuntimeState()
    recorder = Recorder(_settings(tmp_path).pcap)
    cleaned = []

    class Pair:
        def __init__(self, config):
            self.recorder = recorder
            self.stopped = False
            self.ended = asyncio.Event()

        async def start(self):
            recorder.start()
            return True

        async def run(self):
            active.set()
            await self.ended.wait()

        async def stop(self):
            if not self.stopped:
                recorder.stop()
                self.stopped = True
                cleaned.append(True)
                self.ended.set()

    async def serve(app, host, port, runtime):
        runtime.uvicorn_server = SimpleNamespace(started=True, should_exit=False)
        await active.wait()
        raise RuntimeError("synthetic serving loss")

    monkeypatch.setattr(module, "AcquisitionPair", Pair)
    monkeypatch.setattr(
        recorder_main, "CaptureLossMonitor", lambda interface: SimpleNamespace(poll_and_log=lambda: None)
    )
    monkeypatch.setattr(recorder_main, "_run_uvicorn", serve)
    with pytest.raises(RuntimeError, match="synthetic serving loss"):
        await recorder_main._run_service(_settings(tmp_path), CaptureIntent.LIVE, state)
    assert cleaned == [True]
    assert not recorder.is_running
    assert state.recorder is None
    assert state.acquisition_task.done()
    assert state.ringbuffer_task.cancelled()
    assert state.capture_stats_task.cancelled()


def test_atomic_snapshot_has_only_bounded_domain_and_no_temporary_file(monkeypatch, tmp_path):
    from otalon_capture import main as adapter_main

    path = tmp_path / "state.json"
    monkeypatch.setattr(adapter_main, "ADAPTER_SNAPSHOT_PATH", str(path))
    adapter_main._write_snapshot("owned", SourceState.RECORDING)
    old = path.open("rb")
    try:
        adapter_main._write_snapshot("next-owned", SourceState.BLOCKED, "dependency_unavailable")
        assert json.loads(old.read())["generation"] == "owned"
        assert len(path.read_bytes()) <= 4096
        assert set(json.loads(path.read_bytes())) == {
            "state",
            "generation",
            "child_pid",
            "updated_monotonic",
            "reason_code",
        }
        assert path.stat().st_mode & 0o777 == 0o600
        assert list(tmp_path.iterdir()) == [path]
    finally:
        old.close()


def test_adapter_heartbeat_refreshes_while_pipeline_is_blocked(monkeypatch, tmp_path):
    from otalon_capture import main as adapter_main

    monkeypatch.setenv("CAPTURE_TYPE", "LIVE")
    monkeypatch.setattr(sys, "argv", ["adapter", "--_capture-generation", "heartbeat-owned"])
    path = tmp_path / "heartbeat.json"
    monkeypatch.setattr(adapter_main, "ADAPTER_SNAPSHOT_PATH", str(path))
    monkeypatch.setattr(adapter_main, "load_dotenv", lambda **kwargs: None)
    monkeypatch.setattr(adapter_main, "configure_logger", lambda config: None)
    monkeypatch.setattr(adapter_main.signal, "signal", lambda *args: None)
    settings = SimpleNamespace(
        log=None, influx=SimpleNamespace(host="synthetic", token=SimpleNamespace(get_secret_value=lambda: "synthetic"))
    )
    monkeypatch.setattr(adapter_main.Settings, "from_json", lambda config: settings)
    monkeypatch.setattr(adapter_main, "wait_for_influx_health", lambda *args, **kwargs: False)
    refreshed = threading.Event()
    in_pipeline = threading.Event()
    snapshots = []
    original_write = adapter_main._write_snapshot
    failure = []

    def write(generation, state, reason=None):
        original_write(generation, state, reason)
        snapshots.append((state, json.loads(path.read_text())["updated_monotonic"]))
        if threading.current_thread().name == "capture-adapter-heartbeat":
            assert in_pipeline.is_set()
            refreshed.set()

    monkeypatch.setattr(adapter_main, "_write_snapshot", write)

    class Pipeline:
        def __init__(self, settings):
            pass

        def run(self):
            in_pipeline.set()
            assert refreshed.wait(2.0), "independent heartbeat did not refresh"

        def stop(self):
            pass

    monkeypatch.setattr(adapter_main, "CapturePipeline", Pipeline)

    def run():
        try:
            adapter_main.main()
        except BaseException as error:
            failure.append(error)

    adapter = threading.Thread(target=run, name="synthetic-adapter")
    adapter.start()
    adapter.join(timeout=3.0)
    assert not adapter.is_alive()
    assert failure == []
    ready = [instant for state, instant in snapshots if state is SourceState.RECORDING]
    assert len(ready) >= 2
    assert ready[-1] > ready[0]
    assert not any(thread.name == "capture-adapter-heartbeat" for thread in threading.enumerate())
