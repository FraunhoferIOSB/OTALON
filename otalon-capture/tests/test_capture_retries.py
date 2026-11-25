"""Scoped A3 acquisition evidence, not authenticated publication acceptance."""

from __future__ import annotations

import asyncio
import io
import json
import sys
import threading
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
from urllib.error import HTTPError

import pytest
from loguru import logger

from capture_runtime import AdapterSnapshot, SourceState
from pcap_recorder import lifecycle
from pcap_recorder import main as recorder_main
from pcap_recorder.recorder import TcpdumpRecorder
from pcap_recorder.settings import PcapRecorderSettings


def _settings(tmp_path):
    return PcapRecorderSettings.model_validate(
        {
            "pcap": {
                "interface": "fake0",
                "chunk_duration_sec": 30,
                "ringbuffer": {"directory": str(tmp_path / "buffer"), "max_total_size_mb": 1, "max_file_count": 1},
                "archive": {"directory": str(tmp_path / "archive")},
            },
            "api": {"host": "127.0.0.1", "port": 9090},
            "log": {"level": "INFO", "file": str(tmp_path / "recorder.log")},
        }
    )


class Clock:
    now = 10.0

    def __call__(self):
        return self.now


class Child:
    pid = 321

    def __init__(self):
        self.returncode = None
        self.reaped = 0
        self.exited = asyncio.Event()

    def terminate(self):
        self.returncode = 0
        self.exited.set()

    def kill(self):
        self.terminate()

    async def wait(self):
        await self.exited.wait()
        self.reaped += 1
        return self.returncode


class Recorder:
    interface = "fake0"

    def __init__(self, config):
        self.is_running = False
        self.stops = 0

    def start(self):
        self.is_running = True

    def stop(self, timeout_s=5.0):
        self.stops += 1
        self.is_running = False


def _owner(monkeypatch, tmp_path):
    clock = Clock()
    monkeypatch.setattr(lifecycle.time, "monotonic", clock)
    monkeypatch.setattr(lifecycle, "ADAPTER_SNAPSHOT_PATH", str(tmp_path / "adapter.json"))
    monkeypatch.setattr(lifecycle, "_interface_exists", lambda interface: True)
    owner = lifecycle.AcquisitionPair(_settings(tmp_path).pcap)
    children, recorders, launches, pauses = [], [], [], []

    async def spawn(*args):
        assert not Path(lifecycle.ADAPTER_SNAPSHOT_PATH).exists()
        assert all(child.reaped == 1 for child in children)
        assert all(recorder.stops == 1 for recorder in recorders)
        child = Child()
        child.pid += len(children)
        children.append(child)
        launches.append((clock(), args[-1], child.pid))
        return child

    def recorder(config):
        result = Recorder(config)
        recorders.append(result)
        return result

    async def pause(seconds):
        pauses.append(seconds)
        clock.now += seconds
        if owner.adapter is not None and owner.recorder is not None:
            snapshot = AdapterSnapshot(SourceState.RECORDING, owner.generation, owner.adapter.pid, clock(), None)
            Path(lifecycle.ADAPTER_SNAPSHOT_PATH).write_text(json.dumps(asdict(snapshot)))

    monkeypatch.setattr(lifecycle.asyncio, "create_subprocess_exec", spawn)
    monkeypatch.setattr(lifecycle, "TcpdumpRecorder", recorder)
    monkeypatch.setattr(owner, "_pause", pause)
    return owner, clock, children, recorders, launches, pauses


@pytest.mark.asyncio
async def test_five_absent_attempts_exact_backoffs_then_idle_no_exec(monkeypatch, tmp_path):
    owner, clock, children, recorders, launches, pauses = _owner(monkeypatch, tmp_path)
    attempts = []
    monkeypatch.setattr(lifecycle, "_interface_exists", lambda interface: attempts.append(clock()) or False)
    began = clock()
    assert await owner.start() is False
    assert [instant - began for instant in attempts] == [0, 2, 6, 14, 30]
    assert pauses == [2, 4, 8, 16]
    assert owner.snapshot.source_state is SourceState.WAITING
    assert owner.snapshot.reason_code == "retry_exhausted"
    assert owner.snapshot.retry_attempt == 5
    assert owner.snapshot.retry_exhausted is True
    assert owner.snapshot.retry_in_seconds is None
    for _ in range(20):
        assert await owner.start() is False
    assert len(attempts) == 5
    assert launches == children == recorders == []
    await owner.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize("delay", [2, 4, 8, 16])
async def test_stop_at_each_backoff_is_immediate_and_never_executes(monkeypatch, tmp_path, delay):
    owner, clock, children, recorders, launches, pauses = _owner(monkeypatch, tmp_path)
    monkeypatch.setattr(lifecycle, "_interface_exists", lambda interface: False)
    observed = []

    async def pause(seconds):
        observed.append(seconds)
        assert owner.snapshot.retry_in_seconds == seconds
        if seconds == delay:
            await owner.stop()
        else:
            clock.now += seconds

    monkeypatch.setattr(owner, "_pause", pause)
    assert await owner.start() is False
    assert observed == [2, 4, 8, 16][: [2, 4, 8, 16].index(delay) + 1]
    assert owner.snapshot.retry_attempt == len(observed)
    assert owner.snapshot.retry_in_seconds is None
    assert launches == []


@pytest.mark.asyncio
@pytest.mark.parametrize("delay", [2, 4, 8, 16])
async def test_real_event_interrupts_each_backoff_without_waiting_for_timer(monkeypatch, tmp_path, delay):
    owner, clock, children, recorders, launches, pauses = _owner(monkeypatch, tmp_path)
    monkeypatch.setattr(lifecycle, "_interface_exists", lambda interface: False)
    entered = asyncio.Event()

    async def pause(seconds):
        if seconds == delay:
            entered.set()
            await lifecycle.AcquisitionPair._pause(owner, seconds)
        else:
            await asyncio.sleep(0)

    monkeypatch.setattr(owner, "_pause", pause)
    attempt = asyncio.create_task(owner.start())
    await asyncio.wait_for(entered.wait(), timeout=1.0)
    await asyncio.wait_for(owner.stop(), timeout=1.0)
    assert await asyncio.wait_for(attempt, timeout=1.0) is False
    assert owner.snapshot.retry_in_seconds is None
    assert launches == []


@pytest.mark.asyncio
@pytest.mark.parametrize("uptime,reset", [(59.999, False), (60, True), (61, True)])
async def test_stable_recording_resets_only_on_later_proven_loss(monkeypatch, tmp_path, uptime, reset):
    owner, clock, children, recorders, launches, pauses = _owner(monkeypatch, tmp_path)
    assert await owner.start()
    assert owner.snapshot.retry_attempt == 1
    clock.now += uptime
    assert owner.snapshot.retry_attempt == 1
    monkeypatch.setattr(lifecycle, "_interface_exists", lambda interface: False)
    children[-1].terminate()
    await owner.run()
    assert children[-1].reaped == recorders[-1].stops == 1
    assert owner.snapshot.source_state is SourceState.DEGRADED
    began = clock()
    attempts = []
    monkeypatch.setattr(lifecycle, "_interface_exists", lambda interface: attempts.append(clock() - began) or False)
    assert await owner.start() is False
    assert clock() - began == 30
    assert attempts == ([0, 2, 6, 14, 30] if reset else [2, 6, 14, 30])
    assert owner.snapshot.retry_attempt == 5
    assert owner.snapshot.retry_exhausted is True
    assert owner.snapshot.source_state is SourceState.DEGRADED
    assert len(launches) == 1
    # A stable loss restarts with immediate attempt 1, not delay-before-attempt 2.
    backoffs = [delay for delay in pauses if delay >= 2]
    assert backoffs == [2, 4, 8, 16]
    await owner.stop()


@pytest.mark.asyncio
async def test_short_flapping_shares_budget_fresh_generation_pid_and_reaps_siblings(monkeypatch, tmp_path):
    owner, clock, children, recorders, launches, pauses = _owner(monkeypatch, tmp_path)
    began = clock()
    for attempt in range(1, 6):
        assert await owner.start()
        assert owner.snapshot.retry_attempt == attempt
        assert owner.snapshot.retry_exhausted is False
        clock.now += 1
        monkeypatch.setattr(lifecycle, "_interface_exists", lambda interface: False)
        children[-1].terminate()
        await owner.run()
        assert owner.snapshot.source_state is SourceState.DEGRADED
        monkeypatch.setattr(lifecycle, "_interface_exists", lambda interface: True)
    assert await owner.start() is False
    assert owner.snapshot.retry_exhausted is True
    assert len(launches) == 5
    assert len({generation for _, generation, _ in launches}) == 5
    assert len({pid for _, _, pid in launches}) == 5
    assert [delay for delay in pauses if delay >= 2] == [2, 4, 8, 16]
    assert clock() - began == pytest.approx(35.5)
    assert all(child.reaped == 1 for child in children)
    assert all(recorder.stops == 1 for recorder in recorders)
    await owner.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize("lost", ["adapter", "recorder", "heartbeat"])
async def test_unproven_loss_blocks_without_retry_even_after_stable_uptime(monkeypatch, tmp_path, lost):
    owner, clock, children, recorders, launches, pauses = _owner(monkeypatch, tmp_path)
    assert await owner.start()
    clock.now += 60
    if lost == "adapter":
        children[-1].terminate()
    elif lost == "recorder":
        recorders[-1].is_running = False
    await owner.run()
    assert owner.snapshot.source_state is SourceState.BLOCKED
    assert await owner.start() is False
    assert len(launches) == 1
    assert children[0].reaped == recorders[0].stops == 1
    await owner.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure", [PermissionError("denied"), HTTPError("synthetic", 401, "auth", {}, None), RuntimeError("unknown")]
)
async def test_reaching_start_errors_are_blocked_not_source_retries(monkeypatch, tmp_path, failure):
    owner, clock, children, recorders, launches, pauses = _owner(monkeypatch, tmp_path)
    calls = []

    async def spawn(*args):
        calls.append(args)
        raise failure

    monkeypatch.setattr(lifecycle.asyncio, "create_subprocess_exec", spawn)
    assert await owner.start() is False
    assert owner.snapshot.source_state is SourceState.BLOCKED
    assert owner.snapshot.retry_exhausted is False
    assert await owner.start() is False
    assert len(calls) == 1
    assert pauses == []
    await owner.stop()


@pytest.mark.asyncio
async def test_explicit_blocked_snapshot_wins_over_absent_interface(monkeypatch, tmp_path):
    owner, clock, children, recorders, launches, pauses = _owner(monkeypatch, tmp_path)
    assert await owner.start()
    snapshot = AdapterSnapshot(SourceState.BLOCKED, owner.generation, owner.adapter.pid, clock(), "privilege_denied")
    Path(lifecycle.ADAPTER_SNAPSHOT_PATH).write_text(json.dumps(asdict(snapshot)))
    monkeypatch.setattr(lifecycle, "_interface_exists", lambda interface: False)
    await owner.run()
    assert owner.snapshot.source_state is SourceState.BLOCKED
    assert owner.snapshot.reason_code == "privilege_denied"
    assert await owner.start() is False
    assert len(launches) == 1


@pytest.mark.asyncio
async def test_startup_stop_unblocks_readiness_wait_and_cleans_pair(monkeypatch, tmp_path):
    owner, clock, children, recorders, launches, pauses = _owner(monkeypatch, tmp_path)
    entered = asyncio.Event()
    original_pause = lifecycle.AcquisitionPair._pause

    async def pause(seconds):
        entered.set()
        await original_pause(owner, seconds)

    monkeypatch.setattr(owner, "_pause", pause)
    attempt = asyncio.create_task(owner.start())
    await entered.wait()
    await owner.stop()
    assert await attempt is False
    assert children[0].reaped == recorders[0].stops == 1
    assert owner.adapter is owner.recorder is None


@pytest.mark.asyncio
async def test_absent_warnings_persist_stdout_file_without_idle_tick_flood(monkeypatch, tmp_path, capsys):
    owner, clock, children, recorders, launches, pauses = _owner(monkeypatch, tmp_path)
    config = _settings(tmp_path).log
    recorder_main._configure_logging(config)
    monkeypatch.setattr(lifecycle, "_interface_exists", lambda interface: False)
    assert await owner.start() is False
    for _ in range(50):
        await owner.start()
    stdout = capsys.readouterr().out
    file_output = Path(config.file).read_text()
    for output in (stdout, file_output):
        assert output.count("attempt ") == 5
        assert "retry_exhausted" in output
        assert "fake0" in output
    await owner.stop()
    logger.remove()
    logger.add(sys.__stderr__)


@pytest.mark.parametrize("mode", ["LIVE", "PCAP"])
def test_native_queue_failure_live_propagates_pcap_eof_is_unchanged(monkeypatch, mode):
    from otalon_capture.netcap import Netcap
    from otalon_capture.settings import CaptureType

    capture = Mock()
    capture.get_next.side_effect = RuntimeError("synthetic queue stopped")
    monkeypatch.setattr(Netcap, "_create_capture", staticmethod(lambda config: capture))
    netcap = Netcap(SimpleNamespace(type=CaptureType(mode)))
    if mode == "LIVE":
        with pytest.raises(RuntimeError, match="synthetic queue stopped"):
            list(netcap.capture_loop())
    else:
        assert list(netcap.capture_loop()) == []


def test_native_stop_uses_exposed_stop_once_and_leaves_no_queue_reader(monkeypatch):
    from otalon_capture.netcap import Netcap
    from otalon_capture.settings import CaptureType

    entered = threading.Event()
    released = threading.Event()
    stopped = []

    class Capture:
        def get_next(self):
            entered.set()
            assert released.wait(1.0)
            raise RuntimeError("intentional queue stop")

        def stop(self):
            stopped.append(True)
            released.set()

    monkeypatch.setattr(Netcap, "_create_capture", staticmethod(lambda config: Capture()))
    netcap = Netcap(SimpleNamespace(type=CaptureType.LIVE))
    errors = []

    def read():
        try:
            assert list(netcap.capture_loop()) == []
        except BaseException as error:
            errors.append(error)

    reader = threading.Thread(target=read, name="owned-native-queue")
    reader.start()
    try:
        assert entered.wait(1.0)
        netcap.stop()
        netcap.stop()
    finally:
        released.set()
        reader.join(timeout=1.0)
    assert not reader.is_alive()
    assert errors == []
    assert stopped == [True]


@pytest.mark.asyncio
async def test_coordinator_cycles_current_recorder_monitor_and_awaits_tick_cleanup(monkeypatch, tmp_path):
    from capture_runtime import CaptureIntent

    state = recorder_main.RuntimeState()
    cycles, finished, monitors, cleanups = [], asyncio.Event(), [], []

    class Pair:
        recorder = None

        def __init__(self, config):
            self.attempt = 0

        async def start(self):
            assert state.recorder is None
            assert all(task.done() for task in (state.ringbuffer_task, state.capture_stats_task) if task)
            self.attempt += 1
            if self.attempt == 3:
                finished.set()
                return False
            self.recorder = Recorder(None)
            self.recorder.start()
            return True

        async def run(self):
            cycles.append(state.recorder)
            assert state.recorder is self.recorder
            await asyncio.sleep(0)
            self.recorder.stop()

        async def stop(self):
            pass

    def monitor(interface):
        monitors.append(state.recorder)
        return SimpleNamespace()

    async def ticks(runtime, component):
        current = runtime.recorder
        try:
            await asyncio.Event().wait()
        finally:
            cleanups.append(current)

    async def serve(app, host, port, runtime):
        runtime.uvicorn_server = SimpleNamespace(started=True, should_exit=False)
        await finished.wait()

    monkeypatch.setattr(lifecycle, "AcquisitionPair", Pair)
    monkeypatch.setattr(recorder_main, "CaptureLossMonitor", monitor)
    monkeypatch.setattr(recorder_main, "_ringbuffer_loop", ticks)
    monkeypatch.setattr(recorder_main, "_capture_stats_loop", ticks)
    monkeypatch.setattr(recorder_main, "_run_uvicorn", serve)
    await recorder_main._run_service(_settings(tmp_path), CaptureIntent.LIVE, state)
    assert len(cycles) == 2
    assert cycles[0] is not cycles[1]
    assert monitors == cycles
    assert cleanups == [cycles[0], cycles[0], cycles[1], cycles[1]]
    assert state.acquisition_task.done()
    assert state.recorder is None


@pytest.mark.parametrize("stage", ["health", "run"])
@pytest.mark.parametrize(
    "failure",
    [
        PermissionError("synthetic denial"),
        HTTPError("synthetic", 403, "auth", {}, None),
        RuntimeError("synthetic unknown"),
    ],
)
def test_adapter_visible_errors_block_and_stop_once_without_heartbeat_leak(monkeypatch, tmp_path, stage, failure):
    from otalon_capture import main as adapter_main

    monkeypatch.setenv("CAPTURE_TYPE", "LIVE")
    monkeypatch.setattr(sys, "argv", ["adapter", "--_capture-generation", "owned"])
    path = tmp_path / "state.json"
    monkeypatch.setattr(adapter_main, "ADAPTER_SNAPSHOT_PATH", str(path))
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
    monkeypatch.setattr(
        adapter_main, "wait_for_influx_health", Mock(side_effect=failure if stage == "health" else None)
    )
    stopped = []

    class Pipeline:
        def __init__(self, config):
            pass

        def run(self):
            raise failure

        def stop(self):
            stopped.append(True)

    monkeypatch.setattr(adapter_main, "CapturePipeline", Pipeline)
    with pytest.raises(type(failure)):
        adapter_main.main()
    assert json.loads(path.read_text())["state"] == "blocked"
    assert stopped == ([] if stage == "health" else [True])
    assert not any(thread.name == "capture-adapter-heartbeat" for thread in threading.enumerate())


@pytest.mark.parametrize("code", [401, 403])
def test_native_advisory_health_does_not_suppress_reaching_auth_errors(monkeypatch, code):
    from otalon_capture import helper

    failure = HTTPError("synthetic", code, "synthetic auth", {}, None)
    request = Mock(side_effect=failure)
    monkeypatch.setattr(helper.request, "urlopen", request)
    event = threading.Event()
    with pytest.raises(HTTPError):
        helper.wait_for_influx_health("http://synthetic.invalid", stop_event=event)
    assert request.call_count == 1


@pytest.mark.parametrize("failure", [PermissionError("synthetic"), RuntimeError("synthetic")])
def test_native_advisory_health_does_not_retry_unknown_or_privilege_errors(monkeypatch, failure):
    from otalon_capture import helper

    request = Mock(side_effect=failure)
    monkeypatch.setattr(helper.request, "urlopen", request)
    with pytest.raises(type(failure)):
        helper.wait_for_influx_health("http://synthetic.invalid", stop_event=threading.Event())
    assert request.call_count == 1


@pytest.mark.asyncio
async def test_every_attempt_has_five_second_deadline_and_rejects_previous_generation(monkeypatch, tmp_path):
    owner, clock, children, recorders, launches, pauses = _owner(monkeypatch, tmp_path)
    stale = None
    deadlines = []

    async def pause(seconds):
        nonlocal stale
        if seconds >= 2:
            clock.now += seconds
            monkeypatch.setattr(lifecycle, "_interface_exists", lambda interface: True)
            return
        clock.now += seconds
        if stale is None:
            stale = AdapterSnapshot(SourceState.RECORDING, "previous-generation", 123, clock(), None)
        Path(lifecycle.ADAPTER_SNAPSHOT_PATH).write_text(json.dumps(asdict(stale)))
        elapsed = clock() - launches[-1][0]
        if elapsed >= 5 - 1e-10:
            if len(deadlines) < len(launches):
                deadlines.append(elapsed)
            monkeypatch.setattr(lifecycle, "_interface_exists", lambda interface: False)

    monkeypatch.setattr(owner, "_pause", pause)
    assert await owner.start() is False
    assert deadlines == pytest.approx([5] * 5)
    assert len(launches) == 5
    assert owner.snapshot.retry_exhausted is True
    assert all(child.reaped == 1 for child in children)
    assert all(recorder.stops == 1 for recorder in recorders)
    await owner.stop()


def test_tcpdump_kill_reap_and_stderr_thread_join_are_bounded_and_idempotent(tmp_path):
    import subprocess

    recorder = TcpdumpRecorder(_settings(tmp_path).pcap)
    child = Mock()
    child.poll.return_value = None
    child.wait.side_effect = [subprocess.TimeoutExpired("synthetic", 2), -9]
    recorder._process = child
    stream = io.StringIO("synthetic startup failure\n")
    drain = threading.Thread(target=recorder._drain_stderr, args=(stream,), name="owned-tcpdump-stderr")
    recorder._stderr_thread = drain
    drain.start()
    recorder.stop(timeout_s=2)
    recorder.stop(timeout_s=2)
    child.terminate.assert_called_once()
    child.kill.assert_called_once()
    assert [call.kwargs["timeout"] for call in child.wait.call_args_list] == [2, 2]
    assert not drain.is_alive()
    assert stream.closed
    assert recorder._process is recorder._stderr_thread is None


@pytest.mark.asyncio
async def test_native_ambiguous_open_error_snapshot_blocks_not_retries(monkeypatch, tmp_path):
    owner, clock, children, recorders, launches, pauses = _owner(monkeypatch, tmp_path)

    async def failed(seconds):
        clock.now += seconds
        snapshot = AdapterSnapshot(
            SourceState.BLOCKED, owner.generation, owner.adapter.pid, clock(), "dependency_unavailable"
        )
        Path(lifecycle.ADAPTER_SNAPSHOT_PATH).write_text(json.dumps(asdict(snapshot)))

    monkeypatch.setattr(owner, "_pause", failed)
    assert await owner.start() is False
    assert owner.snapshot.source_state is SourceState.BLOCKED
    assert owner.snapshot.retry_attempt == 1
    assert await owner.start() is False
    assert len(launches) == 1
    assert children[0].reaped == recorders[0].stops == 1


@pytest.mark.asyncio
async def test_proven_interface_loss_reaps_live_pair_despite_fresh_heartbeat(monkeypatch, tmp_path):
    owner, clock, children, recorders, launches, pauses = _owner(monkeypatch, tmp_path)
    assert await owner.start()
    checks = []

    def absent(interface):
        checks.append(interface)
        return False

    async def pause(seconds):
        pytest.fail("proven absent source was ignored while heartbeat stayed ready")

    monkeypatch.setattr(lifecycle, "_interface_exists", absent)
    monkeypatch.setattr(owner, "_pause", pause)
    await owner.run()
    assert checks == ["fake0"]
    assert owner.snapshot.source_state is SourceState.DEGRADED
    assert owner.snapshot.reason_code == "source_absent"
    assert children[0].reaped == recorders[0].stops == 1


@pytest.mark.asyncio
async def test_runtime_monitor_error_blocks_and_reaps_not_silent_recording(monkeypatch, tmp_path):
    owner, clock, children, recorders, launches, pauses = _owner(monkeypatch, tmp_path)
    assert await owner.start()
    monkeypatch.setattr(owner, "_read_snapshot", Mock(side_effect=RuntimeError("synthetic unknown")))
    await owner.run()
    assert owner.snapshot.source_state is SourceState.BLOCKED
    assert await owner.start() is False
    assert children[0].reaped == recorders[0].stops == 1
