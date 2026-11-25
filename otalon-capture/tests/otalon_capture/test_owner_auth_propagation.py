"""AUTH2 owner regressions using constructed records and numeric transport errors."""

from __future__ import annotations

import queue
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import Mock

import pytest
from influxdb_client_3 import InfluxDBError
from influxdb_client_3.write_client.rest import ApiException
from loguru import logger
from urllib3 import HTTPResponse

from capture_runtime import CaptureIntent, SourceState
from otalon_capture import main as adapter_main
from otalon_capture import pipeline as pipeline_module
from otalon_capture.influxdb_writer import InfluxDBWriter
from otalon_capture.pipeline import CapturePipeline
from otalon_capture.settings import Settings
from otalon_capture.worker import AggregationWorker
from otalon_capture.write_failure import TerminalWriteError


def settings(*, sparse=False, secondary=None, batch=1, host="http://127.0.0.1:1"):
    config = {
        "host": host,
        "token": "constructed-token",
        "database": "constructed",
        "measurement_name": "main",
        "tags": [],
        "fields": {"packet_count": "get_total_packet_count"},
    }
    return Settings(
        influx=config,
        capture={"source": "constructed", "type": "PCAP", "interval": 1000},
        write_options={"batch_size": batch, "flush_interval": 1000000, "jitter_interval": 0, "precision": "ms"},
        log={"level": "INFO", "file": "constructed.log"},
        preprocess={"aggregate_sparse_ports": sparse},
        mac_aggregation={"enabled": secondary == "mac"},
        proto_aggregation={"enabled": secondary == "proto"},
        mac_influx={**config, "measurement_name": "mac", "fields": {"packet_count": "get_out_total_packets"}},
        proto_influx={**config, "measurement_name": "proto", "fields": {"packet_count": "get_proto_total_packets"}},
    )


def record(time=1600000000375):
    return {
        "time": time,
        "uci": "02:00:00:00:00:01/02:00:00:00:00:02/VLAN/IP/192.0.2.1/192.0.2.2/443/1024/TCP",
        "packet_count": 1,
        "total_volume": 100,
    }


class Capture:
    def __init__(self, records):
        self.records = records
        self.stopped = False

    def capture_loop(self):
        yield from self.records

    def stop(self):
        self.stopped = True


@pytest.fixture
def quiet_logs():
    messages = []
    sink = logger.add(lambda message: messages.append(str(message)), diagnose=False, backtrace=False)
    try:
        yield messages
    finally:
        logger.remove(sink)


def refused(status, shape):
    if shape == "api":
        return ApiException(status=status, reason="constructed diagnostic")
    return InfluxDBError(response=HTTPResponse(status=status, body=b"constructed diagnostic"))


def writer_fixture(monkeypatch, status, shape="influx", *, batch=1, refused_measurement=None):
    clients = []

    class Client:
        def __init__(self, *args, **kwargs):
            self.calls = 0
            self.closes = 0
            clients.append(self)

        def write(self, points):
            self.calls += 1
            if refused_measurement is None or points[0]._name == refused_measurement:
                raise refused(status, shape)

        def close(self):
            self.closes += 1

    monkeypatch.setattr("otalon_capture.influxdb_writer.InfluxDBClient3", Client)
    config = settings(batch=batch)
    return InfluxDBWriter(config.influx, config.write_options, 1000), clients


class Aggregator:
    def __init__(self, phase):
        self.phase = phase
        self.adds = []
        self.flushes = []

    def add(self, value):
        self.adds.append(value)
        return [value, value] if self.phase in {"record", "drain"} else []

    def flush(self, force=False):
        self.flushes.append(force)
        return [record(), record()] if (self.phase == "idle" and not force) or self.phase == "final" else []


@pytest.mark.parametrize("status", [401, 403])
@pytest.mark.parametrize("shape", ["influx", "api"])
@pytest.mark.parametrize("phase", ["record", "idle", "drain", "final", "close"])
def test_worker_retains_refusal_and_settles_without_repeat(monkeypatch, quiet_logs, status, shape, phase):
    writer, clients = writer_fixture(monkeypatch, status, shape, batch=100 if phase == "close" else 1)
    if phase == "close":
        writer.write(record())
    work = queue.Queue()
    aggregator = Aggregator(phase)
    worker = AggregationWorker("auth2-worker", work, aggregator, writer, poll_timeout=0.01)
    if phase in {"record", "drain"}:
        for _ in range(3):
            work.put(record())
    try:
        if phase in {"drain", "final", "close"}:
            worker.stop()
        else:
            worker.start()
            worker.join(timeout=0.5)
            worker.stop()
            worker.join(timeout=2.0)
        evidence = getattr(worker, "terminal_error", None)
        assert isinstance(evidence, TerminalWriteError), "terminal worker refusal was lost"
        assert evidence.status == status
        assert evidence.category == "permanent_auth_refusal"
        assert evidence.__context__ is None and evidence.__cause__ is None
        assert worker.terminal_error is not evidence
        assert work.unfinished_tasks == 0
        assert clients[0].calls == 1
        assert clients[0].closes == 1
        assert worker.records_failed == (1 if phase in {"record", "drain"} else 0)
        if phase in {"record", "drain"}:
            assert len(aggregator.adds) == 1
            assert aggregator.flushes == []
        worker.stop()
        assert clients[0].closes == 1
    finally:
        worker.stop()
        if worker.ident is not None:
            worker.join(timeout=2.0)
        try:
            writer.close()
        except TerminalWriteError:
            pass
        assert not worker.is_alive()


@pytest.mark.parametrize("auth", [False, True])
def test_started_worker_stop_only_signals_and_owner_finalizes(monkeypatch, quiet_logs, auth):
    entered = threading.Event()
    release = threading.Event()
    stopping = threading.Event()
    events = []
    work = queue.Queue()
    for index in range(3):
        work.put(index)

    class HeldAggregator:
        def add(self, value):
            events.append(("add", value, threading.get_ident()))
            if value == 0:
                entered.set()
                assert release.wait(2.0)
            return [value]

        def flush(self, force=False):
            events.append(("flush", force, threading.get_ident()))
            return []

    class Writer:
        def write(self, value):
            events.append(("write", value, threading.get_ident()))
            if auth:
                raise TerminalWriteError(403)

        def close(self):
            events.append(("close", None, threading.get_ident()))

    worker = AggregationWorker("auth2-held", work, HeldAggregator(), Writer(), poll_timeout=0.01)

    def stop():
        worker.stop()
        stopping.set()

    stopper = threading.Thread(target=stop)
    worker.start()
    try:
        assert entered.wait(1.0)
        stopper.start()
        assert stopping.wait(1.0)
        assert events == [("add", 0, worker.ident)], "caller raced held owner cleanup"
        assert worker.is_alive()
        release.set()
        worker.join(timeout=2.0)
        assert not worker.is_alive()
        assert all(event[2] == worker.ident for event in events)
        assert events[-1][0] == "close"
        assert work.unfinished_tasks == 0
        assert [event[1] for event in events if event[0] == "write"] == ([0] if auth else [0, 1, 2])
        assert sum(event[0] == "close" for event in events) == 1
    finally:
        release.set()
        worker.stop()
        worker.join(timeout=2.0)
        if stopper.ident is not None:
            stopper.join(timeout=2.0)
        assert not worker.is_alive() and not stopper.is_alive()


@pytest.mark.parametrize("status", [401, 403])
@pytest.mark.parametrize("phase", ["first", "sparse-eof", "close"])
def test_pipeline_refusal_never_returns_completed(monkeypatch, quiet_logs, status, phase):
    writer, clients = writer_fixture(monkeypatch, status, batch=100 if phase == "close" else 1)
    monkeypatch.setattr(pipeline_module, "create_writer", lambda *args: writer)
    original = record()
    capture = Capture([original, record(original["time"] + 1)] if phase == "first" else [original])
    pipeline = CapturePipeline(settings(sparse=phase == "sparse-eof"), capture=capture)
    try:
        with pytest.raises(TerminalWriteError) as caught:
            pipeline.run()
        assert caught.value.status == status
        assert caught.value.__context__ is None and caught.value.__cause__ is None
        assert clients[0].calls == clients[0].closes == 1
        assert capture.stopped
        assert pipeline.result.points_written == (1 if phase == "close" else 0)
        assert original == record()
    finally:
        pipeline.stop()
        try:
            writer.close()
        except TerminalWriteError:
            pass


@pytest.mark.parametrize("secondary", ["mac", "proto"])
@pytest.mark.parametrize("status", [401, 403])
def test_secondary_eof_auth_fails_despite_successful_main(monkeypatch, quiet_logs, secondary, status):
    fixture_writer, clients = writer_fixture(monkeypatch, status, refused_measurement=secondary)
    # The first allocated fixture writer is not a pipeline owner.
    config = settings(secondary=secondary)
    capture = Capture([record()])
    pipeline = CapturePipeline(config, capture=capture)
    workers = []
    original_start = pipeline._start_aggregation_workers

    def start():
        original_start()
        workers.extend(pipeline._workers)

    monkeypatch.setattr(pipeline, "_start_aggregation_workers", start)
    try:
        with pytest.raises(TerminalWriteError) as caught:
            pipeline.run()
        assert caught.value.status == status
        assert clients[1].calls == 1
        assert clients[2].calls == 1
        assert clients[1].closes == clients[2].closes == 1
        assert all(not worker.is_alive() and worker.input_queue.unfinished_tasks == 0 for worker in workers)
        assert pipeline.result.points_written == 1
    finally:
        pipeline.stop()
        for worker in workers:
            worker.stop()
            worker.join(timeout=2.0)
        fixture_writer.close()


def test_pipeline_polls_idle_refusal_before_next_primary_publication(monkeypatch, quiet_logs):
    writer, clients = writer_fixture(monkeypatch, 403)
    secondary_queue = queue.Queue()
    worker = AggregationWorker("auth2-idle", secondary_queue, Aggregator("idle"), writer, poll_timeout=0.01)
    main_writer = Mock()
    monkeypatch.setattr(pipeline_module, "create_writer", lambda *args: main_writer)

    class IdleCapture(Capture):
        def capture_loop(self):
            worker.join(timeout=0.5)
            yield record()

    capture = IdleCapture([])
    pipeline = CapturePipeline(settings(), capture=capture)

    def start():
        pipeline._workers.append(worker)
        worker.start()

    monkeypatch.setattr(pipeline, "_start_aggregation_workers", start)
    try:
        with pytest.raises(TerminalWriteError):
            pipeline.run()
        main_writer.write.assert_not_called()
        assert pipeline.result.points_written == pipeline.result.records_processed == 0
        assert clients[0].calls == 1
    finally:
        pipeline.stop()
        worker.stop()
        worker.join(timeout=2.0)
        assert not worker.is_alive()


def test_secondary_refusal_releases_buffered_main_without_publication(monkeypatch, quiet_logs):
    fixture_writer, clients = writer_fixture(monkeypatch, 403, refused_measurement="proto")
    config = settings(secondary="proto", batch=100)
    pipeline = CapturePipeline(config, capture=Capture([record()]))
    try:
        with pytest.raises(TerminalWriteError):
            pipeline.run()
        assert clients[1].calls == 0, "main buffer was published after secondary refusal"
        assert clients[2].calls == 1
        assert clients[1].closes == clients[2].closes == 1
        assert len(pipeline._writer._buffer) == 1
    finally:
        pipeline.stop()
        fixture_writer.close()


@pytest.mark.parametrize("primary_auth", [False, True])
def test_terminal_auth_outranks_generic_failure_and_release_error(monkeypatch, quiet_logs, primary_auth):
    primary = RuntimeError("constructed primary")
    releases = []

    class Writer:
        def write(self, value):
            if primary_auth:
                raise TerminalWriteError(401) from primary

        def close(self):
            releases.append(1)
            if primary_auth:
                raise RuntimeError("constructed release")
            raise TerminalWriteError(403) from primary

    class BrokenCapture(Capture):
        def capture_loop(self):
            yield record()
            raise primary

    monkeypatch.setattr(pipeline_module, "create_writer", lambda *args: Writer())
    pipeline = CapturePipeline(settings(), capture=BrokenCapture([]))
    try:
        with pytest.raises(TerminalWriteError) as caught:
            pipeline.run()
        assert caught.value.status == (401 if primary_auth else 403)
        assert caught.value.__cause__ is None and caught.value.__context__ is None
        assert releases == [1]
    finally:
        pipeline.stop()


def test_generic_primary_failure_survives_generic_cleanup(monkeypatch, quiet_logs):
    primary = RuntimeError("constructed primary")
    writer = Mock()
    writer.close.side_effect = ValueError("constructed cleanup")

    class BrokenCapture(Capture):
        def capture_loop(self):
            raise primary
            yield

    monkeypatch.setattr(pipeline_module, "create_writer", lambda *args: writer)
    capture = BrokenCapture([])
    pipeline = CapturePipeline(settings(), capture=capture)
    with pytest.raises(RuntimeError) as caught:
        pipeline.run()
    assert caught.value is primary
    writer.close.assert_called_once()
    assert capture.stopped


def test_worker_start_failure_keeps_partial_owner_in_cleanup(monkeypatch, quiet_logs):
    main_writer = Mock()
    worker_writer = Mock()
    created = iter([main_writer, worker_writer])
    monkeypatch.setattr(pipeline_module, "create_writer", lambda *args: next(created))
    monkeypatch.setattr(AggregationWorker, "start", Mock(side_effect=RuntimeError("constructed start")))
    capture = Capture([])
    pipeline = CapturePipeline(settings(secondary="proto"), capture=capture)
    with pytest.raises(RuntimeError, match="constructed start"):
        pipeline.run()
    assert capture.stopped
    main_writer.close.assert_called_once()
    worker_writer.close.assert_called_once()
    assert pipeline._workers == []


def test_pipeline_retains_held_worker_after_real_join_timeout(monkeypatch, quiet_logs):
    entered = threading.Event()
    release = threading.Event()
    timed_out = threading.Event()
    ended = threading.Event()
    failures = []
    work = queue.Queue()
    work.put(record())

    class HeldAggregator:
        def add(self, value):
            entered.set()
            assert release.wait(13.0)
            return []

        def flush(self, force=False):
            return []

    writer = Mock()
    worker = AggregationWorker("auth2-timeout", work, HeldAggregator(), writer, poll_timeout=0.01)
    monkeypatch.setattr(pipeline_module, "create_writer", lambda *args: Mock())
    pipeline = CapturePipeline(settings(), capture=Capture([]))

    def observe(message):
        if "auth2-timeout" in str(message) and "did not terminate within timeout" in str(message):
            timed_out.set()

    sink = logger.add(observe, diagnose=False, backtrace=False)

    def start():
        pipeline._workers.append(worker)
        worker.start()
        assert entered.wait(1.0)

    monkeypatch.setattr(pipeline, "_start_aggregation_workers", start)

    def run():
        try:
            pipeline.run()
        except BaseException as error:
            failures.append(error)
        finally:
            ended.set()

    owner = threading.Thread(target=run, name="auth2-pipeline-owner")
    owner.start()
    try:
        assert entered.wait(1.0)
        assert timed_out.wait(11.0), "established ten-second join boundary not observed"
        assert worker.is_alive() and worker in pipeline._workers
        assert not ended.is_set(), "unsettled worker reported completed"
        writer.close.assert_not_called()
        release.set()
        owner.join(timeout=2.0)
        assert not owner.is_alive() and not worker.is_alive()
        assert failures == []
        writer.close.assert_called_once()
        assert pipeline._workers == []
        assert work.unfinished_tasks == 0
    finally:
        release.set()
        pipeline.stop()
        worker.stop()
        owner.join(timeout=2.0)
        worker.join(timeout=2.0)
        logger.remove(sink)
        assert not owner.is_alive() and not worker.is_alive()


def test_terminal_worker_settles_late_enqueued_record_without_processing(monkeypatch, quiet_logs):
    writer, clients = writer_fixture(monkeypatch, 401)
    work = queue.Queue()
    work.put(record())
    aggregator = Aggregator("record")
    worker = AggregationWorker("auth2-late-queue", work, aggregator, writer, poll_timeout=0.01)
    try:
        worker.start()
        worker.join(timeout=1.0)
        assert not worker.is_alive()
        work.put(record())
        worker.stop()
        assert work.unfinished_tasks == 0
        assert len(aggregator.adds) == 1
        assert clients[0].calls == clients[0].closes == 1
    finally:
        worker.stop()
        worker.join(timeout=2.0)
        try:
            writer.close()
        except TerminalWriteError:
            pass


@pytest.mark.parametrize("status", [401, 403])
def test_adapter_auth_is_blocked_sanitized_and_not_clean(monkeypatch, quiet_logs, status):
    config = settings()
    monkeypatch.setattr(adapter_main, "load_dotenv", lambda **kwargs: None)
    monkeypatch.setattr(adapter_main, "resolve_capture_intent", lambda: CaptureIntent.LIVE)
    monkeypatch.setattr(adapter_main.Settings, "from_json", lambda path: config)
    monkeypatch.setattr(adapter_main, "configure_logger", lambda config: None)
    monkeypatch.setattr(adapter_main.signal, "signal", lambda *args: None)
    monkeypatch.setattr(adapter_main, "wait_for_influx_health", lambda *args, **kwargs: True)
    monkeypatch.setattr(sys, "argv", ["adapter", "--_capture-generation", "auth2-owned"])
    snapshots = []
    monkeypatch.setattr(
        adapter_main, "_write_snapshot", lambda generation, state, reason=None: snapshots.append((state, reason))
    )
    raw = RuntimeError("constructed-private-cause")

    class Pipeline:
        def run(self):
            raise TerminalWriteError(status) from raw

        def stop(self):
            pass

    monkeypatch.setattr(adapter_main, "_construct_pipeline", lambda config: Pipeline())
    with pytest.raises(TerminalWriteError) as caught:
        adapter_main.main()
    assert caught.value.__cause__ is None and caught.value.__context__ is None, "raw adapter chain survived"
    assert snapshots[-1][0] is SourceState.BLOCKED
    assert snapshots[-1][1] in {"upstream_unavailable", "dependency_unavailable"}
    assert not any(thread.name == "capture-adapter-heartbeat" for thread in threading.enumerate())
    assert not any("terminated cleanly" in message for message in quiet_logs), "false adapter success"
    assert not any("constructed-private-cause" in message for message in quiet_logs), "raw adapter log"


@pytest.mark.parametrize("status", [401, 403])
def test_actual_client_loopback_pipeline_eof_refuses_once(quiet_logs, status):
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            calls.append(1)
            self.send_response(status)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    server.timeout = 0.1
    done = threading.Event()

    def serve():
        while not done.is_set():
            server.handle_request()

    serving = threading.Thread(target=serve, name="auth2-loopback")
    serving.start()
    pipeline = None
    try:
        config = settings(batch=100, host=f"http://127.0.0.1:{server.server_port}")
        pipeline = CapturePipeline(config, capture=Capture([record()]))
        with pytest.raises(TerminalWriteError) as caught:
            pipeline.run()
        assert caught.value.status == status
        assert calls == [1]
        with pytest.raises(TerminalWriteError):
            pipeline._writer.close()
        assert calls == [1]
    finally:
        if pipeline is not None:
            pipeline.stop()
            try:
                pipeline._writer.close()
            except TerminalWriteError:
                pass
        done.set()
        serving.join(timeout=2.0)
        server.server_close()
        assert not serving.is_alive()
