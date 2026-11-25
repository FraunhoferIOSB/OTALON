"""Real shared runner/service failure outcomes, with constructed owner fixtures."""

from __future__ import annotations

import threading

import pytest
from influxdb_client_3 import InfluxDBError
from loguru import logger
from urllib3 import HTTPResponse

from otalon_capture.pipeline import CapturePipeline
from otalon_capture.settings import Settings
from otalon_capture.write_failure import TerminalWriteError
from pcap_import import runner as runner_module
from pcap_import.models import ImportPhase, ImportRequest, ImportState
from pcap_import.runner import PipelineImportRunner
from pcap_import.service import ImportService, WorkerBusyError


@pytest.mark.parametrize("status", [401, 403])
@pytest.mark.parametrize("cancel", [False, True])
def test_real_runner_service_auth_remains_failed_until_settled(monkeypatch, tmp_path, status, cancel):
    entered = threading.Event()
    release = threading.Event()
    clients = []
    pipelines = []
    reports = []
    events = []
    path = tmp_path / "constructed.pcap"
    path.write_bytes(b"constructed source boundary")
    original_bytes = path.read_bytes()
    config = Settings(
        influx={
            "host": "http://127.0.0.1:1",
            "token": "constructed",
            "database": "constructed",
            "measurement_name": "main",
            "tags": [],
            "fields": {"packet_count": "get_total_packet_count"},
        },
        capture={"source": str(path), "type": "PCAP", "interval": 1000},
        write_options={"batch_size": 100, "flush_interval": 1000000, "jitter_interval": 0, "precision": "ms"},
        log={"level": "INFO", "file": "constructed.log"},
        preprocess={"aggregate_sparse_ports": False},
    )

    class Client:
        def __init__(self, *args, **kwargs):
            self.calls = 0
            self.closes = 0
            clients.append(self)

        def write(self, points):
            self.calls += 1
            entered.set()
            assert release.wait(2.0)
            raise InfluxDBError(response=HTTPResponse(status=status, body=b"constructed-private-body"))

        def close(self):
            self.closes += 1

    class Capture:
        def capture_loop(self):
            yield {"time": 1600000000375, "packet_count": 1}

        def stop(self):
            pass

    class Reporter:
        def report(self, display_id, update):
            reports.append(update.model_copy(deep=True))

    monkeypatch.setattr("otalon_capture.influxdb_writer.InfluxDBClient3", Client)
    monkeypatch.setattr("otalon_capture.pipeline.Netcap", lambda config: Capture())
    monkeypatch.setattr(runner_module, "_load_import_settings", lambda *args: config)
    assert runner_module.CapturePipeline is CapturePipeline
    runner = PipelineImportRunner("constructed", import_dir=str(tmp_path))
    original_build = runner._build_pipeline

    def build(settings, progress, cancel_event):
        def track(phase, event):
            events.append(phase)
            progress(phase, event)

        pipeline = original_build(settings, track, cancel_event)
        pipelines.append(pipeline)
        return pipeline

    monkeypatch.setattr(runner, "_build_pipeline", build)
    service = ImportService(runner, Reporter())
    job = ImportRequest(display_id="auth2-owned", file_path=str(path))
    try:
        service.submit(job)
        assert entered.wait(1.0)
        assert service.busy
        with pytest.raises(WorkerBusyError):
            service.submit(ImportRequest(display_id="second", file_path=str(path)))
        if cancel:
            service.cancel(job.display_id)
            assert service.status.state is ImportState.CANCELLING
        assert clients[0].closes == 0
        release.set()
        assert service.wait_for_idle(timeout=3.0)
        final = service.status
        assert final.state is ImportState.FAILED, "permanent auth became cancelled/completed"
        assert final.result is None
        assert final.error == f"TerminalWriteError: InfluxDB write refused: permanent_auth_refusal (HTTP {status})."
        assert clients[0].calls == clients[0].closes == 1
        assert reports[-1].state is ImportState.FAILED
        assert all(update.result is None and update.state is not ImportState.COMPLETED for update in reports)
        assert ImportPhase.WRITING not in events
        assert path.read_bytes() == original_bytes
        assert not any(thread.name == "import-cancel-watch" for thread in threading.enumerate())
    finally:
        release.set()
        assert service.wait_for_idle(timeout=3.0)
        for pipeline in pipelines:
            pipeline.stop()
            try:
                pipeline._writer.close()
            except TerminalWriteError:
                pass


@pytest.mark.parametrize("terminal", [False, True])
def test_auth_before_cancel_and_no_ambient_transport_traceback(terminal):
    reports = []
    messages = []
    sink = logger.add(lambda message: messages.append(str(message)), diagnose=False, backtrace=False)
    raw = RuntimeError("constructed-private-ambient")

    class Runner:
        def run(self, job, progress, cancel_event):
            cancel_event.set()
            if terminal:
                raise TerminalWriteError(403) from raw
            raise RuntimeError("generic 401 text is not numeric evidence")

    class Reporter:
        def report(self, display_id, update):
            reports.append(update)

    service = ImportService(Runner(), Reporter())
    try:
        service.submit(ImportRequest(display_id="auth2-sanitized", file_path="/constructed/input.pcap"))
        assert service.wait_for_idle(timeout=2.0)
        assert service.status.state is (ImportState.FAILED if terminal else ImportState.CANCELLED)
        assert service.status.result is None
        assert not any("constructed-private-ambient" in message for message in messages), "raw ambient traceback logged"
        assert all(update.result is None for update in reports)
    finally:
        assert service.wait_for_idle(timeout=2.0)
        logger.remove(sink)


def test_terminal_service_logging_without_cancel_does_not_leak_ambient_cause():
    messages = []
    sink = logger.add(lambda message: messages.append(str(message)), diagnose=False, backtrace=False)

    class Runner:
        def run(self, job, progress, cancel_event):
            raise TerminalWriteError(401) from RuntimeError("constructed-private-ambient")

    service = ImportService(Runner())
    try:
        service.submit(ImportRequest(display_id="auth2-log", file_path="/constructed/input.pcap"))
        assert service.wait_for_idle(timeout=2.0)
        assert service.status.state is ImportState.FAILED
        assert not any("constructed-private-ambient" in message for message in messages), "raw ambient traceback logged"
    finally:
        assert service.wait_for_idle(timeout=2.0)
        logger.remove(sink)
