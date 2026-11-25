"""Tests for the import runner and the shared capture pipeline it reuses.

The decisive property verified here is that measurements keep the timestamps
recorded in the capture: the pipeline must derive the covered time range from
the records themselves, never from the wall clock.
"""

from __future__ import annotations

import importlib.util
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List

import pytest
from pydantic import ValidationError

from pcap_import._adapter import CapturePipeline, CaptureType, PipelineResult, Settings
from pcap_import.models import ImportPhase, ImportRequest
from pcap_import.runner import ImportPathError, PipelineImportRunner, _load_import_settings, _summarise

pytestmark = pytest.mark.unit

CONFIG_PATH = Path(__file__).resolve().parents[2] / "config" / "config.json"

# The adapter package resolves differently in the container and the dev tree
# (see ``pcap_import._adapter``); patch the module actually in use.
_PIPELINE_MODULE = CapturePipeline.__module__

HISTORIC_MS = 1_600_000_000_000


UCI = "00:11:22:33:44:55/66:77:88:99:aa:bb/VLAN/IP/10.0.0.1/10.0.0.2/443/1024/TCP"


def fake_record(time_ms: int, uci: str = UCI) -> Dict[str, Any]:
    """Build a raw Netcap++ record carrying its own capture timestamp.

    Netcap++ yields mapping-like records keyed by ``time``; the aggregator reads
    that key and the resulting aggregate exposes it again via ``get_time()``.
    """

    return {
        "uci": uci,
        "time": time_ms,
        "packet_count": 1,
        "total_volume": 100,
        "mean_packet_size": 100.0,
        "min_packet_size": 100,
        "max_packet_size": 100,
        "std_packet_size": 0.0,
        "mean_interarrival_time": 1.0,
        "min_interarrival_time": 1.0,
        "max_interarrival_time": 1.0,
        "std_interarrival_time": 0.0,
    }


class FakeCapture:
    """Capture double yielding a fixed list of records."""

    def __init__(self, records: List[Any]) -> None:
        self._records = records
        self.stopped = False

    def capture_loop(self) -> Iterator[Any]:
        for record in self._records:
            if self.stopped:
                return
            yield record

    def stop(self) -> None:
        self.stopped = True


@pytest.fixture
def offline_settings(monkeypatch: pytest.MonkeyPatch) -> Settings:
    """Load the adapter config with env placeholders satisfied, writers stubbed."""

    monkeypatch.setenv("INFLUX_URL", "http://localhost:8181")
    monkeypatch.setenv("INFLUX_TOKEN", "test-token")
    monkeypatch.setenv("CAPTURE_SOURCE", "eth0")
    monkeypatch.setenv("CAPTURE_TYPE", "LIVE")
    monkeypatch.setenv("NETCAP_LOG_FILE", "/tmp/netcap-test.log")
    monkeypatch.setenv("PCAP_BUFFER_DIR", "/tmp/pcap-buffer")
    monkeypatch.setenv("PCAP_ARCHIVE_DIR", "/tmp/pcap-archive")
    settings = Settings.from_json(CONFIG_PATH)
    disabled_mac = settings.mac_aggregation.model_copy(update={"enabled": False})
    disabled_proto = settings.proto_aggregation.model_copy(update={"enabled": False})
    return settings.model_copy(update={"mac_aggregation": disabled_mac, "proto_aggregation": disabled_proto})


class StubWriter:
    """Writer double recording everything the pipeline hands it."""

    def __init__(self) -> None:
        self.written: List[Any] = []
        self.closed = False

    def write(self, value: Any) -> None:
        self.written.append(value)

    def flush(self, force: bool = False) -> None:
        return None

    def close(self) -> None:
        self.closed = True


class TestPipelineTimestamps:
    """The capture's own timestamps must survive the pipeline unchanged."""

    def test_covered_range_comes_from_records_not_the_clock(
        self, offline_settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        writer = StubWriter()
        monkeypatch.setattr(_PIPELINE_MODULE + ".create_writer", lambda config, settings: writer)

        records = [fake_record(HISTORIC_MS), fake_record(HISTORIC_MS + 60_000)]
        pipeline = CapturePipeline(offline_settings, capture=FakeCapture(records))
        result = pipeline.run()

        assert result.records_processed == 2
        assert result.first_record_ms == HISTORIC_MS
        assert result.last_record_ms is not None
        assert result.last_record_ms >= HISTORIC_MS + 60_000

        now_ms = int(datetime.now(tz=timezone.utc).timestamp() * 1000)
        assert result.last_record_ms < now_ms
        assert writer.closed is True

    def test_writer_receives_records_carrying_get_time(
        self, offline_settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        writer = StubWriter()
        monkeypatch.setattr(_PIPELINE_MODULE + ".create_writer", lambda config, settings: writer)

        pipeline = CapturePipeline(offline_settings, capture=FakeCapture([fake_record(HISTORIC_MS)]))
        pipeline.run()

        assert writer.written, "pipeline wrote nothing"
        for value in writer.written:
            assert value.get_time() == HISTORIC_MS

    def test_stop_ends_the_run(self, offline_settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
        writer = StubWriter()
        monkeypatch.setattr(_PIPELINE_MODULE + ".create_writer", lambda config, settings: writer)

        capture = FakeCapture([fake_record(HISTORIC_MS + index) for index in range(100)])
        pipeline = CapturePipeline(offline_settings, capture=capture)
        pipeline.stop()
        result = pipeline.run()

        assert result.records_processed <= 1
        assert capture.stopped is True


class TestImportSettings:
    """The runner must switch the adapter config into PCAP mode over the file."""

    def test_capture_source_and_type_are_overridden(self, offline_settings: Settings) -> None:
        settings = _load_import_settings(str(CONFIG_PATH), "/import/abc.pcap")

        assert settings.capture.type is CaptureType.PCAP
        assert settings.capture.source == "/import/abc.pcap"

    def test_influx_target_is_taken_from_the_adapter_config(self, offline_settings: Settings) -> None:
        settings = _load_import_settings(str(CONFIG_PATH), "/import/abc.pcap")

        assert settings.influx.measurement_name == offline_settings.influx.measurement_name
        assert settings.influx.database == offline_settings.influx.database

    @pytest.mark.parametrize("source", [None, ""])
    def test_none_unset_or_empty_source_is_overridden_before_resolution(
        self, source, offline_settings, monkeypatch, tmp_path
    ):
        monkeypatch.setenv("CAPTURE_TYPE", "NONE")
        if source is None:
            monkeypatch.delenv("CAPTURE_SOURCE", raising=False)
        else:
            monkeypatch.setenv("CAPTURE_SOURCE", source)
        monkeypatch.delenv("PCAP_BUFFER_DIR", raising=False)
        monkeypatch.delenv("PCAP_ARCHIVE_DIR", raising=False)
        payload = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        payload["unknown_ignored"] = "$UNUSED_A1_EXTRA"
        monkeypatch.delenv("UNUSED_A1_EXTRA", raising=False)
        before = dict(os.environ)
        config = tmp_path / "adapter.json"
        config.write_text(json.dumps(payload), encoding="utf-8")
        settings = _load_import_settings(str(config), "/import/abc.pcap")
        assert settings.capture.type is CaptureType.PCAP
        assert settings.capture.source == "/import/abc.pcap"
        assert settings.influx == offline_settings.influx
        assert settings.write_options == offline_settings.write_options
        assert settings.log == offline_settings.log
        assert settings.preprocess == offline_settings.preprocess
        assert settings.mac_influx == offline_settings.mac_influx
        assert settings.proto_influx == offline_settings.proto_influx
        assert dict(os.environ) == before

    @pytest.mark.parametrize("field", ["influx", "write_options", "log", "preprocess", "mac_aggregation"])
    def test_import_still_validates_genuine_worker_settings(self, field, offline_settings, monkeypatch, tmp_path):
        monkeypatch.setenv("CAPTURE_TYPE", "NONE")
        monkeypatch.delenv("CAPTURE_SOURCE", raising=False)
        payload = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        payload[field] = "not a configuration object"
        config = tmp_path / "invalid.json"
        config.write_text(json.dumps(payload), encoding="utf-8")
        with pytest.raises(ValidationError, match=field):
            _load_import_settings(str(config), "/import/abc.pcap")

    @pytest.mark.parametrize("missing", ["INFLUX_URL", "INFLUX_TOKEN", "NETCAP_LOG_FILE"])
    def test_import_keeps_required_environment_strict(self, missing, offline_settings, monkeypatch):
        monkeypatch.setenv("CAPTURE_TYPE", "NONE")
        monkeypatch.delenv("CAPTURE_SOURCE", raising=False)
        monkeypatch.delenv(missing)
        with pytest.raises(RuntimeError, match=missing):
            _load_import_settings(str(CONFIG_PATH), "/import/abc.pcap")

    def test_runner_uses_exported_import_loader_after_containment(self, offline_settings, monkeypatch, tmp_path):
        from pcap_import import _adapter
        from pcap_import import runner as runner_module

        assert runner_module.CaptureType is _adapter.CaptureType
        capture = tmp_path / "owned.pcap"
        capture.write_bytes(b"\xd4\xc3\xb2\xa1")
        calls = []

        def load(config, file_path):
            calls.append((config, file_path))
            return offline_settings

        monkeypatch.setattr(runner_module, "load_import_settings", load)
        runner = PipelineImportRunner(str(CONFIG_PATH), import_dir=str(tmp_path))
        monkeypatch.setattr(runner, "_build_pipeline", lambda *args: object())
        monkeypatch.setattr(runner, "_drive", lambda *args: PipelineResult())
        runner.run(ImportRequest(display_id="a1", file_path=str(capture)), lambda *args: None, threading.Event())
        assert calls == [(Path(CONFIG_PATH), str(capture.resolve()))]
        assert _adapter.load_import_settings.__self__ is _adapter.Settings

    @pytest.mark.parametrize("root", ["otalon_capture", "otalon-capture.src.otalon_capture"])
    def test_import_loader_is_exported_in_both_adapter_layouts(self, root, offline_settings, monkeypatch):
        from pcap_import import _adapter

        actual_import = _adapter.import_module

        def selected_import(name):
            if name.startswith(root + "."):
                return actual_import("otalon_capture." + name.rsplit(".", 1)[-1])
            raise ModuleNotFoundError(name)

        monkeypatch.setattr(_adapter, "import_module", selected_import)
        spec = importlib.util.spec_from_file_location("a1_adapter_layout", _adapter.__file__)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        monkeypatch.setenv("CAPTURE_TYPE", "NONE")
        monkeypatch.delenv("CAPTURE_SOURCE", raising=False)
        settings = module.load_import_settings(CONFIG_PATH, "/import/layout.pcap")
        assert settings.capture.type is module.CaptureType.PCAP
        assert settings.capture.source == "/import/layout.pcap"

    @pytest.mark.parametrize("source", [None, ""])
    def test_none_runner_drives_internal_pcap_and_preserves_fractional_record_times(
        self, source, offline_settings, monkeypatch, tmp_path
    ):
        monkeypatch.setenv("CAPTURE_TYPE", "NONE")
        if source is None:
            monkeypatch.delenv("CAPTURE_SOURCE", raising=False)
        else:
            monkeypatch.setenv("CAPTURE_SOURCE", source)
        capture = tmp_path / "owned.pcap"
        capture.write_bytes(b"\xd4\xc3\xb2\xa1")
        config = tmp_path / "adapter.json"
        payload = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        payload["mac_aggregation"]["enabled"] = False
        payload["proto_aggregation"]["enabled"] = False
        config.write_text(json.dumps(payload), encoding="utf-8")
        writer = StubWriter()
        seen = []

        def file_reader(settings):
            assert settings.type is CaptureType.PCAP
            assert settings.source == str(capture.resolve())
            seen.append(settings)
            return FakeCapture([fake_record(HISTORIC_MS + 375), fake_record(HISTORIC_MS + 1375)])

        monkeypatch.setattr(_PIPELINE_MODULE + ".Netcap", file_reader)
        monkeypatch.setattr(_PIPELINE_MODULE + ".create_writer", lambda *args: writer)
        result = PipelineImportRunner(str(config), import_dir=str(tmp_path)).run(
            ImportRequest(display_id="a1", file_path=str(capture)), lambda *args: None, threading.Event()
        )
        assert len(seen) == 1
        assert result["records_processed"] == 2
        assert result["time_start"] == "2020-09-13T12:26:40.375000+00:00"
        assert result["time_end"] == "2020-09-13T12:26:41.375000+00:00"
        assert [value.get_time() for value in writer.written] == [HISTORIC_MS + 375, HISTORIC_MS + 1375]
        assert writer.closed is True


class TestMissingFile:
    """A missing capture file is a job failure, raised for the service to record."""

    def test_missing_file_raises_file_not_found(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # The path must be INSIDE the import volume, otherwise containment
        # rejects it before the existence check (audit CAP-02). Point the
        # volume at tmp_path so this still tests "absent file". PCAP-007
        # moved the boundary onto the runner's own configuration, which the
        # service builds from ``PcapImportSettings.import_dir``.
        runner = PipelineImportRunner(adapter_config_file=str(CONFIG_PATH), import_dir=str(tmp_path))
        job = ImportRequest(display_id="job-1", file_path=str(tmp_path / "absent.pcap"))
        events: List[str] = []

        def progress(_phase: ImportPhase, event: str) -> None:
            events.append(event)

        with pytest.raises(FileNotFoundError):
            runner.run(job, progress, threading.Event())
        assert events, "runner reported no progress before failing"

    def test_path_outside_the_import_volume_is_refused(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A readable file outside the volume must never be imported."""
        import_dir = tmp_path / "import"
        import_dir.mkdir()
        outsider = tmp_path / "secret.pcap"
        outsider.write_bytes(b"\xd4\xc3\xb2\xa1")

        runner = PipelineImportRunner(adapter_config_file=str(CONFIG_PATH), import_dir=str(import_dir))
        job = ImportRequest(display_id="job-1", file_path=str(outsider))

        with pytest.raises(ImportPathError):
            runner.run(job, lambda _phase, _event: None, threading.Event())


class TestSummary:
    """The reported result carries the capture's range, not the import's clock."""

    def test_summary_prefers_record_timestamps(self) -> None:
        result = PipelineResult(
            records_processed=3,
            points_written=2,
            first_record_ms=HISTORIC_MS,
            last_record_ms=HISTORIC_MS + 1000,
        )
        job = ImportRequest(display_id="job-1", file_path="/import/a.pcap")

        summary: Dict[str, Any] = _summarise(result, job)

        assert summary["records_processed"] == 3
        assert summary["points_written"] == 2
        assert summary["time_start"].startswith("2020-")
        assert summary["time_end"].startswith("2020-")

    def test_summary_falls_back_to_the_owner_window(self) -> None:
        window_start = datetime(2020, 9, 13, 12, 26, 40, tzinfo=timezone.utc)
        job = ImportRequest(
            display_id="job-1",
            file_path="/import/a.pcap",
            time_start=window_start,
            time_end=window_start,
        )

        summary = _summarise(PipelineResult(), job)

        assert summary["time_start"] == window_start.isoformat()
        assert summary["time_end"] == window_start.isoformat()
