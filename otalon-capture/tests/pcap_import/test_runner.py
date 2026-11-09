"""Tests for the import runner and the shared capture pipeline it reuses.

The decisive property verified here is that measurements keep the timestamps
recorded in the capture: the pipeline must derive the covered time range from
the records themselves, never from the wall clock.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List

import pytest

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
