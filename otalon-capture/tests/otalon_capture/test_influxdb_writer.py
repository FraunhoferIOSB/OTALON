"""Tests for the InfluxDB writer wrapper."""

from __future__ import annotations

import json
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, List

import pytest

from otalon_capture.influxdb_writer import InfluxDBWriter, _map_precision
from otalon_capture.pipeline import CapturePipeline
from otalon_capture.settings import InfluxConfig, Settings, WriteOptionsConfig
from pcap_import import runner as import_runner


class DummyValue:
    def get_uci(self) -> str:
        return "uci-value"

    def get_total_packet_count(self) -> int:
        return 1

    def get_total_volume(self) -> int:
        return 10

    def get_mean_packet_size(self) -> float:
        return 10.0

    def get_min_packet_size(self) -> int:
        return 1

    def get_max_packet_size(self) -> int:
        return 10

    def get_sd_packet_size(self) -> float:
        return 0.0

    def get_mean_packet_inter_arrival_time(self) -> float:
        return 1.0

    def get_min_packet_inter_arrival_time(self) -> float:
        return 0.5

    def get_max_packet_inter_arrival_time(self) -> float:
        return 2.0

    def get_sd_packet_inter_arrival_time(self) -> float:
        return 0.1

    def get_record_start(self) -> int:
        return 1_000


@pytest.fixture
def influx_config() -> InfluxConfig:
    return InfluxConfig(
        host="http://localhost",
        token="secret",
        database="db",
        measurement_name="measurement",
        tags=["uci"],
        fields={
            "packet_count": "get_total_packet_count",
            "total_volume": "get_total_volume",
        },
    )


@pytest.fixture
def write_options() -> WriteOptionsConfig:
    return WriteOptionsConfig(batch_size=1, flush_interval=1, jitter_interval=0, precision="ms")


def test_map_precision_returns_expected() -> None:
    with pytest.raises(ValueError, match="millisecond"):
        _map_precision("s")
    assert _map_precision("ms") is not None
    assert _map_precision("invalid") == _map_precision("ms")


def test_writer_normalizes_fields(
    monkeypatch: pytest.MonkeyPatch,
    influx_config: InfluxConfig,
    write_options: WriteOptionsConfig,
) -> None:
    written_points: List[Any] = []

    class DummyClient:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def write(self, points: List[Any]) -> None:
            written_points.extend(points)

        def close(self) -> None:
            pass

    monkeypatch.setattr(
        "otalon_capture.influxdb_writer.InfluxDBClient3",
        DummyClient,
    )

    writer = InfluxDBWriter(influx_config, write_options, window_interval_ms=1_000)
    writer.write(DummyValue())
    writer.flush(force=True)

    assert len(written_points) == 1
    point = written_points[0]
    assert point._fields["packet_count"] == 1


def test_writer_handles_write_failure(
    monkeypatch: pytest.MonkeyPatch,
    influx_config: InfluxConfig,
    write_options: WriteOptionsConfig,
) -> None:
    written_calls: List[List[Any]] = []

    class FailingClient:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def write(self, points: List[Any]) -> None:
            written_calls.append(points)
            raise RuntimeError("write failed")

        def close(self) -> None:
            pass

    monkeypatch.setattr(
        "otalon_capture.influxdb_writer.InfluxDBClient3",
        FailingClient,
    )

    writer = InfluxDBWriter(influx_config, write_options, window_interval_ms=1_000)
    writer.write(DummyValue())
    writer.flush(force=True)

    assert len(written_calls) == 2


class HistoricValue(DummyValue):
    """Record whose ``get_time`` reports a capture time far in the past.

    Mirrors what a PCAP import yields: the record carries the time it was
    captured, not the time it is being written.
    """

    def __init__(self, time_ms: int) -> None:
        self._time_ms = time_ms

    def get_time(self) -> int:
        return self._time_ms


class ClocklessValue(DummyValue):
    """Record exposing no usable ``get_time``, forcing the wall-clock fallback."""

    def get_time(self) -> None:
        return None


def _collect_point(
    monkeypatch: pytest.MonkeyPatch,
    influx_config: InfluxConfig,
    write_options: WriteOptionsConfig,
    value: Any,
) -> Any:
    """Write ``value`` through the writer and return the resulting point."""

    written_points: List[Any] = []

    class DummyClient:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def write(self, points: List[Any]) -> None:
            written_points.extend(points)

        def close(self) -> None:
            pass

    monkeypatch.setattr(
        "otalon_capture.influxdb_writer.InfluxDBClient3",
        DummyClient,
    )

    writer = InfluxDBWriter(influx_config, write_options, window_interval_ms=1_000)
    writer.write(value)
    writer.flush(force=True)
    assert len(written_points) == 1
    return written_points[0]


def test_point_time_comes_from_the_record_not_the_clock(
    monkeypatch: pytest.MonkeyPatch,
    influx_config: InfluxConfig,
    write_options: WriteOptionsConfig,
) -> None:
    """A record's own timestamp must land in the past, not at import time.

    This is what allows a PCAP import to fill a historical gap. Regression
    guard for the ``get_time`` read in ``_build_point``.
    """

    import datetime as _datetime

    historic_ms = 1_600_000_000_123
    point = _collect_point(monkeypatch, influx_config, write_options, HistoricValue(historic_ms))

    expected = _datetime.datetime.fromtimestamp(historic_ms // 1000, tz=_datetime.timezone.utc).replace(
        microsecond=123_000
    )
    assert point._time == expected
    assert point._time.year == 2020


def test_point_time_falls_back_to_now_without_a_record_time(
    monkeypatch: pytest.MonkeyPatch,
    influx_config: InfluxConfig,
    write_options: WriteOptionsConfig,
) -> None:
    """Without a usable record time the writer falls back to the wall clock."""

    import datetime as _datetime

    point = _collect_point(monkeypatch, influx_config, write_options, ClocklessValue())

    now = _datetime.datetime.now(tz=_datetime.timezone.utc)
    assert abs((now - point._time).total_seconds()) < 60


@pytest.mark.parametrize("precision,multiplier", [("ms", 1), ("us", 1000), ("ns", 1_000_000)])
def test_serialization_retains_original_milliseconds(monkeypatch, influx_config, write_options, precision, multiplier):
    options = write_options.model_copy(update={"precision": precision})
    point = _collect_point(monkeypatch, influx_config, options, HistoricValue(4_123))
    assert point._time.microsecond == 123_000
    assert int(point.to_line_protocol(precision=_map_precision(precision)).rsplit(" ", 1)[1]) == 4_123 * multiplier


NATIVE_ALIASES = [
    ("get_total_packet_count", "packet_count"),
    ("get_sd_packet_size", "std_packet_size"),
    ("get_mean_packet_inter_arrival_time", "mean_interarrival_time"),
    ("get_min_packet_inter_arrival_time", "min_interarrival_time"),
    ("get_max_packet_inter_arrival_time", "max_interarrival_time"),
    ("get_sd_packet_inter_arrival_time", "std_interarrival_time"),
]
DIRECTED_UCI = "02:00:00:00:00:01/02:00:00:00:00:02/VLAN/IP/192.0.2.1/192.0.2.2/443/1024/TCP"
NATIVE_METRICS = {
    "packet_count": 5,
    "total_volume": 617,
    "mean_packet_size": 123.4,
    "min_packet_size": 71,
    "max_packet_size": 211,
    "std_packet_size": 19.3,
    "mean_interarrival_time": 0.31,
    "min_interarrival_time": 0.11,
    "max_interarrival_time": 0.79,
    "std_interarrival_time": 0.17,
}


@pytest.fixture
def native_settings(influx_config, write_options) -> Settings:
    # Use the shipped accessor mapping, including the absent optional collapsed
    # port count, without resolving runtime secrets or opening a capture source.
    config_path = Path(__file__).resolve().parents[2] / "config" / "config.json"
    fields = json.loads(config_path.read_text())["influx"]["fields"]
    return Settings(
        influx=influx_config.model_copy(update={"fields": fields}),
        capture={"source": "synthetic", "type": "LIVE", "interval": 1000},
        write_options=write_options,
        log={"level": "INFO", "file": "synthetic.log", "verbose": False},
        preprocess={"aggregate_sparse_ports": False},
        mac_aggregation={"enabled": False},
        proto_aggregation={"enabled": False},
    )


@pytest.fixture
def client_spy(monkeypatch):
    clients = []

    class ClientSpy:
        def __init__(self, *args, **kwargs):
            self.points = []
            self.closed = False
            clients.append(self)

        def write(self, points):
            self.points.extend(points)

        def close(self):
            self.closed = True

    monkeypatch.setattr("otalon_capture.influxdb_writer.InfluxDBClient3", ClientSpy)
    return clients


@pytest.mark.parametrize("accessor,alias", NATIVE_ALIASES)
def test_native_mapping_alias_is_only_an_absent_key_fallback(accessor, alias):
    writer = InfluxDBWriter.__new__(InfluxDBWriter)
    bare = accessor[4:]
    assert writer._extract_attribute({alias: 44}, accessor) == 44
    assert writer._extract_attribute({}, accessor) is None
    assert writer._extract_attribute({bare: 43, alias: 44}, accessor) == 43
    assert writer._extract_attribute({bare: None, alias: 44}, accessor) is None
    assert writer._extract_attribute({accessor: 42, bare: 43, alias: 44}, accessor) == 42
    assert writer._extract_attribute({accessor: None, bare: 43, alias: 44}, accessor) is None
    assert writer._extract_attribute({accessor: 0, bare: 43, alias: 44}, accessor) == 0

    getter_mapping = type("GetterMapping", (dict,), {accessor: lambda self: 41})
    assert writer._extract_attribute(getter_mapping({accessor: 42, bare: 43, alias: 44}), accessor) == 41
    null_getter_mapping = type("NullGetterMapping", (dict,), {accessor: lambda self: None})
    assert writer._extract_attribute(null_getter_mapping({accessor: 42, bare: 43, alias: 44}), accessor) is None


@pytest.mark.parametrize("precision,multiplier", [("ms", 1), ("us", 1000), ("ns", 1_000_000)])
@pytest.mark.parametrize("reverse", [False, True])
def test_sparse_disabled_native_pipeline_writes_all_configured_metrics(
    monkeypatch, native_settings, client_spy, precision, multiplier, reverse
):
    records = [
        {"uci": DIRECTED_UCI, "time": 4_123, **NATIVE_METRICS},
        {
            "uci": DIRECTED_UCI,
            "time": 4_187,
            **{name: value * 2 for name, value in NATIVE_METRICS.items()},
        },
    ]
    if reverse:
        records.reverse()
    originals = [dict(record) for record in records]
    settings = native_settings.model_copy(
        update={"write_options": native_settings.write_options.model_copy(update={"precision": precision})}
    )

    class SyntheticCapture:
        def capture_loop(self):
            yield from records

        def stop(self):
            pass

    captures = []

    def capture_factory(config):
        captures.append(config)
        return SyntheticCapture()

    monkeypatch.setattr("otalon_capture.pipeline.Netcap", capture_factory)
    live_result = CapturePipeline(settings).run()
    # Exercise the real import runner's constructor/delegation and drive method,
    # replacing only its native capture boundary with the same synthetic source.
    assert import_runner.CapturePipeline is CapturePipeline
    runner = import_runner.PipelineImportRunner(adapter_config_file="synthetic")
    cancel = threading.Event()
    imported_settings = settings.model_copy(
        update={"capture": settings.capture.model_copy(update={"type": import_runner.CaptureType.PCAP})}
    )
    pipeline = runner._build_pipeline(imported_settings, lambda phase, event: None, cancel)
    assert type(pipeline) is CapturePipeline
    import_result = runner._drive(pipeline, cancel)

    assert [config.type.value for config in captures] == ["LIVE", "PCAP"]
    assert len(client_spy) == 2
    for result, client in zip([live_result, import_result], client_spy):
        assert result.records_processed == result.points_written == 2
        assert (result.first_record_ms, result.last_record_ms) == (4_123, 4_187)
        assert client.closed is True
        assert len(client.points) == 2
        for record, point in zip(records, client.points):
            expected = {name: record[name] for name in NATIVE_METRICS}
            assert point._fields == expected
            assert point._tags == {"uci": DIRECTED_UCI}
            expected_time = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(milliseconds=record["time"])
            assert point._time == expected_time
            identity, fields, timestamp = point.to_line_protocol(precision=_map_precision(precision)).split(" ")
            assert identity == f"measurement,uci={DIRECTED_UCI}"
            serialized = dict(field.split("=", 1) for field in fields.split(","))
            assert {name: float(value.removesuffix("i")) for name, value in serialized.items()} == expected
            for name in ("packet_count", "total_volume", "min_packet_size", "max_packet_size"):
                assert serialized[name].endswith("i")
            assert int(timestamp) == record["time"] * multiplier
    assert records == originals


def test_sparse_disabled_native_pipeline_second_precision_never_constructs_client(native_settings, client_spy):
    settings = native_settings.model_copy(
        update={"write_options": native_settings.write_options.model_copy(update={"precision": "s"})}
    )

    class ForbiddenCapture:
        def capture_loop(self):
            pytest.fail("coarse precision must fail before reading records")

        def stop(self):
            pass

    with pytest.raises(ValueError, match="millisecond"):
        CapturePipeline(settings, capture=ForbiddenCapture())
    assert client_spy == []
