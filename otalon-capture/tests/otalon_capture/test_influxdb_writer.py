"""Tests for the InfluxDB writer wrapper."""

from __future__ import annotations

from typing import Any, List

import pytest

from otalon_capture.influxdb_writer import InfluxDBWriter, _map_precision
from otalon_capture.settings import InfluxConfig, WriteOptionsConfig


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
    assert _map_precision("s") is not None
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

    historic_ms = 1_600_000_000_000
    point = _collect_point(monkeypatch, influx_config, write_options, HistoricValue(historic_ms))

    expected = _datetime.datetime.fromtimestamp((historic_ms + 1_000 - 1) // 1000, tz=_datetime.timezone.utc).replace(
        microsecond=0
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
