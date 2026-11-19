"""Tests for aggregation of Netcap++ sparse port records."""

from __future__ import annotations

from typing import Any, Dict

import pytest

from otalon_capture.aggregation import (
    AggregatedNetcapRecord,
    AggregationBucket,
    SparsePortAggregator,
    _safe_int,
    _safe_num,
    _uci_to_parts,
)


def _record(**overrides: Any) -> Dict[str, Any]:
    base = {
        "uci": "00:11:22:33:44:55/66:77:88:99:aa:bb/VLAN/IP/10.0.0.1/10.0.0.2/443/1024/TCP",
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
        "record_start": 1_000,
    }
    base.update(overrides)
    return base


@pytest.mark.parametrize(
    ("uci", "expected"),
    [
        ("a/b/c/d/e/f/g/h/i", ["a", "b", "c", "d", "e", "f", "g", "h", "i"]),
        ("a/b", ["a", "b", "", "", "", "", "", "", ""]),
    ],
)
def test_uci_to_parts_padding(uci: str, expected: list[str]) -> None:
    assert _uci_to_parts(uci) == expected


@pytest.mark.parametrize(
    ("value", "default", "expected"),
    [("10", 0.0, 10.0), ("invalid", 1.0, 1.0), (None, 2.0, 2.0)],
)
def test_safe_num(value: Any, default: float, expected: float) -> None:
    assert _safe_num(value, default) == expected


@pytest.mark.parametrize(
    ("value", "default", "expected"),
    [("10", 0, 10), ("invalid", 1, 1), (None, 2, 2)],
)
def test_safe_int(value: Any, default: int, expected: int) -> None:
    assert _safe_int(value, default) == expected


def test_aggregation_bucket_builds_expected_record() -> None:
    bucket = AggregationBucket()
    bucket.add(_record())
    record = bucket.build(
        sec_ts=1_000,
        uci_base=("00:11:22:33:44:55", "66:77:88:99:aa:bb", "VLAN", "IP", "10.0.0.1", "10.0.0.2", "TCP"),
    )
    assert isinstance(record, AggregatedNetcapRecord)
    assert record.packet_count == 1
    assert record.total_volume == 100
    assert record.min_packet_size == 100
    assert record.max_packet_size == 100
    assert record.collapsed_port_count is None


def test_aggregation_bucket_merges_multiple_ports() -> None:
    bucket = AggregationBucket()
    bucket.add(_record(uci="00:11:22:33:44:55/66:77:88:99:aa:bb/VLAN/IP/10.0.0.1/10.0.0.2/443/1024/TCP"))
    bucket.add(_record(uci="00:11:22:33:44:55/66:77:88:99:aa:bb/VLAN/IP/10.0.0.1/10.0.0.2/444/1025/TCP"))
    bucket.add(_record(uci="00:11:22:33:44:55/66:77:88:99:aa:bb/VLAN/IP/10.0.0.1/10.0.0.2/445/1026/TCP"))
    bucket.add(_record(uci="00:11:22:33:44:55/66:77:88:99:aa:bb/VLAN/IP/10.0.0.1/10.0.0.2/446/1027/TCP"))
    bucket.add(_record(uci="00:11:22:33:44:55/66:77:88:99:aa:bb/VLAN/IP/10.0.0.1/10.0.0.2/447/1028/TCP"))
    record = bucket.build(
        sec_ts=1_000,
        uci_base=("00", "11", "22", "33", "44", "55", "PROTO"),
    )
    assert record.get_uci().split("/")[6:8] == ["*", "*"]
    assert record.collapsed_port_count == 10


def test_aggregation_bucket_merges_dst_ports() -> None:
    bucket = AggregationBucket()
    bucket.add(
        _record(uci="00:11:22:33:44:55/66:77:88:99:aa:bb//IPv4/192.168.0.1/192.168.0.2/80/1024/Ethernet:IPv4:TCP")
    )
    bucket.add(
        _record(uci="00:11:22:33:44:55/66:77:88:99:aa:bb//IPv4/192.168.0.1/192.168.0.2/80/1025/Ethernet:IPv4:TCP")
    )
    bucket.add(
        _record(uci="00:11:22:33:44:55/66:77:88:99:aa:bb//IPv4/192.168.0.1/192.168.0.2/80/1026/Ethernet:IPv4:TCP")
    )
    bucket.add(
        _record(uci="00:11:22:33:44:55/66:77:88:99:aa:bb//IPv4/192.168.0.1/192.168.0.2/80/1027/Ethernet:IPv4:TCP")
    )
    bucket.add(
        _record(uci="00:11:22:33:44:55/66:77:88:99:aa:bb//IPv4/192.168.0.1/192.168.0.2/80/1028/Ethernet:IPv4:TCP")
    )
    record = bucket.build(
        sec_ts=1_000,
        uci_base=("00", "11", "22", "33", "44", "55", "PROTO"),
    )
    assert record.get_uci().split("/")[6:8] == ["80", "*"]
    assert record.collapsed_port_count == 5


def test_aggregation_bucket_merges_src_ports() -> None:
    bucket = AggregationBucket()
    bucket.add(
        _record(uci="00:11:22:33:44:55/66:77:88:99:aa:bb//IPv4/192.168.0.1/192.168.0.2/1024/80/Ethernet:IPv4:TCP")
    )
    bucket.add(
        _record(uci="00:11:22:33:44:55/66:77:88:99:aa:bb//IPv4/192.168.0.1/192.168.0.2/1025/80/Ethernet:IPv4:TCP")
    )
    bucket.add(
        _record(uci="00:11:22:33:44:55/66:77:88:99:aa:bb//IPv4/192.168.0.1/192.168.0.2/1026/80/Ethernet:IPv4:TCP")
    )
    bucket.add(
        _record(uci="00:11:22:33:44:55/66:77:88:99:aa:bb//IPv4/192.168.0.1/192.168.0.2/1027/80/Ethernet:IPv4:TCP")
    )
    bucket.add(
        _record(uci="00:11:22:33:44:55/66:77:88:99:aa:bb//IPv4/192.168.0.1/192.168.0.2/1028/80/Ethernet:IPv4:TCP")
    )
    record = bucket.build(
        sec_ts=1_000,
        uci_base=("00", "11", "22", "33", "44", "55", "PROTO"),
    )
    assert record.get_uci().split("/")[6:8] == ["*", "80"]
    assert record.collapsed_port_count == 5


def test_sparse_port_aggregator_force_flush() -> None:
    aggregator = SparsePortAggregator(enabled=True)
    aggregator.add(_record())
    flushed = aggregator.flush(force=True)
    assert len(flushed) == 1
    assert isinstance(flushed[0], AggregatedNetcapRecord)


def test_aggregated_record_get_collapsed_port_count() -> None:
    record = AggregatedNetcapRecord(
        time=1_000,
        uci="a/b/c/d/e/f/g/h/i",
        packet_count=1,
        total_volume=100,
        mean_packet_size=100.0,
        min_packet_size=100,
        max_packet_size=100,
        std_packet_size=0.0,
        mean_interarrival_time=1.0,
        min_interarrival_time=1.0,
        max_interarrival_time=1.0,
        std_interarrival_time=0.0,
        collapsed_port_count=7,
    )
    assert record.get_collapsed_port_count() == 7


@pytest.mark.parametrize("enabled", [True, False])
@pytest.mark.parametrize("interval_ms", [1000, 375])
@pytest.mark.parametrize("reverse", [True, False])
def test_independent_window_starts_survive_port_grouping(enabled, interval_ms, reverse):
    """Independent file pipelines must not compete at a floored point key."""
    from datetime import datetime, timezone

    from otalon_capture.influxdb_writer import InfluxDBWriter, _map_precision
    from otalon_capture.settings import InfluxConfig

    starts = [4_123, 4_187]
    if reverse:
        starts.reverse()
    config = InfluxConfig(
        host="http://localhost",
        token="synthetic-only",
        database="test",
        measurement_name="network_metrics",
        tags=["uci"],
        fields={"packet_count": "packet_count"},
    )
    runs = []
    for _ in range(2):
        lines = []
        for start in starts:
            agg = SparsePortAggregator(enabled, emit_interval_ms=interval_ms)
            values = []
            for port in [32001, 32002]:
                values += agg.add(_record(time=start, uci=f"src/dst/0/6/192.0.2.1/192.0.2.2/{port}/80/TCP"))
            values += agg.flush(force=True)
            assert len(values) == (1 if enabled else 2)
            writer = InfluxDBWriter.__new__(InfluxDBWriter)
            writer.config = config
            writer.window_interval_ms = interval_ms
            writer.write_precision = _map_precision("ms")
            writer.int_fields = {"packet_count"}
            for value in values:
                point = writer._build_point(value)
                assert point._time == datetime.fromtimestamp(start // 1000, tz=timezone.utc).replace(
                    microsecond=start % 1000 * 1000
                )
                line = point.to_line_protocol(precision=writer.write_precision)
                assert int(line.rsplit(" ", 1)[1]) == start
                lines.append(line)
                if enabled:
                    assert value.time == start
                    assert value.packet_count == 2
                    assert value.total_volume == 200
                    assert value.mean_packet_size == 100
                    assert value.uci.split("/")[6:8] == ["*", "80"]
                    assert value.collapsed_port_count == 2
        assert len(set(lines)) == len(lines)
        runs.append(sorted(lines))
    assert runs[0] == runs[1]


@pytest.mark.parametrize("kind", ["sparse", "mac", "proto"])
@pytest.mark.parametrize("reverse", [True, False])
def test_only_identical_original_window_starts_share_a_bucket(kind, reverse):
    from otalon_capture.mac_aggregation import MacAggregator
    from otalon_capture.proto_aggregation import ProtoAggregator

    agg = {"sparse": SparsePortAggregator, "mac": MacAggregator, "proto": ProtoAggregator}[kind](True, 375)
    values = []
    windows = [(4_123, [32001, 32002]), (4_187, [32003])]
    if reverse:
        windows.reverse()
    for start, ports in windows:
        for port in ports:
            values += agg.add(_record(time=start, uci=f"src/dst/0/6/192.0.2.1/192.0.2.2/{port}/80/TCP"))
    values += agg.flush(force=True)
    assert {v.time for v in values} == {4_123, 4_187}
    if kind == "mac":
        outbound = sorted((v.time, v.out_conn_count, v.out_total_packets) for v in values if v.mac_address == "src")
        assert outbound == [(4_123, 2.0, 2.0), (4_187, 1.0, 1.0)]
    elif kind == "proto":
        assert sorted((v.time, v.proto_conn_count, v.proto_total_packets) for v in values) == [
            (4_123, 2.0, 2.0),
            (4_187, 1.0, 1.0),
        ]
    else:
        assert sorted((v.time, v.packet_count) for v in values) == [(4_123, 2), (4_187, 1)]
