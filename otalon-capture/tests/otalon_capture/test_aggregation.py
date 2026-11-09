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
