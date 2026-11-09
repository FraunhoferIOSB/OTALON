"""Tests for streaming protocol aggregation."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, Dict, List

import pytest
from otalon_capture.proto_aggregation import (
    ProtoAggregatedRecord,
    ProtoAggregator,
    ProtoBucket,
    _safe_stdev,
)

SAMPLE_RAW_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "sample_raw.csv"
SAMPLE_PROTO_AGG_PATH = (
    Path(__file__).resolve().parents[3] / ".dev" / "netcap_extending" / "sample_proto_aggregated_df.csv"
)

PROTOCOL_MAP = {
    0: "Ethernet:VLAN:PROFINET_RT:PROFINET_RT_IO",
    5: "Ethernet:LLDP",
    8: "Ethernet:IPv4:TCP:OPC-UA",
    13: "Ethernet:IPv4:TCP:HTTPResponse",
    15: "Ethernet:IPv4:TCP:HTTPRequest",
    18: "Ethernet:IPv4:TCP",
    19: "Ethernet:PROFINET_RT:PROFINET_RT_PTCP",
}


def _raw_record(**overrides: Any) -> Dict[str, Any]:
    """Build a minimal raw Netcap record dict."""
    base: Dict[str, Any] = {
        "time": 1000,
        "uci": "aa:bb:cc:dd:ee:01/aa:bb:cc:dd:ee:02//IPv4/10.0.0.1/10.0.0.2/80/1024/Ethernet:IPv4:TCP",
        "packet_count": 10,
        "total_volume": 1000.0,
        "mean_packet_size": 100.0,
        "min_packet_size": 50,
        "max_packet_size": 200,
        "std_packet_size": 25.0,
        "mean_interarrival_time": 5.0,
        "min_interarrival_time": 1.0,
        "max_interarrival_time": 10.0,
        "std_interarrival_time": 3.0,
        "protocols": 18,
    }
    base.update(overrides)
    return base


class TestSafeStdev:
    """Tests for the _safe_stdev helper."""

    def test_empty_list(self) -> None:
        assert _safe_stdev([]) == 0.0

    def test_single_value(self) -> None:
        assert _safe_stdev([42]) == 0.0

    def test_two_values(self) -> None:
        result = _safe_stdev([10, 20])
        assert abs(result - 7.0710678118654755) < 1e-6

    def test_multiple_identical_values(self) -> None:
        assert _safe_stdev([5, 5, 5]) == 0.0


class TestProtoBucket:
    """Tests for ProtoBucket accumulation and finalization."""

    def test_single_record(self) -> None:
        bucket = ProtoBucket()
        record = _raw_record()
        bucket.add(record, src_mac="aa:bb", dst_mac="cc:dd")

        result = bucket.build(1000, "Ethernet:IPv4:TCP")
        assert result.proto_conn_count == 1.0
        assert result.proto_total_packets == 10.0
        assert result.proto_total_volume == 1000.0
        assert result.proto_mean_packet_size == 100.0
        assert result.proto_std_packet_size == 25.0
        assert result.proto_min_packet_size == 50.0
        assert result.proto_max_packet_size == 200.0
        assert result.proto_range_packet_size == 150.0
        assert result.proto_mean_interarrival == 5.0
        assert result.proto_std_interarrival == 3.0
        assert result.proto_min_interarrival == 1.0
        assert result.proto_max_interarrival == 10.0
        assert result.proto_unique_src_mac == 1.0
        assert result.proto_unique_dst_mac == 1.0
        assert result.proto_unique_mac_pairs == 1.0
        assert result.proto_mean_packets_per_conn == 10.0
        assert result.proto_std_packets_per_conn == 0.0
        assert result.proto_mean_volume_per_conn == 1000.0

    def test_multiple_records_topology(self) -> None:
        bucket = ProtoBucket()
        bucket.add(_raw_record(), src_mac="aa:bb", dst_mac="cc:dd")
        bucket.add(_raw_record(), src_mac="ee:ff", dst_mac="cc:dd")
        bucket.add(_raw_record(), src_mac="aa:bb", dst_mac="gg:hh")

        result = bucket.build(1000, "TCP")
        assert result.proto_unique_src_mac == 2.0
        assert result.proto_unique_dst_mac == 2.0
        assert result.proto_unique_mac_pairs == 3.0

    def test_behavior_features_std(self) -> None:
        bucket = ProtoBucket()
        bucket.add(
            _raw_record(packet_count=10, total_volume=1000.0),
            src_mac="a",
            dst_mac="b",
        )
        bucket.add(
            _raw_record(packet_count=20, total_volume=2000.0),
            src_mac="c",
            dst_mac="d",
        )

        result = bucket.build(1000, "TCP")
        assert result.proto_mean_packets_per_conn == 15.0
        assert abs(result.proto_std_packets_per_conn - 7.0710678118654755) < 1e-6
        assert result.proto_mean_volume_per_conn == 1500.0

    def test_weighted_mean_packet_size(self) -> None:
        bucket = ProtoBucket()
        bucket.add(
            _raw_record(packet_count=10, mean_packet_size=100.0),
            src_mac="a",
            dst_mac="b",
        )
        bucket.add(
            _raw_record(packet_count=30, mean_packet_size=200.0),
            src_mac="a",
            dst_mac="b",
        )

        result = bucket.build(1000, "TCP")
        expected = (100.0 * 10 + 200.0 * 30) / 40.0
        assert abs(result.proto_mean_packet_size - expected) < 1e-6

    def test_min_max_iat(self) -> None:
        bucket = ProtoBucket()
        bucket.add(
            _raw_record(min_interarrival_time=2.0, max_interarrival_time=10.0),
            src_mac="a",
            dst_mac="b",
        )
        bucket.add(
            _raw_record(min_interarrival_time=1.0, max_interarrival_time=20.0),
            src_mac="a",
            dst_mac="b",
        )

        result = bucket.build(1000, "TCP")
        assert result.proto_min_interarrival == 1.0
        assert result.proto_max_interarrival == 20.0

    def test_empty_bucket(self) -> None:
        bucket = ProtoBucket()
        result = bucket.build(1000, "TCP")
        assert result.proto_conn_count == 0.0
        assert result.proto_total_packets == 0.0
        assert result.proto_mean_packet_size == 0.0
        assert result.proto_range_packet_size == 0.0


class TestProtoAggregator:
    """Tests for ProtoAggregator streaming logic."""

    def test_disabled_returns_empty(self) -> None:
        agg = ProtoAggregator(enabled=False)
        result = agg.add(_raw_record())
        assert result == []

    def test_force_flush_emits_records(self) -> None:
        agg = ProtoAggregator(enabled=True, protocol_map=PROTOCOL_MAP)
        agg.add(_raw_record(time=1000, protocols=18))
        results = agg.flush(force=True)
        assert len(results) == 1
        assert isinstance(results[0], ProtoAggregatedRecord)
        assert results[0].protocol == "Ethernet:IPv4:TCP"

    def test_multiple_protocols_same_second(self) -> None:
        agg = ProtoAggregator(enabled=True, protocol_map=PROTOCOL_MAP)
        agg.add(_raw_record(time=1000, protocols=18))
        agg.add(_raw_record(time=1000, protocols=8))
        results = agg.flush(force=True)
        assert len(results) == 2
        protocols = {r.protocol for r in results}
        assert "Ethernet:IPv4:TCP" in protocols
        assert "Ethernet:IPv4:TCP:OPC-UA" in protocols

    def test_flush_disabled_returns_empty(self) -> None:
        agg = ProtoAggregator(enabled=False)
        assert agg.flush(force=True) == []

    def test_unknown_protocol_fallback(self) -> None:
        agg = ProtoAggregator(enabled=True, protocol_map={})
        agg.add(_raw_record(time=1000, protocols=42))
        results = agg.flush(force=True)
        assert results[0].protocol == "proto_42"

    def test_second_boundary_grouping(self) -> None:
        """Verify that records in different seconds produce separate groups.

        With data-driven flush, second 1000 is emitted when the first
        record from second 2000 arrives via ``add()``.  The final
        ``flush(force=True)`` emits the remaining second 2000.
        """
        agg = ProtoAggregator(enabled=True, protocol_map=PROTOCOL_MAP)
        all_results: List[ProtoAggregatedRecord] = []
        all_results.extend(agg.add(_raw_record(time=1000, protocols=18)))
        all_results.extend(agg.add(_raw_record(time=1500, protocols=18)))
        all_results.extend(agg.add(_raw_record(time=2000, protocols=18)))
        all_results.extend(agg.flush(force=True))

        time_groups: Dict[int, List[ProtoAggregatedRecord]] = {}
        for r in all_results:
            time_groups.setdefault(r.time, []).append(r)

        assert 1000 in time_groups
        assert 2000 in time_groups

    def test_getter_methods(self) -> None:
        agg = ProtoAggregator(enabled=True, protocol_map=PROTOCOL_MAP)
        agg.add(_raw_record(time=1000, protocols=18))
        results = agg.flush(force=True)
        record = results[0]

        assert record.get_time() == 1000
        assert record.get_protocol() == "Ethernet:IPv4:TCP"
        assert record.get_proto_conn_count() == 1.0
        assert record.get_proto_total_packets() == 10.0
        assert record.get_proto_total_volume() == 1000.0
        assert record.get_proto_min_packet_size() == 50.0
        assert record.get_proto_max_packet_size() == 200.0
        assert record.get_proto_range_packet_size() == 150.0


def _load_sample_raw() -> List[Dict[str, Any]]:
    """Load sample_raw.csv and convert to list of raw record dicts."""
    records = []
    with open(SAMPLE_RAW_PATH, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ts_str = row["time"]
            from datetime import datetime

            dt = datetime.fromisoformat(ts_str)
            ts_ms = int(dt.timestamp() * 1000)

            records.append(
                {
                    "time": ts_ms,
                    "uci": row["uci"],
                    "packet_count": int(row["packet_count"]),
                    "total_volume": float(row["total_volume"]),
                    "mean_packet_size": float(row["mean_packet_size"]),
                    "min_packet_size": int(row["min_packet_size"]),
                    "max_packet_size": int(row["max_packet_size"]),
                    "std_packet_size": float(row["std_packet_size"]),
                    "mean_interarrival_time": float(row["mean_interarrival_time"]),
                    "min_interarrival_time": float(row["min_interarrival_time"]),
                    "max_interarrival_time": float(row["max_interarrival_time"]),
                    "std_interarrival_time": float(row["std_interarrival_time"]),
                    "protocols": int(row["protocols"]),
                }
            )
    return records


@pytest.mark.golden
class TestProtoAggregatorGolden:
    """Golden tests: feed sample_raw.csv data and verify structural properties."""

    @pytest.fixture()
    def aggregator_results(self) -> List[ProtoAggregatedRecord]:
        """Run the Proto aggregator on sample_raw.csv and return all results.

        With data-driven flush, ``add()`` returns completed second-buckets
        as new seconds arrive, so we must collect results from both
        ``add()`` calls and the final ``flush(force=True)``.
        """
        raw_records = _load_sample_raw()
        agg = ProtoAggregator(enabled=True, protocol_map=PROTOCOL_MAP)
        all_results: List[ProtoAggregatedRecord] = []
        for record in raw_records:
            all_results.extend(agg.add(record))
        all_results.extend(agg.flush(force=True))
        return all_results

    def test_produces_results(self, aggregator_results: List[ProtoAggregatedRecord]) -> None:
        assert len(aggregator_results) > 0

    def test_feature_count_per_record(self, aggregator_results: List[ProtoAggregatedRecord]) -> None:
        record = aggregator_results[0]
        feature_attrs = [
            a
            for a in dir(record)
            if not a.startswith("_") and a not in ("time", "protocol") and not callable(getattr(record, a))
        ]
        assert len(feature_attrs) == 18

    def test_known_protocols_appear(self, aggregator_results: List[ProtoAggregatedRecord]) -> None:
        """Check that known protocols from the sample data appear in results."""
        all_protos = {r.protocol for r in aggregator_results}
        assert "Ethernet:IPv4:TCP" in all_protos
        assert "Ethernet:VLAN:PROFINET_RT:PROFINET_RT_IO" in all_protos

    def test_self_contained_golden_single_protocol(self) -> None:
        """Verify exact feature values from two connections of the same protocol.

        Exercises all 18 features with manually computed expected values matching
        the Polars offline pipeline formulas.
        """
        agg = ProtoAggregator(enabled=True, protocol_map={18: "Ethernet:IPv4:TCP"})

        agg.add(
            {
                "time": 5000,
                "uci": "AA:BB/CC:DD//IPv4/10.0.0.1/10.0.0.2/80/1024/Ethernet:IPv4:TCP",
                "packet_count": 10,
                "total_volume": 1000.0,
                "mean_packet_size": 100.0,
                "min_packet_size": 50,
                "max_packet_size": 200,
                "std_packet_size": 20.0,
                "mean_interarrival_time": 5.0,
                "min_interarrival_time": 1.0,
                "max_interarrival_time": 10.0,
                "std_interarrival_time": 2.0,
                "protocols": 18,
            }
        )
        agg.add(
            {
                "time": 5000,
                "uci": "EE:FF/CC:DD//IPv4/10.0.0.3/10.0.0.2/80/2048/Ethernet:IPv4:TCP",
                "packet_count": 30,
                "total_volume": 6000.0,
                "mean_packet_size": 200.0,
                "min_packet_size": 100,
                "max_packet_size": 400,
                "std_packet_size": 50.0,
                "mean_interarrival_time": 3.0,
                "min_interarrival_time": 0.5,
                "max_interarrival_time": 8.0,
                "std_interarrival_time": 1.5,
                "protocols": 18,
            }
        )

        results = agg.flush(force=True)
        assert len(results) == 1
        r = results[0]

        assert r.protocol == "Ethernet:IPv4:TCP"

        assert abs(r.proto_conn_count - 2.0) < 1e-6
        assert abs(r.proto_total_packets - 40.0) < 1e-6
        assert abs(r.proto_total_volume - 7000.0) < 1e-6

        expected_mean_ps = (100.0 * 10 + 200.0 * 30) / 40.0
        assert abs(r.proto_mean_packet_size - expected_mean_ps) < 1e-6
        expected_std_ps = (20.0 + 50.0) / 2.0
        assert abs(r.proto_std_packet_size - expected_std_ps) < 1e-6
        assert abs(r.proto_min_packet_size - 50.0) < 1e-6
        assert abs(r.proto_max_packet_size - 400.0) < 1e-6
        assert abs(r.proto_range_packet_size - 350.0) < 1e-6

        expected_mean_iat = (5.0 * 10 + 3.0 * 30) / 40.0
        assert abs(r.proto_mean_interarrival - expected_mean_iat) < 1e-6
        expected_std_iat = (2.0 + 1.5) / 2.0
        assert abs(r.proto_std_interarrival - expected_std_iat) < 1e-6
        assert abs(r.proto_min_interarrival - 0.5) < 1e-6
        assert abs(r.proto_max_interarrival - 10.0) < 1e-6

        assert abs(r.proto_unique_src_mac - 2.0) < 1e-6
        assert abs(r.proto_unique_dst_mac - 1.0) < 1e-6
        assert abs(r.proto_unique_mac_pairs - 2.0) < 1e-6

        assert abs(r.proto_mean_packets_per_conn - 20.0) < 1e-6
        import statistics

        expected_std_ppc = statistics.stdev([10, 30])
        assert abs(r.proto_std_packets_per_conn - expected_std_ppc) < 1e-6
        assert abs(r.proto_mean_volume_per_conn - 3500.0) < 1e-6
