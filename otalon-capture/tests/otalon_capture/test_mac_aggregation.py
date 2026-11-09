"""Tests for streaming MAC-address aggregation."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, Dict, List

import pytest
from otalon_capture.mac_aggregation import (
    DirectionalMacBucket,
    MacAggregatedRecord,
    MacAggregator,
    MacSecondBucket,
)

SAMPLE_RAW_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "sample_raw.csv"
SAMPLE_MAC_AGG_PATH = Path(__file__).resolve().parents[3] / ".dev" / "netcap_extending" / "sample_mac_aggregated_df.csv"

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


class TestDirectionalMacBucket:
    """Tests for DirectionalMacBucket accumulation and finalization."""

    def test_single_record_outbound(self) -> None:
        bucket = DirectionalMacBucket()
        record = _raw_record()
        bucket.add(record, peer_mac="aa:bb:cc:dd:ee:02")

        features = bucket.build("out")
        assert features["out_conn_count"] == 1.0
        assert features["out_total_packets"] == 10.0
        assert features["out_total_volume"] == 1000.0
        assert features["out_mean_packet_size"] == 100.0
        assert features["out_std_packet_size"] == 25.0
        assert features["out_min_packet_size"] == 50.0
        assert features["out_max_packet_size"] == 200.0
        assert features["out_mean_interarrival"] == 5.0
        assert features["out_std_interarrival"] == 3.0
        assert features["out_unique_dst_count"] == 1.0
        assert features["out_unique_proto_count"] == 1.0

    def test_single_record_inbound(self) -> None:
        bucket = DirectionalMacBucket()
        record = _raw_record()
        bucket.add(record, peer_mac="aa:bb:cc:dd:ee:01")

        features = bucket.build("in")
        assert features["in_conn_count"] == 1.0
        assert features["in_total_packets"] == 10.0
        assert features["in_unique_src_count"] == 1.0
        assert features["in_unique_proto_count"] == 1.0

    def test_multiple_records_weighted_mean(self) -> None:
        bucket = DirectionalMacBucket()
        bucket.add(
            _raw_record(packet_count=10, mean_packet_size=100.0, total_volume=1000.0),
            peer_mac="peer1",
        )
        bucket.add(
            _raw_record(packet_count=20, mean_packet_size=200.0, total_volume=4000.0),
            peer_mac="peer2",
        )

        features = bucket.build("out")
        assert features["out_conn_count"] == 2.0
        assert features["out_total_packets"] == 30.0
        assert features["out_total_volume"] == 5000.0
        expected_mean_ps = (100.0 * 10 + 200.0 * 20) / 30.0
        assert abs(features["out_mean_packet_size"] - expected_mean_ps) < 1e-6
        assert features["out_unique_dst_count"] == 2.0

    def test_zero_packets_safe_division(self) -> None:
        bucket = DirectionalMacBucket()
        bucket.add(
            _raw_record(packet_count=0, mean_packet_size=0.0, total_volume=0.0),
            peer_mac="peer1",
        )

        features = bucket.build("out")
        assert features["out_mean_packet_size"] == 0.0
        assert features["out_mean_interarrival"] == 0.0

    def test_empty_bucket_defaults(self) -> None:
        bucket = DirectionalMacBucket()
        features = bucket.build("out")
        assert features["out_conn_count"] == 0.0
        assert features["out_total_packets"] == 0.0
        assert features["out_mean_packet_size"] == 0.0
        assert features["out_unique_dst_count"] == 0.0


class TestMacSecondBucket:
    """Tests for MacSecondBucket dominant protocol logic."""

    def test_dominant_protocol_from_counter(self) -> None:
        bucket = MacSecondBucket()
        bucket.protocol_counter[18] = 5
        bucket.protocol_counter[8] = 3
        assert bucket.dominant_protocol(PROTOCOL_MAP) == "Ethernet:IPv4:TCP"

    def test_dominant_protocol_unknown(self) -> None:
        bucket = MacSecondBucket()
        assert bucket.dominant_protocol(PROTOCOL_MAP) == "unknown"

    def test_dominant_protocol_fallback(self) -> None:
        bucket = MacSecondBucket()
        bucket.protocol_counter[999] = 1
        assert bucket.dominant_protocol(PROTOCOL_MAP) == "proto_999"


class TestMacAggregator:
    """Tests for MacAggregator streaming logic."""

    def test_disabled_returns_empty(self) -> None:
        agg = MacAggregator(enabled=False)
        result = agg.add(_raw_record())
        assert result == []

    def test_force_flush_emits_records(self) -> None:
        agg = MacAggregator(enabled=True, protocol_map=PROTOCOL_MAP)
        agg.add(_raw_record(time=1000))
        results = agg.flush(force=True)
        assert len(results) >= 1
        assert all(isinstance(r, MacAggregatedRecord) for r in results)

    def test_single_outbound_record(self) -> None:
        agg = MacAggregator(enabled=True, protocol_map=PROTOCOL_MAP)
        agg.add(
            _raw_record(
                time=1000,
                uci="AA:BB/CC:DD//IPv4/10.0.0.1/10.0.0.2/80/1024/Ethernet:IPv4:TCP",
                packet_count=5,
                total_volume=500.0,
                protocols=18,
            )
        )
        results = agg.flush(force=True)
        mac_map = {r.mac_address: r for r in results}

        aa_bb = mac_map["AA:BB"]
        assert aa_bb.out_conn_count == 1.0
        assert aa_bb.out_total_packets == 5.0
        assert aa_bb.out_total_volume == 500.0
        assert aa_bb.out_unique_dst_count == 1.0

        cc_dd = mac_map["CC:DD"]
        assert cc_dd.in_conn_count == 1.0
        assert cc_dd.in_total_packets == 5.0

    def test_ratio_features(self) -> None:
        agg = MacAggregator(enabled=True, protocol_map=PROTOCOL_MAP)
        agg.add(
            _raw_record(
                time=1000,
                uci="AA:BB/CC:DD//IPv4/10.0.0.1/10.0.0.2/80/1024/TCP",
                packet_count=10,
                total_volume=1000.0,
            )
        )
        agg.add(
            _raw_record(
                time=1000,
                uci="CC:DD/AA:BB//IPv4/10.0.0.2/10.0.0.1/1024/80/TCP",
                packet_count=20,
                total_volume=2000.0,
            )
        )
        results = agg.flush(force=True)
        mac_map = {r.mac_address: r for r in results}

        aa_bb = mac_map["AA:BB"]
        assert aa_bb.out_total_packets == 10.0
        assert aa_bb.in_total_packets == 20.0
        assert abs(aa_bb.ratio_in_out_packets - 2.0) < 1e-6
        assert abs(aa_bb.ratio_in_out_volume - 2.0) < 1e-6
        assert aa_bb.total_conn_count == 2.0
        assert aa_bb.total_unique_peers == 2.0

    def test_flush_disabled_returns_empty(self) -> None:
        agg = MacAggregator(enabled=False)
        assert agg.flush(force=True) == []

    def test_second_boundary_grouping(self) -> None:
        """Verify that records in different seconds produce separate groups.

        With data-driven flush, second 1000 is emitted when the first
        record from second 2000 arrives via ``add()``.  The final
        ``flush(force=True)`` emits the remaining second 2000.
        """
        agg = MacAggregator(enabled=True, protocol_map=PROTOCOL_MAP)
        all_results: List[MacAggregatedRecord] = []
        all_results.extend(agg.add(_raw_record(time=1000, uci="AA:BB/CC:DD//IPv4/10.0.0.1/10.0.0.2/80/1024/TCP")))
        all_results.extend(agg.add(_raw_record(time=1500, uci="AA:BB/CC:DD//IPv4/10.0.0.1/10.0.0.2/80/1025/TCP")))
        all_results.extend(agg.add(_raw_record(time=2000, uci="AA:BB/CC:DD//IPv4/10.0.0.1/10.0.0.2/80/1026/TCP")))
        all_results.extend(agg.flush(force=True))

        time_groups: Dict[int, List[MacAggregatedRecord]] = {}
        for r in all_results:
            time_groups.setdefault(r.time, []).append(r)

        assert 1000 in time_groups
        assert 2000 in time_groups


def _load_sample_raw() -> List[Dict[str, Any]]:
    """Load sample_raw.csv and convert to list of raw record dicts.

    Timestamps are truncated to second boundaries (milliseconds) to match
    the second-aligned bucketing used by the aggregators.
    """
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
class TestMacAggregatorGolden:
    """Golden tests: feed sample_raw.csv data and verify structural properties."""

    @pytest.fixture()
    def aggregator_results(self) -> List[MacAggregatedRecord]:
        """Run the MAC aggregator on sample_raw.csv and return all results.

        With data-driven flush, ``add()`` returns completed second-buckets
        as new seconds arrive, so we must collect results from both
        ``add()`` calls and the final ``flush(force=True)``.
        """
        raw_records = _load_sample_raw()
        agg = MacAggregator(enabled=True, protocol_map=PROTOCOL_MAP)
        all_results: List[MacAggregatedRecord] = []
        for record in raw_records:
            all_results.extend(agg.add(record))
        all_results.extend(agg.flush(force=True))
        return all_results

    def test_produces_results(self, aggregator_results: List[MacAggregatedRecord]) -> None:
        assert len(aggregator_results) > 0

    def test_feature_count_per_record(self, aggregator_results: List[MacAggregatedRecord]) -> None:
        record = aggregator_results[0]
        feature_attrs = [
            a
            for a in dir(record)
            if not a.startswith("_")
            and a not in ("time", "mac_address", "dominant_protocol")
            and not callable(getattr(record, a))
        ]
        assert len(feature_attrs) == 26

    def test_all_records_have_mac_address(self, aggregator_results: List[MacAggregatedRecord]) -> None:
        for r in aggregator_results:
            assert r.mac_address != ""
            assert r.mac_address != "unknown"

    def test_known_mac_appears(self, aggregator_results: List[MacAggregatedRecord]) -> None:
        """Check that known MACs from the sample data appear in results."""
        all_macs = {r.mac_address for r in aggregator_results}
        assert "02:00:00:00:00:01" in all_macs
        assert "02:00:00:00:00:02" in all_macs

    def test_bidirectional_symmetry(self, aggregator_results: List[MacAggregatedRecord]) -> None:
        """For a known bidirectional pair, verify out/in packets are non-zero."""
        selected = [r for r in aggregator_results if r.mac_address == "02:00:00:00:00:01"]
        assert selected
        assert any(r.out_total_packets > 0 for r in selected)
        assert any(r.in_total_packets > 0 for r in selected)

    def test_self_contained_golden_two_records(self) -> None:
        """Verify exact feature values from two manually specified records.

        This uses the same aggregation formulas as the offline Polars pipeline.
        """
        agg = MacAggregator(enabled=True, protocol_map=PROTOCOL_MAP)

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
                "uci": "CC:DD/AA:BB//IPv4/10.0.0.2/10.0.0.1/1024/80/Ethernet:IPv4:TCP",
                "packet_count": 20,
                "total_volume": 4000.0,
                "mean_packet_size": 200.0,
                "min_packet_size": 100,
                "max_packet_size": 300,
                "std_packet_size": 40.0,
                "mean_interarrival_time": 3.0,
                "min_interarrival_time": 0.5,
                "max_interarrival_time": 8.0,
                "std_interarrival_time": 1.5,
                "protocols": 18,
            }
        )

        results = agg.flush(force=True)
        mac_map = {r.mac_address: r for r in results}

        aa_bb = mac_map["AA:BB"]
        assert abs(aa_bb.out_conn_count - 1.0) < 1e-6
        assert abs(aa_bb.out_total_packets - 10.0) < 1e-6
        assert abs(aa_bb.out_total_volume - 1000.0) < 1e-6
        assert abs(aa_bb.out_mean_packet_size - 100.0) < 1e-6
        assert abs(aa_bb.out_std_packet_size - 20.0) < 1e-6
        assert abs(aa_bb.out_min_packet_size - 50.0) < 1e-6
        assert abs(aa_bb.out_max_packet_size - 200.0) < 1e-6
        assert abs(aa_bb.out_mean_interarrival - 5.0) < 1e-6
        assert abs(aa_bb.out_std_interarrival - 2.0) < 1e-6
        assert abs(aa_bb.out_unique_dst_count - 1.0) < 1e-6
        assert abs(aa_bb.out_unique_proto_count - 1.0) < 1e-6

        assert abs(aa_bb.in_conn_count - 1.0) < 1e-6
        assert abs(aa_bb.in_total_packets - 20.0) < 1e-6
        assert abs(aa_bb.in_total_volume - 4000.0) < 1e-6
        assert abs(aa_bb.in_mean_packet_size - 200.0) < 1e-6
        assert abs(aa_bb.in_std_packet_size - 40.0) < 1e-6

        assert abs(aa_bb.ratio_in_out_packets - 2.0) < 1e-6
        assert abs(aa_bb.ratio_in_out_volume - 4.0) < 1e-6
        assert abs(aa_bb.total_conn_count - 2.0) < 1e-6
        assert abs(aa_bb.total_unique_peers - 2.0) < 1e-6
