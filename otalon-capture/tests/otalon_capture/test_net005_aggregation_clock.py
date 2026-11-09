"""Regression tests for CAP-05 — flush eligibility must follow record time.

``SparsePortAggregator`` keys its buckets by RECORD timestamp but used to
decide which buckets had expired by comparing against the WALL CLOCK
(``time.time()``). The two are unrelated whenever data is not arriving
live:

* replaying a PCAP recorded in the past made every bucket instantly
  "expired", so aggregation degenerated into pass-through and the
  collapsed-port aggregation it exists to perform never happened;
* a processing backlog or an NTP step could expire a bucket that was
  still filling, splitting one second of traffic across several emitted
  records.
"""

from __future__ import annotations

from typing import Any, Dict, List

import pytest

from otalon_capture.aggregation import AggregatedNetcapRecord, SparsePortAggregator

BASE_UCI = "00:11:22:33:44:55/66:77:88:99:aa:bb/VLAN/IP/10.0.0.1/10.0.0.2/443/{port}/TCP"


def _record(time_ms: int, port: int = 1024) -> Dict[str, Any]:
    return {
        "time": time_ms,
        "uci": BASE_UCI.format(port=port),
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
        "record_start": time_ms,
    }


def _aggregator(wall_clock_s: float) -> SparsePortAggregator:
    """Aggregator whose wall clock is pinned, with ticking always due."""
    aggregator = SparsePortAggregator(enabled=True, emit_interval_ms=0)
    aggregator._time_provider = lambda: wall_clock_s
    ticks = iter(range(0, 10_000, 10))
    aggregator._monotonic_provider = lambda: next(ticks)
    return aggregator


class TestCutoffFollowsRecordTime:
    def test_historical_replay_still_aggregates(self) -> None:
        """A 2020 capture replayed in 2026 must not flush instantly."""
        aggregator = _aggregator(wall_clock_s=1_780_000_000.0)
        second = 1_600_000_000_000

        flushed: List[AggregatedNetcapRecord] = []
        for port in (1024, 1025, 1026):
            flushed.extend(aggregator.add(_record(second, port=port)))

        assert flushed == [], "buckets of the current record second must stay open"
        assert second in aggregator.buckets

    def test_a_later_record_second_closes_the_previous_one(self) -> None:
        aggregator = _aggregator(wall_clock_s=1_780_000_000.0)
        first = 1_600_000_000_000
        aggregator.add(_record(first, port=1024))
        aggregator.add(_record(first, port=1025))

        flushed = aggregator.add(_record(first + 1_000, port=1026))

        assert len(flushed) == 1
        assert flushed[0].time == first
        assert first not in aggregator.buckets

    def test_ports_within_one_second_are_collapsed_together(self) -> None:
        """The point of the aggregator: one record per second, not per port."""
        aggregator = _aggregator(wall_clock_s=1_780_000_000.0)
        second = 1_600_000_000_000
        for port in range(1024, 1034):
            aggregator.add(_record(second, port=port))

        flushed = aggregator.add(_record(second + 1_000, port=2048))

        assert len(flushed) == 1
        assert flushed[0].packet_count == 10

    def test_a_future_dated_capture_does_not_flush_everything(self) -> None:
        """Clock skew the other way must not hold buckets open forever either."""
        aggregator = _aggregator(wall_clock_s=1_600_000_000.0)
        future = 1_900_000_000_000
        aggregator.add(_record(future, port=1024))
        flushed = aggregator.add(_record(future + 1_000, port=1025))

        assert len(flushed) == 1
        assert flushed[0].time == future

    def test_wall_clock_movement_alone_does_not_flush(self) -> None:
        """An NTP step must not expire a bucket that is still filling."""
        wall = {"now": 1_600_000_000.0}
        aggregator = SparsePortAggregator(enabled=True, emit_interval_ms=0)
        aggregator._time_provider = lambda: wall["now"]
        ticks = iter(range(0, 10_000, 10))
        aggregator._monotonic_provider = lambda: next(ticks)

        second = 1_600_000_000_000
        aggregator.add(_record(second, port=1024))

        # The host clock jumps an hour forward; the data has not moved on.
        wall["now"] += 3_600.0
        flushed = aggregator.add(_record(second, port=1025))

        assert flushed == []
        assert second in aggregator.buckets

    def test_force_flush_still_emits_everything(self) -> None:
        aggregator = _aggregator(wall_clock_s=1_780_000_000.0)
        second = 1_600_000_000_000
        aggregator.add(_record(second, port=1024))

        flushed = aggregator.flush(force=True)

        assert len(flushed) == 1
        assert isinstance(flushed[0], AggregatedNetcapRecord)
        assert aggregator.buckets == {}

    def test_cutoff_falls_back_to_the_wall_clock_before_any_record(self) -> None:
        """With no data-side clock yet there is nothing to flush anyway."""
        aggregator = _aggregator(wall_clock_s=1_600_000_000.0)

        assert aggregator._current_second_bucket() == 1_600_000_000_000

    def test_the_cutoff_tracks_the_newest_record(self) -> None:
        aggregator = _aggregator(wall_clock_s=1_780_000_000.0)
        aggregator.add(_record(1_600_000_000_000))
        aggregator.add(_record(1_600_000_005_000))
        # An out-of-order straggler must not rewind the cutoff.
        aggregator.add(_record(1_600_000_002_000))

        assert aggregator._current_second_bucket() == 1_600_000_005_000

    def test_disabled_aggregator_passes_records_through(self) -> None:
        aggregator = SparsePortAggregator(enabled=False)
        value = _record(1_600_000_000_000)

        assert aggregator.add(value) == [value]
