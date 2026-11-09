"""Regression tests for the SUITE-033 capture-side error-swallowing fixes.

* QUA-08 — ``AggregationWorker`` called ``task_done()`` only on the success
  path, so a record that raised left the queue's unfinished-task counter
  permanently high (deadlocking any ``queue.join()``) and vanished without
  being counted anywhere.
* QUA-10 — ``InfluxDBWriter._extract_attribute`` used only ``getattr``, so a
  dict record yielded ``None`` for every tag and field. The resulting
  field-less point is a silent no-op for InfluxDB while the pipeline still
  counted it in ``points_written`` — an import reporting success having
  written nothing.
"""

from __future__ import annotations

import queue
import threading
from typing import Any, Dict, List

import pytest

from otalon_capture.influxdb_writer import InfluxDBWriter
from otalon_capture.settings import InfluxConfig
from otalon_capture.worker import AggregationWorker

pytestmark = pytest.mark.unit


class _Aggregator:
    """Aggregator double that can be told to explode on a given record."""

    def __init__(self, explode_on: Any = None) -> None:
        self.explode_on = explode_on
        self.seen: List[Any] = []

    def add(self, record: Any) -> List[Any]:
        if self.explode_on is not None and record == self.explode_on:
            raise RuntimeError("aggregator exploded")
        self.seen.append(record)
        return []

    def flush(self, force: bool = False) -> List[Any]:
        return []


class _Writer:
    def __init__(self) -> None:
        self.written: List[Any] = []
        self.closed = False

    def write(self, value: Any) -> None:
        self.written.append(value)

    def close(self) -> None:
        self.closed = True


def _join_with_timeout(q: queue.Queue, timeout: float = 5.0) -> bool:
    """Wait for ``q.join()``, returning False instead of hanging forever.

    A bare ``q.join()`` in a test turns the very regression under test (a
    leaked unfinished-task counter) into a suite-wide hang rather than a
    failure, so it is always bounded here.
    """
    done = threading.Event()

    def _waiter() -> None:
        q.join()
        done.set()

    threading.Thread(target=_waiter, daemon=True).start()
    return done.wait(timeout)


def _worker(aggregator: Any, input_queue: queue.Queue) -> AggregationWorker:
    return AggregationWorker(
        name="test-worker",
        input_queue=input_queue,
        aggregator=aggregator,
        writer=_Writer(),
        poll_timeout=0.05,
    )


class TestTaskDonePairing:
    """QUA-08 — task_done() must run exactly once per successful get()."""

    def test_a_failing_record_still_calls_task_done(self) -> None:
        """Without this, queue.join() blocks forever."""
        q: queue.Queue = queue.Queue()
        worker = _worker(_Aggregator(explode_on="boom"), q)
        q.put("boom")

        worker.start()
        completed = _join_with_timeout(q)
        worker.stop()
        worker.join(timeout=3.0)

        assert completed, "queue.join() deadlocked after a failing record"

    def test_a_failing_record_is_counted(self) -> None:
        """A dropped record must be visible, not merely logged."""
        q: queue.Queue = queue.Queue()
        worker = _worker(_Aggregator(explode_on="boom"), q)
        q.put("boom")

        worker.start()
        assert _join_with_timeout(q), "queue.join() deadlocked"
        worker.stop()
        worker.join(timeout=3.0)

        assert worker.records_failed == 1

    def test_the_worker_survives_a_failing_record(self) -> None:
        """One bad record must not stop the loop consuming later ones."""
        q: queue.Queue = queue.Queue()
        aggregator = _Aggregator(explode_on="boom")
        worker = _worker(aggregator, q)

        worker.start()
        q.put("boom")
        q.put("good")
        assert _join_with_timeout(q), "queue.join() deadlocked"
        worker.stop()
        worker.join(timeout=3.0)

        assert "good" in aggregator.seen
        assert worker.records_failed == 1

    def test_successful_records_are_not_counted_as_failures(self) -> None:
        q: queue.Queue = queue.Queue()
        worker = _worker(_Aggregator(), q)

        worker.start()
        q.put("a")
        q.put("b")
        assert _join_with_timeout(q), "queue.join() deadlocked"
        worker.stop()
        worker.join(timeout=3.0)

        assert worker.records_failed == 0

    def test_drain_queue_also_pairs_task_done(self) -> None:
        """The shutdown drain had the identical defect."""
        q: queue.Queue = queue.Queue()
        worker = _worker(_Aggregator(explode_on="boom"), q)
        q.put("boom")
        q.put("good")

        worker._drain_queue()

        assert q.unfinished_tasks == 0
        assert worker.records_failed == 1


def _writer_with(fields: Dict[str, str], tags: list[str]) -> InfluxDBWriter:
    """Build a writer with a stubbed client, so nothing touches the network."""
    config = InfluxConfig(
        host="http://localhost:8181",
        token="t",
        database="netcap",
        measurement_name="network_metrics",
        tags=tags,
        fields=fields,
    )
    writer = InfluxDBWriter.__new__(InfluxDBWriter)
    writer.config = config
    writer.int_fields = set()
    writer.write_precision = "ms"
    writer.window_interval_ms = 1000
    writer._bucket_seconds = None
    return writer


class _Record:
    """Object-style record with the accessor shape the writer expects."""

    def get_uci(self) -> str:
        return "uci-1"

    def get_packet_count(self) -> int:
        return 7

    def get_time(self) -> int:
        return 1_772_831_280_000


class TestDictRecordsProduceRealPoints:
    """QUA-10 — dict records used to yield an empty, silently-dropped point."""

    def test_object_record_still_works(self) -> None:
        writer = _writer_with({"packet_count": "get_packet_count"}, ["uci"])

        point = writer._build_point(_Record())

        assert point is not None

    def test_dict_record_with_accessor_names_resolves(self) -> None:
        """PCAP import hands the writer plain dicts."""
        writer = _writer_with({"packet_count": "get_packet_count"}, ["uci"])
        record = {"uci": "uci-1", "get_packet_count": 7, "time": 1_772_831_280_000}

        point = writer._build_point(record)

        assert point is not None

    def test_dict_record_with_bare_keys_resolves(self) -> None:
        """``get_time`` must also find a plain ``time`` key."""
        writer = _writer_with({"packet_count": "packet_count"}, ["uci"])
        record = {"uci": "uci-1", "packet_count": 7, "time": 1_772_831_280_000}

        point = writer._build_point(record)

        assert point is not None

    def test_a_record_with_no_usable_fields_raises(self) -> None:
        """The core of QUA-10: never emit a field-less point as success."""
        writer = _writer_with({"packet_count": "get_packet_count"}, ["uci"])

        with pytest.raises(ValueError, match="no writable fields"):
            writer._build_point({"unrelated": "value"})

    def test_the_error_names_the_expected_fields(self) -> None:
        writer = _writer_with({"packet_count": "get_packet_count"}, ["uci"])

        with pytest.raises(ValueError) as exc:
            writer._build_point({"unrelated": "value"})

        assert "packet_count" in str(exc.value)
        assert "network_metrics" in str(exc.value)

    def test_extract_attribute_prefers_the_accessor(self) -> None:
        """An object's accessor must win over a same-named mapping key."""
        writer = _writer_with({}, [])

        assert writer._extract_attribute(_Record(), "get_packet_count") == 7

    def test_extract_attribute_reads_mapping_keys(self) -> None:
        writer = _writer_with({}, [])

        assert writer._extract_attribute({"packet_count": 42}, "packet_count") == 42

    def test_extract_attribute_strips_the_get_prefix(self) -> None:
        writer = _writer_with({}, [])

        assert writer._extract_attribute({"time": 5}, "get_time") == 5

    def test_extract_attribute_returns_none_for_unknown_keys(self) -> None:
        writer = _writer_with({}, [])

        assert writer._extract_attribute({"a": 1}, "missing") is None
