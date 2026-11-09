"""Tests for the generic aggregation worker thread."""

from __future__ import annotations

import queue
import time
from typing import Any, List
from unittest.mock import MagicMock

from otalon_capture.worker import AggregationWorker


class FakeAggregator:
    """Minimal aggregator stub for testing the worker loop."""

    def __init__(self) -> None:
        self.add_calls: List[Any] = []
        self.flush_calls: int = 0
        self.force_flush_calls: int = 0
        self.add_results: List[Any] = []

    def add(self, value: Any) -> List[Any]:
        """Record the call and return pre-configured results."""
        self.add_calls.append(value)
        return list(self.add_results)

    def flush(self, force: bool = False) -> List[Any]:
        """Track flush calls."""
        if force:
            self.force_flush_calls += 1
        else:
            self.flush_calls += 1
        return []


class FakeWriter:
    """Minimal writer stub for testing the worker loop."""

    def __init__(self) -> None:
        self.written: List[Any] = []
        self.flushed: int = 0
        self.closed: bool = False

    def write(self, value: Any) -> None:
        """Record written values."""
        self.written.append(value)

    def flush(self, force: bool = False) -> None:
        """Track flush calls."""
        self.flushed += 1

    def close(self) -> None:
        """Track close calls."""
        self.closed = True


class TestAggregationWorker:
    """Tests for AggregationWorker lifecycle and data flow."""

    def test_worker_processes_records(self) -> None:
        input_queue: queue.Queue = queue.Queue()
        aggregator = FakeAggregator()
        aggregator.add_results = ["result_1"]
        writer = FakeWriter()

        worker = AggregationWorker(
            name="test-worker",
            input_queue=input_queue,
            aggregator=aggregator,
            writer=writer,
            poll_timeout=0.1,
        )
        input_queue.put({"test": "record"})
        worker.start()

        time.sleep(0.3)
        worker.stop()
        worker.join(timeout=5.0)

        assert len(aggregator.add_calls) >= 1
        assert aggregator.add_calls[0] == {"test": "record"}
        assert "result_1" in writer.written

    def test_worker_stops_gracefully(self) -> None:
        input_queue: queue.Queue = queue.Queue()
        aggregator = FakeAggregator()
        writer = FakeWriter()

        worker = AggregationWorker(
            name="test-stop",
            input_queue=input_queue,
            aggregator=aggregator,
            writer=writer,
            poll_timeout=0.1,
        )
        worker.start()
        time.sleep(0.2)
        worker.stop()
        worker.join(timeout=5.0)

        assert not worker.is_alive()
        assert writer.closed
        assert aggregator.force_flush_calls >= 1

    def test_worker_drains_queue_on_stop(self) -> None:
        input_queue: queue.Queue = queue.Queue()
        aggregator = FakeAggregator()
        writer = FakeWriter()

        for i in range(5):
            input_queue.put({"record": i})

        worker = AggregationWorker(
            name="test-drain",
            input_queue=input_queue,
            aggregator=aggregator,
            writer=writer,
            poll_timeout=0.1,
        )
        worker.start()
        time.sleep(0.3)
        worker.stop()
        worker.join(timeout=5.0)

        assert len(aggregator.add_calls) == 5

    def test_worker_periodic_flush_on_empty_queue(self) -> None:
        input_queue: queue.Queue = queue.Queue()
        aggregator = FakeAggregator()
        writer = FakeWriter()

        worker = AggregationWorker(
            name="test-periodic",
            input_queue=input_queue,
            aggregator=aggregator,
            writer=writer,
            poll_timeout=0.1,
        )
        worker.start()
        time.sleep(0.5)
        worker.stop()
        worker.join(timeout=5.0)

        assert aggregator.flush_calls >= 1

    def test_worker_is_daemon_thread(self) -> None:
        input_queue: queue.Queue = queue.Queue()
        aggregator = FakeAggregator()
        writer = FakeWriter()

        worker = AggregationWorker(
            name="test-daemon",
            input_queue=input_queue,
            aggregator=aggregator,
            writer=writer,
        )
        assert worker.daemon is True

    def test_worker_handles_aggregator_exception(self) -> None:
        input_queue: queue.Queue = queue.Queue()
        writer = FakeWriter()

        failing_aggregator = MagicMock()
        failing_aggregator.add.side_effect = ValueError("test error")
        failing_aggregator.flush.return_value = []

        worker = AggregationWorker(
            name="test-exception",
            input_queue=input_queue,
            aggregator=failing_aggregator,
            writer=writer,
            poll_timeout=0.1,
        )
        input_queue.put({"bad": "record"})
        worker.start()
        time.sleep(0.3)
        worker.stop()
        worker.join(timeout=5.0)

        assert not worker.is_alive()
