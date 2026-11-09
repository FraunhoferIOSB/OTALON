"""Generic aggregation worker thread for streaming pipelines.

Provides :class:`AggregationWorker`, a daemon thread that reads raw records
from a :class:`queue.Queue`, feeds them into an aggregator, and writes the
resulting records through an :class:`InfluxDBWriter`.
"""

from __future__ import annotations

import queue
import threading
from typing import Any, List, Protocol

from loguru import logger


class Aggregator(Protocol):
    """Structural type expected from MAC / Proto aggregators."""

    def add(self, value: Any) -> List[Any]: ...

    def flush(self, force: bool = False) -> List[Any]: ...


class Writer(Protocol):
    """Structural type expected from an InfluxDB writer."""

    def write(self, value: Any) -> None: ...

    def flush(self, force: bool = False) -> None: ...

    def close(self) -> None: ...


class AggregationWorker(threading.Thread):
    """Generic worker thread: Queue -> Aggregator -> Writer.

    The worker reads from *input_queue* with a timeout so periodic
    time-based flushes can fire even when no new records arrive.

    Args:
        name: Human-readable thread name for logging.
        input_queue: Queue of raw record dicts to consume.
        aggregator: Streaming aggregator (``MacAggregator`` or ``ProtoAggregator``).
        writer: InfluxDB writer instance for the target measurement.
        poll_timeout: Seconds to wait on the queue before performing a periodic flush.
    """

    def __init__(
        self,
        name: str,
        input_queue: queue.Queue,
        aggregator: Any,
        writer: Any,
        poll_timeout: float = 1.0,
    ) -> None:
        super().__init__(name=name, daemon=True)
        self.input_queue = input_queue
        self.aggregator = aggregator
        self.writer = writer
        self.poll_timeout = poll_timeout
        self._running = True
        self.records_failed = 0
        """Records dropped because processing raised.

        A failed record used to vanish silently: the exception was logged
        but nothing counted it, so a worker degrading to "drops everything"
        looked identical to a quiet network (audit QUA-08).
        """

    def run(self) -> None:
        """Consume records from the queue until :meth:`stop` is called."""
        logger.info("Worker '{name}' started.", name=self.name)
        while self._running:
            try:
                record = self.input_queue.get(timeout=self.poll_timeout)
            except queue.Empty:
                self._periodic_flush()
                continue

            # task_done() must run exactly once per successful get(), even
            # when processing raises. Calling it only on the success path
            # left the queue's unfinished-task counter permanently high, so
            # any queue.join() blocked forever and the dropped record was
            # invisible in the counters (audit QUA-08).
            try:
                self._process_record(record)
            except Exception as exc:
                logger.exception(
                    "Worker '{name}' failed to process a record, dropping it: {error}",
                    name=self.name,
                    error=exc,
                )
                self.records_failed += 1
            finally:
                self.input_queue.task_done()
        logger.info("Worker '{name}' exiting run loop.", name=self.name)

    def stop(self) -> None:
        """Signal the worker to stop and flush remaining data.

        After calling ``stop()``, the caller should ``join()`` the thread to
        wait for the final flush to complete.
        """
        logger.info("Worker '{name}' stopping — draining queue and flushing.", name=self.name)
        self._running = False
        self._drain_queue()
        self._final_flush()

    def _process_record(self, record: Any) -> None:
        """Feed a single record into the aggregator and write any emitted results."""
        for result in self.aggregator.add(record):
            self.writer.write(result)

    def _periodic_flush(self) -> None:
        """Flush time-expired buckets during idle periods."""
        for result in self.aggregator.flush():
            self.writer.write(result)

    def _drain_queue(self) -> None:
        """Process all remaining records in the queue without blocking.

        Like the main loop, ``task_done()`` is paired with ``get_nowait()``
        in a ``finally`` so a failing record during shutdown can neither
        skip the counter nor abort the drain (audit QUA-08).
        """
        while True:
            try:
                record = self.input_queue.get_nowait()
            except queue.Empty:
                break

            try:
                self._process_record(record)
            except Exception as exc:
                logger.exception(
                    "Worker '{name}' failed to process a record while draining: {error}",
                    name=self.name,
                    error=exc,
                )
                self.records_failed += 1
            finally:
                self.input_queue.task_done()

    def _final_flush(self) -> None:
        """Force-flush the aggregator and close the writer."""
        try:
            for result in self.aggregator.flush(force=True):
                self.writer.write(result)
        except Exception as exc:
            logger.exception(
                "Worker '{name}' flush failed: {error}",
                name=self.name,
                error=exc,
            )
        try:
            self.writer.close()
        except Exception as exc:
            logger.exception(
                "Worker '{name}' writer close failed: {error}",
                name=self.name,
                error=exc,
            )
        logger.info("Worker '{name}' shutdown complete.", name=self.name)
