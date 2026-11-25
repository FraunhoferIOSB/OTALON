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

from .influxdb_writer import InfluxDBWriter
from .write_failure import TerminalWriteError


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
        self._terminal_status: int | None = None
        self._terminal_lock = threading.Lock()
        self._finalized = False
        self.records_failed = 0
        """Records dropped because processing raised.

        A failed record used to vanish silently: the exception was logged
        but nothing counted it, so a worker degrading to "drops everything"
        looked identical to a quiet network (audit QUA-08).
        """

    def run(self) -> None:
        """Consume records from the queue until :meth:`stop` is called."""
        logger.info("Worker '{name}' started.", name=self.name)
        try:
            while self._running and self._terminal_status is None:
                try:
                    record = self.input_queue.get(timeout=self.poll_timeout)
                except queue.Empty:
                    if self._running:
                        self._periodic_flush()
                    continue

                try:
                    self._process_record(record)
                except TerminalWriteError as failure:
                    self.refuse_publication(failure.status)
                    self.records_failed += 1
                except Exception as exc:
                    logger.exception(
                        "Worker '{name}' failed to process a record, dropping it: {error}",
                        name=self.name,
                        error=exc,
                    )
                    self.records_failed += 1
                finally:
                    self.input_queue.task_done()
        except TerminalWriteError as failure:
            self.refuse_publication(failure.status)
        finally:
            self._running = False
            try:
                self._drain_queue()
            finally:
                self._final_flush()
        logger.info("Worker '{name}' exiting run loop.", name=self.name)

    @property
    def terminal_error(self) -> TerminalWriteError | None:
        """Return fresh numeric-only evidence, never an exception retained by a thread."""
        status = self._terminal_status
        return TerminalWriteError(status) if status is not None else None

    def refuse_publication(self, status: int) -> None:
        """Stop later publication when this worker or its pipeline observes refusal."""
        with self._terminal_lock:
            if self._terminal_status is None:
                self._terminal_status = TerminalWriteError(status).status
        self._running = False

    def stop(self) -> None:
        """Signal stop; a started worker drains and finalizes on its own thread.

        After calling ``stop()``, the caller should ``join()`` the thread to
        wait for the final flush to complete.
        """
        logger.info("Worker '{name}' stopping.", name=self.name)
        self._running = False
        if self.ident is None:
            self._drain_queue()
            self._final_flush()
        elif not self.is_alive() and self._terminal_status is not None:
            # A producer can enqueue between terminal thread exit and owner polling.
            self._drain_queue()

    def _process_record(self, record: Any) -> None:
        """Feed a single record into the aggregator and write any emitted results."""
        if self._terminal_status is not None:
            return
        for result in self.aggregator.add(record):
            if self._terminal_status is not None:
                break
            self.writer.write(result)

    def _periodic_flush(self) -> None:
        """Flush time-expired buckets during idle periods."""
        if self._terminal_status is not None:
            return
        for result in self.aggregator.flush():
            if self._terminal_status is not None:
                break
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
            except TerminalWriteError as failure:
                self.refuse_publication(failure.status)
                self.records_failed += 1
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
        if self._finalized:
            return
        self._finalized = True
        try:
            if self._terminal_status is None:
                for result in self.aggregator.flush(force=True):
                    if self._terminal_status is not None:
                        break
                    self.writer.write(result)
        except TerminalWriteError as failure:
            self.refuse_publication(failure.status)
        except Exception as exc:
            if self._terminal_status is not None:
                logger.warning("Worker '{name}' finalization failed after refusal.", name=self.name)
            else:
                logger.exception(
                    "Worker '{name}' flush failed: {error}",
                    name=self.name,
                    error=exc,
                )
        try:
            if self._terminal_status is not None and isinstance(self.writer, InfluxDBWriter):
                # A sibling's refusal must not force-publish this writer's buffered values.
                with self.writer._lock:
                    self.writer._closed = True
                    self.writer._release_client_locked()
            self.writer.close()
        except TerminalWriteError as failure:
            self.refuse_publication(failure.status)
        except Exception as exc:
            if self._terminal_status is not None:
                logger.warning("Worker '{name}' release failed after refusal.", name=self.name)
            else:
                logger.exception(
                    "Worker '{name}' writer close failed: {error}",
                    name=self.name,
                    error=exc,
                )
        logger.info(
            "Worker '{name}' finalized; terminal_auth={failed}.",
            name=self.name,
            failed=self._terminal_status is not None,
        )
