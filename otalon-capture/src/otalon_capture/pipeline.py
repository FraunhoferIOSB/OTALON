"""Reusable capture pipeline shared by the live adapter and the import worker.

The pipeline owns the whole path from a Netcap++ capture source to InfluxDB:
sparse-port aggregation, the optional MAC/protocol aggregation workers, and the
buffered :class:`~otalon_capture.influxdb_writer.InfluxDBWriter`. Both the live
adapter (``main.py``) and the PCAP import worker drive the *same* object, so an
imported capture is aggregated and written by exactly the code that handles live
traffic.
"""

from __future__ import annotations

import queue
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterator, List, Optional, Protocol, Union

from loguru import logger

from .aggregation import SparsePortAggregator
from .influxdb_writer import InfluxDBWriter
from .mac_aggregation import MacAggregator
from .netcap import Netcap
from .proto_aggregation import ProtoAggregator
from .settings import InfluxConfig, Settings
from .worker import AggregationWorker

QUEUE_MAX_SIZE = 10000

DEFAULT_PROGRESS_INTERVAL = 5000


class CaptureLike(Protocol):
    """Structural type of a Netcap++ capture source driven by the pipeline."""

    def capture_loop(self) -> Iterator[Any]:
        """Yield capture records until the source is exhausted or stopped."""
        ...

    def stop(self) -> None:
        """Signal the capture source to stop yielding records."""
        ...


@dataclass
class PipelineResult:
    """Outcome of a single pipeline run.

    Attributes:
        records_processed: Number of raw capture records consumed.
        points_written: Number of values handed to the InfluxDB writer.
        first_record_ms: Epoch milliseconds of the earliest written value.
        last_record_ms: Epoch milliseconds of the latest written value.
    """

    records_processed: int = 0
    points_written: int = 0
    first_record_ms: Optional[int] = None
    last_record_ms: Optional[int] = None


def create_writer(config: Optional[InfluxConfig], settings: Settings) -> Optional[InfluxDBWriter]:
    """Build an :class:`InfluxDBWriter` for ``config`` using shared write options.

    Args:
        config: Target measurement configuration, or ``None`` when disabled.
        settings: Adapter settings supplying write options and capture interval.

    Returns:
        A configured writer, or ``None`` when ``config`` is ``None``.
    """

    if config is None:
        return None
    return InfluxDBWriter(
        config,
        settings.write_options,
        settings.capture.interval,
        settings.log.verbose,
    )


def _protocol_map(settings: Settings) -> Dict[Union[int, str], str]:
    """Widen the configured protocol map to the key type the aggregators accept."""

    return {key: name for key, name in settings.protocol_map.items()}


def _record_timestamp_ms(value: Any) -> Optional[int]:
    """Return the record's own epoch milliseconds, or ``None`` when unavailable.

    The timestamp is read from the record itself; the wall clock is never used
    here, so an imported capture keeps the times contained in the file.
    """

    raw: Any = None
    attribute = getattr(value, "get_time", None)
    if attribute is not None:
        raw = attribute() if callable(attribute) else attribute
    elif isinstance(value, Mapping):
        raw = value.get("time")
    if raw is None:
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


class CapturePipeline:
    """Drive a Netcap++ capture through aggregation into InfluxDB."""

    def __init__(
        self,
        settings: Settings,
        capture: Optional[CaptureLike] = None,
        progress: Optional[Callable[[PipelineResult], None]] = None,
        progress_interval: int = DEFAULT_PROGRESS_INTERVAL,
    ) -> None:
        """Wire capture source, aggregators, workers and writers.

        Args:
            settings: Fully resolved adapter settings.
            capture: Capture source to consume. Defaults to a :class:`Netcap`
                built from ``settings.capture``.
            progress: Optional callback invoked every ``progress_interval``
                records with the running :class:`PipelineResult`.
            progress_interval: Record count between ``progress`` invocations.
        """

        self._settings = settings
        self._capture: CaptureLike = capture if capture is not None else Netcap(settings.capture)
        self._progress = progress
        self._progress_interval = max(1, int(progress_interval))
        self._running = True
        self._result = PipelineResult()

        self._writer = create_writer(settings.influx, settings)
        self._aggregator = SparsePortAggregator(
            enabled=settings.preprocess.aggregate_sparse_ports,
            emit_interval_ms=settings.preprocess.emit_interval_ms,
        )
        self._workers: List[AggregationWorker] = []
        self._mac_queue: Optional["queue.Queue[Any]"] = None
        self._proto_queue: Optional["queue.Queue[Any]"] = None

    @property
    def result(self) -> PipelineResult:
        """Return the running (or final) result of this pipeline."""

        return self._result

    def run(self) -> PipelineResult:
        """Consume the capture source until exhaustion or :meth:`stop`.

        Returns:
            The :class:`PipelineResult` describing the completed run.

        Raises:
            Exception: Any error raised by the capture source or write path is
                propagated after the pipeline has been cleaned up, so a caller
                (for example the import worker) can record it as a failure.
        """

        self._start_aggregation_workers()
        try:
            for value in self._capture.capture_loop():
                if not self._running:
                    break
                self._handle_record(value)
        finally:
            self._shutdown()
        return self._result

    def stop(self) -> None:
        """Signal the pipeline and its capture source to stop."""

        self._running = False
        try:
            self._capture.stop()
        except Exception as error:  # noqa: BLE001 - stopping must never raise
            logger.warning("Capture stop failed: {error}", error=error)

    def _handle_record(self, value: Any) -> None:
        """Fan a raw record out to the workers and into the write path."""

        self._enqueue_record(value)
        self._result.records_processed += 1
        if self._settings.preprocess.aggregate_sparse_ports:
            for aggregated_value in self._aggregator.add(value):
                self._write(aggregated_value)
        else:
            self._write(value)
        if self._progress is not None and self._result.records_processed % self._progress_interval == 0:
            self._progress(self._result)

    def _write(self, value: Any) -> None:
        """Write one value and track counters plus the covered time range."""

        if self._writer is not None:
            self._writer.write(value)
        self._result.points_written += 1
        timestamp_ms = _record_timestamp_ms(value)
        if timestamp_ms is None:
            return
        if self._result.first_record_ms is None or timestamp_ms < self._result.first_record_ms:
            self._result.first_record_ms = timestamp_ms
        if self._result.last_record_ms is None or timestamp_ms > self._result.last_record_ms:
            self._result.last_record_ms = timestamp_ms

    def _enqueue_record(self, record: Any) -> None:
        """Fan-out a raw record to MAC/Proto queues without blocking.

        A full queue drops the record with a warning so backpressure from the
        secondary pipelines can never stall the main capture loop.
        """

        if self._mac_queue is not None:
            try:
                self._mac_queue.put_nowait(record)
            except queue.Full:
                logger.warning("MAC aggregation queue full — dropping record.")
        if self._proto_queue is not None:
            try:
                self._proto_queue.put_nowait(record)
            except queue.Full:
                logger.warning("Proto aggregation queue full — dropping record.")

    def _start_aggregation_workers(self) -> None:
        """Start the MAC and protocol aggregation workers when enabled."""

        self._start_mac_worker()
        self._start_proto_worker()

    def _start_mac_worker(self) -> None:
        """Start the MAC aggregation worker when it is enabled and configured."""

        settings = self._settings
        if not settings.mac_aggregation.enabled:
            return
        writer = create_writer(settings.mac_influx, settings)
        if writer is None:
            logger.warning("MAC aggregation enabled but mac_influx config is missing.")
            return
        aggregator = MacAggregator(
            enabled=True,
            emit_interval_ms=settings.mac_aggregation.emit_interval_ms,
            protocol_map=_protocol_map(settings),
        )
        self._mac_queue = self._spawn_worker("mac-aggregation", aggregator, writer)

    def _start_proto_worker(self) -> None:
        """Start the protocol aggregation worker when enabled and configured."""

        settings = self._settings
        if not settings.proto_aggregation.enabled:
            return
        writer = create_writer(settings.proto_influx, settings)
        if writer is None:
            logger.warning("Proto aggregation enabled but proto_influx config is missing.")
            return
        aggregator = ProtoAggregator(
            enabled=True,
            emit_interval_ms=settings.proto_aggregation.emit_interval_ms,
            protocol_map=_protocol_map(settings),
        )
        self._proto_queue = self._spawn_worker("proto-aggregation", aggregator, writer)

    def _spawn_worker(self, name: str, aggregator: Any, writer: Any) -> "queue.Queue[Any]":
        """Create, start and register one aggregation worker thread."""

        work_queue: "queue.Queue[Any]" = queue.Queue(maxsize=QUEUE_MAX_SIZE)
        worker = AggregationWorker(
            name=name,
            input_queue=work_queue,
            aggregator=aggregator,
            writer=writer,
        )
        worker.start()
        self._workers.append(worker)
        logger.info("Aggregation worker '{name}' started.", name=name)
        return work_queue

    def _shutdown(self) -> None:
        """Flush the aggregator, close the writer and stop all workers."""

        try:
            if self._settings.preprocess.aggregate_sparse_ports:
                for aggregated_value in self._aggregator.flush(force=True):
                    self._write(aggregated_value)
        except Exception as error:  # noqa: BLE001 - cleanup must not mask the cause
            logger.exception("Flush aggregation failed: {error}", error=error)
        if self._writer is not None:
            try:
                self._writer.close()
            except Exception as error:  # noqa: BLE001 - cleanup must not mask the cause
                logger.exception("Closing InfluxDB writer failed: {error}", error=error)
        self._stop_aggregation_workers()

    def _stop_aggregation_workers(self) -> None:
        """Stop worker threads gracefully and wait for their final flush."""

        for worker in self._workers:
            try:
                worker.stop()
            except Exception as error:  # noqa: BLE001 - keep stopping the rest
                logger.exception(
                    "Error stopping worker '{name}': {error}",
                    name=worker.name,
                    error=error,
                )
        for worker in self._workers:
            worker.join(timeout=10.0)
            if worker.is_alive():
                logger.warning(
                    "Worker '{name}' did not terminate within timeout.",
                    name=worker.name,
                )
        self._workers = []
