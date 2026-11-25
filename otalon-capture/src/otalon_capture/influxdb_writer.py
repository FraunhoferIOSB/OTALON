"""InfluxDB client wrapper tailored for Netcap++ output."""

from __future__ import annotations

import random
import threading
import time
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from typing import Any, List

from influxdb_client_3 import InfluxDBClient3
from influxdb_client_3 import InfluxDBClient3 as _Client3
from influxdb_client_3 import Point, WriteOptions, WritePrecision, WriteType, write_client_options
from loguru import logger

from .settings import InfluxConfig, WriteOptionsConfig
from .write_failure import TerminalWriteError, permanent_auth_status


class ClientReleaseError(RuntimeError):
    """Sanitized release failure; component evidence is held separately."""

    def __init__(self) -> None:
        super().__init__("InfluxDB client release failed.")


def _map_precision(precision: Any) -> WritePrecision:
    """Map configuration precision string to :class:`WritePrecision`."""

    try:
        precision_value = str(precision or "").strip().lower()
    except Exception:  # noqa: BLE001 - defensive conversion guard
        precision_value = "ms"
    if precision_value == "s":
        raise ValueError("write precision 's' cannot preserve native millisecond window timestamps; use ms, us or ns")
    mapping = {
        "ns": WritePrecision.NS,
        "us": WritePrecision.US,
        "µs": WritePrecision.US,
        "ms": WritePrecision.MS,
    }
    return mapping.get(precision_value, WritePrecision.MS)


def _success_callback(configuration: InfluxConfig, data: str) -> None:
    logger.success(
        "Successfully wrote batch data of size {batch_size} to measurement '{measurement}'.",
        batch_size=len(data),
        measurement=configuration.measurement_name,
    )


def _error_callback(configuration: InfluxConfig, data: str, exception: BaseException) -> None:
    status = permanent_auth_status(exception)
    if status is not None:
        logger.error("InfluxDB write refused: permanent_auth_refusal (HTTP {status}).", status=status)
        return
    logger.error(
        "Failed writing batch for measurement '{measurement}'. Data size {batch_size}. Error: {error}",
        measurement=configuration.measurement_name,
        batch_size=len(data),
        error=exception,
    )


def _retry_callback(configuration: InfluxConfig, data: str, exception: BaseException) -> None:
    status = permanent_auth_status(exception)
    if status is not None:
        logger.warning("InfluxDB write refused: permanent_auth_refusal (HTTP {status}).", status=status)
        return
    logger.warning(
        "Retrying batch for measurement '{measurement}'. Data size {batch_size}. Error: {error}",
        measurement=configuration.measurement_name,
        batch_size=len(data),
        error=exception,
    )


class InfluxDBWriter:
    """Buffered synchronous writer wrapping the InfluxDB Python client."""

    def __init__(
        self,
        influx_config: InfluxConfig,
        write_options: WriteOptionsConfig,
        window_interval_ms: int,
        verbose: bool = False,
    ) -> None:
        self._buffer: List[Point] = []
        self._lock = threading.Lock()
        self._terminal_status: int | None = None
        self._closed = False
        self._released = False
        self.release_failures: tuple[str, ...] = ()
        self.config = influx_config
        self.window_interval_ms = int(window_interval_ms)
        self.int_fields = {"packet_count", "total_volume", "min_packet_size", "max_packet_size", "collapsed_port_count"}
        self.verbose = verbose

        self.write_precision = _map_precision(write_options.precision)
        self.batch_size = max(1, int(write_options.batch_size))
        self.flush_interval = max(1, int(write_options.flush_interval))
        self.jitter_interval = max(0, int(write_options.jitter_interval))

        write_opts = WriteOptions(
            write_type=WriteType.synchronous,
            batch_size=self.batch_size,
            flush_interval=self.flush_interval,
            jitter_interval=self.jitter_interval,
            write_precision=self.write_precision,
        )

        self.client = InfluxDBClient3(
            host=str(self.config.host),
            token=self.config.token.get_secret_value(),
            database=self.config.database,
            write_client_options=write_client_options(
                success_callback=lambda key, data: _success_callback(self.config, data),
                error_callback=lambda key, data, exc: _error_callback(self.config, data, exc),
                retry_callback=lambda key, data, exc: _retry_callback(self.config, data, exc),
                write_options=write_opts,
            ),
            auth_scheme="Bearer",
        )

        self._next_flush_deadline_ms = self._compute_next_deadline()

    def write(self, value: Any) -> None:
        """Transform ``value`` into a point and enqueue it for writing."""

        with self._lock:
            self._raise_if_terminal()
            if self._closed:
                raise RuntimeError("InfluxDB writer is closed.")
            point = self._build_point(value)
            self._buffer.append(point)
            self._maybe_flush_locked()

    def flush(self, force: bool = False) -> None:
        """Flush buffered points, optionally forcing a write."""

        with self._lock:
            self._raise_if_terminal()
            if self._closed:
                return
            if force:
                self._flush_locked()
            else:
                self._maybe_flush_locked()

    def close(self) -> None:
        """Flush once, release once even on failure, and retain terminal truth."""

        with self._lock:
            if not self._closed:
                try:
                    if self._terminal_status is None:
                        self._flush_locked()
                finally:
                    self._closed = True
                    self._release_client_locked()
            self._raise_if_terminal()
            if self.release_failures:
                raise ClientReleaseError() from None

    def _raise_if_terminal(self) -> None:
        if self._terminal_status is not None:
            # Fresh signals avoid retaining transport exceptions or growing tracebacks in the latch.
            try:
                raise TerminalWriteError(self._terminal_status) from None
            except TerminalWriteError as failure:
                failure.__context__ = None
                raise

    def _release_client_locked(self) -> None:
        if self._released:
            return
        self._released = True
        if isinstance(self.client, _Client3):
            # Inspected synchronous Client3.close is sequential; do not lose later releases.
            resources = [
                ("write_api", getattr(self.client, "_write_api", None)),
                ("query_api", getattr(self.client, "_query_api", None)),
                ("http_client", getattr(self.client, "_client", None)),
            ]
        else:
            resources = [("client", self.client)]
        failures = []
        for name, resource in resources:
            if resource is None:
                continue
            try:
                resource.close()
            except BaseException:
                failures.append(name)
        self.release_failures = tuple(failures)

    def _build_point(self, value: Any) -> Point:
        point = Point(self.config.measurement_name)
        for tag in self.config.tags:
            tag_value = self._extract_attribute(value, tag)
            if hasattr(tag_value, "as_uri"):
                tag_value = tag_value.as_uri()
            point.tag(tag, tag_value)

        field_count = 0
        for field_name, method_name in self.config.fields.items():
            raw_value = self._extract_attribute(value, method_name)
            normalised = self._normalize_field_value(field_name, raw_value)
            if normalised is None:
                continue
            point.field(field_name, normalised)
            field_count += 1

        if field_count == 0:
            # A point with no fields is a silent no-op for InfluxDB, but the
            # caller still counts it as written. Refuse it loudly instead of
            # reporting a successful import that stored nothing (audit
            # QUA-10).
            raise ValueError(
                f"record produced no writable fields for measurement "
                f"'{self.config.measurement_name}'; expected any of "
                f"{sorted(self.config.fields)} on a {type(value).__name__}"
            )

        start_ms = self._extract_attribute(value, "get_time")
        try:
            start_int = int(start_ms)
        except Exception:  # noqa: BLE001 - defensive conversion guard
            start_int = int(datetime.now().timestamp() * 1000)
        timestamp = self._compute_point_timestamp(start_int)
        point.time(timestamp, self.write_precision)
        return point

    def _normalize_field_value(self, name: str, value: Any) -> Any:
        if value is None:
            return None
        try:
            if name in self.int_fields:
                return int(value)
            return float(value)
        except Exception:  # noqa: BLE001 - defensive conversion guard
            return None

    def _extract_attribute(self, value: Any, attribute_name: str) -> Any:
        """Read one attribute from a record object OR mapping.

        Records reach the writer in two shapes: aggregate objects with
        ``get_*`` accessors, and plain dicts from the PCAP import path.
        Only ``getattr`` was tried, so every dict record produced ``None``
        for every tag and field — a point with no fields at all, which
        InfluxDB accepts as a no-op while ``points_written`` still counted
        it as success (audit QUA-10).

        Mirrors the mapping handling in ``pipeline.py:97-101``: the
        accessor wins when present, then the mapping key, and then the
        key with any ``get_`` prefix stripped (``get_time`` → ``time``).
        Native producer aliases are tried only when both mapping keys are
        absent; explicit values, including ``None``, retain precedence.
        """
        attribute = getattr(value, attribute_name, None)
        if attribute is not None:
            return attribute() if callable(attribute) else attribute
        if isinstance(value, Mapping):
            if attribute_name in value:
                return value[attribute_name]
            bare_name = attribute_name[4:] if attribute_name.startswith("get_") else attribute_name
            if bare_name in value:
                return value[bare_name]
            aliases = {
                "get_total_packet_count": "packet_count",
                "get_sd_packet_size": "std_packet_size",
                "get_mean_packet_inter_arrival_time": "mean_interarrival_time",
                "get_min_packet_inter_arrival_time": "min_interarrival_time",
                "get_max_packet_inter_arrival_time": "max_interarrival_time",
                "get_sd_packet_inter_arrival_time": "std_interarrival_time",
            }
            alias = aliases.get(attribute_name)
            return value.get(alias) if alias is not None else None
        return None

    def _maybe_flush_locked(self) -> None:
        now_ms = self._now_ms()
        if len(self._buffer) >= self.batch_size or now_ms >= self._next_flush_deadline_ms:
            self._flush_locked()

    def _flush_locked(self) -> None:
        self._raise_if_terminal()
        if not self._buffer:
            self._next_flush_deadline_ms = self._compute_next_deadline()
            return

        points = self._buffer
        self._buffer = []
        try:
            self.client.write(points)
        except BaseException as exc:
            points.extend(self._buffer)
            self._buffer = points
            if not isinstance(exc, Exception):
                raise
            self._terminal_status = permanent_auth_status(exc)
            if self._terminal_status is None:
                logger.error(
                    "InfluxDB write failed ({error}). Retrying on next flush window with {count} buffered points.",
                    error=exc,
                    count=len(points),
                )
                self._next_flush_deadline_ms = self._now_ms() + self.flush_interval
                return

        if self._terminal_status is not None:
            logger.error(
                "InfluxDB write refused: permanent_auth_refusal (HTTP {status}).",
                status=self._terminal_status,
            )
            self._raise_if_terminal()

        logger.debug(
            "InfluxDB flush: wrote {count} point(s) to measurement '{measurement}'.",
            count=len(points),
            measurement=self.config.measurement_name,
        )
        if self.verbose:
            logger.debug("Flushed {count} points to InfluxDB.", count=len(points))
        self._next_flush_deadline_ms = self._compute_next_deadline()

    def _compute_point_timestamp(self, start_ms: int) -> datetime:
        """Label points by the real native window start, independently of line units."""
        if self.write_precision == WritePrecision.S:
            raise ValueError("second write precision cannot preserve native millisecond window timestamps")
        return datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(milliseconds=int(start_ms))

    def _compute_next_deadline(self) -> int:
        jitter = 0
        if self.jitter_interval > 0:
            jitter = random.randint(-self.jitter_interval, self.jitter_interval)
        return self._now_ms() + max(1, self.flush_interval + jitter)

    def _now_ms(self) -> int:
        return int(time.monotonic() * 1000)
