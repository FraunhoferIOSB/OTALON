"""Anomaly persistence layer with gap-based interval splitting and upsert.

Splits continuous anomaly sequences into discrete intervals based on time
gaps, generates deterministic anomaly IDs, and upserts records into
PostgreSQL via SQLAlchemy ``session.merge()``. The persisted schema
matches the OpenSpec ``cyberclas--anomaly-persistence`` DDL.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

import polars as pl
from otalon_common.types import is_ml_type
from loguru import logger

from otalon_clas.common.postgres_connector import AnomalyRecord, PostgresConnector
from otalon_clas.detection.frequency_monitor import ABSENCE_ANOMALY, FrequencyResult
from otalon_clas.detection.suppression import SuppressionService

DEFAULT_GAP_TOLERANCE_SECONDS: int = 30
DEFAULT_ML_CONFIDENCE_PERSIST_THRESHOLD: float = 0.60


@dataclass
class _AnomalyInterval:
    """Represents a single anomaly interval for persistence.

    ``open_ended`` marks an interval whose end is still moving: the
    episode is known to have started at ``start_ts`` but has not
    finished yet, and every subsequent detection tick merely extends
    ``end_ts``. Such an interval is identified by its start alone (see
    :func:`_generate_anomaly_id`), so repeated ticks update one row
    instead of inserting a new one per poll.
    """

    module: str
    series_id: str
    anomaly_type: str
    start_ts: datetime
    end_ts: datetime
    rows: list[dict[str, Any]] = field(default_factory=list)
    open_ended: bool = False


class AnomalyPersister:
    """Persists detected anomaly intervals to PostgreSQL.

    Splits anomaly DataFrames into gap-based intervals, computes per-interval
    summaries, and upserts records using deterministic IDs.

    Args:
        connector: PostgreSQL connector providing session management.
        gap_tolerance_seconds: Maximum gap between rows to be grouped
            into the same interval.
    """

    def __init__(
        self,
        connector: PostgresConnector,
        gap_tolerance_seconds: int = DEFAULT_GAP_TOLERANCE_SECONDS,
        suppression_service: SuppressionService | None = None,
        ml_confidence_persist_threshold: float = DEFAULT_ML_CONFIDENCE_PERSIST_THRESHOLD,
        drop_low_signal_anomalies: bool = True,
    ) -> None:
        """Initialize the anomaly persister.

        Args:
            connector: PostgreSQL connector.
            gap_tolerance_seconds: Gap tolerance for interval splitting.
            suppression_service: Optional service that resolves
                per-``(series_id, anomaly_type)`` suppression rules.
                When ``None``, no suppression is applied (legacy behaviour).
            ml_confidence_persist_threshold: Minimum ML confidence below
                which a pure-false-positive row (severity 0, vfc 0) is
                dropped before persistence.
            drop_low_signal_anomalies: Master switch for the low-signal
                drop. ``False`` reverts to verbose persistence.
        """
        self._connector = connector
        self._gap_tolerance_seconds = gap_tolerance_seconds
        self._suppression_service = suppression_service
        self._ml_confidence_persist_threshold = float(ml_confidence_persist_threshold)
        self._drop_low_signal_anomalies = bool(drop_low_signal_anomalies)

    def persist(
        self,
        anomalies: pl.DataFrame,
        module: str,
        tag_key: str,
    ) -> int:
        """Persist anomalies from a DataFrame to PostgreSQL.

        Filters for anomalous rows, applies the suppression / low-signal
        drop gate (when configured), splits into intervals per series,
        and upserts each interval as an AnomalyRecord.

        Args:
            anomalies: Detection result DataFrame with anomaly columns.
            module: Name of the detection module.
            tag_key: Column identifying each series.

        Returns:
            Number of anomaly records upserted.
        """
        anomalous = _filter_anomalous(anomalies)
        if anomalous.is_empty():
            return 0

        anomalous = self._apply_suppression_and_lowsignal_gate(anomalous, tag_key)
        if anomalous.is_empty():
            return 0

        intervals = self._split_into_intervals(anomalous, module, tag_key)
        return self._upsert_intervals(intervals)

    def persist_absence(
        self,
        results: list[FrequencyResult],
        module: str,
        observed_at: datetime,
    ) -> int:
        """Persist AbsenceAnomaly results as their own anomaly rows.

        Absence is *missing* evidence: the series produced no row in the
        current detection window, so it cannot travel through the
        bounds-shaped fusion DataFrame (``fusion._attach_frequency_flags``
        left-joins onto ``bounds_df`` and an absent series has no row
        there). This method is the dedicated write path for that case.

        The interval is anchored at the deadline the absence started at
        (``FrequencyResult.absence_since``), not at the tick that noticed
        it, and is marked ``open_ended``. Its deterministic id therefore
        stays constant while the silence lasts, so a series that is
        absent for an hour occupies exactly one row whose ``end_ts``
        advances — no row per 5 s poll.

        Rows carry no feature values and no bound severities because
        none exist; ``violated_features`` stays empty.

        Args:
            results: Frequency check results for one module. Non-absence
                and non-anomalous entries are ignored.
            module: Detection module name.
            observed_at: Timestamp of the current detection tick, used
                as the interval's moving end.

        Returns:
            Number of absence records upserted.
        """
        intervals = self._build_absence_intervals(results, module, observed_at)
        if not intervals:
            return 0
        return self._upsert_intervals(intervals)

    def _build_absence_intervals(
        self,
        results: list[FrequencyResult],
        module: str,
        observed_at: datetime,
    ) -> list[_AnomalyInterval]:
        """Turn absence results into open-ended intervals, honouring suppression.

        The low-signal gate is deliberately not applied: it only targets
        ML-labelled rows with zero severity and zero violated features,
        and an absence row is neither ML-derived nor expected to carry
        feature evidence. Operator suppressions ARE honoured, using the
        same ``(series_id, anomaly_type)`` contract as the bounds path.
        """
        intervals: list[_AnomalyInterval] = []
        for result in results:
            if not result.is_anomaly or result.anomaly_type != ABSENCE_ANOMALY:
                continue
            if result.absence_since is None:
                logger.warning(
                    "absence_result_without_deadline series_id={sid!r}",
                    sid=result.series_id,
                )
                continue
            if self._is_suppressed(result.series_id, result.anomaly_type):
                continue
            start_ts = _as_utc(result.absence_since)
            end_ts = max(_as_utc(observed_at), start_ts)
            intervals.append(
                _AnomalyInterval(
                    module=module,
                    series_id=result.series_id,
                    anomaly_type=result.anomaly_type,
                    start_ts=start_ts,
                    end_ts=end_ts,
                    rows=[
                        {
                            "confidence": result.confidence,
                            "last_seen": result.last_seen,
                        }
                    ],
                    open_ended=True,
                )
            )
        return intervals

    def _is_suppressed(self, series_id: str, anomaly_type: str) -> bool:
        """Return True when an operator suppression covers this pair."""
        if self._suppression_service is None or not series_id or not anomaly_type:
            return False
        entry = self._suppression_service.is_suppressed(series_id, anomaly_type)
        if entry is None:
            return False
        logger.info(
            "anomaly_suppressed series_id={sid!r} anomaly_type={atype!r} " "suppression_id={suid} reason={reason!r}",
            sid=series_id,
            atype=anomaly_type,
            suid=entry.suppression_id,
            reason=entry.reason,
        )
        return True

    def _apply_suppression_and_lowsignal_gate(
        self,
        anomalous: pl.DataFrame,
        tag_key: str,
    ) -> pl.DataFrame:
        """Drop rows matched by an active suppression or by the low-signal gate.

        For each anomalous row:

        * If a suppression exists for ``(series_id, anomaly_type)``, the
          row is dropped and an INFO-level structured log
          ``anomaly_suppressed`` is emitted.
        * Else, when ``drop_low_signal_anomalies`` is enabled and the
          row has ``bound_severity_max == 0``,
          ``violated_feature_count == 0`` and an ML-derived
          ``anomaly_type`` whose ``confidence`` is below the configured
          threshold, the row is dropped and a DEBUG-level
          ``anomaly_dropped_low_signal`` log is emitted.

        Returns the filtered DataFrame.
        """
        if anomalous.is_empty():
            return anomalous

        keep_mask: list[bool] = []
        for row in anomalous.iter_rows(named=True):
            series_id = str(row.get(tag_key, ""))
            anomaly_type = str(row.get("anomaly_type", ""))

            if self._suppression_service is not None and series_id and anomaly_type:
                entry = self._suppression_service.is_suppressed(series_id, anomaly_type)
                if entry is not None:
                    logger.info(
                        "anomaly_suppressed series_id={sid!r} "
                        "anomaly_type={atype!r} suppression_id={suid} "
                        "reason={reason!r}",
                        sid=series_id,
                        atype=anomaly_type,
                        suid=entry.suppression_id,
                        reason=entry.reason,
                    )
                    keep_mask.append(False)
                    continue

            if self._drop_low_signal_anomalies and _is_low_signal_row(row, self._ml_confidence_persist_threshold):
                logger.debug(
                    "anomaly_dropped_low_signal series_id={sid!r} " "anomaly_type={atype!r} confidence={conf}",
                    sid=series_id,
                    atype=anomaly_type,
                    conf=row.get("confidence"),
                )
                keep_mask.append(False)
                continue

            keep_mask.append(True)

        if all(keep_mask):
            return anomalous
        if not any(keep_mask):
            return anomalous.clear()
        return anomalous.filter(pl.Series("__keep", keep_mask))

    def _split_into_intervals(
        self,
        df: pl.DataFrame,
        module: str,
        tag_key: str,
    ) -> list[_AnomalyInterval]:
        """Split anomalous rows into gap-based intervals per series.

        Args:
            df: Anomalous rows sorted by time.
            module: Detection module name.
            tag_key: Series identifier column.

        Returns:
            List of discrete anomaly intervals.
        """
        sorted_df = df.sort("time")
        intervals: list[_AnomalyInterval] = []

        for (series_id,), group_df in sorted_df.group_by(tag_key):
            series_intervals = self._split_series(group_df, module, str(series_id))
            intervals.extend(series_intervals)

        return intervals

    def _split_series(
        self,
        group_df: pl.DataFrame,
        module: str,
        series_id: str,
    ) -> list[_AnomalyInterval]:
        """Split a single series into intervals based on time gaps.

        Args:
            group_df: Rows for one series, sorted by time.
            module: Detection module name.
            series_id: Series identifier.

        Returns:
            List of intervals for this series.
        """
        rows = group_df.sort("time").to_dicts()
        if not rows:
            return []

        gap = timedelta(seconds=self._gap_tolerance_seconds)
        intervals: list[_AnomalyInterval] = []
        current: _AnomalyInterval | None = None

        for row in rows:
            row_time = _parse_row_time(row)
            if row_time is None:
                continue
            anomaly_type = str(row.get("anomaly_type", ""))

            if current is None or self._should_split(current, row_time, anomaly_type, gap):
                if current is not None:
                    intervals.append(current)
                current = _AnomalyInterval(
                    module=module,
                    series_id=series_id,
                    anomaly_type=anomaly_type,
                    start_ts=row_time,
                    end_ts=row_time,
                    rows=[row],
                )
            else:
                current.end_ts = row_time
                current.rows.append(row)

        if current is not None:
            intervals.append(current)

        return intervals

    def _should_split(
        self,
        current: _AnomalyInterval,
        row_time: datetime,
        anomaly_type: str,
        gap: timedelta,
    ) -> bool:
        """Determine whether to start a new interval.

        Args:
            current: Currently open interval.
            row_time: Timestamp of the new row.
            anomaly_type: Anomaly type of the new row.
            gap: Maximum allowed gap.

        Returns:
            True if a new interval should be started.
        """
        if anomaly_type != current.anomaly_type:
            return True
        return (row_time - current.end_ts) > gap

    def _upsert_intervals(self, intervals: list[_AnomalyInterval]) -> int:
        """Upsert anomaly intervals into PostgreSQL.

        Args:
            intervals: Anomaly intervals to persist.

        Returns:
            Number of records upserted.
        """
        if not intervals:
            return 0

        count = 0
        with self._connector.session() as session:
            for interval in intervals:
                record = _build_record(interval)
                # Preserve existing grouping links: a re-emitted live
                # anomaly with the same id must not have its
                # ``alarm_id`` and ``is_grouped`` reset to defaults,
                # otherwise the next grouping cycle would treat it as
                # ungrouped again and re-increment the alarm's
                # ``anomaly_type_stats`` counters on every tick.
                existing = session.get(AnomalyRecord, record.id)
                if existing is not None:
                    record.alarm_id = existing.alarm_id
                    record.is_grouped = existing.is_grouped
                    record.confirmed = existing.confirmed
                session.merge(record)
                count += 1

        logger.info("Upserted {} anomaly records to PostgreSQL", count)
        return count


def _filter_anomalous(df: pl.DataFrame) -> pl.DataFrame:
    """Filter DataFrame to only anomalous rows.

    Args:
        df: Full detection result DataFrame.

    Returns:
        Filtered DataFrame with only anomalous rows.
    """
    if "is_anomaly" not in df.columns:
        return pl.DataFrame()
    return df.filter(pl.col("is_anomaly") == True)  # noqa: E712


def _is_low_signal_row(row: dict[str, Any], ml_confidence_threshold: float) -> bool:
    """Return True when the row is a pure ML-only false positive.

    A row is considered low-signal when ALL of:

    * ``bound_severity_max`` is 0 (or missing);
    * ``violated_feature_count`` is 0 (or missing);
    * ``anomaly_type`` is an ML-derived label (not a bounds / frequency
      type);
    * ``confidence`` is below ``ml_confidence_threshold``.

    These rows are produced when fusion adopts an ML label for a
    non-bound-violating bucket (e.g. ``arp_scan`` on legitimate ARP
    discovery traffic with a deterministic IsolationForest score around
    0.57). They are not actionable by bounds tuning and merely add
    persistent noise.
    """
    anomaly_type = str(row.get("anomaly_type", ""))
    if not is_ml_type(anomaly_type):
        return False
    severity = row.get("severity", row.get("bound_severity_max"))
    try:
        severity_val = float(severity) if severity is not None else 0.0
    except (TypeError, ValueError):
        severity_val = 0.0
    if severity_val > 0.0:
        return False
    vfc_raw = row.get("violated_features", "")
    if isinstance(vfc_raw, list):
        if len(vfc_raw) > 0:
            return False
    elif isinstance(vfc_raw, str):
        stripped = vfc_raw.strip()
        if stripped and stripped != "[]":
            return False
    try:
        confidence = float(row.get("confidence", 0.0) or 0.0)
    except (TypeError, ValueError):
        confidence = 0.0
    return confidence < float(ml_confidence_threshold)


def _build_record(interval: _AnomalyInterval) -> AnomalyRecord:
    """Build an AnomalyRecord ORM object from an interval.

    Uses a deterministic ID:
    ``{module}|{series_id}|{start_ts}|{end_ts}|{anomaly_type}``.

    Args:
        interval: Anomaly interval data.

    Returns:
        Populated AnomalyRecord ready for upsert.
    """
    if interval.anomaly_type == ABSENCE_ANOMALY:
        return _build_absence_record(interval)

    anomaly_id = _generate_anomaly_id(interval)
    confidence = _compute_interval_confidence(interval.rows)
    severity_max, severity_mean = _compute_interval_severity(interval.rows)
    violated_features = _collect_violated_features(interval.rows)

    return AnomalyRecord(
        id=anomaly_id,
        module=interval.module,
        series_id=interval.series_id,
        anomaly_type=interval.anomaly_type,
        start_ts=interval.start_ts,
        end_ts=interval.end_ts,
        is_anomaly=True,
        confidence=confidence,
        confirmed=False,
        is_grouped=False,
        bound_severity_max=severity_max,
        bound_severity_mean=severity_mean,
        violated_feature_count=len(violated_features),
        violated_features=violated_features,
        violated_feature_details=_build_violated_details(interval.rows),
        feature_summary=_build_feature_summary(interval.rows),
        rate_summary=_build_rate_summary(interval),
        ml_details=_build_ml_details(interval.rows),
    )


def _generate_anomaly_id(interval: _AnomalyInterval) -> str:
    """Generate a deterministic anomaly ID from interval attributes.

    Format: ``{module}|{series_id}|{start_iso}|{end_iso}``, or
    ``{module}|{series_id}|{start_iso}|{anomaly_type}`` for an
    ``open_ended`` interval.

    The ``anomaly_type`` is intentionally not part of the closed-interval
    key. Otherwise the same ``(series, bucket)`` produces multiple rows
    whenever the fused type label switches between consecutive live
    ticks (e.g. a bounds violation getting re-classified as
    ``T0846/arp_scan`` and later ``T0888/port_scan``). Treating those as
    one record means the most recent fusion outcome simply overwrites
    the previous type via ``session.merge()``.

    An open-ended interval inverts that trade-off: its ``end_ts`` moves
    on every tick, so including the end would mint a new id per poll.
    It is keyed by its start instead — which for absence is the frozen
    deadline instant — and carries the type to keep it distinct from any
    value anomaly that starts at the same second.

    Args:
        interval: Anomaly interval.

    Returns:
        Deterministic ID string.
    """
    start_iso = interval.start_ts.isoformat()
    if interval.open_ended:
        return f"{interval.module}|{interval.series_id}|{start_iso}|{interval.anomaly_type}"
    end_iso = interval.end_ts.isoformat()
    return f"{interval.module}|{interval.series_id}|{start_iso}|{end_iso}"


def _as_utc(value: datetime) -> datetime:
    """Return a timezone-aware UTC datetime for a naive or aware input."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _build_absence_record(interval: _AnomalyInterval) -> AnomalyRecord:
    """Build the AnomalyRecord for an absence interval.

    Absence carries no observed data for the interval, so every
    feature-derived column stays honestly empty:

    * ``violated_features`` is ``[]`` and ``violated_feature_count`` 0 —
      no feature was measured, let alone violated.
    * ``bound_severity_max`` / ``bound_severity_mean`` are ``None``
      rather than ``0.0``, distinguishing "no bounds evidence exists"
      from "bounds were checked and found compliant".
    * ``feature_summary`` and ``ml_details`` are empty; no ML ran.
    * ``rate_summary`` records the silence itself:
      ``silence_seconds`` and the ``last_seen`` instant the deadline was
      derived from.
    """
    rows = interval.rows
    confidence = _compute_interval_confidence(rows)
    last_seen = rows[0].get("last_seen") if rows else None
    rate_summary: dict[str, Any] = {
        "silence_seconds": (interval.end_ts - interval.start_ts).total_seconds(),
        "absence_since": interval.start_ts.isoformat(),
    }
    if isinstance(last_seen, datetime):
        rate_summary["last_seen"] = _as_utc(last_seen).isoformat()

    return AnomalyRecord(
        id=_generate_anomaly_id(interval),
        module=interval.module,
        series_id=interval.series_id,
        anomaly_type=interval.anomaly_type,
        start_ts=interval.start_ts,
        end_ts=interval.end_ts,
        is_anomaly=True,
        confidence=confidence,
        confirmed=False,
        is_grouped=False,
        bound_severity_max=None,
        bound_severity_mean=None,
        violated_feature_count=0,
        violated_features=[],
        violated_feature_details={},
        feature_summary={},
        rate_summary=rate_summary,
        ml_details={},
    )


def _compute_interval_confidence(rows: list[dict[str, Any]]) -> float:
    """Compute mean confidence across interval rows.

    Args:
        rows: Row dicts from the interval.

    Returns:
        Mean confidence value.
    """
    if not rows:
        return 0.0
    total = sum(float(r.get("confidence", 0.0)) for r in rows)
    return total / len(rows)


def _compute_interval_severity(rows: list[dict[str, Any]]) -> tuple[float, float]:
    """Compute max and mean severity across interval rows.

    Args:
        rows: Row dicts from the interval.

    Returns:
        Tuple of (max_severity, mean_severity).
    """
    if not rows:
        return 0.0, 0.0
    severities = [float(r.get("severity", 0.0)) for r in rows]
    return max(severities), sum(severities) / len(severities)


def _collect_violated_features(rows: list[dict[str, Any]]) -> list[str]:
    """Collect the union of violated feature names across rows.

    Args:
        rows: Row dicts from the interval.

    Returns:
        Sorted list of unique violated feature names.
    """
    features: set[str] = set()
    for row in rows:
        vf = row.get("violated_features", "")
        if not vf or vf == "[]":
            continue
        if isinstance(vf, list):
            for item in vf:
                if item:
                    features.add(str(item))
        else:
            for part in str(vf).split(","):
                stripped = part.strip()
                if stripped:
                    features.add(stripped)
    return sorted(features)


def _build_feature_summary(rows: list[dict[str, Any]]) -> dict[str, dict[str, float]]:
    """Build a summary of feature statistics across interval rows.

    Args:
        rows: Row dicts from the interval.

    Returns:
        Dict mapping feature name to a stats dict with count, sum, mean,
        min, max, and std.
    """
    feature_values: dict[str, list[float]] = {}
    skip = {
        "time",
        "is_anomaly",
        "anomaly_type",
        "confidence",
        "severity",
        "violated_features",
        "ml_type",
        "ml_confidence",
        "ensemble_type",
        "ensemble_confidence",
    }
    for row in rows:
        for key, val in row.items():
            if key in skip:
                continue
            if isinstance(val, bool):
                continue
            if isinstance(val, (int, float)):
                feature_values.setdefault(key, []).append(float(val))

    summary: dict[str, dict[str, float]] = {}
    for feat, values in feature_values.items():
        if not values:
            continue
        std_val = statistics.pstdev(values) if len(values) > 1 else 0.0
        summary[feat] = {
            "count": len(values),
            "sum": sum(values),
            "mean": sum(values) / len(values),
            "min": min(values),
            "max": max(values),
            "std": std_val,
        }

    return summary


def _build_rate_summary(interval: _AnomalyInterval) -> dict[str, float]:
    """Build a summary of rate statistics for the interval.

    For ``conn`` modules, packet/byte rate fields are added when the
    underlying rows expose ``packet_count`` and ``byte_count``.

    Args:
        interval: Anomaly interval.

    Returns:
        Dict with rate summary fields.
    """
    duration = (interval.end_ts - interval.start_ts).total_seconds()
    duration_safe = max(duration, 1.0)
    summary: dict[str, float] = {
        "duration_seconds": duration,
        "row_count": len(interval.rows),
        "rate_per_second": len(interval.rows) / duration_safe,
    }

    if interval.module == "conn":
        packet_total = 0.0
        byte_total = 0.0
        for row in interval.rows:
            packet_total += float(row.get("packet_count", 0) or 0)
            # InfluxDB exposes the cumulative bytes as ``total_volume``
            # rather than ``byte_count``. Fall back to the latter for
            # backward compatibility with older fixtures.
            byte_total += float(row.get("total_volume", row.get("byte_count", 0)) or 0)
        summary["packet_rate_pps"] = packet_total / duration_safe
        summary["byte_rate_Bps"] = byte_total / duration_safe

    return summary


def _build_violated_details(rows: list[dict[str, Any]]) -> dict[str, int]:
    """Build a summary of violated feature occurrence counts.

    Args:
        rows: Row dicts from the interval.

    Returns:
        Dict mapping feature names to violation counts.
    """
    counts: dict[str, int] = {}
    for row in rows:
        vf = row.get("violated_features", "")
        if not vf or vf == "[]":
            continue
        if isinstance(vf, list):
            iterable = (str(x) for x in vf if x)
        else:
            iterable = (p.strip() for p in str(vf).split(",") if p.strip())
        for part in iterable:
            counts[part] = counts.get(part, 0) + 1
    return counts


def _build_ml_details(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a summary of ML classification details.

    Args:
        rows: Row dicts from the interval.

    Returns:
        Dict with ML type counts and confidence statistics.
    """
    ml_types: dict[str, int] = {}
    ml_confidences: list[float] = []

    for row in rows:
        ml_type = row.get("ml_type") or row.get("ensemble_type")
        if ml_type:
            ml_types[str(ml_type)] = ml_types.get(str(ml_type), 0) + 1
        ml_conf = row.get("ml_confidence") or row.get("ensemble_confidence")
        if ml_conf is not None:
            try:
                ml_confidences.append(float(ml_conf))
            except (TypeError, ValueError):
                continue

    if not ml_types and not ml_confidences:
        return {}

    label = max(ml_types, key=ml_types.get) if ml_types else None
    details: dict[str, Any] = {"type_counts": ml_types}
    if label is not None:
        details["label"] = label
    if ml_confidences:
        details["confidence_mean"] = sum(ml_confidences) / len(ml_confidences)
        details["confidence_min"] = min(ml_confidences)
        details["confidence_max"] = max(ml_confidences)
        details["confidence_count"] = len(ml_confidences)

    return details


def _parse_row_time(row: dict[str, Any]) -> datetime | None:
    """Parse the ``time`` field from a row dict to a UTC datetime.

    Args:
        row: Row data dictionary.

    Returns:
        Parsed datetime or None if parsing fails.
    """
    raw = row.get("time")
    if raw is None:
        return None
    if isinstance(raw, datetime):
        return raw.replace(tzinfo=timezone.utc) if raw.tzinfo is None else raw
    try:
        return datetime.fromisoformat(str(raw)).replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        logger.warning("Failed to parse timestamp: {}", raw)
        return None
