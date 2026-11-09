"""Multi-module alarm grouping with greedy forward merge.

Aggregates anomaly records from multiple detection modules into alarm
groups based on temporal overlap and configurable gap tolerance. The
persisted schema matches the OpenSpec ``cyberclas--anomaly-persistence``
``alarms`` table DDL.
"""

from __future__ import annotations

import math
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from loguru import logger

from otalon_clas.common.postgres_connector import Alarm, AnomalyRecord, PostgresConnector

DEFAULT_GAP_TOLERANCE_SECONDS: int = 30
DEFAULT_MAX_ALARM_DURATION_SECONDS: int = 3600
MULTI_MODULE_SENTINEL: str = "multi"


@dataclass
class _MergeCandidate:
    """Intermediate representation of a mergeable anomaly for grouping."""

    anomaly_id: str
    module: str
    series_id: str
    anomaly_type: str
    start_ts: datetime
    end_ts: datetime
    confidence: float
    severity: float
    bucket_seconds: int = 0


@dataclass
class _AlarmGroupState:
    """Mutable state for an in-progress alarm group."""

    start_ts: datetime
    end_ts: datetime
    primary_type: str
    modules: set[str] = field(default_factory=set)
    series_ids: set[str] = field(default_factory=set)
    anomaly_ids: list[str] = field(default_factory=list)
    type_stats: dict[str, dict[str, Any]] = field(default_factory=dict)
    max_severity: float = 0.0
    confidences: list[float] = field(default_factory=list)
    last_bucket_seconds: int = 0


def group_anomalies(
    anomaly_records: list[AnomalyRecord],
    gap_tolerance_seconds: int = DEFAULT_GAP_TOLERANCE_SECONDS,
    series_bucket_seconds: dict[str, int] | None = None,
) -> list[dict[str, Any]]:
    """Group anomaly records into multi-module alarm groups.

    Args:
        anomaly_records: List of AnomalyRecord ORM objects.
        gap_tolerance_seconds: Maximum temporal gap for merging.
        series_bucket_seconds: Optional mapping of series_id to its
            aggregation bucket size in seconds. When supplied the merge
            algorithm uses
            ``max(gap_tolerance_seconds, bucket_seconds_of_either_anomaly)``
            so that a single attack that straddles a bucket boundary
            (e.g. an aitm_arp burst spanning the 60s mark) does not
            split into two alarms just because the resulting per-bucket
            anomaly timestamps are exactly one bucket apart.

    Returns:
        List of alarm group dicts ready for persistence.
    """
    candidates = _records_to_candidates(anomaly_records, series_bucket_seconds)
    return merge_anomalies_into_groups(candidates, gap_tolerance_seconds)


def merge_anomalies_into_groups(
    candidates: list[_MergeCandidate],
    gap_tolerance_seconds: int = DEFAULT_GAP_TOLERANCE_SECONDS,
) -> list[dict[str, Any]]:
    """Greedy forward merge of anomaly candidates into alarm groups.

    Args:
        candidates: Anomaly merge candidates.
        gap_tolerance_seconds: Maximum gap for merging.

    Returns:
        List of finalized alarm group dicts.
    """
    if not candidates:
        return []

    sorted_candidates = sorted(candidates, key=lambda c: c.start_ts)
    base_gap = timedelta(seconds=gap_tolerance_seconds)
    # Cap the bucket-aware extension at twice the base gap. Without a
    # cap a series with a 600s aggregation bucket would let the merge
    # span ten minutes, which over-merges otherwise distinct attack
    # episodes. Two times the base gap covers the common 1s/5s/30s/60s
    # bucket sizes without bridging gaps between separate attacks.
    max_gap = base_gap * 2
    groups: list[dict[str, Any]] = []
    current = _init_group_from_candidate(sorted_candidates[0])

    for candidate in sorted_candidates[1:]:
        bucket_aware_gap = min(
            max_gap,
            max(
                base_gap,
                timedelta(seconds=current.last_bucket_seconds),
                timedelta(seconds=candidate.bucket_seconds),
            ),
        )
        if _can_merge(current, candidate, bucket_aware_gap):
            _merge_into_group(current, candidate)
        else:
            groups.append(_finalize_group(current))
            current = _init_group_from_candidate(candidate)

    groups.append(_finalize_group(current))
    logger.info(
        "Merged {} anomalies into {} alarm groups",
        len(candidates),
        len(groups),
    )
    return groups


def persist_alarm_groups(
    connector: PostgresConnector,
    groups: list[dict[str, Any]],
    window_start: datetime | None = None,
) -> int:
    """Persist alarm groups to PostgreSQL and link contained anomalies.

    Each group is upserted into the ``alarms`` table; for every contained
    anomaly the ``alarm_id`` foreign key is set and ``is_grouped`` is
    flipped to ``True``.

    When ``window_start`` is supplied the function also removes alarms
    inside the rolling window that are NOT part of the new group set.
    This avoids orphaned alarm records when a re-merging pass produces
    a slightly different ID (for example because a new anomaly extended
    the alarm's ``end_timestamp``).

    Args:
        connector: PostgreSQL connector.
        groups: Alarm group dicts from :func:`merge_anomalies_into_groups`.
        window_start: Optional UTC cutoff that bounds the cleanup of
            stale alarm records.

    Returns:
        Number of alarm group records upserted.
    """
    if not groups:
        return 0

    count = 0
    gap = timedelta(seconds=DEFAULT_GAP_TOLERANCE_SECONDS)
    with connector.session() as session:
        # First pass: try to reuse the ID of an existing alarm whose
        # window and series_ids overlap the new group. This stabilises
        # the alarm ID across re-grouping cycles even when ``end_ts``
        # advances or the primary_type changes.
        candidate_alarms: list[Alarm] = []
        if window_start is not None:
            candidate_alarms = session.query(Alarm).filter(Alarm.end_timestamp >= window_start - gap).all()
            for alarm in candidate_alarms:
                session.expunge(alarm)

        used_existing_ids: set[str] = set()
        for group_data in groups:
            preferred_id = _find_existing_alarm_id(group_data, candidate_alarms, gap, used_existing_ids)
            if preferred_id is not None:
                group_data["id"] = preferred_id
                used_existing_ids.add(preferred_id)

        new_ids = {g["id"] for g in groups}

        if window_start is not None:
            stale_alarms = (
                session.query(Alarm.id).filter(Alarm.end_timestamp >= window_start).filter(~Alarm.id.in_(new_ids)).all()
            )
            stale_ids = [row[0] for row in stale_alarms]
            if stale_ids:
                session.query(AnomalyRecord).filter(AnomalyRecord.alarm_id.in_(stale_ids)).update(
                    {
                        AnomalyRecord.alarm_id: None,
                        AnomalyRecord.is_grouped: False,
                    },
                    synchronize_session=False,
                )
                session.query(Alarm).filter(Alarm.id.in_(stale_ids)).delete(synchronize_session=False)
                logger.info(
                    "Removed {} stale alarm records from rolling window",
                    len(stale_ids),
                )

        for group_data in groups:
            existing = session.query(Alarm).filter(Alarm.id == group_data["id"]).one_or_none()
            _preserve_rf_classification(group_data, existing)
            record = _build_alarm_record(group_data)
            session.merge(record)
            anomaly_ids = group_data.get("anomaly_ids", [])
            if anomaly_ids:
                session.query(AnomalyRecord).filter(AnomalyRecord.id.in_(anomaly_ids)).update(
                    {
                        AnomalyRecord.alarm_id: record.id,
                        AnomalyRecord.is_grouped: True,
                    },
                    synchronize_session=False,
                )
            count += 1

    logger.info("Upserted {} alarm groups to PostgreSQL", count)
    return count


def incremental_group_ungrouped_anomalies(
    connector: PostgresConnector,
    gap_tolerance_seconds: int = DEFAULT_GAP_TOLERANCE_SECONDS,
    max_alarm_duration_seconds: int = DEFAULT_MAX_ALARM_DURATION_SECONDS,
    lookback_seconds: int = 600,
) -> list[dict[str, Any]]:
    """Legacy-style incremental grouping.

    Loads only anomalies that have not been grouped yet (``is_grouped =
    False``) and tries to fold each one into an existing recent alarm
    whose time window plus ``gap_tolerance_seconds`` overlaps. If no
    candidate is found, a brand-new UUID-keyed alarm is created with
    just that single anomaly. This is the same approach used by the
    legacy ``otalon-clas`` ``group_anomalies`` flow and avoids the
    re-grouping race condition that produced mega-alarms in the
    previous SHA1-based implementation.

    Args:
        connector: PostgreSQL connector.
        gap_tolerance_seconds: Maximum gap between an anomaly and an
            existing alarm window for them to be merged.
        max_alarm_duration_seconds: Maximum resulting alarm span. Values
            less than or equal to zero disable the cap.
        lookback_seconds: How far back to load existing alarms that
            should be considered as merge candidates.

    Returns:
        A list of ``touched`` alarm-summary dicts (newly created or whose
        ``end_timestamp`` advanced during this cycle) with the keys
        ``alarm_id``, ``start_ts``, ``end_ts``, ``primary_type``,
        ``series_ids``, ``module``, ``is_new``. Used by the caller to
        flag the matching PCAP chunks. An empty list is returned when
        nothing changed.
    """
    cutoff = datetime.now(tz=timezone.utc) - timedelta(seconds=lookback_seconds)
    gap = timedelta(seconds=gap_tolerance_seconds)

    touched_alarms: list[dict[str, Any]] = []

    with connector.session() as session:
        new_anomalies: list[AnomalyRecord] = (
            session.query(AnomalyRecord)
            .filter(AnomalyRecord.is_anomaly.is_(True))
            .filter(AnomalyRecord.is_grouped.is_(False))
            .filter(AnomalyRecord.start_ts >= cutoff)
            .order_by(AnomalyRecord.start_ts.asc())
            .all()
        )
        if not new_anomalies:
            return touched_alarms

        candidate_alarms: list[Alarm] = session.query(Alarm).filter(Alarm.end_timestamp >= cutoff).all()

        # Snapshot end-timestamps of pre-existing alarms so we can later
        # tell which alarms were genuinely extended by this cycle.
        previous_end_ts: dict[str, datetime] = {str(alarm.id): alarm.end_timestamp for alarm in candidate_alarms}

        created = 0
        merged = 0
        # Track which alarm rows were touched during this cycle so we
        # can emit one PCAP flag per alarm at the end (not per anomaly).
        touched_alarm_ids: set[str] = set()
        for anomaly in new_anomalies:
            target_alarm = _find_mergable_alarm(anomaly, candidate_alarms, gap, max_alarm_duration_seconds)
            if target_alarm is None:
                target_alarm = _create_alarm_from_anomaly(anomaly)
                session.add(target_alarm)
                candidate_alarms.append(target_alarm)
                created += 1
            else:
                _merge_anomaly_into_alarm(target_alarm, anomaly)
                merged += 1
            anomaly.alarm_id = target_alarm.id
            anomaly.is_grouped = True
            touched_alarm_ids.add(str(target_alarm.id))

        # Mutated alarm rows are auto-tracked by the session; explicit
        # session.merge is only needed for the freshly created Alarm
        # rows that were not yet attached. Since `session.add()` was
        # already called above for new alarms, we have nothing extra
        # to do here.

        # Flush so freshly created alarms get their auto-generated IDs
        # populated, then build the touched-alarm summary list. We
        # detach copies via ``_alarm_to_summary`` so the caller can
        # safely use them after the session closes.
        session.flush()
        for alarm in candidate_alarms:
            alarm_id = str(alarm.id)
            if alarm_id not in touched_alarm_ids:
                continue
            previous = previous_end_ts.get(alarm_id)
            is_new = previous is None
            is_extended = previous is not None and alarm.end_timestamp != previous
            if not (is_new or is_extended):
                continue
            touched_alarms.append(_alarm_to_summary(alarm, is_new=is_new))

    if created or merged:
        logger.info(
            "Grouping cycle: {} anomalies merged ({} new alarms, {} updates)",
            created + merged,
            created,
            merged,
        )
    return touched_alarms


def _alarm_to_summary(alarm: Alarm, *, is_new: bool) -> dict[str, Any]:
    """Build a session-safe summary dict for the post-grouping flag step.

    The returned dict only contains primitive values so callers may use
    it after the originating SQLAlchemy session has been closed. The
    ``primary_type`` is normalised to a string (joining lists with
    ``"/"`` to match the legacy ``otalon-clas`` payload shape).
    """
    primary_type = alarm.primary_type
    if isinstance(primary_type, list):
        primary_type_label = "/".join(str(p) for p in primary_type)
    else:
        primary_type_label = str(primary_type or "unknown")

    series_ids = alarm.series_ids
    if series_ids is None:
        series_list: list[str] = []
    elif isinstance(series_ids, (list, tuple)):
        series_list = [str(s) for s in series_ids]
    else:
        series_list = [str(series_ids)]

    return {
        "alarm_id": str(alarm.id),
        "start_ts": alarm.start_timestamp,
        "end_ts": alarm.end_timestamp,
        "primary_type": primary_type_label,
        "series_ids": sorted(series_list),
        "module": getattr(alarm, "module", "") or "",
        "is_new": is_new,
    }


def _find_mergable_alarm(
    anomaly: AnomalyRecord,
    candidates: list[Alarm],
    gap: timedelta,
    max_alarm_duration_seconds: int = DEFAULT_MAX_ALARM_DURATION_SECONDS,
) -> Alarm | None:
    """Return the existing alarm whose window overlaps the anomaly with ``gap``.

    Picks the alarm with the closest ``end_timestamp`` to the anomaly's
    ``start_ts`` so that consecutive anomalies of the same attack stick
    to the same alarm rather than scattering across multiple candidates.

    Args:
        anomaly: The anomaly record to merge.
        candidates: Existing alarm rows considered for merging.
        gap: Gap tolerance for window overlap.
        max_alarm_duration_seconds: Maximum resulting alarm span. Values
            less than or equal to zero disable the cap.

    Returns:
        The best-matching alarm or ``None`` if no candidate fits.
    """
    a_start = _ensure_utc(anomaly.start_ts)
    a_end = _ensure_utc(anomaly.end_ts)
    best: Alarm | None = None
    best_distance = gap + timedelta(seconds=1)
    for alarm in candidates:
        c_start = _ensure_utc(alarm.start_timestamp)
        c_end = _ensure_utc(alarm.end_timestamp)
        if a_start > c_end + gap or a_end < c_start - gap:
            continue
        if max_alarm_duration_seconds > 0:
            resulting_start = min(c_start, a_start)
            resulting_end = max(c_end, a_end)
            if resulting_end - resulting_start > timedelta(seconds=max_alarm_duration_seconds):
                continue
        # distance = how far behind the alarm's end the new anomaly sits
        if a_start >= c_end:
            distance = a_start - c_end
        elif a_end <= c_start:
            distance = c_start - a_end
        else:
            distance = timedelta(0)
        if distance < best_distance:
            best_distance = distance
            best = alarm
    return best


def _extract_protocols_label(anomaly: AnomalyRecord) -> str:
    """Return the protocol stack label of an anomaly's ``series_id``.

    UCIs are slash-separated and end with the protocol stack token
    (e.g. ``Ethernet:ARP`` or ``Ethernet:IPv4:TCP``). The function
    returns the trailing segment, or an empty string when the field is
    missing or malformed.

    Args:
        anomaly: The anomaly record.

    Returns:
        Protocol-stack label suitable as a ``protocol_penalties`` key.
    """
    series = str(anomaly.series_id or "")
    if "/" not in series:
        return series
    return series.rsplit("/", 1)[-1]


def _safe_div(value: float, divisor: float) -> float:
    """Return ``value/divisor`` clipped to ``[0, 1]`` (0 on bad input)."""
    if divisor <= 0.0:
        return 0.0
    if not math.isfinite(value) or not math.isfinite(divisor):
        return 0.0
    return max(0.0, min(value / divisor, 1.0))


def _recompute_scores(stats: dict[str, Any]) -> None:
    """Recompute the legacy composite score for every entry in ``stats``.

    Mirrors :func:`otalon_clas.detection.grouping.compute_primary_type`:

    * Reference values (``packet_rate_ref`` / ``byte_rate_ref`` /
      ``coverage_ref`` / ``count_ref``) are the means across all
      currently tracked types in this alarm.
    * Each component is normalised against its reference and clipped
      to ``[0, 1]``.
    * Composite =
      ``w_rate*traffic + w_cov*coverage + w_persist*count``.
    * Score = ``conf_factor * composite * protocol_penalty`` with
      ``conf_factor = confidence_mean ** SCORE_GAMMA``.
    * ``score_norm`` divides each entry by the maximum score in this
      alarm.

    Mutates ``stats`` in place; non-dict entries are ignored.
    """
    typed = [(k, v) for k, v in stats.items() if isinstance(v, dict)]
    if not typed:
        return

    def _avg(values: list[float]) -> float:
        positive = [v for v in values if math.isfinite(v) and v > 0.0]
        if not positive:
            return 0.0
        return sum(positive) / len(positive)

    pr_vals = [float(v.get("packet_rate_sum", 0.0)) / max(int(v.get("rate_count", 0)), 1) for _, v in typed]
    br_vals = [float(v.get("byte_rate_sum", 0.0)) / max(int(v.get("rate_count", 0)), 1) for _, v in typed]
    coverage_vals = [float(v.get("type_series_count", 0)) for _, v in typed]
    count_vals = [float(v.get("count", 0)) for _, v in typed]

    pr_ref = _avg(pr_vals)
    br_ref = _avg(br_vals)
    cov_ref = max(_avg(coverage_vals), 1.0)
    cnt_ref = max(_avg(count_vals), 1.0)

    raw_scores: dict[str, float] = {}
    for k, v in typed:
        rc = max(int(v.get("rate_count", 0)), 1)
        pr = float(v.get("packet_rate_sum", 0.0)) / rc
        br = float(v.get("byte_rate_sum", 0.0)) / rc
        cov = float(v.get("type_series_count", 0))
        cnt = float(v.get("count", 0))
        ppc = max(int(v.get("protocol_penalty_count", 0)), 1)
        pen_sum = float(v.get("protocol_penalty_sum", 0.0))
        pen = max(0.0, min(pen_sum / ppc, 1.0))
        conf_mean = max(0.0, min(float(v.get("confidence_mean", 0.0)), 1.0))

        traffic_n = SCORE_WEIGHT_PACKET_RATE * _safe_div(pr, pr_ref) + SCORE_WEIGHT_BYTE_RATE * _safe_div(br, br_ref)
        composite = (
            SCORE_WEIGHT_RATE * traffic_n
            + SCORE_WEIGHT_COVERAGE * _safe_div(cov, cov_ref)
            + SCORE_WEIGHT_PERSISTENCE * _safe_div(cnt, cnt_ref)
        )
        conf_factor = conf_mean**SCORE_GAMMA
        raw = conf_factor * composite * pen

        v["traffic_n"] = traffic_n
        v["coverage_n"] = _safe_div(cov, cov_ref)
        v["count_n"] = _safe_div(cnt, cnt_ref)
        v["packet_rate_mean"] = pr
        v["byte_rate_mean"] = br
        v["protocol_penalty_mean"] = pen
        v["score"] = raw
        raw_scores[k] = raw

    max_score = max(raw_scores.values(), default=0.0)
    for k, raw in raw_scores.items():
        stats[k]["score_norm"] = (raw / max_score) if max_score > 0.0 else 0.0


def _create_alarm_from_anomaly(anomaly: AnomalyRecord) -> Alarm:
    """Spawn a fresh Alarm row seeded with one anomaly.

    Initialises the per-type statistics with the same fields used by
    :func:`_merge_anomaly_into_alarm` (rate sums, protocol penalty
    accumulators, series-id bookkeeping) so that subsequent merges
    extend the same structure.
    """
    a_start = _ensure_utc(anomaly.start_ts)
    a_end = _ensure_utc(anomaly.end_ts)
    confidence = float(anomaly.confidence or 0.0)
    anomaly_type = str(anomaly.anomaly_type or "NoBounds")
    protocols_label = _extract_protocols_label(anomaly)
    penalty = DEFAULT_PROTOCOL_PENALTIES.get(protocols_label, 1.0)
    rate_summary: dict[str, Any] = anomaly.rate_summary or {}
    packet_rate = float(rate_summary.get("packet_rate_pps", 0.0) or 0.0)
    byte_rate = float(rate_summary.get("byte_rate_Bps", 0.0) or 0.0)

    series_id_str = str(anomaly.series_id)

    has_rate = packet_rate > 0.0 or byte_rate > 0.0
    type_stats: dict[str, Any] = {
        anomaly_type: {
            "primary_type": anomaly_type,
            "interval_count": 1,
            "count": 1,
            "confidence_sum": confidence,
            "confidence_mean": confidence,
            "confidence_min": confidence,
            "confidence_max": confidence,
            "packet_rate_sum": packet_rate if has_rate else 0.0,
            "byte_rate_sum": byte_rate if has_rate else 0.0,
            "rate_count": 1 if has_rate else 0,
            "protocol_penalty_sum": float(penalty),
            "protocol_penalty_count": 1,
            "series_ids_for_type": [series_id_str],
            "type_series_count": 1,
            "score": 0.0,
            "score_norm": 0.0,
        }
    }
    _recompute_scores(type_stats)
    return Alarm(
        id=uuid.uuid4().hex,
        module=str(anomaly.module),
        start_timestamp=a_start,
        end_timestamp=a_end,
        primary_type=anomaly_type,
        multi_type=False,
        confirmed=False,
        is_active=True,
        series_ids=[series_id_str],
        anomaly_type_stats=type_stats,
    )


DEFAULT_PROTOCOL_PENALTIES: dict[str, float] = {
    "Ethernet:ARP": 0.6,
    "Ethernet:IPv4:TCP": 0.8,
    "Ethernet:IPv4:UDP": 0.8,
}
"""Multiplicative score penalties for noisy / broadcast-heavy protocol stacks.

Mirrors the ``otalon-clas/config/config.json`` entry under
``prediction.anomaly_grouping.protocol_penalties``. Stacks that are not
listed default to a penalty of ``1.0``."""

SCORE_WEIGHT_RATE: float = 0.60
SCORE_WEIGHT_COVERAGE: float = 0.20
SCORE_WEIGHT_PERSISTENCE: float = 0.20
SCORE_WEIGHT_PACKET_RATE: float = 0.70
SCORE_WEIGHT_BYTE_RATE: float = 0.30
SCORE_GAMMA: float = 1.0
"""Score component weights from the legacy ``compute_primary_type`` formula.

The composite is ``w_rate*traffic + w_cov*coverage + w_persist*count``,
multiplied by ``confidence_mean ** SCORE_GAMMA`` and the protocol
penalty. Within ``traffic`` the packet-rate counts 70% and the byte
rate 30%."""


def _merge_anomaly_into_alarm(alarm: Alarm, anomaly: AnomalyRecord) -> None:
    """Mutate ``alarm`` in place to incorporate ``anomaly``.

    Extends the alarm's time window, adds the new ``series_id``,
    updates per-type statistics, and re-selects ``primary_type`` based
    on the dominant anomaly type. RF-injected fields in
    ``anomaly_type_stats`` are preserved.
    """
    a_start = _ensure_utc(anomaly.start_ts)
    a_end = _ensure_utc(anomaly.end_ts)
    confidence = float(anomaly.confidence or 0.0)
    anomaly_type = str(anomaly.anomaly_type or "NoBounds")
    protocols_label = _extract_protocols_label(anomaly)
    penalty = DEFAULT_PROTOCOL_PENALTIES.get(protocols_label, 1.0)
    rate_summary: dict[str, Any] = anomaly.rate_summary or {}
    packet_rate = float(rate_summary.get("packet_rate_pps", 0.0) or 0.0)
    byte_rate = float(rate_summary.get("byte_rate_Bps", 0.0) or 0.0)

    if alarm.module != str(anomaly.module):
        alarm.module = MULTI_MODULE_SENTINEL

    if a_start < _ensure_utc(alarm.start_timestamp):
        alarm.start_timestamp = a_start
    if a_end > _ensure_utc(alarm.end_timestamp):
        alarm.end_timestamp = a_end

    series_set = set(alarm.series_ids or [])
    if anomaly.series_id not in series_set:
        series_set.add(str(anomaly.series_id))
        alarm.series_ids = sorted(series_set)

    stats: dict[str, Any] = dict(alarm.anomaly_type_stats or {})
    entry = dict(stats.get(anomaly_type, {})) if isinstance(stats, dict) else {}
    if not entry or "interval_count" not in entry:
        entry = {
            "primary_type": anomaly_type,
            "interval_count": 0,
            "count": 0,
            "confidence_sum": 0.0,
            "confidence_mean": confidence,
            "confidence_min": confidence,
            "confidence_max": confidence,
            "packet_rate_sum": 0.0,
            "byte_rate_sum": 0.0,
            "rate_count": 0,
            "protocol_penalty_sum": 0.0,
            "protocol_penalty_count": 0,
            "series_ids_for_type": [],
            "score": 0.0,
            "score_norm": 0.0,
        }
    entry["interval_count"] = int(entry.get("interval_count", 0)) + 1
    entry["count"] = int(entry.get("count", 0)) + 1
    entry["confidence_sum"] = float(entry.get("confidence_sum", 0.0)) + confidence
    entry["confidence_mean"] = entry["confidence_sum"] / int(entry["interval_count"])
    entry["confidence_min"] = min(float(entry.get("confidence_min", confidence)), confidence)
    entry["confidence_max"] = max(float(entry.get("confidence_max", confidence)), confidence)

    if packet_rate > 0.0 or byte_rate > 0.0:
        entry["packet_rate_sum"] = float(entry.get("packet_rate_sum", 0.0)) + packet_rate
        entry["byte_rate_sum"] = float(entry.get("byte_rate_sum", 0.0)) + byte_rate
        entry["rate_count"] = int(entry.get("rate_count", 0)) + 1

    entry["protocol_penalty_sum"] = float(entry.get("protocol_penalty_sum", 0.0)) + float(penalty)
    entry["protocol_penalty_count"] = int(entry.get("protocol_penalty_count", 0)) + 1

    series_for_type = list(entry.get("series_ids_for_type", []) or [])
    if anomaly.series_id and str(anomaly.series_id) not in series_for_type:
        series_for_type.append(str(anomaly.series_id))
        entry["series_ids_for_type"] = series_for_type
    entry["type_series_count"] = len(series_for_type)

    stats[anomaly_type] = entry

    _recompute_scores(stats)
    alarm.anomaly_type_stats = stats

    # Re-select primary type: keep RF label if it is one of the entries,
    # otherwise pick by largest interval_count.
    rf_label = None
    for key, val in stats.items():
        if isinstance(val, dict) and val.get("rf_classified_at"):
            rf_label = key
            break
    if rf_label is not None:
        alarm.primary_type = rf_label
    else:
        # Prefer MITRE / technical_method labels (anything that is not
        # ``NoBounds`` / ``BoundViolation``) over rule-based anomaly
        # types. Within the MITRE candidates rank by the legacy
        # composite score (already stored in ``score_norm``) so that
        # a single high-confidence background burst can no longer
        # outrank an attack class that triggered many anomalies.
        rule_only = {"NoBounds", "BoundViolation"}
        mitre_entries = [(k, v) for k, v in stats.items() if isinstance(v, dict) and k not in rule_only]
        if mitre_entries:
            top_score = max(float(v.get("score", 0.0)) for _, v in mitre_entries)
            tied = sorted(k for k, v in mitre_entries if float(v.get("score", 0.0)) == top_score)
            alarm.primary_type = tied[0]
        else:
            alarm.primary_type = max(
                stats.items(),
                key=lambda kv: int(kv[1].get("interval_count", 0)) if isinstance(kv[1], dict) else 0,
            )[0]
    alarm.multi_type = len([k for k in stats if k not in ("BoundViolation", "NoBounds")]) > 1
    alarm.is_active = True


def _find_existing_alarm_id(
    group_data: dict[str, Any],
    candidates: list[Alarm],
    gap: timedelta,
    used_ids: set[str],
) -> str | None:
    """Find the best existing alarm whose ID should be reused for ``group_data``.

    A candidate alarm matches when:
      1. Its time window overlaps the new group's window with ``gap``
         tolerance on both ends.
      2. At least one of its ``series_ids`` is also present in the new
         group.
      3. Its ID has not already been claimed by another group in the
         current persist call.

    Among multiple matches the one with the largest series-set
    intersection wins; ties go to the alarm with the closest
    ``start_timestamp``.

    Args:
        group_data: New group dict to assign an ID to.
        candidates: Alarms loaded from the rolling window.
        gap: Gap tolerance used for window-overlap checks.
        used_ids: Alarm IDs already taken by earlier groups in this run.

    Returns:
        The existing alarm ID to reuse, or ``None`` when no candidate
        matches.
    """
    new_start = _ensure_utc(group_data["start_timestamp"])
    new_end = _ensure_utc(group_data["end_timestamp"])
    new_series: set[str] = set(group_data.get("series_ids") or [])
    if not new_series:
        return None

    best_id: str | None = None
    best_score: tuple[float, float] = (0.0, float("inf"))
    for alarm in candidates:
        if str(alarm.id) in used_ids:
            continue
        existing_series = set(alarm.series_ids or [])
        overlap = new_series & existing_series
        if not overlap:
            continue
        # Jaccard-style overlap ratio against the smaller of the two
        # series sets. Demanding at least half of the smaller side
        # prevents a mega-alarm with hundreds of series from absorbing
        # any unrelated single-series alarm that happens to share one
        # background series.
        smaller = min(len(new_series), len(existing_series))
        overlap_ratio = len(overlap) / smaller if smaller > 0 else 0.0
        if overlap_ratio < 0.5:
            continue
        a_start = _ensure_utc(alarm.start_timestamp)
        a_end = _ensure_utc(alarm.end_timestamp)
        # Only reuse the alarm ID when the new group sits inside or
        # close to the existing alarm's time window. ``gap`` is used as
        # the symmetric tolerance, matching the live merge tolerance.
        if new_start > a_end + gap or new_end < a_start - gap:
            continue
        time_distance = abs((new_start - a_start).total_seconds())
        score = (overlap_ratio, -time_distance)
        if score > (best_score[0], -best_score[1]):
            best_id = str(alarm.id)
            best_score = (overlap_ratio, time_distance)

    return best_id


def _preserve_rf_classification(
    group_data: dict[str, Any],
    existing: Alarm | None,
) -> None:
    """Carry forward an existing RF classification across re-grouping cycles.

    When an alarm with the same ID already carries an ``rf_classified_at``
    entry, the regrouped alarm inherits the RF ``primary_type`` and the
    ``rf_*`` keys. Otherwise repeated grouping passes would overwrite
    the RF prediction with the bounds-/frequency-based primary_type
    derived from raw anomaly type counts.

    Args:
        group_data: Mutable dict produced by :func:`merge_anomalies_into_groups`.
        existing: Pre-existing Alarm row, or ``None`` for a new alarm.
    """
    if existing is None:
        return
    existing_stats = existing.anomaly_type_stats or {}
    if not isinstance(existing_stats, dict):
        return

    rf_entry: dict[str, Any] | None = None
    rf_label: str | None = None
    for key, entry in existing_stats.items():
        if isinstance(entry, dict) and entry.get("rf_classified_at"):
            rf_entry = dict(entry)
            rf_label = key
            break
    if rf_label is None or rf_entry is None:
        return

    new_stats: dict[str, Any] = dict(group_data.get("anomaly_type_stats") or {})
    new_stats[rf_label] = rf_entry
    group_data["anomaly_type_stats"] = new_stats
    group_data["primary_type"] = rf_label


def apply_group_classification(
    connector: PostgresConnector,
    alarm_id: str,
    mitre_label: str,
    technical_method: str,
    confidence: float,
    classified_at: datetime,
) -> bool:
    """Persist an alarm-group-classifier prediction to an existing alarm.

    Sets ``alarms.primary_type`` to ``mitre_label`` and adds the
    ``rf_label``, ``rf_confidence`` and ``rf_classified_at`` keys to the
    matching entry in ``alarms.anomaly_type_stats`` so that
    :class:`otalon_api` consumers can surface the prediction.

    Args:
        connector: PostgreSQL connector.
        alarm_id: ID of the alarm row to update.
        mitre_label: Predicted MITRE label (e.g. ``T0846/arp_scan``).
        technical_method: Underlying technical_method label (raw class name).
        confidence: Prediction confidence score.
        classified_at: Timestamp of the classification.

    Returns:
        ``True`` if the alarm was updated, ``False`` when the alarm was
        not found or the prediction was already applied.
    """
    classified_iso = _ensure_utc(classified_at).isoformat()
    with connector.session() as session:
        alarm = session.query(Alarm).filter(Alarm.id == alarm_id).one_or_none()
        if alarm is None:
            logger.warning("apply_group_classification: alarm {} not found", alarm_id)
            return False

        stats: dict[str, Any] = dict(alarm.anomaly_type_stats or {})
        existing_entry = dict(stats.get(mitre_label, {})) if isinstance(stats, dict) else {}
        if existing_entry.get("rf_classified_at") == classified_iso:
            return False

        existing_entry.setdefault("primary_type", mitre_label)
        existing_entry.setdefault("interval_count", 0)
        existing_entry.setdefault("count", 0)
        existing_entry.setdefault("confidence_mean", float(confidence))
        existing_entry.setdefault("score_norm", 0.0)
        existing_entry["rf_label"] = mitre_label
        existing_entry["rf_technical_method"] = technical_method
        existing_entry["rf_confidence"] = float(confidence)
        existing_entry["rf_classified_at"] = classified_iso

        stats[mitre_label] = existing_entry

        alarm.primary_type = mitre_label
        alarm.anomaly_type_stats = stats
    logger.info(
        "GroupClassifier: alarm {} classified as {} (conf={:.3f})",
        alarm_id,
        mitre_label,
        confidence,
    )
    return True


def fetch_alarms_pending_classification(
    connector: PostgresConnector,
    limit: int = 100,
    lookback_seconds: int = 600,
) -> list[Alarm]:
    """Return alarms that have not yet been classified.

    An alarm is considered pending when its ``anomaly_type_stats`` does
    not contain a ``rf_classified_at`` marker for any entry. The query
    looks at all alarms whose ``end_timestamp`` falls into the rolling
    ``lookback_seconds`` window — including alarms that have already
    been deactivated. This is necessary because short attacks (a few
    seconds long) can be persisted, deactivated, and reach this query
    inside the same grouping cycle, so filtering on ``is_active`` would
    silently drop them before the RF gets a chance to classify.

    Args:
        connector: PostgreSQL connector.
        limit: Maximum number of alarms to return.
        lookback_seconds: How far back (in seconds) to consider alarms
            for classification. Defaults to ten minutes.

    Returns:
        List of detached :class:`Alarm` ORM instances.
    """
    cutoff = datetime.now(tz=timezone.utc) - timedelta(seconds=lookback_seconds)
    with connector.session() as session:
        query = (
            session.query(Alarm)
            .filter(Alarm.end_timestamp >= cutoff)
            .order_by(Alarm.start_timestamp.desc())
            .limit(limit)
        )
        rows = query.all()
        session.expunge_all()

    pending: list[Alarm] = []
    for alarm in rows:
        stats = alarm.anomaly_type_stats or {}
        already_classified = False
        if isinstance(stats, dict):
            for entry in stats.values():
                if isinstance(entry, dict) and entry.get("rf_classified_at"):
                    already_classified = True
                    break
        if not already_classified:
            pending.append(alarm)
    return pending


def _records_to_candidates(
    records: list[AnomalyRecord],
    series_bucket_seconds: dict[str, int] | None = None,
) -> list[_MergeCandidate]:
    """Convert AnomalyRecord ORM objects to merge candidates.

    Args:
        records: List of ORM anomaly records.
        series_bucket_seconds: Optional mapping of series_id to its
            aggregation bucket size in seconds. When provided, each
            candidate carries the bucket size of its series so the
            merge step can adjust its gap tolerance accordingly.

    Returns:
        List of merge candidate dataclass instances.
    """
    bucket_lookup = series_bucket_seconds or {}
    candidates: list[_MergeCandidate] = []
    for rec in records:
        sid = str(rec.series_id)
        candidates.append(
            _MergeCandidate(
                anomaly_id=str(rec.id),
                module=str(rec.module),
                series_id=sid,
                anomaly_type=str(rec.anomaly_type),
                start_ts=_ensure_utc(rec.start_ts),
                end_ts=_ensure_utc(rec.end_ts),
                confidence=float(rec.confidence or 0.0),
                severity=float(rec.bound_severity_max or 0.0),
                bucket_seconds=int(bucket_lookup.get(sid, 0)),
            )
        )
    return candidates


def _init_group_from_candidate(candidate: _MergeCandidate) -> _AlarmGroupState:
    """Initialize a new alarm group state from the first candidate.

    Args:
        candidate: First anomaly candidate in the group.

    Returns:
        Initialized group state.
    """
    state = _AlarmGroupState(
        start_ts=candidate.start_ts,
        end_ts=candidate.end_ts,
        primary_type=candidate.anomaly_type,
        modules={candidate.module},
        series_ids={candidate.series_id},
        anomaly_ids=[candidate.anomaly_id],
        max_severity=candidate.severity,
        confidences=[candidate.confidence],
        last_bucket_seconds=candidate.bucket_seconds,
    )
    _accumulate_type_stat(state, candidate)
    return state


def _can_merge(group: _AlarmGroupState, candidate: _MergeCandidate, gap: timedelta) -> bool:
    """Check whether a candidate can be merged into the current group."""
    return (candidate.start_ts - group.end_ts) <= gap


def _merge_into_group(group: _AlarmGroupState, candidate: _MergeCandidate) -> None:
    """Merge a candidate into the current alarm group."""
    if candidate.end_ts > group.end_ts:
        group.end_ts = candidate.end_ts
    group.modules.add(candidate.module)
    group.series_ids.add(candidate.series_id)
    group.anomaly_ids.append(candidate.anomaly_id)
    group.confidences.append(candidate.confidence)
    group.max_severity = max(group.max_severity, candidate.severity)
    group.last_bucket_seconds = max(group.last_bucket_seconds, candidate.bucket_seconds)
    _accumulate_type_stat(group, candidate)


def _accumulate_type_stat(group: _AlarmGroupState, candidate: _MergeCandidate) -> None:
    """Update per-anomaly-type statistics within an alarm group state."""
    stat = group.type_stats.setdefault(
        candidate.anomaly_type,
        {
            "interval_count": 0,
            "score": 0.0,
            "confidences": [],
        },
    )
    stat["interval_count"] += 1
    stat["score"] += candidate.severity
    stat["confidences"].append(candidate.confidence)


def _finalize_group(group: _AlarmGroupState) -> dict[str, Any]:
    """Finalize a group state into a persistable dict.

    Args:
        group: Completed group state.

    Returns:
        Dict with all alarm fields ready for ORM upsert.
    """
    primary_type = _select_primary_type(group)
    type_stats = _build_anomaly_type_stats(group, primary_type)
    multi_type = len(group.type_stats) > 1
    module = sorted(group.modules)[0] if len(group.modules) == 1 else MULTI_MODULE_SENTINEL

    return {
        "id": _generate_group_id(group),
        "module": module,
        "start_timestamp": group.start_ts,
        "end_timestamp": group.end_ts,
        "primary_type": primary_type,
        "multi_type": multi_type,
        "confirmed": False,
        "is_active": True,
        "series_ids": sorted(group.series_ids),
        "anomaly_type_stats": type_stats,
        "anomaly_ids": list(group.anomaly_ids),
    }


def _select_primary_type(group: _AlarmGroupState) -> str:
    """Pick the primary anomaly type by highest interval count, then score."""
    if not group.type_stats:
        return group.primary_type
    return max(
        group.type_stats.items(),
        key=lambda kv: (kv[1]["interval_count"], kv[1]["score"]),
    )[0]


def _build_anomaly_type_stats(
    group: _AlarmGroupState,
    primary_type: str,
) -> dict[str, dict[str, Any]]:
    """Build the cleaned ``anomaly_type_stats`` dict per type.

    Each entry contains the flat statistics that ``otalon-api``
    consumes: ``interval_count``, ``count``, ``confidence_mean``,
    ``confidence_min``, ``confidence_max``, ``score``, ``score_norm``,
    plus ``primary_type`` for context.

    Args:
        group: Completed group state.
        primary_type: Resolved primary anomaly type label.

    Returns:
        Dict mapping anomaly type to a flat stats dict.
    """
    result: dict[str, dict[str, Any]] = {}
    total_score = sum(stat["score"] for stat in group.type_stats.values()) or 1.0
    for atype, stat in group.type_stats.items():
        confidences = stat["confidences"]
        if confidences:
            confidence_mean = sum(confidences) / len(confidences)
            confidence_min = min(confidences)
            confidence_max = max(confidences)
        else:
            confidence_mean = 0.0
            confidence_min = 0.0
            confidence_max = 0.0
        result[atype] = {
            "primary_type": primary_type,
            "interval_count": stat["interval_count"],
            "count": stat["interval_count"],
            "confidence_mean": confidence_mean,
            "confidence_min": confidence_min,
            "confidence_max": confidence_max,
            "score": stat["score"],
            "score_norm": stat["score"] / total_score,
        }
    return result


def _generate_group_id(group: _AlarmGroupState) -> str:
    """Generate a fresh random UUID for a new alarm group.

    The caller is expected to first try to reuse an existing alarm
    record's ID (see :func:`persist_alarm_groups`); only when no
    overlap with an existing alarm is found does a brand-new UUID get
    minted. Random IDs avoid the instability of content-derived hashes
    (which change whenever ``end_ts`` advances) and keep alarm IDs
    stable across re-grouping cycles.

    Args:
        group: Group state (kept for signature compatibility).

    Returns:
        Hex-encoded UUID4 string usable as primary key.
    """
    del group  # unused
    return uuid.uuid4().hex


def _build_alarm_record(group_data: dict[str, Any]) -> Alarm:
    """Build an Alarm ORM object from a group dict.

    Args:
        group_data: Finalized group dict.

    Returns:
        Populated Alarm ORM instance.
    """
    return Alarm(
        id=group_data["id"],
        module=group_data["module"],
        start_timestamp=group_data["start_timestamp"],
        end_timestamp=group_data["end_timestamp"],
        primary_type=group_data["primary_type"],
        multi_type=group_data["multi_type"],
        confirmed=group_data["confirmed"],
        is_active=group_data["is_active"],
        series_ids=group_data["series_ids"],
        anomaly_type_stats=group_data["anomaly_type_stats"],
    )


def _ensure_utc(dt: Any) -> datetime:
    """Ensure a datetime value has UTC timezone info."""
    if dt is None:
        return datetime.now(tz=timezone.utc)
    if isinstance(dt, datetime):
        return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
    return datetime.fromisoformat(str(dt)).replace(tzinfo=timezone.utc)
