"""Rule-based post-processing stage for anomaly grouping and scoring.

Groups anomaly intervals by series, computes composite scores using
configurable weights, and selects the primary anomaly type for each group.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

import polars as pl
from otalon_clas.common.settings import (AnomalyGroupingConfig,
                                                ScoringConfig)
from otalon_clas.pipeline.base import PostProcessingStage
from otalon_common.types import is_ml_type
from loguru import logger

DEFAULT_GAP_TOLERANCE_SECONDS: int = 10


@dataclass
class _TypeAccumulator:
    """Accumulates scoring data for a single anomaly type within a group."""

    event_count: int = 0
    confidence_sum: float = 0.0
    confidence_max: float = 0.0
    severity_sum: float = 0.0
    interval_count: int = 0


@dataclass
class _GroupState:
    """Mutable state for an in-progress anomaly group."""

    series_id: str
    module_name: str
    start_time: datetime
    end_time: datetime
    anomaly_rows: list[dict[str, Any]] = field(default_factory=list)
    type_accumulators: dict[str, _TypeAccumulator] = field(default_factory=dict)


class RuleBasedStage(PostProcessingStage):
    """Rule-based anomaly grouping and composite scoring stage.

    Groups temporally adjacent anomalies per series, scores each group
    using configurable weight factors, and resolves the primary anomaly
    type considering ML label preference rules.

    Args:
        gap_tolerance_seconds: Maximum gap between anomalies to be grouped.
        cross_module_correlation: Whether to enable cross-module correlation.
        module_weights: Per-module importance weights.
        grouping_config: Full anomaly grouping configuration.
        enabled: Whether this stage is active.
    """

    def __init__(
        self,
        gap_tolerance_seconds: int = DEFAULT_GAP_TOLERANCE_SECONDS,
        cross_module_correlation: bool = True,
        module_weights: dict[str, float] | None = None,
        grouping_config: AnomalyGroupingConfig | None = None,
        enabled: bool = True,
    ) -> None:
        """Initialize the rule-based stage.

        Args:
            gap_tolerance_seconds: Gap tolerance for grouping.
            cross_module_correlation: Enable cross-module grouping.
            module_weights: Module weight mapping.
            grouping_config: Full anomaly grouping config.
            enabled: Active flag.
        """
        self._gap_tolerance_seconds = gap_tolerance_seconds
        self._cross_module_correlation = cross_module_correlation
        self._module_weights = module_weights or {"conn": 1.0, "mac_traffic": 0.8, "proto_traffic": 0.6}
        self._grouping_config = grouping_config or AnomalyGroupingConfig()
        self._enabled = enabled

    def is_enabled(self) -> bool:
        """Return whether this stage is active.

        Returns:
            True if the stage should execute.
        """
        return self._enabled

    def process(self, anomalies: pl.DataFrame) -> pl.DataFrame:
        """Process anomalies through rule-based grouping and scoring.

        Args:
            anomalies: Input anomaly DataFrame with ``time``, ``anomaly_type``,
                ``is_anomaly``, ``confidence``, and module/series columns.

        Returns:
            DataFrame enriched with group-level scoring columns.
        """
        if anomalies.is_empty():
            return _append_scoring_columns(anomalies)

        only_anomalous = anomalies.filter(pl.col("is_anomaly") == True)  # noqa: E712
        if only_anomalous.is_empty():
            return _append_scoring_columns(anomalies)

        groups = self._group_anomalies(only_anomalous)
        scored = self._score_groups(groups)
        return _merge_scores_back(anomalies, scored)

    def _group_anomalies(self, df: pl.DataFrame) -> list[_GroupState]:
        """Split anomalies into temporal groups per series.

        Args:
            df: Anomalous rows sorted by time.

        Returns:
            List of group states.
        """
        sorted_df = df.sort("time")
        rows = sorted_df.to_dicts()
        groups: list[_GroupState] = []
        active: dict[str, _GroupState] = {}

        for row in rows:
            series_id = self._extract_series_id(row)
            row_time = _parse_row_time(row)
            if row_time is None:
                continue

            self._accumulate_row(row, series_id, row_time, active, groups)

        groups.extend(active.values())
        return groups

    def _accumulate_row(
        self,
        row: dict[str, Any],
        series_id: str,
        row_time: datetime,
        active: dict[str, _GroupState],
        completed: list[_GroupState],
    ) -> None:
        """Accumulate a single row into the appropriate group.

        Args:
            row: Row dict from the anomaly DataFrame.
            series_id: Resolved series identifier.
            row_time: Parsed row timestamp.
            active: Currently open groups by series.
            completed: List of finalized groups.
        """
        gap = timedelta(seconds=self._gap_tolerance_seconds)

        if series_id in active:
            group = active[series_id]
            if (row_time - group.end_time) <= gap:
                _update_group(group, row, row_time)
                return
            completed.append(group)

        new_group = _create_group(row, series_id, row_time)
        active[series_id] = new_group

    def _extract_series_id(self, row: dict[str, Any]) -> str:
        """Extract series identifier from a row dict.

        Args:
            row: Row data dictionary.

        Returns:
            String series identifier.
        """
        for candidate in ("uci", "mac_address", "protocol", "series_id"):
            if candidate in row and row[candidate] is not None:
                return str(row[candidate])
        return "unknown"

    def _score_groups(self, groups: list[_GroupState]) -> list[dict[str, Any]]:
        """Score each group and resolve primary anomaly types.

        Args:
            groups: List of anomaly groups.

        Returns:
            List of scoring result dicts.
        """
        scoring = self._grouping_config.scoring
        protocol_penalties = self._grouping_config.protocol_penalties
        results: list[dict[str, Any]] = []

        for group in groups:
            result = _score_single_group(group, scoring, self._module_weights, protocol_penalties)
            results.append(result)

        return results


def _score_single_group(
    group: _GroupState,
    scoring: ScoringConfig,
    module_weights: dict[str, float],
    protocol_penalties: dict[str, float],
) -> dict[str, Any]:
    """Compute composite score and primary type for a single group.

    Args:
        group: The anomaly group state.
        scoring: Scoring weight configuration.
        module_weights: Per-module weights.
        protocol_penalties: Per-protocol penalty factors.

    Returns:
        Dict with primary_type, score, interval_count, confidence_stats.
    """
    weights = scoring.weights
    primary_type = _resolve_primary_type(group, scoring)
    module_weight = module_weights.get(group.module_name, 1.0)

    traffic_n = _compute_traffic_rate(group)
    coverage_n = _compute_coverage(group)
    count_n = min(len(group.anomaly_rows) / 10.0, 1.0)
    severity_n = _compute_severity(group)
    conf_factor = _compute_confidence_factor(group)
    protocol_penalty = _get_protocol_penalty(group, protocol_penalties)

    score = (
        conf_factor
        * (
            weights.rate * traffic_n
            + weights.coverage * coverage_n
            + weights.persist * count_n
            + weights.severity * severity_n
        )
        * protocol_penalty
        * module_weight
    )

    confidence_values = [r.get("confidence", 0.0) for r in group.anomaly_rows]
    return {
        "series_id": group.series_id,
        "start_time": group.start_time.isoformat(),
        "end_time": group.end_time.isoformat(),
        "primary_type": primary_type,
        "score": round(score, 6),
        "interval_count": len(group.anomaly_rows),
        "confidence_stats": {
            "mean": sum(confidence_values) / max(len(confidence_values), 1),
            "max": max(confidence_values) if confidence_values else 0.0,
            "min": min(confidence_values) if confidence_values else 0.0,
        },
    }


def _resolve_primary_type(group: _GroupState, scoring: ScoringConfig) -> str:
    """Resolve the primary anomaly type from accumulated type scores.

    ML labels are preferred when mean confidence >= threshold AND
    total events >= threshold.

    Args:
        group: The anomaly group state.
        scoring: Scoring configuration with ML preference thresholds.

    Returns:
        Primary anomaly type string.
    """
    if not group.type_accumulators:
        return ""

    best_ml_type = _find_best_ml_type(group, scoring)
    if best_ml_type is not None:
        return best_ml_type

    best_type = ""
    best_count = 0
    for atype, acc in group.type_accumulators.items():
        if acc.event_count > best_count:
            best_count = acc.event_count
            best_type = atype
    return best_type


def _find_best_ml_type(group: _GroupState, scoring: ScoringConfig) -> str | None:
    """Find the best ML type that meets preference thresholds.

    Args:
        group: The anomaly group state.
        scoring: Scoring configuration.

    Returns:
        Best ML type string or None if no ML type qualifies.
    """
    min_conf = scoring.ml_primary_min_mean_confidence
    min_events = scoring.ml_primary_min_event_sum
    best_type: str | None = None
    best_conf: float = 0.0

    for atype, acc in group.type_accumulators.items():
        if not is_ml_type(atype):
            continue
        mean_conf = acc.confidence_sum / max(acc.event_count, 1)
        if mean_conf >= min_conf and acc.event_count >= min_events:
            if mean_conf > best_conf:
                best_conf = mean_conf
                best_type = atype

    return best_type


def _compute_traffic_rate(group: _GroupState) -> float:
    """Compute normalized traffic rate for the group.

    Args:
        group: The anomaly group state.

    Returns:
        Normalized rate in [0, 1].
    """
    duration = (group.end_time - group.start_time).total_seconds()
    if duration <= 0:
        return 0.0
    rate = len(group.anomaly_rows) / duration
    return min(rate, 1.0)


def _compute_coverage(group: _GroupState) -> float:
    """Compute feature coverage from violated features across the group.

    Args:
        group: The anomaly group state.

    Returns:
        Normalized coverage in [0, 1].
    """
    all_violated: set[str] = set()
    for row in group.anomaly_rows:
        vf = row.get("violated_features", "")
        if vf and vf != "[]":
            parts = [p.strip() for p in str(vf).split(",") if p.strip()]
            all_violated.update(parts)
    return min(len(all_violated) / 10.0, 1.0)


def _compute_severity(group: _GroupState) -> float:
    """Compute average severity across group accumulators.

    Args:
        group: The anomaly group state.

    Returns:
        Normalized severity in [0, 1].
    """
    total_severity = 0.0
    total_events = 0
    for acc in group.type_accumulators.values():
        total_severity += acc.severity_sum
        total_events += acc.event_count
    if total_events == 0:
        return 0.0
    return min(total_severity / total_events, 1.0)


def _compute_confidence_factor(group: _GroupState) -> float:
    """Compute the confidence factor as weighted mean across accumulators.

    Args:
        group: The anomaly group state.

    Returns:
        Confidence factor in [0, 1].
    """
    total_conf = 0.0
    total_events = 0
    for acc in group.type_accumulators.values():
        total_conf += acc.confidence_sum
        total_events += acc.event_count
    if total_events == 0:
        return 0.0
    return min(total_conf / total_events, 1.0)


def _get_protocol_penalty(
    group: _GroupState,
    protocol_penalties: dict[str, float],
) -> float:
    """Retrieve the protocol penalty for the group's series.

    Args:
        group: The anomaly group state.
        protocol_penalties: Protocol-to-penalty mapping.

    Returns:
        Penalty factor (defaults to 1.0 if no match).
    """
    for row in group.anomaly_rows:
        for key in ("protocol_stack", "protocol"):
            proto = row.get(key, "")
            if proto and proto in protocol_penalties:
                return protocol_penalties[proto]
    return 1.0


def _create_group(row: dict[str, Any], series_id: str, row_time: datetime) -> _GroupState:
    """Create a new group state from an initial row.

    Args:
        row: Row data dictionary.
        series_id: Resolved series identifier.
        row_time: Parsed row timestamp.

    Returns:
        Initialized group state.
    """
    module_name = str(row.get("module_name", ""))
    group = _GroupState(
        series_id=series_id,
        module_name=module_name,
        start_time=row_time,
        end_time=row_time,
    )
    _update_group(group, row, row_time)
    return group


def _update_group(group: _GroupState, row: dict[str, Any], row_time: datetime) -> None:
    """Update a group state with a new anomaly row.

    Severity accumulators are updated within this function, ensuring they
    are initialized before the processing loop.

    Args:
        group: Group state to update.
        row: Row data dictionary.
        row_time: Parsed row timestamp.
    """
    group.anomaly_rows.append(row)
    if row_time > group.end_time:
        group.end_time = row_time
    if row_time < group.start_time:
        group.start_time = row_time

    anomaly_type = str(row.get("anomaly_type", ""))
    confidence = float(row.get("confidence", 0.0))
    severity = float(row.get("severity", 0.0))

    if anomaly_type not in group.type_accumulators:
        group.type_accumulators[anomaly_type] = _TypeAccumulator()

    acc = group.type_accumulators[anomaly_type]
    acc.event_count += 1
    acc.confidence_sum += confidence
    acc.confidence_max = max(acc.confidence_max, confidence)
    acc.severity_sum += severity
    acc.interval_count += 1


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


def _append_scoring_columns(df: pl.DataFrame) -> pl.DataFrame:
    """Append empty scoring columns to a DataFrame.

    Args:
        df: Input DataFrame.

    Returns:
        DataFrame with added scoring columns.
    """
    return df.with_columns(
        pl.lit("").alias("primary_type"),
        pl.lit(0.0).alias("group_score"),
        pl.lit(0).alias("group_interval_count"),
    )


def _merge_scores_back(
    original: pl.DataFrame,
    scored_groups: list[dict[str, Any]],
) -> pl.DataFrame:
    """Merge group-level scores back onto the original anomaly DataFrame.

    Args:
        original: Full anomaly DataFrame (including non-anomalous rows).
        scored_groups: Scored group result dicts.

    Returns:
        DataFrame with group scoring columns added.
    """
    if not scored_groups:
        return _append_scoring_columns(original)

    score_lookup: dict[str, dict[str, Any]] = {}
    for group in scored_groups:
        sid = group["series_id"]
        if sid not in score_lookup or group["score"] > score_lookup[sid]["score"]:
            score_lookup[sid] = group

    rows = original.to_dicts()
    primary_types: list[str] = []
    scores: list[float] = []
    interval_counts: list[int] = []

    for row in rows:
        sid = _extract_series_id_from_row(row)
        entry = score_lookup.get(sid)
        if entry is not None:
            primary_types.append(entry["primary_type"])
            scores.append(entry["score"])
            interval_counts.append(entry["interval_count"])
        else:
            primary_types.append("")
            scores.append(0.0)
            interval_counts.append(0)

    return original.with_columns(
        pl.Series("primary_type", primary_types, dtype=pl.Utf8),
        pl.Series("group_score", scores, dtype=pl.Float64),
        pl.Series("group_interval_count", interval_counts, dtype=pl.Int64),
    )


def _extract_series_id_from_row(row: dict[str, Any]) -> str:
    """Extract series identifier from a row for score lookup.

    Args:
        row: Row data dictionary.

    Returns:
        Series identifier string.
    """
    for candidate in ("uci", "mac_address", "protocol", "series_id"):
        if candidate in row and row[candidate] is not None:
            return str(row[candidate])
    return "unknown"
