"""Service layer for frequency-profile and rhythm-state queries.

Reads the ``frequency_profiles`` table written by otalon-clas and
derives the quantities the connections-page RHYTHM lane needs:
effective detector factors with their provenance, the absence deadline,
and the current detector state.

The detector's own arithmetic is mirrored exactly:

* ``effective_factor = per_profile_override ?? global_default``
* ``absence_timeout = max(mean_interval * effective_absence,
  absence_timeout_floor_s)``
* ``absence_deadline = last_seen + absence_timeout``

so the API never reports a deadline the detector would not act on.

It also owns the UI-101 correction path: a non-mutating Preview that
returns a canonical diff, ``before_snapshot`` and detector-threshold
impact; an Apply that delegates the atomic override plus audit write to
the repository; an advisory suggestion grounded in persisted event
history; and the per-series audit history read. Only
``tolerance_factor.override`` and ``absence_factor.override`` are
writable — learned cadence stays retraining-owned.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from math import ceil, isfinite
from typing import Any, Sequence

from loguru import logger

from otalon_api.api.schemas.frequency import (
    EffectiveFactor,
    FactorSource,
    FrequencyEventRecord,
    FrequencyEventsResponse,
    FrequencyFactorDiff,
    FrequencyHistoryRecord,
    FrequencyHistoryResponse,
    FrequencyOverrideApplyResponse,
    FrequencyOverridePreviewResponse,
    FrequencyOverrideSnapshot,
    FrequencyOverrideSuggestion,
    FrequencyProfileResponse,
    FrequencySuggestionEvidence,
    FrequencyThresholdImpact,
    RhythmState,
)
from otalon_api.domain.netcap.proto_resolver import ProtoHashResolver
from otalon_api.domain.topology.uci import base_key_without_ports, is_wildcard_uci
from otalon_api.repositories.postgres_repo import FrequencyProfileNotFound, PostgresRepository
from otalon_api.utils import run_in_thread

SUPPORTED_MODULES: frozenset[str] = frozenset({"conn", "mac_traffic", "proto_traffic"})
"""Modules for which otalon-clas trains frequency profiles.

``netcap`` is deliberately absent: it is the InfluxDB database name and
a legacy wire alias for connection data, never a module the frequency
monitor writes profiles under.
"""

DEFAULT_TOLERANCE_FACTOR: float = 2.0
DEFAULT_ABSENCE_FACTOR: float = 3.0

DEFAULT_RELATIVE_FLOOR_FACTOR: float = 0.5
"""Detector floor multiplier on ``mean_interval``.

Mirrors otalon-clas ``frequency_monitor.relative_floor_factor``. The
detector's deviation threshold is
``max(tolerance * std_interval, relative_floor_factor * mean_interval)``,
so on strictly periodic traffic the floor can dominate and a tolerance
change becomes a no-op. UI-101 must say so instead of implying an effect.
"""

SUGGESTION_WINDOW_DAYS: int = 14
"""Strict lookback window for evidence-backed rhythm suggestions."""

SUGGESTION_MARGIN: float = 1.15
"""Safety margin applied to worst observed evidence before proposing."""

FREQUENCY_ANOMALY: str = "FrequencyAnomaly"
ABSENCE_ANOMALY: str = "AbsenceAnomaly"

_OPEN_ANOMALY_GRACE_SECONDS: float = 120.0
"""How stale an anomaly's ``end_ts`` may be and still count as open.

otalon-clas extends an open interval's ``end_ts`` on every detection
tick (5 s live poll). A couple of minutes of slack absorbs a slow tick
or a brief worker restart without reporting a long-finished episode as
if it were still running.
"""

DEFAULT_LAST_SEEN_WRITE_LAG_SECONDS: float = 60.0
"""Upper bound on how stale the persisted ``last_seen`` may legitimately be.

otalon-clas keeps ``last_seen`` exact in memory but flushes it to
PostgreSQL in batches (``last_seen_flush_interval_seconds``, default
60 s) so a 5 s poll over ~200 profiles does not become a write storm.
The persisted column therefore trails reality by up to one interval.

This matters for fast series: a PROFINET flow with
``mean_interval = 1 s`` has a 3 s absence timeout, so its persisted
``last_seen`` is almost always "older than the deadline" purely because
of write-back lag. Deriving absence from that would report a perfectly
healthy 1 s-cadence connection as silent. The deadline comparison is
therefore only trusted once the silence exceeds the write-lag budget as
well; inside the budget the authoritative signal is whether the detector
actually wrote an AbsenceAnomaly row.
"""


class FrequencyService:
    """Serves frequency profiles enriched with derived rhythm state."""

    def __init__(
        self,
        postgres_repo: PostgresRepository,
        proto_resolver: ProtoHashResolver | None = None,
        tolerance_default: float = DEFAULT_TOLERANCE_FACTOR,
        absence_default: float = DEFAULT_ABSENCE_FACTOR,
        last_seen_write_lag_seconds: float = DEFAULT_LAST_SEEN_WRITE_LAG_SECONDS,
        absence_timeout_floor_seconds: float = 45.0,
        absence_interval_cap_seconds: float = 86400.0,
        relative_floor_factor: float = DEFAULT_RELATIVE_FLOOR_FACTOR,
    ) -> None:
        """Initialize the frequency service.

        Args:
            postgres_repo: PostgreSQL repository for profile access.
            tolerance_default: Global default frequency-tolerance factor,
                mirroring the detector configuration.
            absence_default: Global default absence-timeout factor.
            last_seen_write_lag_seconds: Tolerated staleness of the
                persisted ``last_seen``, matching the detector's batched
                write-back interval. See
                :data:`DEFAULT_LAST_SEEN_WRITE_LAG_SECONDS`.
            absence_timeout_floor_seconds: Lower bound mirrored from the
                otalon-clas detector's ``poll_interval + delay + margin``.
                This setting and the detector floor MUST stay in sync.
            absence_interval_cap_seconds: Upper bound on
                ``mean_interval`` for which absence deadline is computed.
                Profiles exceeding this cap have no deadline, mirroring
                otalon-clas ``absence_interval_cap_seconds``.
            relative_floor_factor: Detector floor multiplier on
                ``mean_interval`` inside
                ``max(tolerance * std, factor * mean)``. Mirrors
                otalon-clas ``relative_floor_factor``; used only to
                report correction impact, never to detect.
        """
        self._postgres_repo = postgres_repo
        self._proto_resolver = proto_resolver
        self._tolerance_default = float(tolerance_default)
        self._absence_default = float(absence_default)
        self._write_lag_budget = float(last_seen_write_lag_seconds)
        self._absence_timeout_floor_s = max(float(absence_timeout_floor_seconds), 0.0)
        self._absence_interval_cap_s = max(float(absence_interval_cap_seconds), 0.0)
        self._relative_floor_factor = max(float(relative_floor_factor), 0.0)

    @run_in_thread
    def get_profile(self, module: str, series_id: str, since: datetime | None = None) -> FrequencyProfileResponse:
        """Return the profile and rhythm state for one series.

        A series without a trained profile is NOT an error: it yields a
        populated response with ``state = no_profile`` so the client can
        render "no profile" as the ordinary condition it is.

        Args:
            module: Detection module name.
            series_id: Series identifier (UCI for ``conn``).

        Returns:
            The profile response, always populated.
        """
        now = datetime.now(timezone.utc)
        resolved_series_id = self._resolve_profile_series(module, series_id)
        rows = self._postgres_repo.query_frequency_profiles(module, [resolved_series_id])
        if not rows:
            logger.debug("no frequency profile for module={} series_id={}", module, series_id)
            return _no_profile_response(module, series_id, now)

        open_anomaly = self._postgres_repo.query_open_frequency_anomaly(module, resolved_series_id)
        absence_counts = (
            self._postgres_repo.count_recent_absence_anomalies(module, [resolved_series_id], since) if since else {}
        )
        frequency_counts = (
            self._postgres_repo.count_recent_frequency_anomalies(module, [resolved_series_id], since) if since else {}
        )
        response = self._build_response(
            rows[0],
            now,
            open_anomaly,
            absence_counts.get(resolved_series_id, 0),
            frequency_counts.get(resolved_series_id, 0),
        )
        return self._add_series_display(module, [response])[0]

    def _resolve_profile_series(self, module: str, series_id: str) -> str:
        """Resolve a wildcard connection to its deterministic profiled sibling."""
        if module != "conn" or not is_wildcard_uci(series_id):
            return series_id
        profiled = self._postgres_repo.query_all_profiled_series_ids(module)
        siblings = sorted(
            candidate
            for candidate in profiled
            if base_key_without_ports(candidate) == base_key_without_ports(series_id)
        )
        return siblings[0] if siblings else series_id

    @run_in_thread
    def list_profiles(
        self,
        module: str,
        series_ids: Sequence[str] | None = None,
        since: datetime | None = None,
    ) -> list[FrequencyProfileResponse]:
        """Return profiles for a module, optionally restricted to some series.

        Series that were requested but carry no profile are returned as
        explicit ``no_profile`` entries rather than being omitted, so a
        caller can tell "not profiled" from "not asked for".

        Args:
            module: Detection module name.
            series_ids: Optional series filter.

        Returns:
            One response per profile (and per requested-but-unprofiled
            series), ordered by series identifier.
        """
        now = datetime.now(timezone.utc)
        rows = self._postgres_repo.query_frequency_profiles(module, series_ids)
        absence_counts = (
            self._postgres_repo.count_recent_absence_anomalies(
                module, [str(row.get("series_id", "")) for row in rows], since
            )
            if since
            else {}
        )
        frequency_counts = (
            self._postgres_repo.count_recent_frequency_anomalies(
                module, [str(row.get("series_id", "")) for row in rows], since
            )
            if since
            else {}
        )
        responses = [
            self._build_response(
                row,
                now,
                self._open_anomaly(row, module),
                absence_counts.get(str(row.get("series_id", "")), 0),
                frequency_counts.get(str(row.get("series_id", "")), 0),
            )
            for row in rows
        ]

        if series_ids is not None:
            found = {r.series_id for r in responses}
            responses.extend(_no_profile_response(module, sid, now) for sid in series_ids if sid not in found)

        return sorted(self._add_series_display(module, responses), key=lambda r: r.series_id)

    def _add_series_display(
        self, module: str, responses: list[FrequencyProfileResponse]
    ) -> list[FrequencyProfileResponse]:
        """Attach readable protocol names to proto traffic responses."""
        if module != "proto_traffic" or self._proto_resolver is None or not responses:
            return responses
        ids = [response.series_id for response in responses]
        displays = self._proto_resolver.resolve_many(ids)
        return [
            response.model_copy(update={"series_display": display}) for response, display in zip(responses, displays)
        ]

    @run_in_thread
    def preview_override(
        self,
        module: str,
        series_id: str,
        requested: dict[str, float | None],
        include_suggestion: bool = False,
    ) -> FrequencyOverridePreviewResponse:
        """Compute a non-mutating override diff, snapshot, and impact.

        Args:
            module: Detection module name.
            series_id: Series identifier.
            requested: Mapping of explicitly supplied payload override
                fields to their new values; ``None`` clears an override.
            include_suggestion: Whether to attach an advisory proposal.

        Returns:
            The preview response.

        Raises:
            FrequencyProfileNotFound: When the series has no profile.
            ValueError: When no override actually changes or a supplied
                value is not a usable positive finite factor.
        """
        row = self._require_profile(module, series_id)
        old_tolerance = _as_float(row.get("tolerance_factor_override"))
        old_absence = _as_float(row.get("absence_factor_override"))
        new_tolerance = _resolve_requested(requested, "tolerance_factor_override", old_tolerance)
        new_absence = _resolve_requested(requested, "absence_factor_override", old_absence)
        _validate_factor("tolerance_factor_override", new_tolerance)
        _validate_factor("absence_factor_override", new_absence)
        if new_tolerance == old_tolerance and new_absence == old_absence:
            raise ValueError("no override change requested")

        diff = [
            _factor_diff("tolerance_factor.override", old_tolerance, new_tolerance, self._tolerance_default),
            _factor_diff("absence_factor.override", old_absence, new_absence, self._absence_default),
        ]
        suggestion = self._build_suggestion(module, series_id, row) if include_suggestion else None
        return FrequencyOverridePreviewResponse(
            module=module,
            series_id=series_id,
            diff=diff,
            before_snapshot=FrequencyOverrideSnapshot(
                tolerance_factor_override=old_tolerance,
                absence_factor_override=old_absence,
            ),
            impact=self._threshold_impact(row, old_tolerance, new_tolerance, new_absence),
            suggestion=suggestion,
        )

    @run_in_thread
    def apply_override(
        self,
        module: str,
        series_id: str,
        requested: dict[str, float | None],
        before_snapshot: dict[str, float | None],
        reason: str,
        actor: str = "operator",
    ) -> FrequencyOverrideApplyResponse:
        """Commit an audited override correction and notify the detector.

        Args:
            module: Detection module name.
            series_id: Series identifier.
            requested: Explicitly supplied payload override fields.
            before_snapshot: The exact snapshot returned by Preview.
            reason: Optional audited operator reason.
            actor: Audited operator identity.

        Returns:
            The apply response including the post-correction profile.

        Raises:
            FrequencyProfileNotFound: When the series has no profile.
            RhythmCorrectionConflict: When the snapshot is stale.
            ValueError: When validation of the requested factors fails.
        """
        row = self._require_profile(module, series_id)
        old_tolerance = _as_float(row.get("tolerance_factor_override"))
        old_absence = _as_float(row.get("absence_factor_override"))
        new_tolerance = _resolve_requested(requested, "tolerance_factor_override", old_tolerance)
        new_absence = _resolve_requested(requested, "absence_factor_override", old_absence)
        _validate_factor("tolerance_factor_override", new_tolerance)
        _validate_factor("absence_factor_override", new_absence)
        if new_tolerance == old_tolerance and new_absence == old_absence:
            raise ValueError("no override change requested")
        result = self._postgres_repo.correct_frequency_overrides(
            module,
            series_id,
            new_tolerance,
            new_absence,
            dict(before_snapshot),
            reason.strip(),
            actor,
        )
        prior = result["prior"]
        diff = [
            _factor_diff(
                "tolerance_factor.override",
                _as_float(prior.get("tolerance_factor_override")),
                new_tolerance,
                self._tolerance_default,
            ),
            _factor_diff(
                "absence_factor.override",
                _as_float(prior.get("absence_factor_override")),
                new_absence,
                self._absence_default,
            ),
        ]
        now = datetime.now(timezone.utc)
        fresh = self._postgres_repo.query_frequency_profile_row(module, series_id)
        profile = (
            self._build_response(fresh, now, self._open_anomaly(fresh, module))
            if fresh is not None
            else _no_profile_response(module, series_id, now)
        )
        return FrequencyOverrideApplyResponse(
            history_id=str(result["history_id"]),
            module=module,
            series_id=series_id,
            diff=diff,
            profile=profile,
            notified=bool(result.get("notified", False)),
        )

    @run_in_thread
    def suggest_override(self, module: str, series_id: str) -> FrequencyOverrideSuggestion:
        """Return an advisory factor proposal grounded in event history.

        Args:
            module: Detection module name.
            series_id: Series identifier.

        Returns:
            The advisory suggestion with its evidence provenance.

        Raises:
            FrequencyProfileNotFound: When the series has no profile.
        """
        row = self._require_profile(module, series_id)
        return self._build_suggestion(module, series_id, row)

    @run_in_thread
    def get_history(self, module: str, series_id: str, limit: int = 200) -> FrequencyHistoryResponse:
        """Return the chronological correction history for one series.

        Args:
            module: Detection module name.
            series_id: Series identifier.
            limit: Maximum number of audit rows.

        Returns:
            The history envelope, empty when the series was never corrected.
        """
        rows = self._postgres_repo.query_frequency_history(module, series_id, limit)
        records = [
            FrequencyHistoryRecord(
                actor=str(row.get("actor") or "unknown"),
                old_tolerance=_as_float(row.get("old_tolerance")),
                new_tolerance=_as_float(row.get("new_tolerance")),
                old_absence=_as_float(row.get("old_absence")),
                new_absence=_as_float(row.get("new_absence")),
                reason=str(row.get("reason") or ""),
                changed_at=_iso(_as_utc(row.get("changed_at"))) or "",
            )
            for row in rows
        ]
        return FrequencyHistoryResponse(
            module=module,
            series_id=series_id,
            count=len(records),
            data=records,
        )

    @run_in_thread
    def get_events(
        self,
        module: str,
        series_id: str,
        since: datetime | None = None,
        limit: int = 50,
    ) -> FrequencyEventsResponse:
        """Return the newest rhythm anomaly episodes for one series.

        The reviewable counterpart to the aggregate
        ``recent_absence_count`` / ``recent_frequency_anomaly_count``
        fields: those say *how many*, this says *which ones and when*.
        An empty envelope is a normal outcome for a series that never
        deviated from its cadence, not an error.

        ``since`` is optional so an unbounded "all history" timeline is
        expressible; the ``limit`` is what bounds the response either way.

        Args:
            module: Detection module name.
            series_id: Series identifier.
            since: Optional inclusive lower bound applied to ``start_ts``.
            limit: Maximum number of episodes to return.

        Returns:
            The event envelope, newest episode first.
        """
        rows = self._postgres_repo.query_recent_frequency_events(module, series_id, since, limit + 1)
        truncated = len(rows) > limit
        records = [_event_record(row) for row in rows[:limit]]
        return FrequencyEventsResponse(
            module=module,
            series_id=series_id,
            count=len(records),
            truncated=truncated,
            data=records,
        )

    def _require_profile(self, module: str, series_id: str) -> dict[str, Any]:
        """Load a profile row or raise the not-found domain error."""
        row = self._postgres_repo.query_frequency_profile_row(module, series_id)
        if row is None:
            raise FrequencyProfileNotFound(f"no frequency profile for {module}:{series_id}")
        return row

    def _threshold_impact(
        self,
        row: dict[str, Any],
        old_tolerance: float | None,
        new_tolerance: float | None,
        new_absence: float | None,
    ) -> FrequencyThresholdImpact:
        """Derive the detector-threshold effect of a proposed tolerance.

        Mirrors the detector's
        ``max(tolerance x std, relative_floor_factor x mean)`` so the
        Correct tab can name a no-op tolerance change and the crossover
        tolerance at which it would start to matter.
        """
        mean_interval = _as_float(row.get("mean_interval"))
        std_interval = _as_float(row.get("std_interval"))
        floor = None if mean_interval is None else self._relative_floor_factor * max(mean_interval, 0.0)
        old_effective = old_tolerance if old_tolerance is not None else self._tolerance_default
        new_effective = new_tolerance if new_tolerance is not None else self._tolerance_default
        old_threshold = _threshold(old_effective, std_interval, floor)
        new_threshold = _threshold(new_effective, std_interval, floor)
        floor_dominates = (
            floor is not None
            and std_interval is not None
            and new_threshold is not None
            and new_effective * std_interval < floor
        )
        crossover = (
            floor / std_interval if floor is not None and std_interval is not None and std_interval > 0.0 else None
        )
        absence_effective = new_absence if new_absence is not None else self._absence_default
        absence_timeout: float | None = None
        if mean_interval is not None and mean_interval > 0.0:
            absence_timeout = max(mean_interval * absence_effective, self._absence_timeout_floor_s)
        return FrequencyThresholdImpact(
            mean_interval_seconds=mean_interval,
            std_interval_seconds=std_interval,
            relative_floor_factor=self._relative_floor_factor,
            floor_seconds=floor,
            old_threshold_seconds=old_threshold,
            new_threshold_seconds=new_threshold,
            floor_dominates=bool(floor_dominates),
            crossover_tolerance_factor=crossover,
            absence_timeout_seconds=absence_timeout,
        )

    def _build_suggestion(
        self,
        module: str,
        series_id: str,
        row: dict[str, Any],
    ) -> FrequencyOverrideSuggestion:
        """Derive advisory factors from persisted frequency/absence events.

        Absence evidence sets the absence factor: the longest observed
        silence plus a safety margin, expressed as a multiple of the
        learned mean interval, so a recurring legitimate gap stops
        firing. Frequency evidence sets the tolerance factor from the
        observed event count relative to the window.

        Both factors are floored at the operator's CURRENT EFFECTIVE
        value (``override ?? global_default``), not just the global
        default. The suggestion is advisory and evidence-based, but it
        must respect an operator's already-applied (looser) setting as a
        lower bound: it never proposes TIGHTENING detection below what is
        already in effect (UI-180). A proposal therefore only ever
        loosens or holds, never fights a deliberate FP-reduction.
        """
        since = datetime.now(timezone.utc) - timedelta(days=SUGGESTION_WINDOW_DAYS)
        events = self._postgres_repo.query_frequency_events(module, series_id, since)
        mean_interval = _as_float(row.get("mean_interval")) or 0.0
        std_interval = _as_float(row.get("std_interval")) or 0.0
        absence_override = _as_float(row.get("absence_factor_override"))
        tolerance_override = _as_float(row.get("tolerance_factor_override"))
        current_effective_absence = self._absence_default if absence_override is None else absence_override
        current_effective_tolerance = self._tolerance_default if tolerance_override is None else tolerance_override
        absence_gaps = [
            gap for gap in (_event_duration_seconds(event) for event in events if _is_absence(event)) if gap is not None
        ]
        frequency_events = [event for event in events if not _is_absence(event)]

        absence_suggested: float | None = None
        if absence_gaps and mean_interval > 0.0:
            worst = max(absence_gaps)
            absence_suggested = _round_quarter(
                max(current_effective_absence, (worst * SUGGESTION_MARGIN) / mean_interval)
            )
        tolerance_suggested: float | None = None
        if frequency_events and std_interval > 0.0 and mean_interval > 0.0:
            tolerance_suggested = _round_tenth(
                max(current_effective_tolerance, (mean_interval * SUGGESTION_MARGIN) / std_interval)
            )

        return FrequencyOverrideSuggestion(
            module=module,
            series_id=series_id,
            tolerance_factor_suggested=tolerance_suggested,
            absence_factor_suggested=absence_suggested,
            evidence=FrequencySuggestionEvidence(
                observations=len(events),
                window_days=SUGGESTION_WINDOW_DAYS,
                method=(
                    "worst observed absence gap x "
                    f"{SUGGESTION_MARGIN} margin over learned mean interval; tolerance from "
                    "mean-to-std ratio, both floored at the current effective factor "
                    "(override ?? global default), never tightening below it"
                ),
            ),
        )

    def _open_anomaly(self, row: dict[str, Any], module: str) -> dict[str, Any] | None:
        """Look up the newest frequency/absence anomaly for a profile row."""
        return self._postgres_repo.query_open_frequency_anomaly(module, str(row.get("series_id", "")))

    def _build_response(
        self,
        row: dict[str, Any],
        now: datetime,
        open_anomaly: dict[str, Any] | None,
        recent_absence_count: int = 0,
        recent_frequency_anomaly_count: int = 0,
    ) -> FrequencyProfileResponse:
        """Assemble one response from a profile row plus derived state."""
        mean_interval = _as_float(row.get("mean_interval"))
        last_seen = _as_utc(row.get("last_seen"))

        tolerance = _effective_factor(row.get("tolerance_factor_override"), self._tolerance_default)
        absence = _effective_factor(row.get("absence_factor_override"), self._absence_default)

        timeout_seconds: float | None = None
        deadline: datetime | None = None
        if mean_interval is not None and mean_interval > 0.0:
            if self._absence_interval_cap_s > 0.0 and mean_interval > self._absence_interval_cap_s:
                timeout_seconds = None
                deadline = None
            else:
                timeout_seconds = max(mean_interval * absence.value, self._absence_timeout_floor_s)
                if last_seen is not None:
                    deadline = last_seen + timedelta(seconds=timeout_seconds)

        active_type, active_since = _resolve_active_anomaly(open_anomaly, now, last_seen)
        state = _resolve_state(
            last_seen=last_seen,
            deadline=deadline,
            now=now,
            active_type=active_type,
            write_lag_budget=self._write_lag_budget,
        )

        return FrequencyProfileResponse(
            module=str(row.get("module", "")),
            series_id=str(row.get("series_id", "")),
            series_display=None,
            state=state,
            has_profile=True,
            mean_interval_seconds=mean_interval,
            std_interval_seconds=_as_float(row.get("std_interval")),
            tolerance_factor=tolerance,
            absence_factor=absence,
            last_seen=_iso(last_seen),
            trained_at=_iso(_as_utc(row.get("trained_at"))),
            now=_iso(now) or "",
            absence_deadline=_iso(deadline),
            absence_timeout_seconds=timeout_seconds,
            seconds_until_deadline=(None if deadline is None else (deadline - now).total_seconds()),
            seconds_since_last_seen=(None if last_seen is None else (now - last_seen).total_seconds()),
            active_anomaly_type=active_type,
            active_anomaly_since=_iso(active_since),
            recent_absence_count=recent_absence_count,
            recent_frequency_anomaly_count=recent_frequency_anomaly_count,
        )


def _event_record(row: dict[str, Any]) -> FrequencyEventRecord:
    """Map one persisted anomaly row onto its timeline record.

    Duration is derived from the persisted interval rather than measured
    separately, and stays ``None`` when either bound is missing — an
    invented length would be indistinguishable from a real one.
    """
    start = _as_utc(row.get("start_ts"))
    end = _as_utc(row.get("end_ts"))
    duration = None if start is None or end is None else (end - start).total_seconds()
    return FrequencyEventRecord(
        anomaly_type=str(row.get("anomaly_type") or ""),
        start_ts=_iso(start) or "",
        end_ts=_iso(end),
        duration_seconds=duration,
        confidence=_as_float(row.get("confidence")),
    )


def _no_profile_response(module: str, series_id: str, now: datetime) -> FrequencyProfileResponse:
    """Build the first-class 'this series has no cadence' response."""
    return FrequencyProfileResponse(
        module=module,
        series_id=series_id,
        series_display=None,
        state=RhythmState.NO_PROFILE,
        has_profile=False,
        now=_iso(now) or "",
    )


def _effective_factor(override: Any, global_default: float) -> EffectiveFactor:
    """Resolve ``override ?? global_default`` and record the provenance."""
    override_value = _as_float(override)
    if override_value is None:
        return EffectiveFactor(
            value=global_default,
            source=FactorSource.GLOBAL_DEFAULT,
            override=None,
            global_default=global_default,
        )
    return EffectiveFactor(
        value=override_value,
        source=FactorSource.OVERRIDE,
        override=override_value,
        global_default=global_default,
    )


def _resolve_active_anomaly(
    open_anomaly: dict[str, Any] | None,
    now: datetime,
    last_seen: datetime | None = None,
) -> tuple[str | None, datetime | None]:
    """Decide whether the newest frequency anomaly is still running.

    An interval counts as open when its ``end_ts`` is within
    :data:`_OPEN_ANOMALY_GRACE_SECONDS` of now; otherwise the episode
    has finished and reporting it as active would be a lie.

    Recency of ``end_ts`` alone is not sufficient for an absence
    episode. otalon-clas advances ``end_ts`` while the silence lasts
    but does not stamp a closing record when traffic resumes, so a row
    from a silence that has *already ended* still looks recent for the
    whole grace window. If ``last_seen`` is newer than the episode's
    ``end_ts``, the series demonstrably spoke after that episode: the
    row is historical and must not be reported as active. See
    :func:`_resolve_state`.
    """
    if not open_anomaly:
        return None, None
    end_ts = _as_utc(open_anomaly.get("end_ts"))
    if end_ts is None or (now - end_ts).total_seconds() > _OPEN_ANOMALY_GRACE_SECONDS:
        return None, None
    anomaly_type = str(open_anomaly.get("anomaly_type") or "") or None
    if anomaly_type == ABSENCE_ANOMALY and _has_recovered(last_seen, end_ts):
        return None, None
    return anomaly_type, _as_utc(open_anomaly.get("start_ts"))


def _has_recovered(last_seen: datetime | None, end_ts: datetime) -> bool:
    """Return True when an observation postdates an absence episode.

    A ``last_seen`` at or after the episode's ``end_ts`` is direct
    evidence that the series resumed: the detector only advances
    ``end_ts`` on ticks where the series was still silent, so an
    observation timestamped later cannot belong to that silence.
    """
    return last_seen is not None and last_seen >= end_ts


def _resolve_state(
    last_seen: datetime | None,
    deadline: datetime | None,
    now: datetime,
    active_type: str | None,
    write_lag_budget: float,
) -> RhythmState:
    """Classify the detector state for one profiled series.

    Absence outranks a frequency verdict: while a series is silent there
    are no new intervals to judge, so a stale FrequencyAnomaly must not
    mask the fact that nothing is arriving at all.

    A persisted AbsenceAnomaly row is authoritative only while no
    observation postdates it. :func:`_resolve_active_anomaly` already
    withholds ``active_type`` for an episode the series has visibly
    recovered from, so ``absence_active`` can never contradict a fresh
    ``last_seen``: a series seen after the episode ended falls through
    to the deadline comparison, which is the live signal.

    The deadline comparison is the fallback for the window between the
    deadline passing and otalon-clas writing that row, and it is
    additionally required to exceed ``write_lag_budget`` — otherwise a
    fast series whose persisted ``last_seen`` merely trails the batched
    write-back would be misreported as absent (see
    :data:`DEFAULT_LAST_SEEN_WRITE_LAG_SECONDS`).
    """
    if active_type == ABSENCE_ANOMALY:
        return RhythmState.ABSENCE_ACTIVE
    if last_seen is None:
        return RhythmState.NO_LAST_SEEN
    if deadline is not None and (now - deadline).total_seconds() > write_lag_budget:
        return RhythmState.ABSENCE_ACTIVE
    if active_type == FREQUENCY_ANOMALY:
        return RhythmState.FREQUENCY_ANOMALY
    return RhythmState.NORMAL


def _as_float(value: Any) -> float | None:
    """Coerce a DB numeric to float, returning None when unusable."""
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _as_utc(value: Any) -> datetime | None:
    """Coerce a DB timestamp to a timezone-aware UTC datetime."""
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _iso(value: datetime | None) -> str | None:
    """Format a datetime as an ISO 8601 string, passing through None."""
    return None if value is None else value.isoformat()


def _resolve_requested(
    requested: dict[str, float | None],
    field: str,
    current: float | None,
) -> float | None:
    """Resolve a payload field to its post-correction override value.

    An absent key means "leave as is"; a present key — including an
    explicit ``None`` — is authoritative, so clearing an override back to
    the global default is expressible.

    Args:
        requested: Explicitly supplied payload fields.
        field: Payload field name.
        current: Currently persisted override.

    Returns:
        The override value that should be persisted.
    """
    if field not in requested:
        return current
    return _as_float(requested[field]) if requested[field] is not None else None


def _validate_factor(field: str, value: float | None) -> None:
    """Reject a non-finite or non-positive detector factor.

    Args:
        field: Payload field name used in the error message.
        value: Proposed override value; ``None`` (restore default) is valid.

    Raises:
        ValueError: When the value is not a finite positive number.
    """
    if value is None:
        return
    if not isfinite(value) or value <= 0.0:
        raise ValueError(f"{field} must be a finite positive number")


def _factor_diff(
    field: str,
    old_override: float | None,
    new_override: float | None,
    global_default: float,
) -> FrequencyFactorDiff:
    """Build the before/after diff entry for one editable factor."""
    old_effective = old_override if old_override is not None else global_default
    new_effective = new_override if new_override is not None else global_default
    return FrequencyFactorDiff(
        field=field,
        old_override=old_override,
        new_override=new_override,
        old_effective=old_effective,
        new_effective=new_effective,
        old_source=(FactorSource.OVERRIDE if old_override is not None else FactorSource.GLOBAL_DEFAULT),
        new_source=(FactorSource.OVERRIDE if new_override is not None else FactorSource.GLOBAL_DEFAULT),
        changed=old_override != new_override,
    )


def _threshold(tolerance: float, std_interval: float | None, floor: float | None) -> float | None:
    """Mirror the detector's ``max(tolerance * std, floor)`` threshold."""
    if std_interval is None and floor is None:
        return None
    std_bound = tolerance * (std_interval or 0.0)
    return max(std_bound, floor or 0.0)


def _is_absence(event: dict[str, Any]) -> bool:
    """Return True when a persisted anomaly row is an absence episode."""
    return str(event.get("anomaly_type") or "") == ABSENCE_ANOMALY


def _event_duration_seconds(event: dict[str, Any]) -> float | None:
    """Return an absence episode's observed silence in seconds."""
    start = _as_utc(event.get("start_ts"))
    end = _as_utc(event.get("end_ts"))
    if start is None or end is None:
        return None
    seconds = (end - start).total_seconds()
    return seconds if seconds > 0.0 else None


def _round_quarter(value: float) -> float:
    """Round up to the nearest quarter step used by the absence factor."""
    return ceil(value * 4.0) / 4.0


def _round_tenth(value: float) -> float:
    """Round up to the nearest tenth step used by the tolerance factor."""
    return ceil(value * 10.0) / 10.0
