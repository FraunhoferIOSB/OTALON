"""Pydantic v2 schemas for the frequency-profile API.

Serves what the connections-page RHYTHM lane needs to render truthfully:
the learned cadence, the effective detector factors including whether an
operator override is active, the real ``last_seen``, the derived absence
deadline, and the current detector state.

It also carries the UI-101 Rhythm Review correction contract: the
Preview/Apply payloads, the canonical ``before_snapshot`` conflict guard,
the override diff and detector-threshold impact, advisory suggestion
evidence, and the per-series audit history. Only the two persisted
override fields ``tolerance_factor.override`` and
``absence_factor.override`` are writable; learned cadence stays
retraining-owned.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class RhythmState(str, Enum):
    """Current frequency-detector state for one series.

    ``NO_PROFILE`` is a first-class, non-error outcome: a connection the
    frequency monitor has never trained a cadence for simply has no
    rhythm to show. It is not a failure and must not be surfaced as one.
    """

    NO_PROFILE = "no_profile"
    NO_LAST_SEEN = "no_last_seen"
    NORMAL = "normal"
    FREQUENCY_ANOMALY = "frequency_anomaly"
    ABSENCE_ACTIVE = "absence_active"


class FactorSource(str, Enum):
    """Provenance of an effective detector factor."""

    OVERRIDE = "override"
    GLOBAL_DEFAULT = "global_default"


class EffectiveFactor(BaseModel):
    """An effective detector factor plus where its value came from.

    The lane must be able to name whether a threshold is operator-tuned
    or the shipped default, so provenance travels with the value instead
    of being inferred client-side.
    """

    value: float = Field(description="Effective factor applied by the detector")
    source: FactorSource = Field(description="Whether the value is an operator override or the global default")
    override: float | None = Field(default=None, description="Per-profile override, null when unset")
    global_default: float = Field(description="Global default from the detector configuration")


class FrequencyProfileResponse(BaseModel):
    """Frequency profile and rhythm state for one series and module.

    All instants are ISO 8601 UTC strings. ``now`` is the server instant
    the derived fields were computed against, so a client can reconcile
    ``last_seen``, ``absence_deadline`` and the countdown against one
    consistent clock rather than mixing in its own.
    """

    module: str
    series_id: str
    series_display: str | None = None
    state: RhythmState
    has_profile: bool

    mean_interval_seconds: float | None = Field(default=None, description="Learned mean inter-arrival interval")
    std_interval_seconds: float | None = Field(default=None, description="Learned inter-arrival standard deviation")

    tolerance_factor: EffectiveFactor | None = Field(
        default=None, description="Effective frequency-tolerance factor and its provenance"
    )
    absence_factor: EffectiveFactor | None = Field(
        default=None, description="Effective absence-timeout factor and its provenance"
    )

    last_seen: str | None = Field(default=None, description="Last observation instant persisted by the detector")
    trained_at: str | None = Field(default=None, description="When this profile's statistics were trained")
    now: str = Field(description="Server instant the derived fields were computed against")

    absence_deadline: str | None = Field(
        default=None,
        description="Instant at which silence becomes an AbsenceAnomaly (last_seen + mean * absence_factor)",
    )
    absence_timeout_seconds: float | None = Field(
        default=None, description="Grace period in seconds between last_seen and the deadline"
    )
    seconds_until_deadline: float | None = Field(
        default=None, description="Signed seconds to the deadline; negative once exceeded"
    )
    seconds_since_last_seen: float | None = Field(default=None, description="Age of last_seen in seconds")

    active_anomaly_type: str | None = Field(
        default=None, description="PascalCase type of the currently open frequency/absence anomaly, if any"
    )
    active_anomaly_since: str | None = Field(default=None, description="Start instant of that open anomaly")
    recent_absence_count: int = Field(
        default=0,
        description="Count of AbsenceAnomaly episodes with start_ts within the requested time window",
    )
    recent_frequency_anomaly_count: int = Field(
        default=0,
        description="Count of FrequencyAnomaly episodes with start_ts within the requested time window",
    )


class FrequencyProfileListResponse(BaseModel):
    """Envelope for a multi-series frequency-profile query."""

    module: str
    count: int
    data: list[FrequencyProfileResponse]


class FrequencyOverrideSnapshot(BaseModel):
    """Canonical before-state of the two editable override columns.

    This is the conflict guard for the Preview/Apply contract: Preview
    returns exactly what it read under the current transaction, Apply
    sends it back unchanged, and the repository compares it against the
    locked row. Only the two persisted override columns take part —
    learned cadence changes through retraining must not invalidate an
    operator's pending correction.

    This model is *inbound* as well as outbound: it is nested in
    :class:`FrequencyOverrideApplyRequest`, so it inherits that payload's
    ``extra="forbid"`` strictness. Silently dropping an unknown key here
    would weaken the guard — a client sending a misspelled snapshot field
    would have its stale value ignored and the apply would pass the
    conflict check it should have failed.
    """

    model_config = ConfigDict(extra="forbid")

    tolerance_factor_override: float | None = Field(
        default=None, description="Persisted tolerance_factor.override at preview time, null when unset"
    )
    absence_factor_override: float | None = Field(
        default=None, description="Persisted absence_factor.override at preview time, null when unset"
    )


class FrequencyOverrideRequest(BaseModel):
    """Requested override values for one frequency profile.

    ``tolerance_factor_override`` and ``absence_factor_override`` are the
    endpoint payload names for the persisted semantic fields
    ``tolerance_factor.override`` and ``absence_factor.override``. A
    field that is absent means "leave as is"; an explicit ``null``
    clears the override and restores the global default. Learned cadence
    (``mean_interval_seconds`` / ``std_interval_seconds``) is not part of
    this payload and is rejected by ``extra="forbid"``.
    """

    model_config = ConfigDict(extra="forbid")

    series_id: str | None = Field(
        default=None,
        description=(
            "Authoritative series identifier. Series identifiers are UCIs containing '/', "
            "which cannot survive a single URL path segment, so this body value wins over "
            "the path when present — the same contract the bounds-correction routes use."
        ),
    )
    tolerance_factor_override: float | None = Field(
        default=None, description="New tolerance_factor.override; explicit null restores the global default"
    )
    absence_factor_override: float | None = Field(
        default=None, description="New absence_factor.override; explicit null restores the global default"
    )

    def requested_fields(self) -> set[str]:
        """Return the payload field names the client explicitly supplied."""
        return set(self.model_fields_set)


class FrequencyOverridePreviewRequest(FrequencyOverrideRequest):
    """Preview payload — the override values only, never a mutation."""


class FrequencyOverrideApplyRequest(FrequencyOverrideRequest):
    """Apply payload — override values plus the audit and conflict guard.

    Reason is optional; there is no typed confirmation phrase in this contract.
    """

    before_snapshot: FrequencyOverrideSnapshot = Field(
        description="Exact snapshot returned by the immediately preceding Preview"
    )
    reason: str = ""


class FrequencyFactorDiff(BaseModel):
    """Before/after view of one editable factor including provenance."""

    field: str = Field(description="Semantic field name, e.g. 'tolerance_factor.override'")
    old_override: float | None = Field(default=None, description="Override before the correction")
    new_override: float | None = Field(default=None, description="Override after the correction")
    old_effective: float = Field(description="Effective factor before the correction")
    new_effective: float = Field(description="Effective factor after the correction")
    old_source: FactorSource = Field(description="Provenance before the correction")
    new_source: FactorSource = Field(description="Provenance after the correction")
    changed: bool = Field(description="Whether this factor changes at all")


class FrequencyThresholdImpact(BaseModel):
    """Detector-threshold impact of a proposed tolerance change.

    The frequency detector applies
    ``max(tolerance x std_interval, relative_floor_factor x mean_interval)``.
    When the mean-interval floor dominates, changing the tolerance factor
    does not move the threshold at all — the operator must be told, and
    the crossover tolerance at which the change would start to bite is
    named explicitly.
    """

    mean_interval_seconds: float | None = Field(default=None, description="Learned mean interval")
    std_interval_seconds: float | None = Field(default=None, description="Learned interval standard deviation")
    relative_floor_factor: float = Field(description="Detector floor factor applied to mean_interval")
    floor_seconds: float | None = Field(default=None, description="relative_floor_factor x mean_interval")
    old_threshold_seconds: float | None = Field(default=None, description="Effective threshold before the correction")
    new_threshold_seconds: float | None = Field(default=None, description="Effective threshold after the correction")
    floor_dominates: bool = Field(description="True when the floor, not tolerance x std, sets the new threshold")
    crossover_tolerance_factor: float | None = Field(
        default=None,
        description="Tolerance factor at which tolerance x std would overtake the floor, null when not derivable",
    )
    absence_timeout_seconds: float | None = Field(
        default=None, description="Absence grace period implied by the proposed absence factor"
    )


class FrequencySuggestionEvidence(BaseModel):
    """Provenance for a server-generated rhythm suggestion."""

    observations: int = Field(description="Number of persisted events the suggestion was derived from")
    window_days: int = Field(description="Length of the strict lookback window in days")
    method: str = Field(description="Human-readable description of the calculation")


class FrequencyOverrideSuggestion(BaseModel):
    """Advisory factor proposal plus the evidence it rests on."""

    module: str
    series_id: str
    tolerance_factor_suggested: float | None = Field(
        default=None, description="Advisory tolerance_factor.override, null when no evidence supports one"
    )
    absence_factor_suggested: float | None = Field(
        default=None, description="Advisory absence_factor.override, null when no evidence supports one"
    )
    evidence: FrequencySuggestionEvidence


class FrequencyOverridePreviewResponse(BaseModel):
    """Non-mutating Preview result: diff, snapshot, and threshold impact."""

    module: str
    series_id: str
    diff: list[FrequencyFactorDiff] = Field(description="One entry per editable factor")
    before_snapshot: FrequencyOverrideSnapshot = Field(description="Snapshot Apply must send back unchanged")
    impact: FrequencyThresholdImpact
    suggestion: FrequencyOverrideSuggestion | None = Field(
        default=None, description="Advisory proposal when the caller asked for one"
    )


class FrequencyOverrideApplyResponse(BaseModel):
    """Result of a committed correction: audit id plus the new profile."""

    history_id: str = Field(description="Identifier of the single appended audit row")
    module: str
    series_id: str
    diff: list[FrequencyFactorDiff]
    profile: FrequencyProfileResponse = Field(description="Profile as it stands after the correction")
    notified: bool = Field(description="Whether the post-commit detector notification was queued")


class FrequencyHistoryRecord(BaseModel):
    """One chronological correction-audit row for a series."""

    actor: str
    old_tolerance: float | None = None
    new_tolerance: float | None = None
    old_absence: float | None = None
    new_absence: float | None = None
    reason: str
    changed_at: str = Field(description="ISO 8601 UTC instant the correction was committed")


class FrequencyHistoryResponse(BaseModel):
    """Envelope for the per-series correction history."""

    module: str
    series_id: str
    count: int
    data: list[FrequencyHistoryRecord]


class FrequencyEventRecord(BaseModel):
    """One persisted absence / frequency anomaly episode for a series.

    This is detector evidence, not a correction: it is the same
    ``anomalies`` row the rhythm state is derived from, narrowed to the
    two rhythm anomaly types. ``duration_seconds`` is derived from the
    persisted interval rather than measured independently, so an episode
    that is still open reports the duration observed so far.
    """

    anomaly_type: str = Field(description="PascalCase anomaly type (AbsenceAnomaly or FrequencyAnomaly)")
    start_ts: str = Field(description="ISO 8601 UTC start instant of the episode")
    end_ts: str | None = Field(default=None, description="ISO 8601 UTC end instant, when persisted")
    duration_seconds: float | None = Field(default=None, description="Episode length derived from start_ts and end_ts")
    confidence: float | None = Field(default=None, description="Detector confidence recorded with the episode")


class FrequencyEventsResponse(BaseModel):
    """Envelope for the per-series rhythm anomaly event timeline."""

    module: str
    series_id: str
    count: int
    truncated: bool = Field(
        default=False,
        description="True when more episodes matched the window than the requested limit returned",
    )
    data: list[FrequencyEventRecord]
