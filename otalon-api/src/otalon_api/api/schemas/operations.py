"""Operations API request/response schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

SourceState = Literal["current", "stale", "no-data"]
Priority = Literal["High", "Medium", "Low"]

# QUA-12 — length bounds for operator-supplied free text that is persisted
# verbatim into unbounded ``text`` audit columns. The caps are far above
# every real value: the longest live series id is 113 characters and the
# module names are single words.
MAX_MODULE_LENGTH = 64
MAX_SERIES_ID_LENGTH = 512
MAX_REASON_LENGTH = 2000


class PipelineSource(BaseModel):
    """Freshness state for a single pipeline source."""

    name: str
    last_record: datetime | None
    age_seconds: int | None
    state: SourceState
    records_per_hour: int
    expected_interval_seconds: int


class PipelineInflux(BaseModel):
    """Latest observed record across the monitored source measurements.

    This is **not** an independent InfluxDB write-health probe. ``last_write``
    is the most recent ``last_record`` timestamp observed across the monitored
    source measurements (``network_metrics``/``mac_traffic``/``proto_traffic``)
    — i.e. the freshest monitored-source record seen — and ``age_seconds`` is
    its age. It reflects observed source freshness, not Influx server health.
    """

    last_write: datetime | None = Field(
        default=None,
        description=(
            "Timestamp of the latest record observed across the monitored "
            "source measurements (not an independent Influx write probe)."
        ),
    )
    age_seconds: int | None = Field(
        default=None,
        description="Age in seconds of the latest observed monitored-source record.",
    )


class PipelineDetection(BaseModel):
    """Detection-cycle freshness metadata."""

    last_cycle: datetime | None
    age_seconds: int | None
    duration_seconds: float | None
    series_evaluated: int | None


class PipelineResponse(BaseModel):
    """Read-only pipeline freshness envelope."""

    sources: list[PipelineSource]
    influx: PipelineInflux
    detection: PipelineDetection
    backlog: int | None


PassiveFreshness = Literal["current", "stale", "no-data"]


class PassiveDiscoveryStatus(BaseModel):
    """Read-only Passive Discovery producer status.

    Every field is derived from persisted ``network_interfaces`` rows
    tagged ``source='passive'`` (written by the
    ``otalon-scan-passive-seeder`` container). This surface is
    read-only: ``runtime_control_enabled`` is always ``False`` because
    the seeder is boot/env-managed and no runtime enable/disable or
    reconfigure control plane is implemented (UI-015 deferred). It never
    reflects seeder process/container health or generic API liveness.
    """

    observed_asset_count: int = Field(
        default=0,
        description="Distinct devices carrying a persisted passive interface.",
    )
    observed_interface_count: int = Field(
        default=0,
        description="Persisted passive network-interface rows (source='passive').",
    )
    latest_seen_at: datetime | None = Field(
        default=None,
        description="Most recent persisted last_seen_passive_at timestamp.",
    )
    first_seen_at: datetime | None = Field(
        default=None,
        description="Earliest persisted first_seen_passive_at timestamp.",
    )
    age_seconds: int | None = Field(
        default=None,
        description="Age in seconds of latest_seen_at, or null when no-data.",
    )
    freshness: PassiveFreshness = Field(
        default="no-data",
        description="current when the latest observation is fresh, stale when old, no-data when never observed.",
    )
    runtime_control_enabled: bool = Field(
        default=False,
        description=(
            "Always false — passive discovery is boot/env-managed and no "
            "runtime control plane exists yet (UI-015 deferred)."
        ),
    )


class AttentionFindingLink(BaseModel):
    """Navigation target for an attention finding."""

    label: str
    route: str


class AttentionFinding(BaseModel):
    """Single ranked operational attention finding."""

    priority: Priority
    kind: str
    title: str
    link: AttentionFindingLink


class AttentionResponse(BaseModel):
    """Ranked list of operational attention findings."""

    findings: list[AttentionFinding]


# ---------------------------------------------------------------------------
# Jobs & Change Audit (UI-075 Wave B)
# ---------------------------------------------------------------------------


class JobListItem(BaseModel):
    """Compact job row returned by ``GET /operations/jobs``."""

    id: int
    display_id: str
    type: str
    title: str
    state: str
    trigger: str
    actor: str | None = None
    started_at: datetime
    ended_at: datetime | None = None
    latest_event: str | None = None
    can_cancel: bool = False
    can_retry: bool = False


class JobDetail(JobListItem):
    """Full job detail including params, phase and log."""

    phase_current: int | None = None
    phase_total: int | None = None
    phase_label: str | None = None
    params: dict[str, Any] = Field(default_factory=dict)
    log: list[Any] = Field(default_factory=list)
    error: str | None = None
    result: str | None = None
    retried_as_id: int | None = None


class JobsListResponse(BaseModel):
    """Envelope for a filterable list of operations jobs."""

    items: list[JobListItem]
    total: int


class JobActionResponse(BaseModel):
    """Response for cancel/retry actions."""

    success: bool
    job: JobDetail | None = None
    message: str | None = None


class AuditListItem(BaseModel):
    """Single Change Audit row returned by ``GET /operations/audit``."""

    id: int
    at: datetime
    category: str
    actor: str
    action: str
    target: str
    reason: str | None = None
    detail: str | None = None


class AuditListResponse(BaseModel):
    """Envelope for a filterable Change Audit list."""

    items: list[AuditListItem]
    total: int


class CaptureStatus(BaseModel):
    """Read-only capture status for the Data Sources page.

    Proxied verbatim from the pcap_recorder ``GET /status`` endpoint. Every
    field is nullable so the endpoint never fabricates a value the recorder
    could not source. ``recording`` reflects the recorder's live capture
    subprocess state, ``interface`` its configured capture interface, and
    ``link_up`` the host carrier state observed by the recorder. All fields
    fall back to ``None`` when the recorder is unreachable or times out.
    """

    interface: str | None = Field(
        default=None,
        description="Configured capture interface name (from recorder config).",
    )
    link_up: bool | None = Field(
        default=None,
        description="Interface carrier state observed by the recorder, if known.",
    )
    recording: bool | None = Field(
        default=None,
        description="Recorder capture-process state; None when unreachable.",
    )
    drops_24h_pct: float | None = Field(
        default=None,
        description="Percentage of packets dropped in the last 24 h, if known.",
    )
    overflows: int | None = Field(
        default=None,
        description="Capture buffer overflow events in the last 24 h, if known.",
    )


class DetectionReadinessItem(BaseModel):
    """Derived readiness facts for one detection module."""

    module: str
    state: str
    detection_mode: str
    bounds_series_count: int
    no_bounds_count: int
    no_bounds_event_count: int | None = None
    no_bounds_series_count: int | None = None
    frequency_profile_count: int
    last_training: datetime | None
    schema_version: str
    schema_compatible: bool
    classification_state: str | None = None
    bounds_state: str | None = None
    frequency_state: str | None = None


class DetectionReadinessResponse(BaseModel):
    """Readiness response for all configured detection modules."""

    modules: list[DetectionReadinessItem]
    live_poll_interval_seconds: int = 5


class BoundReviewTimelineEvent(BaseModel):
    """A structured, truthful event on a Series/UCI timeline.

    ``features`` lists real bound violations for bounded events, or tracked
    module features for NoBounds events; it is never inferred by index.
    """

    ts: datetime
    type: str
    features: list[str] = Field(default_factory=list)


class BoundReviewItem(BaseModel):
    """One aggregated Series/UCI envelope in Bound Review."""

    module: str
    series_id: str
    series_display: str | None = None
    available_features: list[str] = Field(default_factory=list)
    feature: str | None = None
    current_bounds: dict[str, Any] = Field(default_factory=dict)
    state: str
    lower: Any = None
    upper: Any = None
    violation_count: int
    nobounds_count: int = 0
    last_event: datetime | None = None
    latest_event_ts: datetime | None = None
    latest_event_type: str | None = None
    affected_features: list[str] = Field(default_factory=list)
    timeline: list[datetime] = Field(default_factory=list)
    timeline_events: list[BoundReviewTimelineEvent] = Field(default_factory=list)
    has_bounds: bool = True
    last_trained_at: datetime | None = None
    ok: bool = False


class BoundsCorrectionPreviewRequest(BaseModel):
    """Requested before/after bounds for a non-mutating preview.

    ``module``/``series_id``/``reason`` are length-bounded (QUA-12): the
    resolved series and the reason are persisted verbatim into the
    immutable ``operations_audit`` row, whose columns are unbounded
    ``text``. The caps are far above every real value (longest live
    series id: 113 chars).
    """

    module: str = Field(min_length=1, max_length=MAX_MODULE_LENGTH)
    series_id: str | None = Field(default=None, max_length=MAX_SERIES_ID_LENGTH)
    action: Literal["expand", "replace", "create"]
    before: dict[str, Any]
    after: dict[str, Any]
    reason: str = Field(default="", max_length=MAX_REASON_LENGTH)


class BoundsCorrectionApplyRequest(BoundsCorrectionPreviewRequest):
    """One-click correction request.

    Apply carries the operator-previewed ``before``/``after`` envelope. The
    route internally re-runs the non-mutating server validation, compares the
    ``before`` snapshot under lock (stale-before guard), then performs the
    canonical audited job/history mutation. Reason is optional; there is no
    typed confirmation phrase in this contract.
    """


class BoundReviewResponse(BaseModel):
    """Filterable Bound Review response."""

    items: list[BoundReviewItem]
    total: int


class BoundSuggestionRequest(BaseModel):
    """Read-only request for a server-computed bound proposal."""

    module: Literal["conn", "mac_traffic", "proto_traffic"]
    series_id: str = Field(min_length=1, max_length=MAX_SERIES_ID_LENGTH)
    action: Literal["expand", "replace", "create"]
    from_: datetime = Field(alias="from")
    to: datetime

    model_config = {"populate_by_name": True}

    @model_validator(mode="after")
    def validate_window(self) -> "BoundSuggestionRequest":
        """Require a non-empty strict half-open window."""
        if self.from_ >= self.to:
            raise ValueError("from must be before to for a strict [from, to) window")
        return self


class BoundSuggestionFeature(BaseModel):
    """Evidence and deterministic rationale for one proposed feature."""

    evidence_count: int = Field(ge=0)
    lower_rationale: str
    upper_rationale: str


class BoundSuggestionResponse(BaseModel):
    """Truthful suggestion; evidence_count is numeric observations, status is feature coverage."""

    module: str
    series_id: str
    action: Literal["expand", "replace", "create"]
    status: Literal["available", "partial", "unavailable"]
    window_from: datetime
    window_to: datetime
    evidence_count: int = Field(
        ge=0,
        description="Total numeric observations across all features in the strict window.",
    )
    current: dict[str, Any]
    proposed: dict[str, Any]
    rationale: dict[str, BoundSuggestionFeature]
    message: str


class BoundsCorrectionRequest(BaseModel):
    """Operator request for a complete bounds envelope.

    ``series_id`` is optional and, when present, authoritatively identifies
    the target series. Real UCIs contain ``/`` which cannot survive an ASGI
    path segment cleanly across every client; the body field is the robust
    channel while the ``{series}`` path segment stays for URL readability.
    """

    module: str = Field(min_length=1, max_length=MAX_MODULE_LENGTH)
    lower_bounds: dict[str, Any]
    upper_bounds: dict[str, Any]
    reason: str = Field(min_length=1, max_length=MAX_REASON_LENGTH)
    series_id: str | None = Field(default=None, max_length=MAX_SERIES_ID_LENGTH)


class ArtifactManifestItem(BaseModel):
    """Read-only classifier metadata and artifact status."""

    artifact: str
    status: str
    model_config = {"extra": "allow"}


class ArtifactManifestResponse(BaseModel):
    """Read-only classifier artifact manifest."""

    items: list[ArtifactManifestItem]


class StorageResponse(BaseModel):
    """Truthful host and contributor storage accounting."""

    host: dict[str, Any]
    ringbuffer: dict[str, Any]
    contributors: list[dict[str, Any]]
    unattributed_gb: float = 0.0


class BackupRequest(BaseModel):
    """Selected backup scope."""

    scope: list[str] = Field(min_length=1)


class ResetPreviewRequest(BaseModel):
    """Read-only reset impact request for one database target."""

    scope: Literal["anomaly-history", "trained-bounds", "detection-results", "factory"]


class InfluxResetPreviewRequest(BaseModel):
    """Read-only InfluxDB reset impact request."""

    scope: Literal["timeseries", "factory"]


class RestoreRequest(BaseModel):
    """Restore scope and typed confirmation."""

    scope: list[str] = Field(min_length=1)
    confirmation: str | None = None
    dry_run: bool = True
    artifact_id: str | None = None


class ResetRequest(BaseModel):
    """Named reset request with mandatory operator confirmation.

    ``dry_run`` defaults to ``True`` so the live unattended run only exercises
    the precheck/rejection path; a real reset requires an explicit
    ``dry_run=false`` plus the exact typed confirmation phrase and (for factory)
    a fresh verified backup.
    """

    scope: Literal["anomaly-history", "trained-bounds", "detection-results", "factory"]
    reason: str = Field(min_length=1, max_length=MAX_REASON_LENGTH)
    confirmation: str = Field(min_length=1, max_length=200)
    dry_run: bool = True


class SupportBundleRequest(BaseModel):
    """Local support bundle destination."""

    output_dir: str = "bundles"


class ServiceActionRequest(BaseModel):
    """Allowlisted service lifecycle action."""

    action: Literal["up", "stop", "restart", "recreate"]
    service: str = Field(min_length=1)
    confirmation: str | None = None


class HealthIncidentSample(BaseModel):
    """Bounded canonical probe sample included in incident detail."""

    service: str
    owning_service: str = ""
    probe_target: str = ""
    running: bool
    in_budget: bool = False
    category: str
    cause: str
    latency_ms: float
    latency_budget_ms: float
    timestamp: datetime | float | None
    detail: str


class HealthIncidentSummary(BaseModel):
    """Backend-owned health incident evidence summary."""

    id: str
    service: str
    owning_service: str = ""
    probe_target: str = ""
    system_service_id: str | None = None
    category: str
    cause: str
    status: Literal["active", "recovered"]
    first_seen: datetime
    last_seen: datetime
    recovered_at: datetime | None
    sample_count: int
    failure_count: int
    latency_budget_ms: float
    worst_latency_ms: float
    acknowledged: bool = False
    acknowledged_at: datetime | None = None
    acknowledged_by: str | None = None
    evidence_type: Literal["operational_health"]
    samples: list[HealthIncidentSample] | None = None


class HealthIncidentListResponse(BaseModel):
    """Bounded health incident history response."""

    items: list[HealthIncidentSummary]
    retention: dict[str, int]
