"""Pydantic configuration models for otalon-clas.

Inherits from ``otalon_common.config.BaseSettings`` for JSON loading
and environment variable resolution. All pipeline behavior is controlled
by these models — no hardcoded pipeline logic.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any, Self

from otalon_common.config import BaseSettings, MissingEnvVarPolicy
from otalon_common.runtime import OTALON_CLAS_SERVICE
from pydantic import BaseModel, field_validator, model_validator

if TYPE_CHECKING:
    from otalon_clas.runtime.runtime_config_repository import RuntimeConfigRepository


class InfluxConfig(BaseModel):
    """InfluxDB connection configuration."""

    url: str
    token: str


class PostgresConfig(BaseModel):
    """PostgreSQL connection configuration."""

    dsn: str


class LoggingConfig(BaseModel):
    """Logging configuration."""

    level: str = "INFO"
    file: str = ""

    @field_validator("level")
    @classmethod
    def _validate_level(cls, v: str) -> str:
        """Ensure the log level is a known level string."""
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = v.upper()
        if upper not in allowed:
            msg = f"Invalid log level '{v}'. Must be one of {sorted(allowed)}."
            raise ValueError(msg)
        return upper


class ModelsConfig(BaseModel):
    """ML model storage configuration."""

    dir: str


class PcapFlaggingConfig(BaseModel):
    """PCAP anomaly flagging configuration."""

    enabled: bool = False
    pcap_recorder_url: str = ""
    timeout_seconds: int = 10


class FrequencyMonitorParams(BaseModel):
    """Frequency/presence monitor parameters.

    ``absence_recovery_cycles`` is the episode hysteresis: how many
    consecutive detection cycles must observe a series again before its
    absence episode counts as closed. It defaults to ``min_intervals``
    worth of evidence so a single relayed packet during a sustained
    disruption cannot tear one silence into many short anomaly rows.

    ``absence_interval_cap_seconds`` is the upper bound on
    ``mean_interval`` for which absence monitoring is active. Profiles
    whose ``mean_interval`` exceeds this cap are silently excluded from
    absence checking: the deadline would be so far in the future
    (``cap * absence_factor``, up to several days) that it is never
    reached in practice, making such profiles effectively blind to
    absence. The default 86400 s (1 day) limits the worst-case absence
    deadline to 3 days at the default factor of 3, which is still
    actionable while keeping very slow profiles (e.g. 2.8-day-polled
    SNMP) from being permanently exempt from absence detection as a
    side effect of an unreachable deadline.

    ``absence_timeout_std_factor`` adds a standard-deviation-aware timeout
    term. It protects high-variance series, where standard deviation
    approaches the mean, from false absence timeouts derived purely from
    the mean interval.
    """

    frequency_tolerance_factor: float = 2.0
    absence_timeout_factor: float = 3.0
    absence_timeout_std_factor: float = 3.0
    min_intervals: int = 5
    relative_floor_factor: float = 0.5
    absence_recovery_cycles: int = 5
    absence_timeout_floor_seconds: float = 0.0
    absence_timeout_margin_seconds: float = 10.0
    absence_interval_cap_seconds: float = 86400.0


class FrequencyMonitorConfig(BaseModel):
    """Frequency/presence monitor configuration."""

    enabled: bool = True
    params: FrequencyMonitorParams = FrequencyMonitorParams()


class PreprocessorConfig(BaseModel):
    """Preprocessor selection and parameters."""

    type: str
    params: dict[str, Any] = {}


class ClassificationConfig(BaseModel):
    """ML classification configuration per module.

    Two independent flags control behaviour:

    * ``enabled`` gates the LIVE-prediction classification pass. It is
      driven by ``$PREDICTION_CLASSIFICATION_ENABLED`` and is mandatorily
      ``True`` in live operation.
    * ``training_enabled`` gates the ML training stage of the boot
      training pipeline. It is driven by ``$TRAINING_CLASSIFICATION_ENABLED``
      and defaults to ``False`` so a plain ``TRAINING_ENABLED=true`` boot
      only runs the bounds + frequency calibration. A boundary retrain
      triggered by the chat-orchestrator MUST leave this flag at
      ``False`` so the productive ``conn_classifier.joblib`` is not
      silently overwritten (see ``.dev/concepts/ml-training-decoupling.md``).

    The optional ``train_window_start``/``train_window_stop`` fields
    define a dedicated time window for ML training data (typically a
    labeled attack-rich window). When unset, ML training reuses the
    bounds training window.
    """

    enabled: bool = True
    training_enabled: bool = False
    algorithm: str = "decision_tree"
    params: dict[str, Any] = {}
    confidence_threshold: float = 0.5
    label_field: str = "module_name"
    mitre_technique_file: str = ""
    balance_per_class: int = 1000
    random_seed: int = 2025
    force_publish_class_set_shrink: bool = False


class ModuleConfig(BaseModel):
    """Per-module pipeline configuration."""

    name: str
    enabled: bool = False
    database: str = "netcap"
    measurement: str
    tag_key: str
    features: list[str]
    blacklist: str | list[str] = ""
    preprocessor: PreprocessorConfig
    bounds_enabled: bool = True
    frequency_monitor: FrequencyMonitorConfig = FrequencyMonitorConfig()
    classification: ClassificationConfig = ClassificationConfig()


class TrainWindowConfig(BaseModel):
    """Training time window boundaries."""

    start: str = ""
    stop: str = ""


class PerFeatureOverride(BaseModel):
    """Per-feature bounds parameter overrides."""

    bounds_variation: float | None = None
    upper_bound_min: float | None = None


class BoundaryTrainingConfig(BaseModel):
    """Boundary/bounds training configuration."""

    quantile: float = 0.0001
    bounds_variation: float = 0.2
    upper_bound_min: float = 2.0
    min_series_coverage_hours: float = 5.0
    time_column: str = "time"
    per_feature_overrides: dict[str, PerFeatureOverride] = {}


class TrainingConfig(BaseModel):
    """Top-level training configuration."""

    boundary: BoundaryTrainingConfig = BoundaryTrainingConfig()


class LivePredictionConfig(BaseModel):
    """Live mode prediction parameters.

    ``delay_seconds`` must cover the ingestion latency of the upstream
    ``otalon-capture`` writer. Measured on the ICS testbed 2026-09-02 at
    5-9 s (idle); 15 s leaves ~6 s headroom while halving the structural
    detection latency (poll + delay). The live window pointer advances
    irreversibly, so a shorter delay permanently drops late-arriving rows
    instead of allowing a later read to recover them — do not go below the
    measured worst case without re-measuring under load.
    """

    poll_interval_seconds: int = 5
    delay_seconds: int = 15
    grouping_interval_seconds: int = 10


class OfflinePredictionConfig(BaseModel):
    """Offline replay prediction parameters.

    STALE/BLOCKED (see CLAS-032-DOC): not exercised since the full otalon-clas
    (formerly cyberclas) refactor; the underlying idea (replay a fixed
    historical window through prediction) remains sound but is unverified
    against the current pipeline. Code is intentionally kept, not deleted.
    The static ``.env``/``.env.compose`` knobs that used to drive this
    (``PREDICTION_OFFLINE_ENABLED/START/STOP``) were removed in SUITE-027;
    re-wire via config.json or a dedicated API trigger before reactivating.
    """

    enabled: bool = False
    start: str = ""
    stop: str = ""
    poll_interval_seconds: int = 5
    gap_tolerance_seconds: int = 30

    @model_validator(mode="after")
    def _validate_offline_window(self) -> OfflinePredictionConfig:
        """Ensure start and stop are set when offline mode is enabled."""
        if self.enabled and (not self.start or not self.stop):
            msg = "prediction.offline.start and stop are required when offline mode is enabled."
            raise ValueError(msg)
        return self


class ScoringWeightsConfig(BaseModel):
    """Composite scoring weight parameters."""

    rate: float = 0.60
    coverage: float = 0.20
    persist: float = 0.20
    severity: float = 0.0


class ScoringConfig(BaseModel):
    """Anomaly grouping scoring configuration."""

    weights: ScoringWeightsConfig = ScoringWeightsConfig()
    ml_primary_min_mean_confidence: float = 0.80
    ml_primary_min_event_sum: float = 2.0
    ml_over_bound_score_ratio: float = 0.50
    ml_multi_type_confidence_gap_ratio: float = 0.25


class AnomalyGroupingConfig(BaseModel):
    """Anomaly grouping configuration."""

    protocol_penalties: dict[str, float] = {
        "Ethernet:ARP": 0.6,
        "Ethernet:IPv4:TCP": 0.8,
        "Ethernet:IPv4:UDP": 0.8,
    }
    min_same_feature_violations_per_series: int = 2
    min_violated_features_per_interval: int = 1
    scoring: ScoringConfig = ScoringConfig()


class PredictionConfig(BaseModel):
    """Top-level prediction configuration."""

    live: LivePredictionConfig = LivePredictionConfig()
    offline: OfflinePredictionConfig = OfflinePredictionConfig()
    anomaly_grouping: AnomalyGroupingConfig = AnomalyGroupingConfig()


class EnsembleMLStageConfig(BaseModel):
    """Ensemble ML post-processing stage configuration."""

    type: str = "ensemble_ml"
    enabled: bool = False
    algorithm: str = "gradient_boosting"
    params: dict[str, Any] = {}


class RuleBasedStageInnerConfig(BaseModel):
    """Rule-based stage inner configuration."""

    gap_tolerance_seconds: int = 10
    max_alarm_duration_seconds: int = 3600
    cross_module_correlation: bool = True
    module_weights: dict[str, float] = {
        "conn": 1.0,
        "mac_traffic": 0.8,
        "proto_traffic": 0.6,
    }


class StageConfig(BaseModel):
    """Generic post-processing stage configuration.

    Supports both ``ensemble_ml`` and ``rule_based`` stage types.
    Extra fields are allowed to support stage-type-specific sub-fields.
    """

    model_config = {"extra": "allow"}

    type: str
    enabled: bool = True


class PipelinePostProcessingConfig(BaseModel):
    """Post-processing pipeline configuration."""

    stages: list[StageConfig] = []


class GroupClassifierRandomForestConfig(BaseModel):
    """Random Forest hyperparameters for the alarm-group classifier.

    Mirrors the workshop ``ml-baseline`` defaults (300 trees, balanced
    class weight, deterministic seed) so that retraining from the same
    snapshot produces results equivalent to the offline baseline.
    """

    n_estimators: int = 300
    max_depth: int | None = None
    min_samples_leaf: int = 1
    class_weight: str | None = "balanced"
    random_state: int = 42
    n_jobs: int = -1


class GroupClassifierCrossValidationConfig(BaseModel):
    """Cross-validation configuration for group-classifier training."""

    n_splits: int = 10
    shuffle: bool = True
    random_state: int = 42


class GroupClassifierTrainingConfig(BaseModel):
    """Training configuration for the alarm-group classifier."""

    enabled: bool = False
    window_start: str = ""
    window_stop: str = ""
    ground_truth_file: str = ""
    feature_set: str = "C"
    label_time_margin_seconds: int = 30
    random_forest: GroupClassifierRandomForestConfig = GroupClassifierRandomForestConfig()
    cross_validation: GroupClassifierCrossValidationConfig = GroupClassifierCrossValidationConfig()


class GroupClassifierConfig(BaseModel):
    """Top-level group-classifier configuration.

    STALE/BLOCKED (see CLAS-031): experimental alarm-group
    MITRE classifier, not successful in evaluation so far and not used
    in production. Code is intentionally kept, not deleted, for a
    possible later retry. The static ``.env``/``.env.compose`` knobs
    that used to drive its one-shot batch training
    (``TRAINING_GROUP_CLASSIFIER_ENABLED``,
    ``GROUP_CLASSIFIER_TRAIN_WINDOW_START/STOP``) were removed in
    SUITE-027; re-supply a window via config.json or a future API
    retrain endpoint before reactivating.

    The group classifier runs after alarm grouping and replaces the
    ``primary_type`` of each alarm with a Random-Forest prediction
    (mapped to a MITRE technique label) when its confidence is at least
    ``confidence_threshold``.
    """

    enabled: bool = False
    model_path: str = ""
    confidence_threshold: float = 0.5
    training: GroupClassifierTrainingConfig = GroupClassifierTrainingConfig()


class FrequencyMonitorPersistenceConfig(BaseModel):
    """Top-level frequency-monitor persistence configuration.

    Gates whether the per-module :class:`FrequencyMonitor` instances
    persist their profiles to PostgreSQL, bootstrap-load on LIVE boot,
    and listen for cache-invalidation NOTIFYs. When ``persistence_enabled``
    is ``False`` (the default for v1), the existing RAM-only path runs
    unchanged — no PG read, no UPSERT, no NOTIFY listener.

    Cache invalidation: an active LISTEN on the
    ``frequency_profile_changed`` channel handles MCP-tool overrides
    immediately. ``refresh_interval_seconds`` is the safety-net
    periodic refresh that catches missed notifies / listener reconnects.

    ``last_seen_flush_interval_seconds`` is the minimum spacing between
    two batched writes of the runtime ``last_seen`` values back to
    PostgreSQL. Without that write-back the persisted column freezes at
    the last training run. Batching keeps it off the 5 s live-poll
    cadence; see ``FrequencyMonitor.flush_last_seen``.
    """

    persistence_enabled: bool = False
    notify_channel: str = "frequency_profile_changed"
    refresh_interval_seconds: int = 60
    absence_timeout_margin_seconds: float = 10.0
    last_seen_flush_interval_seconds: int = 60


class SuppressionConfig(BaseModel):
    """Anomaly-suppression and low-signal drop configuration.

    Controls the gate the persistence layer applies BEFORE writing rows
    to ``anomalies`` / ``alarms``:

    * ``suppression_cache_ttl_s`` caches the active suppression list per
      batch; longer TTLs reduce DB pressure but increase the staleness
      of newly-added suppressions.
    * ``ml_confidence_persist_threshold`` is the lower bound under which
      a pure-false-positive row (severity 0, no violated features) is
      dropped when ``drop_low_signal_anomalies`` is enabled.
    * ``drop_low_signal_anomalies`` is the master switch for the
      low-signal drop. Default true; operators can disable for
      verbose-persistence debugging.
    """

    suppression_cache_ttl_s: int = 30
    ml_confidence_persist_threshold: float = 0.60
    drop_low_signal_anomalies: bool = True


class PortRuleRefreshConfig(BaseModel):
    """Port-collapse rule refresh thread configuration (CLAS-033).

    Static defaults are loaded from ``config.json``; every field is
    hot-overridable at runtime via ``runtime_config`` keys under
    ``detection.conn.port_rule_refresh.*`` without a process restart. The
    refresh thread re-reads the overrides each cycle via :meth:`resolve`.
    """

    enabled: bool = True
    interval_seconds: int = 300
    lookback_hours: int = 6
    confirm_cycles: int = 2
    min_samples: int = 2
    rotation_distinct_ports: int = 3

    def resolve(self, repo: RuntimeConfigRepository) -> PortRuleRefreshConfig:
        """Return a new config with ``runtime_config`` hot-overrides applied.

        Every key falls back to this config's static default when no
        ``runtime_config`` row exists, so the result is always complete.

        Args:
            repo: Runtime configuration repository to read overrides from.

        Returns:
            A new :class:`PortRuleRefreshConfig` with effective values.
        """
        prefix = "detection.conn.port_rule_refresh"
        return PortRuleRefreshConfig(
            enabled=repo.get_bool(OTALON_CLAS_SERVICE, f"{prefix}.enabled", default=self.enabled),
            interval_seconds=repo.get_int(
                OTALON_CLAS_SERVICE,
                f"{prefix}.interval_seconds",
                default=self.interval_seconds,
            ),
            lookback_hours=repo.get_int(
                OTALON_CLAS_SERVICE,
                f"{prefix}.lookback_hours",
                default=self.lookback_hours,
            ),
            confirm_cycles=repo.get_int(
                OTALON_CLAS_SERVICE,
                f"{prefix}.confirm_cycles",
                default=self.confirm_cycles,
            ),
            min_samples=repo.get_int(
                OTALON_CLAS_SERVICE,
                f"{prefix}.min_samples",
                default=self.min_samples,
            ),
            rotation_distinct_ports=repo.get_int(
                OTALON_CLAS_SERVICE,
                f"{prefix}.rotation_distinct_ports",
                default=self.rotation_distinct_ports,
            ),
        )


class AppConfig(BaseSettings):
    """Root application configuration for otalon-clas.

    Inherits ``from_json()`` and ENV placeholder resolution from
    ``otalon_common.config.BaseSettings``, pinning ``json_arrays=True`` so a
    JSON-array-shaped environment value such as ``SERIES_BLACKLIST`` becomes
    a list instead of one long string (CLAS-038).

    ``expand_nested`` stays False: no otalon-clas placeholder references a
    further variable, and secrets such as ``POSTGRES_DSN`` may legitimately
    contain a ``$`` that ``expandvars`` would silently eat.
    """

    influx: InfluxConfig
    postgres: PostgresConfig
    logging: LoggingConfig = LoggingConfig()
    models: ModelsConfig
    pcap_flagging: PcapFlaggingConfig = PcapFlaggingConfig()
    modules: list[ModuleConfig] = []
    training: TrainingConfig = TrainingConfig()
    prediction: PredictionConfig = PredictionConfig()
    pipeline_post_processing: PipelinePostProcessingConfig = PipelinePostProcessingConfig()
    group_classifier: GroupClassifierConfig = GroupClassifierConfig()
    suppression: SuppressionConfig = SuppressionConfig()
    frequency_monitor: FrequencyMonitorPersistenceConfig = FrequencyMonitorPersistenceConfig()
    port_rule_refresh: PortRuleRefreshConfig = PortRuleRefreshConfig()

    @classmethod
    def from_json(
        cls,
        path: str | Path,
        env_policy: MissingEnvVarPolicy = MissingEnvVarPolicy.RAISE,
        default: str | None = None,
        json_arrays: bool = True,
        expand_nested: bool = False,
    ) -> Self:
        """Load settings from a JSON config file, resolving ``$ENV_VAR``.

        Args:
            path: Path to the JSON configuration file.
            env_policy: Policy for missing variables; RAISE by default.
            default: Fallback value when env_policy is USE_DEFAULT.
            json_arrays: Parse JSON-looking values as JSON. True by default so
                ``SERIES_BLACKLIST`` resolves to a list of patterns.
            expand_nested: Expand nested ``$`` references in resolved values.

        Returns:
            A validated settings instance.
        """
        return super().from_json(
            path,
            env_policy=env_policy,
            default=default,
            json_arrays=json_arrays,
            expand_nested=expand_nested,
        )

    def get_enabled_modules(self) -> list[ModuleConfig]:
        """Return only modules where ``enabled`` is True.

        Returns:
            Filtered list of active module configurations.
        """
        return [m for m in self.modules if m.enabled]
