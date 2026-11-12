"""Orchestration module for otalon-clas anomaly detection pipeline.

Handles startup, mode dispatch (training / offline / live), and per-module
detection cycles including bounds checking, frequency monitoring, ML
classification, result fusion, anomaly persistence, and alarm grouping.
"""

from __future__ import annotations

import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping, Protocol, cast, overload

import numpy as np
import polars as pl
from loguru import logger
from otalon_common.config import MissingEnvVarPolicy
from otalon_common.connection import DynamicBucketConfig, PortCollapseConfig
from otalon_common.logging import configure_logging

from otalon_clas.common.artifact_integrity import ArtifactIntegrityError
from otalon_clas.common.config_validator import validate_config
from otalon_clas.common.influx_connector import InfluxModule
from otalon_clas.common.model_store import ModelStore
from otalon_clas.common.pcap_flag_client import PcapFlagClient
from otalon_clas.common.postgres_connector import (
    Alarm,
    AnomalyRecord,
    PostgresConnector,
)
from otalon_clas.common.settings import (
    AppConfig,
    ModuleConfig,
    RuleBasedStageInnerConfig,
)
from otalon_clas.detection.anomaly_persister import AnomalyPersister
from otalon_clas.detection.bounds_manager import (
    BoundsManager,
    BoundsRepository,
    BoundsTrainer,
)
from otalon_clas.detection.frequency_monitor import (
    ABSENCE_ANOMALY,
    FREQUENCY_ANOMALY,
    FrequencyMonitor,
    FrequencyResult,
)
from otalon_clas.detection.frequency_profile_repository import (
    FrequencyProfileInvalidator,
    FrequencyProfileRepository,
)
from otalon_clas.detection.fusion import fuse_results
from otalon_clas.detection.grouping import (
    apply_group_classification,
    fetch_alarms_pending_classification,
)
from otalon_clas.detection.series_blacklist import SeriesBlacklist
from otalon_clas.detection.suppression import SuppressionService
from otalon_clas.ml.group_classifier import (
    GroupAlarmLabeler,
    GroupClassifier,
    GroupClassifierStore,
    GroupClassifierTrainer,
    GroupClassifierTrainingRepository,
    extract_alarm_features,
)
from otalon_clas.ml.pipeline import MLPipeline
from otalon_clas.ml.registry import get_backend
from otalon_clas.pipeline.builder import PipelineBuilder
from otalon_clas.preprocessing.connection import ConnectionPreprocessor
from otalon_clas.preprocessing.port_rules_repository import (
    PortCollapseRulesRepository,
)
from otalon_clas.preprocessing.registry import get_preprocessor
from otalon_clas.runtime.bounds_invalidator import BoundsInvalidator
from otalon_clas.runtime.module_bundle import InferenceModel, ModuleBundle
from otalon_clas.runtime.port_rule_refresher import PortRuleRefresher
from otalon_clas.runtime.runtime_config_repository import RuntimeConfigRepository
from otalon_clas.runtime.runtime_keys import register_runtime_keys
from otalon_clas.runtime.runtime_supervisor import RuntimeSupervisor
from otalon_clas.runtime.series_blacklist_source import SeriesBlacklistSource


class MLPredictionError(RuntimeError):
    """A structural fault in the ML prediction path.

    Raised for conditions that will recur on every tick — a mismatch
    between the deployed model and the configured features, absent
    feature or join columns, or a failure inside the model itself. These
    used to be swallowed by a blanket ``except Exception`` that logged
    and returned ``None``, so classification silently stayed off while
    the UI showed untyped anomalies indistinguishable from "no attack
    detected" (audit CLAS-03).
    """


def main() -> None:
    """Application entry point: load config, initialize components, dispatch mode."""
    register_runtime_keys()
    config = _load_config()
    _setup_logging(config)
    logger.info("otalon-clas starting")

    errors = validate_config(config)
    if errors:
        logger.error("Configuration validation failed with {} errors", len(errors))
        sys.exit(1)

    pg = _init_postgres(config)
    pcap_client = _init_pcap_client(config)
    model_store = ModelStore(models_dir=config.models.dir)
    bounds_repository = BoundsRepository(connector=pg)
    rules_repository = PortCollapseRulesRepository(connector=pg)
    frequency_repository = _init_frequency_repository(config, pg)
    bundles = _build_module_bundles(config, bounds_repository, rules_repository, frequency_repository)
    pipeline_builder = PipelineBuilder(
        config=config.pipeline_post_processing,
        grouping_config=config.prediction.anomaly_grouping,
    )

    logger.info("Initialized {} enabled module(s)", len(bundles))

    try:
        _dispatch_mode(config, pg, pcap_client, model_store, bundles, pipeline_builder)
    finally:
        _shutdown(bundles, pg)


def _load_config() -> AppConfig:
    """Load and validate the application configuration from JSON.

    ``SERIES_BLACKLIST`` is the conn-module boot fallback and may be
    legitimately unset — the ``runtime_config`` row
    ``detection.series_blacklist`` is the primary source (CLAS-071). An
    unset variable resolves to an empty blacklist instead of failing
    boot under the RAISE policy, which stays in force for every other
    placeholder because the resolver's missing-variable policy is
    global per call.

    Returns:
        Parsed and validated AppConfig instance.
    """
    os.environ.setdefault("SERIES_BLACKLIST", "[]")
    config = AppConfig.from_json("config/config.json", env_policy=MissingEnvVarPolicy.RAISE)
    logger.info("Configuration loaded successfully")
    return config


def _setup_logging(config: AppConfig) -> None:
    """Configure loguru logging from the application config.

    Retention is set explicitly to 14 days (SUITE-066) so rotated log
    files are pruned regardless of defaults drifting in
    ``configure_logging``.

    Args:
        config: Application configuration with logging settings.
    """
    log_file = config.logging.file if config.logging.file else None
    configure_logging(
        log_file=log_file,
        console_level=config.logging.level,
        retention="14 days",
    )


@dataclass(frozen=True)
class DetectionOutcome:
    """Result of one module detection window.

    ``fused`` carries the bounds/frequency/ML fusion DataFrame for the
    series observed in the window. ``absence_results`` carries the
    verdicts for series that were NOT observed — they cannot appear in
    ``fused`` because fusion is shaped by the bounds DataFrame, which
    only has rows for observed series.
    """

    fused: pl.DataFrame | None
    absence_results: list[FrequencyResult]
    observed_at: datetime


@dataclass(frozen=True, slots=True)
class LiveDetectionGateSnapshot:
    """Immutable live detection gates for one polling tick."""

    bounds_enabled: Mapping[str, bool] = field(default_factory=dict)
    classification_enabled: Mapping[str, bool] = field(default_factory=dict)
    frequency_enabled: Mapping[str, bool] = field(default_factory=dict)
    series_blacklist: SeriesBlacklist | None = None

    def __post_init__(self) -> None:
        """Freeze gate mappings so workers share one stable snapshot."""
        object.__setattr__(self, "bounds_enabled", MappingProxyType(dict(self.bounds_enabled)))
        object.__setattr__(
            self,
            "classification_enabled",
            MappingProxyType(dict(self.classification_enabled)),
        )
        object.__setattr__(self, "frequency_enabled", MappingProxyType(dict(self.frequency_enabled)))

    def for_module(self, module_name: str) -> tuple[bool, bool]:
        """Return effective bounds and classification gates."""
        return (
            self.bounds_enabled[module_name],
            self.classification_enabled[module_name],
        )


class LiveGateRepository(Protocol):
    """Protocol for the boolean runtime reads needed by one live tick."""

    @overload
    def get_bool(
        self,
        service: str,
        key: str,
        default: None = None,
    ) -> bool | None: ...
    @overload
    def get_bool(
        self,
        service: str,
        key: str,
        default: bool,
    ) -> bool: ...

    def get_bool(
        self,
        service: str,
        key: str,
        default: bool | None = None,
    ) -> bool | None:
        """Read one persisted boolean runtime value."""


def _init_postgres(config: AppConfig) -> PostgresConnector:
    """Initialize the PostgreSQL connector and create tables.

    Args:
        config: Application configuration with database settings.

    Returns:
        Ready-to-use PostgresConnector.
    """
    pg = PostgresConnector(dsn=config.postgres.dsn)
    pg.create_tables()
    logger.info("PostgreSQL connector initialized, tables ensured")
    return pg


def _init_pcap_client(config: AppConfig) -> PcapFlagClient | None:
    """Initialize the PCAP flag client if enabled.

    Args:
        config: Application configuration with PCAP flagging settings.

    Returns:
        PcapFlagClient instance or None if disabled.
    """
    if not config.pcap_flagging.enabled:
        return None

    client = PcapFlagClient(
        base_url=config.pcap_flagging.pcap_recorder_url,
        timeout_seconds=config.pcap_flagging.timeout_seconds,
    )
    if client.health_check():
        logger.info("PCAP flag client connected to {}", config.pcap_flagging.pcap_recorder_url)
    else:
        logger.warning("PCAP flag client health check failed; flagging may not work")
    return client


def _init_frequency_repository(config: AppConfig, pg: PostgresConnector) -> FrequencyProfileRepository | None:
    """Build the frequency-profile repository when persistence is enabled.

    Returns ``None`` when ``frequency_monitor.persistence_enabled`` is
    ``False`` so the per-module monitors fall back to the legacy
    RAM-only path.
    """
    if not config.frequency_monitor.persistence_enabled:
        logger.info("Frequency-profile persistence is DISABLED — monitors run in RAM-only mode")
        return None
    logger.info("Frequency-profile persistence ENABLED")
    return FrequencyProfileRepository(connector=pg)


def _build_module_bundles(
    config: AppConfig,
    bounds_repository: BoundsRepository,
    rules_repository: PortCollapseRulesRepository,
    frequency_repository: FrequencyProfileRepository | None,
) -> list[ModuleBundle]:
    """Instantiate all runtime objects for each enabled module.

    Args:
        config: Application configuration.
        bounds_repository: Shared bounds repository (DB-backed).
        rules_repository: Shared port-collapse rules repository.
        frequency_repository: Shared frequency-profile repository, or
            ``None`` when persistence is disabled (legacy RAM-only mode).

    Returns:
        List of ModuleBundle instances, one per enabled module.
    """
    bundles: list[ModuleBundle] = []
    for mod in config.get_enabled_modules():
        bundle = _create_single_bundle(config, mod, bounds_repository, rules_repository, frequency_repository)
        bundles.append(bundle)
    return bundles


def _create_single_bundle(
    config: AppConfig,
    mod: ModuleConfig,
    bounds_repository: BoundsRepository,
    rules_repository: PortCollapseRulesRepository,
    frequency_repository: FrequencyProfileRepository | None,
) -> ModuleBundle:
    """Create the runtime bundle for one module.

    Args:
        config: Global application configuration.
        mod: Per-module configuration.

    Returns:
        Fully initialized ModuleBundle.
    """
    influx = InfluxModule(
        url=config.influx.url,
        token=config.influx.token,
        database=mod.database,
        measurement=mod.measurement,
        tag_key=mod.tag_key,
        features=mod.features,
        module_name=mod.name,
    )
    preprocessor_cls = get_preprocessor(mod.preprocessor.type)
    preprocessor_kwargs: dict[str, Any] = {
        "tag_key": mod.tag_key,
        "features": mod.features,
        "params": mod.preprocessor.params,
    }
    if preprocessor_cls is ConnectionPreprocessor:
        preprocessor_kwargs["module_name"] = mod.name
        preprocessor_kwargs["rules_repository"] = rules_repository
    preprocessor = preprocessor_cls(**preprocessor_kwargs)
    bounds_manager = BoundsManager(
        module_name=mod.name,
        repository=bounds_repository,
        cache_ttl_seconds=24 * 3600,
        blacklist=mod.blacklist,
    )
    bounds_trainer = BoundsTrainer(blacklist=mod.blacklist)
    freq_monitor = FrequencyMonitor(
        frequency_tolerance_factor=mod.frequency_monitor.params.frequency_tolerance_factor,
        absence_timeout_factor=mod.frequency_monitor.params.absence_timeout_factor,
        absence_timeout_std_factor=mod.frequency_monitor.params.absence_timeout_std_factor,
        min_intervals=mod.frequency_monitor.params.min_intervals,
        relative_floor_factor=mod.frequency_monitor.params.relative_floor_factor,
        absence_recovery_cycles=mod.frequency_monitor.params.absence_recovery_cycles,
        absence_timeout_floor_seconds=(
            config.prediction.live.poll_interval_seconds
            + config.prediction.live.delay_seconds
            + config.frequency_monitor.absence_timeout_margin_seconds
        ),
        absence_interval_cap_seconds=mod.frequency_monitor.params.absence_interval_cap_seconds,
        blacklist=mod.blacklist,
        repository=frequency_repository,
        module_name=mod.name,
        last_seen_flush_interval_seconds=config.frequency_monitor.last_seen_flush_interval_seconds,
    )
    backend_cls = get_backend(mod.classification.algorithm)
    backend = backend_cls(**mod.classification.params)
    ml_pipeline = MLPipeline(backend=backend, confidence_threshold=mod.classification.confidence_threshold)

    logger.info(
        "Module '{}' bundle created (preprocessor={}, algorithm={})",
        mod.name,
        mod.preprocessor.type,
        mod.classification.algorithm,
    )
    return ModuleBundle(
        config=mod,
        influx=influx,
        preprocessor=preprocessor,
        bounds_manager=bounds_manager,
        bounds_trainer=bounds_trainer,
        bounds_repository=bounds_repository,
        freq_monitor=freq_monitor,
        ml_pipeline=ml_pipeline,
    )


def _dispatch_mode(
    config: AppConfig,
    pg: PostgresConnector,
    pcap_client: PcapFlagClient | None,
    model_store: ModelStore,
    bundles: list[ModuleBundle],
    pipeline_builder: PipelineBuilder,
) -> None:
    """Dispatch execution to the appropriate mode based on configuration.

    Priority chain: training -> offline -> live.

    Args:
        config: Application configuration.
        pg: PostgreSQL connector.
        pcap_client: Optional PCAP flagging client.
        model_store: ML model persistence store.
        bundles: Per-module runtime bundles.
        pipeline_builder: Post-processing pipeline.
    """
    if _legacy_training_requested():
        logger.error(
            "Static bounds/classifier boot training is no longer supported; use "
            "POST /api/v1/training/retrain-boundaries or "
            "POST /api/v1/training/retrain-classifier"
        )
        sys.exit(1)

    # STALE/BLOCKED (see CLAS-031): experimental, not evaluated as
    # successful; env-driven boot window removed in SUITE-027. Dispatch
    # path kept intentionally for a possible later retry.
    if config.group_classifier.training.enabled:
        logger.info("Entering GROUP_CLASSIFIER_TRAINING mode")
        run_group_classifier_training(config, pg, bundles)
        logger.info("Group-classifier training complete, exiting")
        sys.exit(0)

    # STALE/BLOCKED (CLAS-032): not exercised since the otalon-clas
    # refactor; env-driven window removed in SUITE-027. Dispatch path
    # kept intentionally for a possible later retry.
    if config.prediction.offline.enabled:
        logger.info("Entering OFFLINE prediction mode")
        run_offline(config, pg, pcap_client, model_store, bundles, pipeline_builder)
        logger.info("Offline prediction complete, exiting")
        sys.exit(0)

    logger.info("Entering LIVE prediction mode")
    supervisor = RuntimeSupervisor(
        config=config,
        pg=pg,
        model_store=model_store,
        bundles=bundles,
        pipeline_builder=pipeline_builder,
    )
    supervisor.run(
        lambda: run_live(
            config,
            pg,
            pcap_client,
            model_store,
            bundles,
            pipeline_builder,
            blacklist_source=supervisor.blacklist_source,
        )
    )


def _legacy_training_requested() -> bool:
    """Detect unsupported static bounds/classifier boot training requests."""
    return os.getenv("TRAINING_ENABLED", "false").lower() == "true"


def run_group_classifier_training(
    config: AppConfig,
    pg: PostgresConnector,
    bundles: list[ModuleBundle],
) -> None:
    """Train the alarm-group Random-Forest classifier.

    Loads alarms from PostgreSQL within the configured training window,
    fetches the underlying network metric rows from InfluxDB, computes
    FS-C feature vectors per alarm, matches each alarm to a MITRE
    ground-truth label, and trains the classifier.

    Args:
        config: Application configuration.
        pg: PostgreSQL connector.
        bundles: Per-module runtime bundles. The ``conn`` bundle is
            required because the InfluxDB query is issued against the
            ``conn`` measurement.
    """
    gc_cfg = config.group_classifier
    train_cfg = gc_cfg.training

    if not train_cfg.window_start or not train_cfg.window_stop:
        logger.error("Group-classifier training: window_start/window_stop must be set")
        sys.exit(1)
    if not train_cfg.ground_truth_file:
        logger.error("Group-classifier training: ground_truth_file must be set")
        sys.exit(1)

    conn_bundle = _find_module_bundle(bundles, "conn")
    if conn_bundle is None:
        logger.error("Group-classifier training: 'conn' module bundle not found")
        sys.exit(1)

    start = _parse_window_timestamp(train_cfg.window_start)
    stop = _parse_window_timestamp(train_cfg.window_stop)
    logger.info(
        "Group-classifier training window: [{}, {}]",
        start.isoformat(),
        stop.isoformat(),
    )
    warn_on_stale_training_window(start, stop)

    repo = GroupClassifierTrainingRepository(pg=pg, influx=conn_bundle.influx)
    alarms = repo.fetch_alarms_in_window(start, stop)
    if not alarms:
        logger.error(
            "Group-classifier training: no alarms found in [{}, {}]. "
            "Run live mode against the training window first to generate alarms.",
            start.isoformat(),
            stop.isoformat(),
        )
        sys.exit(1)

    repo.prefetch_window(start, stop)

    labeler = GroupAlarmLabeler(
        ground_truth_path=train_cfg.ground_truth_file,
        time_margin_seconds=train_cfg.label_time_margin_seconds,
    )

    feature_rows: list[np.ndarray] = []
    labels: list[str] = []
    feature_names_used: list[str] = []
    skipped_no_label = 0
    skipped_no_rows = 0

    for alarm in alarms:
        label = labeler.label(alarm.start_ts, alarm.end_ts)
        if label is None:
            skipped_no_label += 1
            continue
        rows = repo.fetch_influx_rows_for_alarm(alarm)
        if rows.is_empty():
            skipped_no_rows += 1
            continue
        duration = max((alarm.end_ts - alarm.start_ts).total_seconds(), 0.0)
        vector, names = extract_alarm_features(
            influx_rows=rows,
            series_ids_count=len(alarm.series_ids),
            duration_seconds=duration,
        )
        feature_rows.append(vector)
        labels.append(label)
        feature_names_used = names

    logger.info(
        "Group-classifier training: {} usable alarms (skipped: no_label={}, no_rows={})",
        len(feature_rows),
        skipped_no_label,
        skipped_no_rows,
    )

    if not feature_rows:
        logger.error("Group-classifier training: no usable training samples after labeling")
        sys.exit(1)

    X = np.vstack(feature_rows)
    y = np.asarray(labels, dtype=object)

    label_distribution = {label: int(np.sum(y == label)) for label in sorted(set(y))}
    logger.info("Group-classifier training: label distribution = {}", label_distribution)

    store = GroupClassifierStore(model_path=gc_cfg.model_path)
    trainer = GroupClassifierTrainer(
        rf_config=train_cfg.random_forest,
        cv_config=train_cfg.cross_validation,
        store=store,
    )
    extra_metadata = {
        "training_window_start": start.isoformat(),
        "training_window_stop": stop.isoformat(),
        "ground_truth_file": train_cfg.ground_truth_file,
        "feature_set": train_cfg.feature_set,
        "label_time_margin_seconds": train_cfg.label_time_margin_seconds,
        "label_distribution": label_distribution,
        "skipped_no_label": skipped_no_label,
        "skipped_no_rows": skipped_no_rows,
    }
    result = trainer.train(
        X=X,
        y=y,
        feature_names=feature_names_used,
        extra_metadata=extra_metadata,
    )
    logger.info(
        "Group-classifier training complete — accuracy={:.4f}, macro_f1={:.4f}",
        result.accuracy_oof,
        result.macro_f1_oof,
    )


GROUP_CLASSIFIER_STALE_WINDOW_DAYS: int = 30
"""Age in days beyond which a configured training window is called stale."""


def warn_on_stale_training_window(
    start: datetime,
    stop: datetime,
    now: datetime | None = None,
) -> bool:
    """Emit a WARNING when the group-classifier training window is stale.

    The alarm-group classifier is trained through a manual batch path whose
    window is pinned in ``config.json`` rather than rolled forward by an API
    retrain job (CLAS-031). A window left untouched for months therefore
    trains on data that may no longer be retained, and used to do so
    silently. This makes that condition audible.

    Args:
        start: Configured window start.
        stop: Configured window stop.
        now: Reference time; defaults to the current UTC time.

    Returns:
        ``True`` when the window is older than
        :data:`GROUP_CLASSIFIER_STALE_WINDOW_DAYS`, else ``False``.
    """
    reference = now if now is not None else datetime.now(tz=timezone.utc)
    window_stop = stop if stop.tzinfo is not None else stop.replace(tzinfo=timezone.utc)
    window_start = start if start.tzinfo is not None else start.replace(tzinfo=timezone.utc)
    age_days = (reference - window_stop).total_seconds() / 86400.0
    if age_days <= GROUP_CLASSIFIER_STALE_WINDOW_DAYS:
        return False
    logger.warning(
        "Group-classifier training: stale training window — [{}, {}] ends {} days old "
        "(threshold {} days). This batch path has no rolling window (CLAS-031); the "
        "configured data may no longer be retained. Update "
        "group_classifier.training.window_start/window_stop before training.",
        window_start.isoformat(),
        window_stop.isoformat(),
        int(age_days),
        GROUP_CLASSIFIER_STALE_WINDOW_DAYS,
    )
    return True


def _parse_window_timestamp(value: str) -> datetime:
    """Parse a configured training-window timestamp into UTC datetime.

    Accepts both ``YYYY-MM-DD HH:MM:SS`` and ISO 8601 forms.

    Args:
        value: Configured timestamp string.

    Returns:
        UTC-aware datetime.
    """
    candidate = value.strip().replace(" ", "T")
    dt = datetime.fromisoformat(candidate)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


# ---------------------------------------------------------------------------
# Live mode
# ---------------------------------------------------------------------------

LIVENESS_MARKER_PATH: Path = Path("/tmp/otalon-clas-last-tick")
"""File whose mtime proves the live loop completed a tick.

otalon-clas is a long-running worker with no HTTP port, so a socket probe
cannot prove liveness: the process stays alive while every detection tick
raises. ``run_live`` touches this marker after a completed tick and the
container healthcheck (Dockerfile ``HEALTHCHECK``) fails when the mtime is
older than the tolerance — a hung dependency or a tick that never returns
therefore surfaces as ``(unhealthy)`` instead of a silently idle container.
The path is a container-internal liveness concern, not service
configuration, so it is a module constant rather than a ``config.json``
entry.
"""


def _touch_liveness_marker(path: Path | None = None) -> None:
    """Stamp the live-loop liveness marker with the current time.

    Failure to write the marker is logged but never fatal: a read-only
    ``/tmp`` must not take the detection pipeline down.

    Args:
        path: Marker file to create or refresh; defaults to
            :data:`LIVENESS_MARKER_PATH` resolved at call time.
    """
    target = path if path is not None else LIVENESS_MARKER_PATH
    try:
        target.touch()
    except OSError:
        logger.warning("Could not update liveness marker at {}", target)


def run_live(
    config: AppConfig,
    pg: PostgresConnector,
    pcap_client: PcapFlagClient | None,
    model_store: ModelStore,
    bundles: list[ModuleBundle],
    pipeline_builder: PipelineBuilder,
    blacklist_source: SeriesBlacklistSource | None = None,
) -> None:
    """Execute live prediction mode with concurrent polling loop.

    Each module is submitted to a thread pool. Alarm grouping fires
    independently on its own cadence.

    Args:
        config: Application configuration.
        pg: PostgreSQL connector.
        pcap_client: Optional PCAP flagging client.
        model_store: ML model persistence store.
        bundles: Per-module runtime bundles.
        pipeline_builder: Post-processing pipeline.
        blacklist_source: Shared series-blacklist runtime source owned by
            the :class:`RuntimeSupervisor` (CLAS-071). Optional so
            non-supervised invocations keep per-module boot defaults.
    """
    _load_persisted_models(model_store, bundles)
    _bootstrap_frequency_profiles(bundles)
    frequency_invalidator = _start_frequency_invalidator(config, pg, bundles)
    bounds_invalidator = _start_bounds_invalidator(config, pg, bundles)
    port_rule_refresher = _start_port_rule_refresher(config, pg, bundles)

    live_cfg = config.prediction.live
    poll_interval = live_cfg.poll_interval_seconds
    delay = live_cfg.delay_seconds
    grouping_interval = live_cfg.grouping_interval_seconds

    gap_tolerance = _compute_dynamic_gap_tolerance(grouping_interval, poll_interval, delay)
    cross_source_gap = _get_rule_based_gap_tolerance(config)
    suppression_cfg = config.suppression
    suppression_service = SuppressionService(
        connector=pg,
        cache_ttl_s=suppression_cfg.suppression_cache_ttl_s,
    )
    persister = AnomalyPersister(
        connector=pg,
        gap_tolerance_seconds=gap_tolerance,
        suppression_service=suppression_service,
        ml_confidence_persist_threshold=suppression_cfg.ml_confidence_persist_threshold,
        drop_low_signal_anomalies=suppression_cfg.drop_low_signal_anomalies,
    )

    last_timestamps: dict[str, str] = {}
    align_cache: dict[str, int] = {b.config.name: _resolve_alignment_seconds(b, poll_interval) for b in bundles}
    for mod_name, align in align_cache.items():
        logger.info(
            "Module '{}': live polling aligned to {}s buckets",
            mod_name,
            align,
        )
    last_grouping_time = time.monotonic()
    runtime_config = RuntimeConfigRepository(pg)
    continuous_recovery = None
    if os.environ.get("CONTINUOUS_RECOVERY_ENABLED", "false").lower() == "true":
        from otalon_clas.recovery.service import CaptureRecovery

        continuous_recovery = CaptureRecovery(
            bundles, pg, pipeline_builder, runtime_config, persistence_policy=persister
        )
        continuous_recovery.start()
        from otalon_clas.recovery.live_outbox import LiveOutboxPersister

        persister = LiveOutboxPersister(
            pg,
            continuous_recovery.progress,
            gap_tolerance_seconds=gap_tolerance,
            suppression_service=suppression_service,
            ml_confidence_persist_threshold=suppression_cfg.ml_confidence_persist_threshold,
            drop_low_signal_anomalies=suppression_cfg.drop_low_signal_anomalies,
        )

    group_classifier = _init_group_classifier(config)
    conn_bundle = _find_module_bundle(bundles, "conn")
    proto_bundle = _find_module_bundle(bundles, "proto_traffic")

    logger.info(
        "Live loop starting (poll={}s, delay={}s, grouping={}s, gap_tolerance={}s, group_classifier={})",
        poll_interval,
        delay,
        grouping_interval,
        gap_tolerance,
        ("active" if (group_classifier is not None and group_classifier.is_active) else "inactive"),
    )

    try:
        _touch_liveness_marker()
        while True:
            tick_start = time.monotonic()
            if continuous_recovery is not None:
                persister.retry()
            _live_tick(
                config,
                pg,
                pcap_client,
                bundles,
                pipeline_builder,
                persister,
                last_timestamps,
                poll_interval,
                delay,
                align_cache,
                runtime_config=runtime_config,
                blacklist_source=blacklist_source,
            )
            last_grouping_time = _maybe_run_grouping(
                config,
                pg,
                gap_tolerance,
                last_grouping_time,
                grouping_interval,
                cross_source_gap,
                group_classifier=group_classifier,
                conn_bundle=conn_bundle,
                pcap_client=pcap_client,
                proto_bundle=proto_bundle,
            )
            _flush_frequency_last_seen(bundles)
            _touch_liveness_marker()
            _sleep_remaining(tick_start, poll_interval)
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt received, shutting down live loop")
    finally:
        # Drain whatever the interval-gated flush has not written yet so
        # a clean shutdown does not lose up to one interval of freshness.
        _flush_frequency_last_seen(bundles, force=True)
        if continuous_recovery is not None:
            continuous_recovery.stop()
        if frequency_invalidator is not None:
            frequency_invalidator.stop()
        bounds_invalidator.stop()
        if port_rule_refresher is not None:
            port_rule_refresher.stop()


def _live_tick(
    config: AppConfig,
    pg: PostgresConnector,
    pcap_client: PcapFlagClient | None,
    bundles: list[ModuleBundle],
    pipeline_builder: PipelineBuilder,
    persister: AnomalyPersister,
    last_timestamps: dict[str, str],
    poll_interval: int,
    delay: int,
    align_cache: dict[str, int],
    runtime_config: RuntimeConfigRepository | None = None,
    blacklist_source: SeriesBlacklistSource | None = None,
) -> None:
    """Execute one polling tick: submit all modules concurrently.

    Args:
        config: Application configuration.
        pg: PostgreSQL connector.
        pcap_client: Optional PCAP flagging client.
        bundles: Per-module runtime bundles.
        pipeline_builder: Post-processing pipeline.
        persister: Anomaly persister.
        last_timestamps: Mutable dict of last processed timestamps.
        poll_interval: Polling interval in seconds.
        delay: Data delay in seconds.
        runtime_config: Optional shared runtime-config repository.
        blacklist_source: Optional shared series-blacklist source (the
            live loop always passes one in live mode).
    """
    now = datetime.now(tz=timezone.utc)
    gate_snapshot = _resolve_live_snapshot(
        runtime_config or RuntimeConfigRepository(pg),
        bundles,
        blacklist_source,
    )

    with ThreadPoolExecutor(max_workers=len(bundles)) as executor:
        futures = {
            executor.submit(
                predict_module,
                bundle,
                last_timestamps,
                now,
                poll_interval,
                delay,
                align_cache.get(bundle.config.name, poll_interval),
                gate_snapshot,
            ): bundle
            for bundle in bundles
        }
        for future in as_completed(futures):
            bundle = futures[future]
            try:
                outcome = future.result()
                _handle_prediction_result(
                    outcome,
                    bundle,
                    pg,
                    pcap_client,
                    persister,
                    pipeline_builder,
                )
            except Exception:
                logger.exception("Module '{}' prediction failed", bundle.config.name)


def _resolve_live_snapshot(
    runtime_config: LiveGateRepository,
    bundles: list[ModuleBundle],
    blacklist_source: SeriesBlacklistSource | None = None,
) -> LiveDetectionGateSnapshot:
    """Resolve gates and the series blacklist once for one live tick.

    The blacklist is resolved (and applied to the per-module consumers)
    BEFORE the gates so the frozen snapshot carries the very instance
    the consumers hold for this tick.
    """
    series_blacklist = _resolve_live_blacklist(blacklist_source, bundles) if blacklist_source is not None else None
    return _resolve_live_detection_gates(runtime_config, bundles, series_blacklist)


def _resolve_live_blacklist(
    blacklist_source: SeriesBlacklistSource,
    bundles: list[ModuleBundle],
) -> SeriesBlacklist | None:
    """Resolve the tick blacklist and push it to the consumers.

    Returns:
        The runtime instance when a row exists, or ``None`` when no row
        exists (each consumer then keeps its ``config.json`` boot
        default, spec "No row keeps boot defaults").
    """
    try:
        runtime_blacklist = blacklist_source.current()
    except Exception:
        logger.exception("Failed to resolve the series blacklist; keeping per-module " "boot defaults for this tick")
        runtime_blacklist = None
    for bundle in bundles:
        bundle.bounds_manager.update_blacklist(runtime_blacklist)
        bundle.freq_monitor.update_blacklist(runtime_blacklist)
    logger.info(
        "Series blacklist: {}",
        (
            f"runtime row active ({len(runtime_blacklist.patterns)} pattern(s))"
            if runtime_blacklist is not None
            else "no runtime row — per-module boot defaults"
        ),
    )
    return runtime_blacklist


def _resolve_live_detection_gates(
    runtime_config: LiveGateRepository,
    bundles: list[ModuleBundle],
    series_blacklist: SeriesBlacklist | None = None,
) -> LiveDetectionGateSnapshot:
    """Resolve all live gates once, falling back independently to boot values."""
    bounds: dict[str, bool] = {}
    classification: dict[str, bool] = {}
    frequency: dict[str, bool] = {}
    for bundle in bundles:
        module_name = bundle.config.name
        bounds[module_name] = _resolve_live_gate(
            runtime_config,
            module_name,
            "bounds_enabled",
            bundle.config.bounds_enabled,
        )
        classification[module_name] = _resolve_live_gate(
            runtime_config,
            module_name,
            "classification_enabled",
            bundle.config.classification.enabled,
        )
        frequency_config = getattr(bundle.config, "frequency_monitor", None)
        if frequency_config is None:
            frequency[module_name] = True
        else:
            frequency[module_name] = _resolve_live_gate(
                runtime_config,
                module_name,
                "frequency_enabled",
                frequency_config.enabled,
            )
    snapshot = LiveDetectionGateSnapshot(
        bounds,
        classification,
        frequency,
        series_blacklist=series_blacklist,
    )
    logger.info(
        "Live detection gates: bounds={} frequency={} classification={}",
        dict(snapshot.bounds_enabled),
        dict(snapshot.frequency_enabled),
        dict(snapshot.classification_enabled),
    )
    return snapshot


def _resolve_live_gate(
    runtime_config: LiveGateRepository,
    module_name: str,
    gate_name: str,
    boot_value: bool,
) -> bool:
    """Read one live gate and retain its boot value on repository failure."""
    key = f"detection.{module_name}.{gate_name}"
    try:
        value = runtime_config.get_bool("otalon-clas", key, default=boot_value)
    except Exception:
        logger.exception("Failed to resolve live runtime gate '{}'; using boot value", key)
        return boot_value
    return boot_value if value is None else value


def _handle_prediction_result(
    outcome: DetectionOutcome | None,
    bundle: ModuleBundle,
    pg: PostgresConnector,
    pcap_client: PcapFlagClient | None,
    persister: AnomalyPersister,
    pipeline_builder: PipelineBuilder,
) -> None:
    """Process a single module detection outcome: persist and flag.

    Absence verdicts are persisted through their own writer because they
    never reach the fused DataFrame. They deliberately bypass the
    post-processing pipeline: rule-based grouping scores groups by
    traffic rate, feature coverage and bound severity, none of which
    exist for a silent series.

    Args:
        outcome: Detection outcome or None if the window was not due.
        bundle: Module runtime bundle.
        pg: PostgreSQL connector.
        pcap_client: Optional PCAP flagging client.
        persister: Anomaly persister.
        pipeline_builder: Post-processing pipeline.
    """
    if outcome is None:
        return

    _persist_absence_results(outcome, bundle, persister)

    result_df = outcome.fused
    if result_df is None or result_df.is_empty():
        return

    post_processed = pipeline_builder.run(result_df)
    persisted_count = persister.persist(post_processed, bundle.config.name, bundle.config.tag_key)

    if persisted_count > 0:
        logger.info(
            "Module '{}': persisted {} anomaly records",
            bundle.config.name,
            persisted_count,
        )
        # NOTE: PCAP flagging happens later, after grouping, so each
        # flag carries the canonical ``alarm_id`` from the alarm row.
        # The per-anomaly ``_flag_pcap`` path was removed because it
        # could never set ``alarm_id`` (the ID is only assigned during
        # grouping) and therefore produced chunks unreachable via
        # ``pcap.get_chunks_by_alarm_id``. See ``_run_grouping_cycle``.


def _flush_frequency_last_seen(bundles: list[ModuleBundle], force: bool = False) -> None:
    """Flush pending runtime ``last_seen`` values for every module.

    Called once per live tick. The per-monitor interval gate means the
    actual PostgreSQL write happens at most every
    ``last_seen_flush_interval_seconds``, so this is cheap on the hot
    path. A failing flush is logged and never breaks the loop.
    """
    for bundle in bundles:
        try:
            bundle.freq_monitor.flush_last_seen(force=force)
        except Exception:
            logger.exception(
                "Module '{}': last_seen flush failed",
                bundle.config.name,
            )


def _persist_absence_results(
    outcome: DetectionOutcome,
    bundle: ModuleBundle,
    persister: AnomalyPersister,
) -> None:
    """Write the absence verdicts of one detection window."""
    if not outcome.absence_results:
        return
    try:
        count = persister.persist_absence(
            outcome.absence_results,
            bundle.config.name,
            outcome.observed_at,
        )
    except Exception:
        logger.exception(
            "Module '{}': absence persistence failed",
            bundle.config.name,
        )
        return
    if count > 0:
        logger.info(
            "Module '{}': persisted {} absence record(s)",
            bundle.config.name,
            count,
        )


def predict_module(
    bundle: ModuleBundle,
    last_timestamps: dict[str, str],
    now: datetime,
    poll_interval: int,
    delay: int,
    align_seconds: int | None = None,
    gate_snapshot: LiveDetectionGateSnapshot | None = None,
) -> DetectionOutcome | None:
    """Run the full detection cycle for one module over a single time window.

    The query window is bucket-aligned to ``align_seconds`` so that every
    polling tick covers complete aggregation buckets. Without alignment
    short polling intervals fragment buckets and produce ``packet_count``
    values lower than the trained bounds.

    An empty window is NOT a reason to skip the presence check: a module
    with no rows at all means every profiled series is unobserved, and
    each series still has to exceed its own absence timeout individually
    before it is reported. Returning early there would make absence
    undetectable exactly in the quiet periods it exists for.

    Args:
        bundle: Module runtime bundle.
        last_timestamps: Mutable dict tracking the last processed timestamp.
        now: Current UTC timestamp.
        poll_interval: Polling interval in seconds.
        delay: Data delay in seconds.
        align_seconds: Optional bucket alignment unit. Falls back to the
            cached resolution if omitted.

    Returns:
        Detection outcome, or None when the window is not yet due.
    """
    mod = bundle.config
    if align_seconds is None:
        align_seconds = _resolve_alignment_seconds(bundle, poll_interval)
    stop = _floor_to_alignment(now - timedelta(seconds=delay), align_seconds)
    start = _resolve_start_timestamp(last_timestamps, mod.name, stop, poll_interval, align_seconds)

    if start >= stop:
        return None

    start_iso = start.isoformat()
    stop_iso = stop.isoformat()

    df = cast(pl.DataFrame, bundle.influx.fetch(start=start_iso, stop=stop_iso))
    last_timestamps[mod.name] = stop_iso

    if df.is_empty():
        return _presence_only_outcome(bundle, stop, stop_iso)

    df_processed = bundle.preprocessor.preprocess_for_prediction(df)
    if df_processed.is_empty():
        return _presence_only_outcome(bundle, stop, stop_iso)
    return _detect(bundle, df_processed, df, stop_iso, gate_snapshot)


def _presence_only_outcome(
    bundle: ModuleBundle,
    observed_at: datetime,
    current_time: str,
) -> DetectionOutcome:
    """Run the presence check alone for a window that produced no rows."""
    freq_results = bundle.freq_monitor.check(
        df=pl.DataFrame(),
        tag_key=bundle.config.tag_key,
        current_time=current_time,
    )
    return DetectionOutcome(
        fused=None,
        absence_results=_absence_results(freq_results),
        observed_at=observed_at,
    )


def _absence_results(freq_results: list[FrequencyResult]) -> list[FrequencyResult]:
    """Filter the frequency results down to the absence verdicts."""
    return [r for r in freq_results if r.is_anomaly and r.anomaly_type == ABSENCE_ANOMALY]


def _detect(
    bundle: ModuleBundle,
    df: pl.DataFrame,
    raw_df: pl.DataFrame,
    current_time: str,
    gate_snapshot: LiveDetectionGateSnapshot | None = None,
) -> DetectionOutcome:
    """Run bounds, frequency, conditional ML, and fuse results.

    The ML gate fires only when bounds or a FrequencyAnomaly flags an
    anomaly. Absence results bypass fusion entirely: an absent series
    has no row in ``bounds_df`` (that is what absence means), so the
    left-join in ``fusion._attach_frequency_flags`` can never carry it.
    They are handed to the caller separately and written by
    :meth:`AnomalyPersister.persist_absence`.

    Args:
        bundle: Module runtime bundle.
        df: Preprocessed data DataFrame for the current window.
        raw_df: Raw (un-preprocessed) DataFrame, used for ML preprocessing.
        current_time: ISO 8601 timestamp for frequency check reference.

    Returns:
        Detection outcome with the fused DataFrame and absence verdicts.
    """
    mod = bundle.config
    bounds_enabled, classification_enabled, frequency_enabled = _module_gates(bundle, gate_snapshot)
    bounds_df = _check_bounds(bundle, df, bounds_enabled)
    # Frequency profiles are trained against the raw observation identity.
    # The prediction preprocessor may collapse ports and rewrite the UCI for
    # ML/bounds, so feeding ``df`` here loses exact trained series keys.
    freq_results = (
        bundle.freq_monitor.check(df=raw_df, tag_key=mod.tag_key, current_time=current_time)
        if frequency_enabled
        else []
    )

    ml_predictions = _gate_ml_prediction(
        bundle,
        bounds_df,
        freq_results,
        raw_df,
        classification_enabled,
    )
    fused = fuse_results(
        bounds_df=bounds_df,
        freq_results=freq_results,
        ml_predictions=ml_predictions,
        tag_key=mod.tag_key,
        label_map=bundle.label_map or None,
    )
    return DetectionOutcome(
        fused=fused,
        absence_results=_absence_results(freq_results),
        observed_at=datetime.fromisoformat(current_time).replace(tzinfo=timezone.utc),
    )


def _module_gates(
    bundle: ModuleBundle,
    gate_snapshot: LiveDetectionGateSnapshot | None,
) -> tuple[bool, bool, bool]:
    """Return live gates, or preserve legacy unconditional offline gates."""
    if gate_snapshot is None:
        return True, True, True
    return (
        gate_snapshot.bounds_enabled[bundle.config.name],
        gate_snapshot.classification_enabled[bundle.config.name],
        gate_snapshot.frequency_enabled.get(bundle.config.name, True),
    )


def _check_bounds(bundle: ModuleBundle, df: pl.DataFrame, enabled: bool) -> pl.DataFrame:
    """Run bounds checks or return a fusion-compatible clean result."""
    if enabled:
        mod = bundle.config
        return bundle.bounds_manager.check(df=df, tag_key=mod.tag_key, features=mod.features)
    logger.info(
        "Module '{}': live bounds gate disabled; bounds evaluation skipped",
        bundle.config.name,
    )
    return df.with_columns(
        pl.lit(False).alias("is_anomaly"),
        pl.lit("").alias("anomaly_type"),
        pl.lit(0.0).alias("confidence"),
        pl.lit("").alias("violated_features"),
        pl.lit(0.0).alias("severity"),
    )


def _gate_ml_prediction(
    bundle: ModuleBundle,
    bounds_df: pl.DataFrame,
    freq_results: list[FrequencyResult],
    raw_df: pl.DataFrame,
    enabled: bool = True,
) -> pl.DataFrame | None:
    """Run ML prediction only when bounds or frequency flags an anomaly.

    Returns a DataFrame with columns ``uci``, ``_bucket_epoch``,
    ``ml_type``, ``ml_confidence`` so that the fusion stage can join
    predictions onto the bounds DataFrame by series and time bucket
    instead of relying on row-order alignment.

    Args:
        bundle: Module runtime bundle.
        bounds_df: Bounds check result DataFrame.
        freq_results: Frequency check results.
        raw_df: Raw data DataFrame for preprocessing.

    Returns:
        Predictions DataFrame or None if the gate is closed.
    """
    if not enabled:
        return None

    # A module without a published artifact cannot classify anything, so the
    # gate is not even evaluated: no anomaly scan, no per-tick warning. The
    # state is announced exactly once per process start when the model load
    # finds no artifact (CLAS-063), and a runtime publication re-opens the
    # gate on the next tick because the snapshot is read here, per call.
    snapshot = getattr(bundle, "model_snapshot", None)
    model = snapshot() if callable(snapshot) else None
    if model is None or not model.label_map or model.scaler is None:
        return None

    has_bounds_anomaly = _has_anomaly_flag(bounds_df)
    # AbsenceAnomaly must NOT open the ML gate. The classifier scores
    # feature vectors of *observed* buckets; an absent series has no
    # bucket in this window, so running ML would only classify the
    # unrelated series that happen to be present and attribute the
    # result to a silence. Only FrequencyAnomaly — a verdict derived
    # from real observed intervals — is a legitimate value-anomaly
    # trigger.
    has_freq_anomaly = any(r.is_anomaly and r.anomaly_type == FREQUENCY_ANOMALY for r in freq_results)

    if not has_bounds_anomaly and not has_freq_anomaly:
        return None

    if getattr(bundle, "ml_degraded_reason", None) is not None:
        return None

    try:
        return _run_ml_prediction(bundle, raw_df, model)
    except MLPredictionError as exc:
        # Structural: it will fail identically next tick. Mark the module
        # ML-degraded so the condition is visible state rather than one
        # log line per 5-second tick, and keep bounds/frequency detection
        # running (audit CLAS-03).
        marker = getattr(bundle, "mark_ml_degraded", None)
        if callable(marker):
            marker(str(exc))
        logger.error(
            "Module '{}': ML classification disabled after a structural failure: {}",
            bundle.config.name,
            exc,
        )
        return None


def _has_anomaly_flag(bounds_df: pl.DataFrame) -> bool:
    """Check whether any row in bounds result is flagged anomalous.

    Args:
        bounds_df: Bounds check result DataFrame.

    Returns:
        True if at least one row has ``is_anomaly == True``.
    """
    if "is_anomaly" not in bounds_df.columns or bounds_df.is_empty():
        return False
    return bounds_df["is_anomaly"].any()


def _resolve_feature_columns(bundle: ModuleBundle, model: Any) -> list[str]:
    """Return the ordered feature columns to score this model with.

    The model's persisted ``feature_columns`` win over the configured
    list. Deriving the order from ``config.json`` at inference time meant
    a config edit silently changed the meaning of the input matrix: a
    reorder of equal-width features still matched on shape, so nothing
    raised while the scaler and the tree read the wrong columns
    (audit CLAS-03).

    Args:
        bundle: Module runtime bundle.
        model: The captured inference snapshot.

    Returns:
        The ordered feature-column names.

    Raises:
        MLPredictionError: When the persisted order is not a subset of the
            columns the configured preprocessor can produce, which means
            the deployed model and the current config disagree.
    """
    configured = list(bundle.preprocessor.get_feature_columns())
    persisted = list(getattr(model, "feature_columns", None) or ())
    if not persisted:
        logger.debug(
            "Module '{}': model has no persisted feature_columns, using configured order",
            bundle.config.name,
        )
        return configured

    unknown = [c for c in persisted if c not in configured]
    if unknown:
        raise MLPredictionError(f"model was trained on feature columns the current config cannot produce: {unknown}")
    if persisted != configured:
        logger.warning(
            "Module '{}': config feature order {} differs from the trained model's {}; " "using the model's order",
            bundle.config.name,
            configured,
            persisted,
        )
    return persisted


def _run_ml_prediction(
    bundle: ModuleBundle,
    raw_df: pl.DataFrame,
    model: Any,
) -> pl.DataFrame | None:
    """Preprocess data, run ML prediction, and return key-aligned predictions.

    The returned DataFrame carries the ``uci`` and ``_bucket_epoch``
    columns alongside ``ml_type`` and ``ml_confidence`` so that the
    fusion stage can join predictions onto the bounds DataFrame by
    series identity and time bucket. This eliminates row-order
    misalignment that occurred when bounds and ML preprocessed the
    same data through independent ``group_by`` paths.

    Feature selection follows the model's own persisted column order.

    Args:
        bundle: Module runtime bundle.
        raw_df: Raw data DataFrame.
        model: Coherent inference snapshot to predict with.

    Returns:
        DataFrame with columns ``uci``, ``_bucket_epoch``, ``ml_type``,
        ``ml_confidence``; or ``None`` when there is simply nothing to
        score (empty input).

    Raises:
        MLPredictionError: On a structural fault — feature/config
            mismatch, missing columns, absent join keys or a failure
            inside the model. These recur on every tick and must not be
            swallowed (audit CLAS-03).
    """
    feature_cols = _resolve_feature_columns(bundle, model)

    try:
        preprocessed = bundle.preprocessor.preprocess_for_prediction(raw_df)
    except Exception as exc:
        raise MLPredictionError(f"preprocessing failed: {exc}") from exc

    if preprocessed.is_empty():
        return None

    missing = [c for c in feature_cols if c not in preprocessed.columns]
    if missing:
        raise MLPredictionError(f"ML feature columns missing from preprocessed data: {missing}")

    key_cols = [c for c in ("uci", "_bucket_epoch") if c in preprocessed.columns]
    if not key_cols:
        raise MLPredictionError("preprocessed data lacks the uci/_bucket_epoch join keys")

    X = preprocessed.select(feature_cols).to_numpy().astype(np.float64)
    if X.shape[0] == 0:
        return None

    n_expected = getattr(model.backend, "n_features_in_", None)
    if n_expected is not None and X.shape[1] != n_expected:
        raise MLPredictionError(
            f"feature width mismatch: model expects {n_expected}, got {X.shape[1]} " f"from columns {feature_cols}"
        )

    logger.debug(
        "Module '{}': ML predict on {} rows, first row sample={}",
        bundle.config.name,
        X.shape[0],
        dict(zip(feature_cols, X[0].tolist())),
    )

    try:
        # Predict against the captured immutable snapshot so backend,
        # scaler and label_map are guaranteed to be the same model
        # generation even if a swap lands mid-tick (audit A-05).
        preds, confs = _predict_with_model(bundle, model, X)
    except Exception as exc:
        raise MLPredictionError(f"model inference failed: {exc}") from exc

    label_map = model.label_map or {}
    ml_types = [label_map.get(int(p), None) for p in preds]

    return preprocessed.select(key_cols).with_columns(
        pl.Series("ml_type", ml_types, dtype=pl.Utf8),
        pl.Series("ml_confidence", confs.tolist(), dtype=pl.Float64),
    )


def _predict_with_model(
    bundle: ModuleBundle,
    model: Any,
    X: np.ndarray,
) -> tuple[np.ndarray, np.ndarray]:
    """Predict using a coherent model snapshot's scaler + backend.

    The confidence-threshold logic is reused from the bundle pipeline
    (a pure, stateless transform), but scaling and inference run against
    the snapshot's own scaler/backend so no live mutation can split the
    pair mid-prediction (audit A-05).
    """
    X_scaled = model.scaler.transform(X)
    predictions = model.backend.predict(X_scaled)
    probabilities = model.backend.predict_proba(X_scaled)
    return bundle.ml_pipeline._apply_threshold(predictions, probabilities)


def _resolve_start_timestamp(
    last_timestamps: dict[str, str],
    module_name: str,
    aligned_stop: datetime,
    poll_interval: int,
    align_seconds: int,
) -> datetime:
    """Determine the bucket-aligned query start timestamp for a module.

    First tick uses ``aligned_stop - max(poll_interval, align_seconds)``.
    Subsequent ticks reuse the previous tick's ``stop`` (already aligned
    to a bucket boundary), ensuring lossless and overlap-free coverage.

    Args:
        last_timestamps: Dict of last processed (aligned) timestamps.
        module_name: Module identifier key.
        aligned_stop: Bucket-aligned upper bound of the current query window.
        poll_interval: Polling interval in seconds.
        align_seconds: Bucket-alignment unit in seconds.

    Returns:
        Query start datetime aligned to a bucket boundary.
    """
    last = last_timestamps.get(module_name)
    if last is None:
        lookback = max(poll_interval, align_seconds)
        return aligned_stop - timedelta(seconds=lookback)
    return datetime.fromisoformat(last)


def _resolve_alignment_seconds(bundle: ModuleBundle, poll_interval: int) -> int:
    """Resolve the bucket alignment unit for live polling.

    The live loop polls every ``poll_interval`` seconds. To keep
    detection latency low, the alignment is set equal to the polling
    interval. Series whose ``bucket_seconds`` is larger than the
    polling interval will see their buckets fragmented across multiple
    ticks; their anomalies are flagged when subsequent ticks complete
    the underlying bucket. This matches legacy ``otalon-clas``
    behaviour and keeps detection latency at ``poll_interval +
    delay_seconds``.

    Args:
        bundle: Module runtime bundle.
        poll_interval: Configured polling interval.

    Returns:
        Alignment unit in seconds (``>=1``).
    """
    return max(poll_interval, 1)


def _floor_to_alignment(dt: datetime, align_seconds: int) -> datetime:
    """Floor a UTC datetime down to the previous ``align_seconds`` boundary.

    Args:
        dt: Input datetime.
        align_seconds: Alignment unit in seconds.

    Returns:
        Datetime aligned to the floor of the boundary.
    """
    if align_seconds <= 1:
        return dt.replace(microsecond=0)
    epoch = int(dt.timestamp())
    floored = (epoch // align_seconds) * align_seconds
    return datetime.fromtimestamp(floored, tz=dt.tzinfo or timezone.utc)


def _extract_max_timestamp(df: pl.DataFrame, fallback: str) -> str:
    """Extract the maximum timestamp from a DataFrame's time column.

    Args:
        df: DataFrame with a ``time`` column.
        fallback: Fallback ISO string if extraction fails.

    Returns:
        ISO 8601 timestamp string.
    """
    if "time" not in df.columns or df.is_empty():
        return fallback
    try:
        max_val = df["time"].max()
        if max_val is None:
            return fallback
        if isinstance(max_val, datetime):
            return max_val.isoformat()
        return str(max_val)
    except Exception:
        return fallback


def _compute_dynamic_gap_tolerance(
    grouping_interval: int,
    poll_interval: int,
    delay: int,
) -> int:
    """Compute dynamic gap tolerance for anomaly grouping.

    Formula: ``max(30, grouping_interval + 2*poll_interval + delay + 2)``.

    Args:
        grouping_interval: Grouping cadence in seconds.
        poll_interval: Polling interval in seconds.
        delay: Data delay in seconds.

    Returns:
        Gap tolerance in seconds.
    """
    return max(30, grouping_interval + 2 * poll_interval + delay + 2)


def _maybe_run_grouping(
    config: AppConfig,
    pg: PostgresConnector,
    gap_tolerance: int,
    last_grouping_time: float,
    grouping_interval: int,
    cross_source_gap: int,
    group_classifier: GroupClassifier | None = None,
    conn_bundle: ModuleBundle | None = None,
    pcap_client: PcapFlagClient | None = None,
    proto_bundle: ModuleBundle | None = None,
) -> float:
    """Run alarm grouping if enough time has elapsed since the last run.

    Args:
        pg: PostgreSQL connector.
        gap_tolerance: Gap tolerance for grouping.
        last_grouping_time: Monotonic timestamp of the last grouping run.
        grouping_interval: Minimum seconds between grouping runs.
        cross_source_gap: Δ for the cross-source match window (§7a D-b,
            read from the rule-based config).
        group_classifier: Optional alarm-group classifier; runs after
            grouping to assign MITRE labels to fresh alarms.
        conn_bundle: Required when ``group_classifier`` is active. The
            ``conn`` module bundle is used to load the underlying network
            metrics for each pending alarm.
        pcap_client: Optional PCAP-flagging client; freshly created or
            time-extended alarms are forwarded to the PCAP recorder so
            the corresponding chunks are labelled with the alarm_id.

    Returns:
        Updated last grouping monotonic timestamp.
    """
    elapsed = time.monotonic() - last_grouping_time
    if elapsed < grouping_interval:
        return last_grouping_time

    _run_grouping_cycle(
        pg,
        gap_tolerance,
        cross_source_gap,
        max_alarm_duration_seconds=_get_rule_based_max_alarm_duration(config),
        pcap_client=pcap_client,
        proto_bundle=proto_bundle,
    )

    if group_classifier is not None and group_classifier.is_active and conn_bundle is not None:
        _run_group_classification_cycle(pg, group_classifier, conn_bundle)

    return time.monotonic()


DEFAULT_GROUPING_LOOKBACK_SECONDS: int = 300


def _get_rule_based_gap_tolerance(config: AppConfig) -> int:
    """Return the rule-based ``gap_tolerance_seconds`` value.

    The x1 cross-source correlation window (§7a D-b) reuses the same tunable
    that drives the rule-based alarm grouping stage, so the two cannot drift
    apart. Mirrors ``PipelineBuilder._create_rule_based``.
    """
    for stage in config.pipeline_post_processing.stages:
        if stage.type != "rule_based":
            continue
        inner = getattr(stage, "config", None)
        if inner is None:
            return RuleBasedStageInnerConfig().gap_tolerance_seconds
        if hasattr(inner, "model_dump"):
            inner = inner.model_dump()
        return RuleBasedStageInnerConfig.model_validate(inner).gap_tolerance_seconds
    return RuleBasedStageInnerConfig().gap_tolerance_seconds


def _get_rule_based_max_alarm_duration(config: AppConfig) -> int:
    """Return configured maximum duration for incrementally grouped alarms."""
    for stage in config.pipeline_post_processing.stages:
        if stage.type != "rule_based":
            continue
        inner = getattr(stage, "config", None)
        if inner is None:
            return RuleBasedStageInnerConfig().max_alarm_duration_seconds
        if hasattr(inner, "model_dump"):
            inner = inner.model_dump()
        return RuleBasedStageInnerConfig.model_validate(inner).max_alarm_duration_seconds
    return RuleBasedStageInnerConfig().max_alarm_duration_seconds


def _run_grouping_cycle(
    pg: PostgresConnector,
    gap_tolerance: int,
    cross_source_gap: int,
    max_alarm_duration_seconds: int = 3600,
    pcap_client: PcapFlagClient | None = None,
    proto_bundle: ModuleBundle | None = None,
) -> None:
    """Re-merge all anomalies inside the rolling lookback window.

    Strategy: every grouping cycle considers ALL anomaly records whose
    ``start_ts`` falls into the last
    :data:`DEFAULT_GROUPING_LOOKBACK_SECONDS` (regardless of
    ``is_grouped``) and rebuilds the alarm groups from scratch. This
    guarantees that anomalies arriving in successive live ticks for the
    same series end up in the same alarm group instead of producing one
    new alarm per tick that always declares ``n_series=1``.

    After grouping, an additive x1 cross-source aggregation step enriches
    conn alarms with same-window mac / proto anomalies (§7a). The step is
    strictly conn-anchored and never re-groups or alters conn alarms.

    Args:
        pg: PostgreSQL connector.
        gap_tolerance: Gap tolerance for merging anomalies into groups.
        max_alarm_duration_seconds: Maximum alarm span; non-positive values
            disable the duration cap.
        cross_source_gap: Δ for the cross-source match window (§7a D-b,
            read from the rule-based config).
        pcap_client: Optional PCAP-flagging client; touched alarms are
            forwarded to the PCAP recorder so the chunks overlapping
            each alarm's window are labelled with the alarm_id (so the
            subagent's ``pcap.get_chunks_by_alarm_id`` tool can find them).
        proto_bundle: Optional ``proto_traffic`` module bundle used to
            recover the protocol vocabulary for the proto stack match.
    """
    try:
        from otalon_clas.detection.grouping import (
            incremental_group_ungrouped_anomalies,
        )

        touched_alarms = incremental_group_ungrouped_anomalies(
            connector=pg,
            gap_tolerance_seconds=gap_tolerance,
            max_alarm_duration_seconds=max_alarm_duration_seconds,
            lookback_seconds=DEFAULT_GROUPING_LOOKBACK_SECONDS,
        )
        _deactivate_stale_alarms(pg, gap_tolerance)
        _run_cross_source_aggregation(pg, proto_bundle, cross_source_gap, touched_alarms)

        if pcap_client is not None and touched_alarms:
            _flag_alarms_to_pcap_recorder(pcap_client, touched_alarms)
    except Exception:
        logger.exception("Grouping cycle failed")


def _run_cross_source_aggregation(
    pg: PostgresConnector,
    proto_bundle: ModuleBundle | None,
    cross_source_gap: int,
    touched_alarms: list[dict[str, Any]],
) -> None:
    """Run the additive x1 cross-source enrichment over recent conn alarms.

    Bounds the enrichment to the time span covered by the alarms touched
    in this grouping cycle (plus the lookback window) so it stays
    side-effect-isolated from the live detection loop.

    Args:
        pg: PostgreSQL connector.
        proto_bundle: Optional ``proto_traffic`` bundle for the protocol
            vocabulary; when absent only mac enrichment is attempted.
        cross_source_gap: Δ window tolerance.
        touched_alarms: Alarms touched in this grouping cycle (used to
            bound the enrichment window).
    """
    try:
        from otalon_clas.detection.cross_source import aggregate_cross_source

        window_start = datetime.now(tz=timezone.utc) - timedelta(seconds=DEFAULT_GROUPING_LOOKBACK_SECONDS)
        protocols = _load_protocol_vocabulary(proto_bundle, window_start)
        aggregate_cross_source(
            connector=pg,
            protocol_vocabulary=protocols,
            gap_tolerance_seconds=cross_source_gap,
            window_start=window_start,
        )
    except Exception:
        logger.exception("Cross-source aggregation failed")


def _load_protocol_vocabulary(
    proto_bundle: ModuleBundle | None,
    window_start: datetime,
) -> list[str]:
    """Recover the proto protocol vocabulary for the hash reverse map.

    Args:
        proto_bundle: Optional ``proto_traffic`` module bundle.
        window_start: Lower bound for the distinct-protocol query.

    Returns:
        Sorted list of distinct protocol-stack strings (empty when no
        proto bundle is available).
    """
    if proto_bundle is None:
        return []
    stop = datetime.now(tz=timezone.utc)
    return proto_bundle.influx.fetch_distinct_tag_values(
        start=window_start.isoformat(),
        stop=stop.isoformat(),
    )


def _flag_alarms_to_pcap_recorder(
    pcap_client: PcapFlagClient,
    touched_alarms: list[dict[str, Any]],
) -> None:
    """Send one PCAP flag-alarm request per freshly created or extended alarm.

    This is the canonical post-grouping flagging path: each alarm's
    full time window is forwarded to the PCAP recorder together with
    its ``alarm_id``, ``module``, ``primary_type`` and ``series_ids``
    labels. The PCAP recorder marks every chunk overlapping the window
    so the subagent's ``pcap.get_chunks_by_alarm_id`` can resolve them
    later. Fire-and-forget: any exception is logged but never raised.

    Args:
        pcap_client: Flagging client (already health-checked at startup).
        touched_alarms: Output of
            :func:`incremental_group_ungrouped_anomalies` — must contain
            ``alarm_id``, ``start_ts``, ``end_ts``, ``primary_type``,
            ``series_ids`` and ``module`` for each entry.
    """
    for alarm in touched_alarms:
        try:
            labels = {
                "module": str(alarm.get("module") or "unknown"),
                "alarm_id": str(alarm["alarm_id"]),
                "primary_type": str(alarm.get("primary_type") or "unknown"),
                "series_ids": ",".join(alarm.get("series_ids") or []),
            }
            pcap_client.flag_alarm(
                start_ts=alarm["start_ts"],
                end_ts=alarm["end_ts"],
                labels=labels,
            )
        except Exception as exc:
            logger.warning(
                "PCAP alarm flagging failed for alarm_id={}: {}",
                alarm.get("alarm_id", "?"),
                exc,
            )


DEFAULT_FALLBACK_BUCKET_SECONDS: int = 60


def _build_series_bucket_lookup(
    pg: PostgresConnector,
    records: list[AnomalyRecord],
) -> dict[str, int]:
    """Build a ``series_id`` → ``bucket_seconds`` map for the given records.

    Looks up the bucket size for each series in the
    ``port_collapse_rules`` table. Series that have no matching rule
    (e.g. live traffic from devices that were not part of the training
    window) fall back to :data:`DEFAULT_FALLBACK_BUCKET_SECONDS`, which
    matches the default used by the live preprocessor when no rule
    fires.

    Args:
        pg: PostgreSQL connector.
        records: Anomaly records being grouped.

    Returns:
        Dict mapping every series_id present in ``records`` to its
        bucket size in seconds.
    """
    series_ids = sorted({str(r.series_id) for r in records})
    if not series_ids:
        return {}

    lookup: dict[str, int] = dict.fromkeys(series_ids, DEFAULT_FALLBACK_BUCKET_SECONDS)
    try:
        from otalon_clas.common.postgres_connector import (  # local import to avoid circular deps
            PortCollapseRuleRecord,
        )

        with pg.session() as session:
            rows = (
                session.query(
                    PortCollapseRuleRecord.normalized_uci,
                    PortCollapseRuleRecord.bucket_seconds,
                )
                .filter(PortCollapseRuleRecord.module == "conn")
                .filter(PortCollapseRuleRecord.normalized_uci.in_(series_ids))
                .all()
            )
        for normalized_uci, bucket_seconds in rows:
            if bucket_seconds and bucket_seconds > 0:
                lookup[str(normalized_uci)] = int(bucket_seconds)
    except Exception:
        logger.exception("Failed to load bucket_seconds map; using fallback")
    return lookup


def _deactivate_stale_alarms(pg: PostgresConnector, gap_tolerance: int) -> None:
    """Mark alarms whose ``end_timestamp`` is older than the grouping
    gap tolerance as ``is_active=false``.

    The cutoff equals ``gap_tolerance``: by definition, two anomalies
    that are more than ``gap_tolerance`` seconds apart belong to two
    different alarm groups, so an alarm that has not received a new
    anomaly within that window is considered closed. Coupling the
    deactivation cutoff to the same constant keeps the semantics of
    "active" consistent with the merging behaviour of the grouping
    algorithm.

    Args:
        pg: PostgreSQL connector.
        gap_tolerance: Gap tolerance in seconds (same value used by
            the alarm-grouping merge step).
    """
    inactivity_cutoff = datetime.now(tz=timezone.utc) - timedelta(seconds=gap_tolerance)
    try:
        with pg.session() as session:
            updated = (
                session.query(Alarm)
                .filter(Alarm.is_active.is_(True))
                .filter(~Alarm.id.startswith("cc_"))
                .filter(Alarm.end_timestamp < inactivity_cutoff)
                .update(
                    {Alarm.is_active: False},
                    synchronize_session=False,
                )
            )
        if updated:
            logger.info(
                "Deactivated {} stale alarms (idle longer than gap_tolerance={}s)",
                updated,
                gap_tolerance,
            )
    except Exception:
        logger.exception("Failed to deactivate stale alarms")


def _run_group_classification_cycle(
    pg: PostgresConnector,
    group_classifier: GroupClassifier,
    conn_bundle: ModuleBundle,
) -> None:
    """Classify recently grouped alarms with the alarm-group classifier.

    Looks up alarms that have not yet received an ``rf_classified_at``
    marker, fetches their underlying network metrics from InfluxDB,
    runs the Random-Forest classifier and applies the prediction to the
    alarm via :func:`apply_group_classification`.

    Args:
        pg: PostgreSQL connector.
        group_classifier: Loaded alarm-group classifier.
        conn_bundle: ``conn`` module bundle providing the InfluxDB module.
    """
    try:
        pending = fetch_alarms_pending_classification(pg, limit=50)
        if not pending:
            return

        repo = GroupClassifierTrainingRepository(pg=pg, influx=conn_bundle.influx)
        classified = 0
        skipped = 0
        for alarm in pending:
            series_ids = list(alarm.series_ids or [])
            if not series_ids:
                skipped += 1
                continue
            start_ts = alarm.start_timestamp
            end_ts = alarm.end_timestamp
            duration = max((end_ts - start_ts).total_seconds(), 0.0)
            try:
                rows = repo.fetch_influx_rows_for_alarm(_alarm_to_training_record(alarm))
            except Exception:
                logger.exception("GroupClassifier: failed to fetch rows for alarm {}", alarm.id)
                continue
            if rows.is_empty():
                skipped += 1
                _mark_alarm_classified_skip(pg, str(alarm.id), "no_influx_rows")
                continue
            prediction = group_classifier.classify(
                influx_rows=rows,
                series_ids_count=len(series_ids),
                duration_seconds=duration,
            )
            if prediction is None:
                skipped += 1
                _mark_alarm_classified_skip(pg, str(alarm.id), "below_threshold")
                continue
            updated = apply_group_classification(
                connector=pg,
                alarm_id=str(alarm.id),
                mitre_label=prediction.mitre_label,
                technical_method=prediction.technical_method,
                confidence=prediction.confidence,
                classified_at=prediction.classified_at,
            )
            if updated:
                classified += 1
        if classified or skipped:
            logger.info(
                "GroupClassifier cycle: {} alarms classified, {} skipped",
                classified,
                skipped,
            )
    except Exception:
        logger.exception("GroupClassifier cycle failed")


def _mark_alarm_classified_skip(
    pg: PostgresConnector,
    alarm_id: str,
    reason: str,
) -> None:
    """Stamp an alarm as ``rf_classified`` with a skip reason.

    Without this marker the alarm would be picked up by every grouping
    cycle indefinitely. The first existing anomaly-type entry receives
    the ``rf_classified_at`` and ``rf_skip_reason`` keys; an entry that
    is API-schema-conformant is created when none exists.

    Args:
        pg: PostgreSQL connector.
        alarm_id: Alarm identifier to mark.
        reason: Short reason code (``"no_influx_rows"`` or
            ``"below_threshold"``).
    """
    from otalon_clas.common.postgres_connector import Alarm

    classified_iso = datetime.now(tz=timezone.utc).isoformat()
    try:
        with pg.session() as session:
            alarm = session.query(Alarm).filter(Alarm.id == alarm_id).one_or_none()
            if alarm is None:
                return
            stats = dict(alarm.anomaly_type_stats or {})
            target_key: str | None = None
            for key, entry in stats.items():
                if isinstance(entry, dict):
                    target_key = key
                    break
            if target_key is None:
                # Defensive: alarm without any existing stats — synthesize
                # an entry that satisfies the API schema.
                target_key = "NoBounds"
                stats[target_key] = {
                    "primary_type": "NoBounds",
                    "interval_count": 0,
                    "count": 0,
                    "confidence_mean": 0.0,
                    "score_norm": 0.0,
                }
            target_entry: dict[Any, Any] = dict(stats[target_key])
            target_entry["rf_classified_at"] = classified_iso
            target_entry["rf_skip_reason"] = reason
            stats[target_key] = target_entry
            # SQLAlchemy legacy Column attr is typed Column[Any] at class
            # level; instance assignment of a dict is valid at runtime.
            alarm.anomaly_type_stats = stats  # type: ignore[assignment]
    except Exception:
        logger.exception("Failed to mark alarm {} as classified-skip", alarm_id)


def _alarm_to_training_record(alarm: Any) -> Any:
    """Adapt an :class:`Alarm` ORM row to a training-repository record.

    Returns:
        :class:`AlarmTrainingRecord`-shaped object usable by the
        repository's row-fetching helpers.
    """
    from otalon_clas.ml.group_classifier.repository import AlarmTrainingRecord

    return AlarmTrainingRecord(
        id=str(alarm.id),
        start_ts=alarm.start_timestamp,
        end_ts=alarm.end_timestamp,
        series_ids=list(alarm.series_ids or []),
    )


def _init_group_classifier(config: AppConfig) -> GroupClassifier | None:
    """Instantiate and load the alarm-group classifier when enabled.

    Args:
        config: Application configuration.

    Returns:
        Loaded :class:`GroupClassifier`, or ``None`` when disabled or
        the model bundle is missing.
    """
    cfg = config.group_classifier
    if not cfg.enabled or not cfg.model_path:
        return None
    store = GroupClassifierStore(model_path=cfg.model_path)
    classifier = GroupClassifier(
        store=store,
        confidence_threshold=cfg.confidence_threshold,
    )
    if not classifier.load():
        return None
    return classifier


def _find_module_bundle(bundles: list[ModuleBundle], module_name: str) -> ModuleBundle | None:
    """Return the bundle for the named module, or ``None`` when missing."""
    for bundle in bundles:
        if bundle.config.name == module_name:
            return bundle
    return None


def _sleep_remaining(tick_start: float, poll_interval: int) -> None:
    """Sleep for the remainder of the polling interval.

    Args:
        tick_start: Monotonic timestamp at tick start.
        poll_interval: Target polling interval in seconds.
    """
    elapsed = time.monotonic() - tick_start
    remaining = max(0.0, poll_interval - elapsed)
    if remaining > 0:
        time.sleep(remaining)


# ---------------------------------------------------------------------------
# Offline mode
# ---------------------------------------------------------------------------


def run_offline(
    config: AppConfig,
    pg: PostgresConnector,
    pcap_client: PcapFlagClient | None,
    model_store: ModelStore,
    bundles: list[ModuleBundle],
    pipeline_builder: PipelineBuilder,
) -> None:
    """Execute offline replay prediction over a fixed time window.

    Iterates from ``start`` to ``stop`` in ``poll_interval_seconds`` steps,
    running the same detection and grouping logic as live mode.

    Args:
        config: Application configuration.
        pg: PostgreSQL connector.
        pcap_client: Optional PCAP flagging client.
        model_store: ML model persistence store.
        bundles: Per-module runtime bundles.
        pipeline_builder: Post-processing pipeline.
    """
    _load_persisted_models(model_store, bundles)

    offline_cfg = config.prediction.offline
    live_cfg = config.prediction.live
    gap_tolerance = offline_cfg.gap_tolerance_seconds
    max_alarm_duration = _get_rule_based_max_alarm_duration(config)
    cross_source_gap = _get_rule_based_gap_tolerance(config)
    suppression_cfg = config.suppression
    suppression_service = SuppressionService(
        connector=pg,
        cache_ttl_s=suppression_cfg.suppression_cache_ttl_s,
    )
    persister = AnomalyPersister(
        connector=pg,
        gap_tolerance_seconds=gap_tolerance,
        suppression_service=suppression_service,
        ml_confidence_persist_threshold=suppression_cfg.ml_confidence_persist_threshold,
        drop_low_signal_anomalies=suppression_cfg.drop_low_signal_anomalies,
    )

    start_dt = datetime.fromisoformat(offline_cfg.start)
    stop_dt = datetime.fromisoformat(offline_cfg.stop)
    step = timedelta(seconds=offline_cfg.poll_interval_seconds)
    grouping_interval = live_cfg.grouping_interval_seconds

    last_timestamps: dict[str, str] = {}
    last_grouping_dt = start_dt
    steps_processed = 0

    logger.info(
        "Offline replay: {} -> {} (step={}s)",
        offline_cfg.start,
        offline_cfg.stop,
        offline_cfg.poll_interval_seconds,
    )

    proto_bundle = _find_module_bundle(bundles, "proto_traffic")
    current = start_dt
    while current < stop_dt:
        window_stop = min(current + step, stop_dt)
        _offline_tick(
            bundles,
            pg,
            pcap_client,
            persister,
            pipeline_builder,
            last_timestamps,
            current,
            window_stop,
        )

        if (window_stop - last_grouping_dt).total_seconds() >= grouping_interval:
            _run_grouping_cycle(
                pg,
                gap_tolerance,
                cross_source_gap,
                max_alarm_duration_seconds=max_alarm_duration,
                pcap_client=pcap_client,
            )
            last_grouping_dt = window_stop

        current = window_stop
        steps_processed += 1

    _run_grouping_cycle(
        pg,
        gap_tolerance,
        cross_source_gap,
        max_alarm_duration_seconds=max_alarm_duration,
        pcap_client=pcap_client,
    )
    _run_offline_cross_source_aggregation(pg, proto_bundle, cross_source_gap, start_dt, stop_dt)
    logger.info("Offline replay complete: {} steps processed", steps_processed)


def _run_offline_cross_source_aggregation(
    pg: PostgresConnector,
    proto_bundle: ModuleBundle | None,
    cross_source_gap: int,
    window_start: datetime,
    window_stop: datetime,
) -> None:
    """Run x1 cross-source enrichment over the full offline replay window.

    Unlike the live path (which bounds enrichment to the rolling
    lookback around ``now``), the offline replay enriches the entire
    historical window it just processed.

    Args:
        pg: PostgreSQL connector.
        proto_bundle: Optional ``proto_traffic`` bundle for the protocol
            vocabulary.
        cross_source_gap: Δ for the cross-source match window (§7a D-b,
            read from the rule-based config).
        window_start: Replay window start.
        window_stop: Replay window stop.
    """
    try:
        from otalon_clas.detection.cross_source import aggregate_cross_source

        protocols: list[str] = []
        if proto_bundle is not None:
            protocols = proto_bundle.influx.fetch_distinct_tag_values(
                start=window_start.isoformat(),
                stop=window_stop.isoformat(),
            )
        aggregate_cross_source(
            connector=pg,
            protocol_vocabulary=protocols,
            gap_tolerance_seconds=cross_source_gap,
            window_start=window_start,
            window_stop=window_stop,
        )
    except Exception:
        logger.exception("Offline cross-source aggregation failed")


def _offline_tick(
    bundles: list[ModuleBundle],
    pg: PostgresConnector,
    pcap_client: PcapFlagClient | None,
    persister: AnomalyPersister,
    pipeline_builder: PipelineBuilder,
    last_timestamps: dict[str, str],
    window_start: datetime,
    window_stop: datetime,
) -> None:
    """Execute one offline tick across all modules.

    Args:
        bundles: Per-module runtime bundles.
        pg: PostgreSQL connector.
        pcap_client: Optional PCAP flagging client.
        persister: Anomaly persister.
        pipeline_builder: Post-processing pipeline.
        last_timestamps: Mutable dict of last processed timestamps.
        window_start: Window start datetime.
        window_stop: Window stop datetime.
    """
    start_iso = window_start.isoformat()
    stop_iso = window_stop.isoformat()

    for bundle in bundles:
        try:
            _offline_predict_module(
                bundle,
                pg,
                pcap_client,
                persister,
                pipeline_builder,
                last_timestamps,
                start_iso,
                stop_iso,
            )
        except Exception:
            logger.exception("Offline tick failed for module '{}'", bundle.config.name)


def _offline_predict_module(
    bundle: ModuleBundle,
    pg: PostgresConnector,
    pcap_client: PcapFlagClient | None,
    persister: AnomalyPersister,
    pipeline_builder: PipelineBuilder,
    last_timestamps: dict[str, str],
    start_iso: str,
    stop_iso: str,
) -> None:
    """Run prediction for a single module during an offline tick.

    Args:
        bundle: Module runtime bundle.
        pg: PostgreSQL connector.
        pcap_client: Optional PCAP flagging client.
        persister: Anomaly persister.
        pipeline_builder: Post-processing pipeline.
        last_timestamps: Mutable dict of last processed timestamps.
        start_iso: Window start ISO timestamp.
        stop_iso: Window stop ISO timestamp.
    """
    mod = bundle.config
    effective_start = last_timestamps.get(mod.name, start_iso)

    df = cast(pl.DataFrame, bundle.influx.fetch(start=effective_start, stop=stop_iso))
    if df.is_empty():
        last_timestamps[mod.name] = stop_iso
        return

    last_timestamps[mod.name] = _extract_max_timestamp(df, stop_iso)
    df_processed = bundle.preprocessor.preprocess_for_prediction(df)
    if df_processed.is_empty():
        return
    outcome = _detect(bundle, df_processed, df, stop_iso)
    _handle_prediction_result(outcome, bundle, pg, pcap_client, persister, pipeline_builder)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _load_persisted_models(model_store: ModelStore, bundles: list[ModuleBundle]) -> None:
    """Load persisted ML models and scalers into module bundles.

    Args:
        model_store: ML model persistence store.
        bundles: Per-module runtime bundles.
    """
    for bundle in bundles:
        _load_single_model(model_store, bundle)


def _load_single_model(model_store: ModelStore, bundle: ModuleBundle) -> None:
    """Attempt to load a persisted model for a single module.

    Args:
        model_store: ML model persistence store.
        bundle: Module runtime bundle to populate.
    """
    try:
        model, scaler, metadata = model_store.load(bundle.config.name)
        raw_map = metadata.get("label_map", {})
        label_map = {int(k): v for k, v in raw_map.items()}
        protocol_map = metadata.get("protocol_map")
        # The trained feature order is part of the model's contract; the
        # prediction path selects columns by it rather than by whatever
        # config.json currently lists (audit CLAS-03).
        raw_features = metadata.get("feature_columns")
        feature_columns = tuple(raw_features) if raw_features else None
        # Build the full inference model first, then publish it as one
        # atomic reference swap so a live reader never sees a partial
        # combination (audit A-05).
        inference_model = InferenceModel(
            backend=model,
            scaler=scaler,
            label_map=label_map,
            protocol_map=protocol_map,
            feature_columns=feature_columns,
        )
        if protocol_map and hasattr(bundle.preprocessor, "load_protocol_map"):
            bundle.preprocessor.load_protocol_map(protocol_map, lock=True)
            logger.info(
                "Module '{}': loaded protocol_map with {} entries",
                bundle.config.name,
                len(protocol_map),
            )
        bundle.set_inference_model(inference_model)
        logger.info(
            "Module '{}': loaded persisted ML model (feature_columns={})",
            bundle.config.name,
            list(feature_columns) if feature_columns else "unset (legacy artifact)",
        )
    except FileNotFoundError:
        # ONE line per process start. The classification gate is not evaluated
        # for this module at all until an artifact is published, so the former
        # per-anomaly-tick warning is gone (CLAS-063).
        logger.warning(
            "Module '{}': no persisted ML model found; classification gate skipped "
            "for this module until a model is published",
            bundle.config.name,
        )
    except ArtifactIntegrityError as exc:
        # Distinct from a generic load failure: the artifact on disk is
        # not the one this suite wrote. Classification stays off and the
        # reason is named, because "corrupt pickle" and "someone swapped
        # the model file" warrant very different operator responses
        # (CLAS-048).
        logger.error(
            "Module '{}': ML model artifact REJECTED by integrity check, " "classification stays off — {}",
            bundle.config.name,
            exc,
        )
        bundle.mark_ml_degraded(f"model integrity check failed: {exc}")
    except Exception as exc:
        # A corrupt or version-incompatible artifact must not take the
        # whole service down at boot: bounds and frequency detection do
        # not depend on the classifier. Leave the module ML-inactive and
        # keep going (mirrors GroupClassifier.load).
        logger.exception(
            "Module '{}': failed to load persisted ML model, classification stays off",
            bundle.config.name,
        )
        bundle.mark_ml_degraded(f"model load failed: {exc}")


def _bootstrap_frequency_profiles(bundles: list[ModuleBundle]) -> None:
    """Load persisted frequency profiles for every bundle, if enabled.

    When ``frequency_monitor.persistence_enabled`` is ``False`` the
    monitors have no repository wired up and this is a per-bundle no-op
    that returns immediately. With the flag on, each module gets a
    single INFO log line so the operator can confirm the cache was
    populated before the first detection tick.
    """
    for bundle in bundles:
        if bundle.freq_monitor.repository is None:
            continue
        try:
            bundle.freq_monitor.bootstrap_from_repository()
        except Exception:
            logger.exception(
                "Module '{}': frequency-profile bootstrap failed; " "continuing with empty cache",
                bundle.config.name,
            )


def _start_frequency_invalidator(
    config: AppConfig,
    pg: PostgresConnector,
    bundles: list[ModuleBundle],
) -> FrequencyProfileInvalidator | None:
    """Start the PG LISTEN/NOTIFY invalidator when persistence is enabled.

    Dispatches each ``(module, series_id)`` payload to the matching
    bundle's :class:`FrequencyMonitor`. The periodic refresh path
    re-runs the bootstrap load for every monitor as a safety net for
    missed notifies (design.md Decision 2 / Fork 2 = c).

    Returns ``None`` when the feature flag is off or no enabled module
    carries a frequency monitor that uses persistence.
    """
    if not config.frequency_monitor.persistence_enabled:
        return None
    bundles_by_module: dict[str, ModuleBundle] = {
        b.config.name: b for b in bundles if b.freq_monitor.repository is not None
    }
    if not bundles_by_module:
        return None

    def _on_invalidate(module: str, series_id: str) -> None:
        bundle = bundles_by_module.get(module)
        if bundle is None:
            logger.debug(
                "frequency NOTIFY for unknown module '{}', series_id '{}' — ignored",
                module,
                series_id,
            )
            return
        bundle.freq_monitor.apply_invalidation(series_id)

    def _on_periodic_refresh() -> None:
        # Periodic safety-net (~60 s): MERGE override changes into the
        # existing cache rather than wiping runtime last_seen. The
        # initial bootstrap at process start (called separately during
        # ModuleBundle construction) still does a full load and the
        # one INFO log line. Audit M1 / A1 / C-05.
        for bundle in bundles_by_module.values():
            try:
                bundle.freq_monitor.bootstrap_from_repository(is_initial=False)
            except Exception:
                logger.exception(
                    "Module '{}': periodic frequency-profile refresh failed",
                    bundle.config.name,
                )

    invalidator = FrequencyProfileInvalidator(
        connector=pg,
        channel=config.frequency_monitor.notify_channel,
        refresh_interval_seconds=config.frequency_monitor.refresh_interval_seconds,
        on_invalidate=_on_invalidate,
        on_periodic_refresh=_on_periodic_refresh,
    )
    invalidator.start()
    return invalidator


def _start_bounds_invalidator(
    config: AppConfig,
    pg: PostgresConnector,
    bundles: list[ModuleBundle],
) -> BoundsInvalidator:
    """Start bounds cache invalidation for every enabled module."""
    bundles_by_module = {bundle.config.name: bundle for bundle in bundles}

    def _on_invalidate(module: str, series_id: str) -> None:
        bundle = bundles_by_module.get(module)
        if bundle is None:
            logger.debug("bounds NOTIFY for unknown module '{}', ignored", module)
            return
        logger.info("Bounds invalidation received for {}/{}", module, series_id)
        bundle.bounds_manager.invalidate()

    def _on_periodic_refresh() -> None:
        for bundle in bundles_by_module.values():
            bundle.bounds_manager.invalidate()

    invalidator = BoundsInvalidator(
        connector=pg,
        poll_interval_seconds=max(10, config.prediction.live.poll_interval_seconds * 2),
        on_invalidate=_on_invalidate,
        on_periodic_refresh=_on_periodic_refresh,
    )
    invalidator.start()
    return invalidator


def _start_port_rule_refresher(
    config: AppConfig,
    pg: PostgresConnector,
    bundles: list[ModuleBundle],
) -> PortRuleRefresher | None:
    """Start the port-rule refresh thread for the conn module (CLAS-033).

    Only the ``conn`` module uses port-collapse rules. If no conn bundle
    is found or port-collapsing is disabled, return ``None``.
    """
    conn_bundle = next((b for b in bundles if b.config.name == "conn"), None)
    if conn_bundle is None:
        logger.debug("No conn module bundle, skipping port-rule refresher")
        return None

    preprocessor = conn_bundle.preprocessor
    if not hasattr(preprocessor, "reload_rules_cache"):
        logger.debug("Conn preprocessor has no reload_rules_cache, skipping refresher")
        return None

    rules_repository = PortCollapseRulesRepository(connector=pg)

    refresher = PortRuleRefresher(
        pg_connector=pg,
        influx_connector=conn_bundle.influx,
        rules_repository=rules_repository,
        port_config=PortCollapseConfig(),
        bucket_config=DynamicBucketConfig(),
        refresh_config=config.port_rule_refresh,
        module_name="conn",
        reload_callback=preprocessor.reload_rules_cache,
    )
    refresher.start()
    logger.info("Port-rule refresher started for module 'conn'")
    return refresher


def _shutdown(bundles: list[ModuleBundle], pg: PostgresConnector) -> None:
    """Release all resources during shutdown.

    Args:
        bundles: Per-module runtime bundles with InfluxDB connections.
        pg: PostgreSQL connector to dispose.
    """
    for bundle in bundles:
        try:
            bundle.influx.close()
        except Exception:
            logger.exception("Failed to close InfluxDB connection for '{}'", bundle.config.name)

    try:
        pg.dispose()
    except Exception:
        logger.exception("Failed to dispose PostgreSQL connection pool")

    logger.info("Shutdown complete")


if __name__ == "__main__":
    main()
