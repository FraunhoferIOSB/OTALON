"""Training helpers shared between boot and runtime retrain paths.

These functions are intentionally free of live-loop state so they can be
called both from the one-shot boot trainer and from the in-process
runtime JobRunner without circular imports.

Two families of helpers live here:

* The eager ``_train_bounds`` / ``_train_frequency`` / ``_train_classification``
  functions train **and publish** in one call. They are used by the
  boot-training path (``run_training``) where there is no live loop to
  protect, so publishing immediately is safe.
* The ``compute_*_candidate`` / ``publish_*_candidate`` functions split
  compute from publish so the runtime JobRunner can train every module
  into isolated, in-memory candidates first and only mutate the live
  DB / files / bundle after *all* candidate training has succeeded
  (audit B-02 / B-03).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, cast

import numpy as np
import polars as pl
from loguru import logger

from otalon_clas.common.model_store import ModelStore
from otalon_clas.common.settings import AppConfig, ModuleConfig
from otalon_clas.detection.frequency_profile_repository import emit_notify
from otalon_clas.ml.labeling import (
    ConnectionLabeler,
    MacLabeler,
    ProtoLabeler,
    load_labels,
)
from otalon_clas.ml.pipeline import MLPipeline
from otalon_clas.ml.registry import get_backend
from otalon_clas.runtime.module_bundle import ModuleBundle

LABELER_MAP: dict[str, type] = {
    "conn": ConnectionLabeler,
    "mac_traffic": MacLabeler,
    "proto_traffic": ProtoLabeler,
}

_CLASSIFIER_MODULES: frozenset[str] = frozenset(
    {"conn", "mac_traffic", "proto_traffic"}
)


def _extract_train_window(df: pl.DataFrame) -> tuple[datetime | None, datetime | None]:
    """Extract first and last timestamps from a training DataFrame."""
    if "time" not in df.columns or df.is_empty():
        return None, None
    try:
        ts_min = df["time"].min()
        ts_max = df["time"].max()
        return _coerce_dt(ts_min), _coerce_dt(ts_max)
    except Exception:
        return None, None


def _coerce_dt(value: Any) -> datetime | None:
    """Coerce a value to a UTC-aware datetime, returning None on failure."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value
    try:
        return datetime.fromisoformat(str(value)).replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Eager trainers (boot path): train + publish in one call
# ---------------------------------------------------------------------------


def _train_bounds(
    config: AppConfig,
    bundle: ModuleBundle,
    df: pl.DataFrame,
    *,
    invalidate_cache: bool = True,
) -> None:
    """Train boundary thresholds for a module and persist them atomically.

    Args:
        config: Application configuration.
        bundle: Module runtime bundle.
        df: Preprocessed training data.
        invalidate_cache: When True, clear the in-memory bounds cache so
            the next live tick reads the newly persisted bounds from
            PostgreSQL.
    """
    candidate = compute_bounds_candidate(config, bundle, df)
    publish_bounds_candidate(bundle, candidate, invalidate_cache=invalidate_cache)


def _train_frequency(
    bundle: ModuleBundle,
    df: pl.DataFrame,
    *,
    notify_channel: str | None = None,
) -> None:
    """Train frequency profiles and optionally emit invalidation NOTIFYs.

    Trains with full-replace semantics, mirroring the bounds trainer
    (``bounds_repository.save(replace=True)`` in
    :func:`publish_bounds_candidate`). Both trainers consume the SAME
    preprocessed training DataFrame over the SAME window, so a series
    absent from the frequency result is absent from the window, not
    merely unprofiled — keeping it would leave a profile no later run
    can ever refresh (the stale-profile pile-up this replaces).

    Args:
        bundle: Module runtime bundle.
        df: Training data DataFrame.
        notify_channel: When supplied, emit a cache-invalidation NOTIFY
            for every trained series so other listeners reload.
    """
    bundle.freq_monitor.train(df=df, tag_key=bundle.config.tag_key, replace=True)
    logger.info(
        "Module '{}': frequency profiles trained ({} series)",
        bundle.config.name,
        bundle.freq_monitor.series_count,
    )
    if notify_channel and bundle.freq_monitor.repository is not None:
        connector = bundle.freq_monitor.repository._connector
        module = bundle.config.name
        for series_id in bundle.freq_monitor.profiles:
            try:
                emit_notify(connector, notify_channel, module, series_id)
            except Exception:
                logger.warning(
                    "Failed to emit frequency NOTIFY for {}.{}",
                    module,
                    series_id,
                )


def _fetch_ml_training_df(
    bundle: ModuleBundle,
    mod: ModuleConfig,
    fallback_start: str,
    fallback_stop: str,
    fallback_df: pl.DataFrame,
) -> pl.DataFrame:
    """Fetch the ML training DataFrame, optionally from a dedicated window."""
    cls_start = mod.classification.train_window_start
    cls_stop = mod.classification.train_window_stop
    if not cls_start or not cls_stop:
        return fallback_df

    if (cls_start, cls_stop) == (fallback_start, fallback_stop):
        return fallback_df

    logger.info(
        "Module '{}': fetching dedicated ML training window [{}, {}]",
        mod.name,
        cls_start,
        cls_stop,
    )
    df = cast(pl.DataFrame, bundle.influx.fetch(start=cls_start, stop=cls_stop))
    if df.is_empty():
        logger.warning(
            "Module '{}': dedicated ML training window returned 0 rows; "
            "falling back to bounds window",
            mod.name,
        )
        return fallback_df
    logger.info("Module '{}': ML training fetched {} rows", mod.name, len(df))
    return df


def _encode_for_training(
    df: pl.DataFrame,
    feature_cols: list[str],
) -> tuple[np.ndarray, np.ndarray, dict[int, str]]:
    """Extract feature matrix and encode string labels to integers."""
    if "label" not in df.columns:
        return np.empty((0, len(feature_cols))), np.empty(0, dtype=int), {}

    available_features = [c for c in feature_cols if c in df.columns]
    X = df.select(available_features).to_numpy().astype(np.float64)
    labels_str = df["label"].to_list()

    unique_labels = sorted(set(labels_str))
    str_to_int = {lbl: idx for idx, lbl in enumerate(unique_labels)}
    label_map = {idx: lbl for lbl, idx in str_to_int.items()}
    y = np.array([str_to_int[lbl] for lbl in labels_str], dtype=int)

    return X, y, label_map


def _train_classification(
    config: AppConfig,
    model_store: ModelStore,
    bundle: ModuleBundle,
    df: pl.DataFrame,
    *,
    mitre_file: str | None = None,
) -> None:
    """Train the ML classifier for a module and persist it atomically.

    Trains into the live ``bundle.ml_pipeline`` — only safe on the boot
    path where no live loop is serving predictions. The runtime path uses
    :func:`train_classifier_candidate` instead so the live bundle is never
    mutated before publication (audit B-03).

    Args:
        config: Application configuration.
        model_store: ML model persistence store.
        bundle: Module runtime bundle.
        df: Training data DataFrame.
        mitre_file: Optional MITRE-technique file override (runtime jobs
            forward ``job.mitre_file`` here; boot uses the module config).
    """
    candidate = train_classifier_candidate(
        bundle, df, pipeline=bundle.ml_pipeline, mitre_file=mitre_file
    )
    if candidate is None:
        return
    publish_classifier_candidate(
        model_store,
        bundle,
        candidate,
        swap_into_bundle=False,
        force_publish_class_set_shrink=bundle.config.classification.force_publish_class_set_shrink,
    )


def _train_module(
    config: AppConfig,
    model_store: ModelStore,
    bundle: ModuleBundle,
    start: str,
    stop: str,
    runtime_config: Any | None = None,
) -> None:
    """Train every enabled artifact type for one module (boot path).

    Fetches the training window from InfluxDB, preprocesses it, and trains
    bounds, frequency, and the ML classifier as enabled by the module
    config. This is the eager boot-training body that was inlined in
    ``main.py`` before the runtime refactor; the runtime path uses the
    staged JobRunner instead.

    Args:
        config: Application configuration.
        model_store: ML model persistence store.
        bundle: Module runtime bundle.
        start: ISO-8601 training-window start.
        stop: ISO-8601 training-window stop.
    """
    mod = bundle.config
    df = cast(pl.DataFrame, bundle.influx.fetch(start=start, stop=stop))
    if df.is_empty():
        logger.warning(
            "Module '{}': no training data in [{}, {}]; skipping",
            mod.name,
            start,
            stop,
        )
        return

    df_processed = bundle.preprocessor.preprocess_for_training(df)
    logger.info(
        "Module '{}': preprocessed {} training rows",
        mod.name,
        len(df_processed),
    )

    if mod.bounds_enabled:
        _train_bounds(config, bundle, df_processed)

    frequency_enabled = mod.frequency_monitor.enabled
    if runtime_config is not None:
        frequency_enabled = runtime_config.get_bool(
            "otalon-clas",
            f"detection.{mod.name}.frequency_enabled",
            default=frequency_enabled,
        )
    if frequency_enabled:
        _train_frequency(bundle, df_processed)

    # ML training is gated on classification.training_enabled (NOT on the
    # live-prediction ``enabled`` flag) per ml-training-decoupling.md.
    if mod.classification.training_enabled:
        ml_df = _fetch_ml_training_df(bundle, mod, start, stop, df)
        _train_classification(config, model_store, bundle, ml_df)
    else:
        logger.info(
            "Module '{}': classification.training_enabled=false, skipping ML training",
            mod.name,
        )


# ---------------------------------------------------------------------------
# Staged trainers (runtime path): compute candidate, publish separately
# ---------------------------------------------------------------------------


@dataclass
class BoundsCandidate:
    """In-memory trained bounds for one module, not yet persisted."""

    module: str
    bounds: dict[str, dict[str, tuple[float, float]]]
    first_ts: datetime | None
    last_ts: datetime | None


@dataclass
class FrequencyCandidate:
    """In-memory trained frequency profiles for one module, not yet persisted."""

    module: str
    profiles: dict[str, Any]


@dataclass
class ClassifierCandidate:
    """Fully-trained isolated classifier artifacts for one module.

    Holds a freshly-built pipeline/scaler and the metadata so publication
    is a pure file write + in-process reference swap; the live bundle is
    never touched during training (audit B-03).
    """

    module: str
    pipeline: MLPipeline
    label_map: dict[int, str]
    metadata: dict[str, Any]
    protocol_map: dict[str, int] | None
    feature_columns: list[str]
    metrics: dict[str, Any] = field(default_factory=dict)


def _load_previous_bounds(
    bundle: ModuleBundle,
) -> dict[str, dict[str, tuple[float, float]]]:
    """Load the currently published bounds for a module.

    The coverage guard (CLAS-028) carries an existing envelope forward for
    a series that lacks enough training coverage, so the published set must
    be known before training. A repository failure degrades to an empty
    mapping: such a series is then skipped without a carried-forward
    envelope rather than failing the whole retrain.
    """
    try:
        return bundle.bounds_repository.load(bundle.config.name)
    except Exception:
        logger.exception(
            "Module '{}': failed to load previous bounds; coverage-skipped "
            "series will not carry an envelope forward",
            bundle.config.name,
        )
        return {}


def compute_bounds_candidate(
    config: AppConfig,
    bundle: ModuleBundle,
    df: pl.DataFrame,
) -> BoundsCandidate:
    """Train bounds into an in-memory candidate WITHOUT persisting.

    Raises:
        ValueError: When the trained bounds set is empty, so an empty
            window fails the whole job before any artifact is published
            (audit F3 / CLAS-011).
    """
    mod = bundle.config
    bounds_dict = bundle.bounds_trainer.train(
        df=df,
        tag_key=mod.tag_key,
        features=mod.features,
        config=config.training.boundary,
        previous_bounds=_load_previous_bounds(bundle),
    )
    if not bounds_dict:
        raise ValueError(
            f"Module '{mod.name}': bounds training produced an empty set; "
            "refusing to publish (empty/insufficient training window)."
        )
    first_ts, last_ts = _extract_train_window(df)
    return BoundsCandidate(
        module=mod.name,
        bounds=bounds_dict,
        first_ts=first_ts,
        last_ts=last_ts,
    )


def publish_bounds_candidate(
    bundle: ModuleBundle,
    candidate: BoundsCandidate,
    *,
    invalidate_cache: bool = True,
) -> None:
    """Persist a bounds candidate atomically and refresh the live cache."""
    bundle.bounds_repository.save(
        module=candidate.module,
        bounds=candidate.bounds,
        first_ts=candidate.first_ts,
        last_ts=candidate.last_ts,
        replace=True,
    )
    if invalidate_cache:
        bundle.bounds_manager.invalidate()
    else:
        bundle.bounds_manager.load_bounds(candidate.bounds)
    logger.info(
        "Module '{}': bounds published for {} series",
        candidate.module,
        len(candidate.bounds),
    )


def compute_frequency_candidate(
    bundle: ModuleBundle,
    df: pl.DataFrame,
) -> FrequencyCandidate:
    """Compute frequency profiles into an in-memory candidate (no persist)."""
    profiles = bundle.freq_monitor.compute_candidate_profiles(df, bundle.config.tag_key)
    return FrequencyCandidate(module=bundle.config.name, profiles=profiles)


def publish_frequency_candidate(
    bundle: ModuleBundle,
    candidate: FrequencyCandidate,
    *,
    notify_channel: str | None = None,
    replace: bool = True,
) -> None:
    """Persist a frequency candidate and emit invalidation NOTIFYs.

    Publishes with full-replace semantics by default, matching
    :func:`publish_bounds_candidate`: the module's persisted profile set
    becomes exactly ``candidate.profiles`` inside one transaction, so a
    retrain swaps the set instead of stacking on top of every earlier
    run. Operator overrides on surviving series are preserved; an
    override on a series the run no longer covers goes with the series.

    Args:
        bundle: Module runtime bundle.
        candidate: Staged frequency profiles for one module.
        notify_channel: Optional PostgreSQL NOTIFY channel.
        replace: Set ``False`` for a deliberately partial publication
            that must not drop series outside the candidate.
    """
    bundle.freq_monitor.publish_profiles(
        candidate.profiles,
        notify_channel=notify_channel,
        replace=replace,
    )


def train_classifier_candidate(
    bundle: ModuleBundle,
    df: pl.DataFrame,
    *,
    pipeline: MLPipeline | None = None,
    mitre_file: str | None = None,
) -> ClassifierCandidate | None:
    """Train an ML classifier into an ISOLATED candidate pipeline.

    Builds a fresh :class:`MLPipeline` (unless *pipeline* is supplied for
    the boot path) so the live ``bundle.ml_pipeline`` is never fitted
    during a runtime retrain (audit B-03). Returns ``None`` when there is
    nothing to train (no mitre file, no labeler, or no labeled samples).

    Args:
        bundle: Module runtime bundle (read-only for the runtime path).
        df: Training data DataFrame.
        pipeline: Pipeline to fit into. When ``None`` a fresh isolated
            pipeline is constructed from the module's algorithm config.
        mitre_file: MITRE-technique file. Falls back to the module config
            when ``None``.
    """
    mod = bundle.config
    effective_mitre = mitre_file or mod.classification.mitre_technique_file
    if not effective_mitre:
        logger.warning(
            "Module '{}': no mitre_technique_file, skipping ML training",
            mod.name,
        )
        return None

    labeler_cls = LABELER_MAP.get(mod.name)
    if labeler_cls is None:
        logger.warning(
            "Module '{}': no labeler registered, skipping ML training", mod.name
        )
        return None

    labels = load_labels(effective_mitre)
    # Both branches now apply the same collapsed/bucketed transform the
    # live prediction path uses; the classifier must be fitted on the
    # distribution it will be scored on (audit CLAS-01).
    if hasattr(bundle.preprocessor, "preprocess_for_ml_training"):
        preprocessed = bundle.preprocessor.preprocess_for_ml_training(df)
    else:
        preprocessed = bundle.preprocessor.preprocess_for_prediction(df)
    preprocessing_mode = "bucketed"
    logger.info(
        "Module '{}': ML preprocess produced {} rows (raw {}, mode={})",
        mod.name,
        len(preprocessed),
        len(df),
        preprocessing_mode,
    )
    labeled_df = labeler_cls(
        labels, label_field=mod.classification.label_field
    ).apply_labels(preprocessed)
    label_counts = (
        labeled_df.group_by("label")
        .len()
        .sort("len", descending=True)
        .head(10)
        .to_dicts()
    )
    logger.info("Module '{}': label distribution top-10 = {}", mod.name, label_counts)
    feature_cols = bundle.preprocessor.get_feature_columns()
    X, y, label_map = _encode_for_training(labeled_df, feature_cols)

    if X.shape[0] == 0:
        logger.warning("Module '{}': no labeled samples after preprocessing", mod.name)
        return None

    candidate_pipeline = pipeline or _build_isolated_pipeline(mod)
    metrics = candidate_pipeline.train(
        X=X,
        y=y,
        balance_per_class=mod.classification.balance_per_class,
        random_seed=mod.classification.random_seed,
    )

    metadata = {
        "module_name": mod.name,
        "algorithm": mod.classification.algorithm,
        "label_map": {str(k): v for k, v in label_map.items()},
        # Records which transform produced the training features so a
        # future train/serve divergence is detectable from the artifact
        # rather than only from wrong predictions (audit CLAS-01).
        "preprocessing_mode": preprocessing_mode,
        **metrics,
    }
    protocol_map = getattr(bundle.preprocessor, "protocol_map", None)
    feature_columns = list(bundle.preprocessor.get_feature_columns())
    logger.info(
        "Module '{}': candidate ML trained — accuracy={:.4f}, f1={:.4f}, Klassen: {}",
        mod.name,
        metrics["accuracy"],
        metrics["f1_weighted"],
        len(label_map),
    )
    return ClassifierCandidate(
        module=mod.name,
        pipeline=candidate_pipeline,
        label_map=label_map,
        metadata=metadata,
        protocol_map=dict(protocol_map) if protocol_map else None,
        feature_columns=feature_columns,
        metrics=metrics,
    )


def publish_classifier_candidate(
    model_store: ModelStore,
    bundle: ModuleBundle,
    candidate: ClassifierCandidate,
    *,
    swap_into_bundle: bool = False,
    force_publish_class_set_shrink: bool = False,
) -> bool:
    """Persist a classifier candidate atomically to disk.

    The in-process swap into the live bundle is performed separately by
    the supervisor under a shared read/write lock (audit A-05), so this
    function only writes the artifact. On the boot path
    ``swap_into_bundle=True`` also mirrors the candidate into the bundle
    since there is no concurrent reader.
    """
    previous_metadata = model_store.current_metadata(candidate.module)
    previous_count = len((previous_metadata or {}).get("label_map", {}))
    published = model_store.save(
        module_name=candidate.module,
        model=candidate.pipeline.backend,
        scaler=candidate.pipeline.scaler,
        metadata=candidate.metadata,
        protocol_map=candidate.protocol_map,
        feature_columns=candidate.feature_columns,
        force_publish_class_set_shrink=force_publish_class_set_shrink,
    )
    logger.info(
        "Module '{}': Klassen: {} (vorher {}){}",
        candidate.module,
        len(candidate.label_map),
        previous_count,
        " — published" if published else " — retained previous model",
    )
    if published and swap_into_bundle:
        bundle.ml_pipeline.backend = candidate.pipeline.backend
        bundle.ml_pipeline.scaler = candidate.pipeline.scaler
        bundle.label_map = dict(candidate.label_map)
    return published


def _build_isolated_pipeline(mod: ModuleConfig) -> MLPipeline:
    """Construct a fresh, unfitted pipeline for candidate training."""
    backend_cls = get_backend(mod.classification.algorithm)
    backend = backend_cls(**mod.classification.params)
    return MLPipeline(
        backend=backend,
        confidence_threshold=mod.classification.confidence_threshold,
    )
