"""Runtime state bundle for a single detection module.

Moved out of ``main.py`` so training helpers and the runtime JobRunner can
import the type without creating circular dependencies with the live-loop
entry point.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any

from otalon_clas.common.influx_connector import InfluxModule
from otalon_clas.common.settings import ModuleConfig
from otalon_clas.detection.bounds_manager import BoundsManager, BoundsRepository, BoundsTrainer
from otalon_clas.detection.frequency_monitor import FrequencyMonitor
from otalon_clas.ml.pipeline import MLPipeline
from otalon_clas.preprocessing.base import BasePreprocessor


@dataclass(frozen=True)
class InferenceModel:
    """Immutable snapshot of the artifacts one prediction tick needs.

    The four inference fields are bundled into a single frozen object so a
    runtime model swap replaces them as ONE atomic reference assignment.
    A prediction reader that captured the previous reference keeps using a
    fully-coherent old model; the next reader sees the fully-coherent new
    model. There is never a torn combination of a new backend with an old
    scaler/label_map (audit A-05 / B-03).
    """

    backend: Any
    scaler: Any
    label_map: dict[int, str]
    protocol_map: dict[str, int] | None = None
    feature_columns: tuple[str, ...] | None = None
    """Ordered feature columns this model was fitted on.

    Persisted by :meth:`ModelStore.save` but previously never read back:
    inference rebuilt the feature list from ``config.json`` instead. A
    config edit that reordered equal-width features therefore fed feature
    *i*'s values into feature *j*'s scaler and tree split — silently wrong
    labels, with nothing raised (audit CLAS-03). Carrying the persisted
    order on the snapshot makes the model's own contract authoritative.

    ``None`` for legacy artifacts saved before the column list was
    recorded; the caller then falls back to the configured order.
    """


@dataclass
class ModuleBundle:
    """Runtime state bundle for a single detection module.

    Groups all per-module objects needed during training and prediction
    so they can be passed around without long parameter lists.

    The ML inference artifacts are additionally exposed as an atomically
    swappable :class:`InferenceModel` reference guarded by ``_model_lock``
    so the live prediction path and a runtime model swap never race
    (audit A-05).
    """

    config: ModuleConfig
    influx: InfluxModule
    preprocessor: BasePreprocessor
    bounds_manager: BoundsManager
    bounds_trainer: BoundsTrainer
    bounds_repository: BoundsRepository
    freq_monitor: FrequencyMonitor
    ml_pipeline: MLPipeline
    label_map: dict[int, str] = field(default_factory=dict)
    _model_lock: threading.RLock = field(default_factory=threading.RLock, repr=False, compare=False)
    _inference_model: InferenceModel | None = field(default=None, repr=False, compare=False)
    _ml_degraded_reason: str | None = field(default=None, repr=False, compare=False)

    @property
    def ml_degraded_reason(self) -> str | None:
        """Why ML classification is disabled for this module, if it is.

        Set when the prediction path hits a structural fault that would
        recur every tick. Bounds and frequency detection keep running
        (audit CLAS-03).
        """
        with self._model_lock:
            return self._ml_degraded_reason

    def mark_ml_degraded(self, reason: str) -> None:
        """Disable ML classification for this module until a new model lands."""
        with self._model_lock:
            self._ml_degraded_reason = reason

    def set_inference_model(self, model: InferenceModel) -> None:
        """Atomically publish a new inference model under the swap lock.

        Also mirrors the fields into ``ml_pipeline``/``label_map`` so any
        legacy reader that still reads those attributes stays coherent.
        Publishing a model clears any degraded state, since a retrain or
        rollback is exactly what is expected to resolve it.
        """
        with self._model_lock:
            self._inference_model = model
            self.ml_pipeline.backend = model.backend
            self.ml_pipeline.scaler = model.scaler
            self.label_map = dict(model.label_map)
            self._ml_degraded_reason = None

    def restore_inference_model(self, model: InferenceModel | None) -> None:
        """Restore inference state and its preprocessor protocol map."""
        if model is None:
            return
        if hasattr(self.preprocessor, "load_protocol_map"):
            self.preprocessor.load_protocol_map(model.protocol_map or {}, lock=True)
        self.set_inference_model(model)

    def model_snapshot(self) -> InferenceModel | None:
        """Return the current inference model under the swap lock.

        Callers get a single immutable reference and can read all four
        fields off it without further locking, guaranteeing a coherent
        (backend, scaler, label_map, protocol_map) tuple.
        """
        with self._model_lock:
            return self._inference_model
