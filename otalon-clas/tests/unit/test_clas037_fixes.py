"""Regression tests for the CLAS-037 P1 batch.

* CLAS-01 — the classifier was trained on unbucketed 1-second rows but
  scored on port-collapsed, time-bucketed rows.
* CLAS-02 — staging persisted port-collapse rules before any publish
  decision, and the compensation path could not undo it.
* CLAS-03 — inference derived its feature order from ``config.json``
  instead of the model's persisted ``feature_columns``, and swallowed
  every failure into a silent ``None``.
* CLAS-04 — ground-truth label bounds were built naive and compared
  against UTC measurement timestamps.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import polars as pl
import pytest

from otalon_clas.ml.labeling import ConnectionLabeler, load_labels
from otalon_clas.preprocessing.connection import ConnectionPreprocessor

pytestmark = pytest.mark.unit


# ── CLAS-01: train/serve preprocessing parity ──────────────────────────


def _raw_frame() -> pl.DataFrame:
    """Two seconds of traffic for one src/dst pair on ephemeral ports."""
    rows = []
    for second in range(4):
        rows.append(
            {
                "time": datetime(2026, 3, 6, 21, 8, second),
                "uci": (
                    "aa:bb:cc:dd:ee:01/aa:bb:cc:dd:ee:02//IPv4/"
                    f"192.168.0.10/192.168.0.20/4840/{40000 + second}/Ethernet:IPv4:TCP"
                ),
                "packet_count": 10.0,
                "total_volume": 1000.0,
            }
        )
    return pl.DataFrame(rows)


def _preprocessor(**kwargs: Any) -> ConnectionPreprocessor:
    defaults: dict[str, Any] = {
        "features": ["packet_count", "total_volume"],
        "tag_key": "uci",
        "module_name": "conn",
        "params": {
            "port_collapsing_enabled": True,
            "include_protocols_feature": True,
        },
    }
    defaults.update(kwargs)
    return ConnectionPreprocessor(**defaults)


class TestTrainServeParity:
    """The ML training transform must equal the prediction transform."""

    def test_ml_training_matches_prediction_schema(self) -> None:
        pre = _preprocessor()
        raw = _raw_frame()

        trained = pre.preprocess_for_ml_training(raw)
        served = _preprocessor().preprocess_for_prediction(raw)

        assert trained.columns == served.columns

    def test_ml_training_matches_prediction_values(self) -> None:
        """Same input must yield an identical feature matrix on both paths."""
        raw = _raw_frame()

        trained = _preprocessor().preprocess_for_ml_training(raw)
        served = _preprocessor().preprocess_for_prediction(raw)

        cols = _preprocessor().get_feature_columns()
        assert trained.select(cols).to_dicts() == served.select(cols).to_dicts()

    def test_ml_training_collapses_ephemeral_ports(self) -> None:
        """The unbucketed path kept per-port UCIs; the fixed one collapses them.

        The four input rows use four different ephemeral source ports. The
        serving path collapses those into a single ``*`` series, and
        training must do the same or it learns per-port series that can
        never occur at inference time.
        """
        raw = _raw_frame()
        trained = _preprocessor().preprocess_for_ml_training(raw)

        assert trained["uci"].n_unique() == 1
        assert "*" in trained["uci"][0]
        assert raw["uci"].n_unique() == 4

    def test_ml_training_emits_the_bucket_join_key(self) -> None:
        trained = _preprocessor().preprocess_for_ml_training(_raw_frame())
        assert "_bucket_epoch" in trained.columns

    def test_empty_input_is_passed_through(self) -> None:
        empty = pl.DataFrame(
            {"time": [], "uci": []},
            schema={"time": pl.Datetime, "uci": pl.Utf8},
        )
        assert _preprocessor().preprocess_for_ml_training(empty).is_empty()


class TestTrainingDoesNotPersistRules:
    """ML training must not rewrite the live rule table as a side effect."""

    def test_ml_training_never_calls_save(self) -> None:
        saved: list[Any] = []

        class _Repo:
            def save(self, module: str, rules: list[Any]) -> int:
                saved.append((module, rules))
                return len(rules)

            def load(self, module: str) -> list[Any]:
                return []

        pre = _preprocessor(rules_repository=_Repo())
        pre.preprocess_for_ml_training(_raw_frame())

        assert saved == [], "ML training must not persist port-collapse rules"


# ── CLAS-03: persisted feature columns drive inference ─────────────────


class _Backend:
    """Minimal backend recording the matrix it was asked to predict on."""

    n_features_in_ = 3

    def __init__(self) -> None:
        self.seen: np.ndarray | None = None

    def predict(self, X: np.ndarray) -> np.ndarray:
        self.seen = X
        return np.zeros(X.shape[0], dtype=int)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        return np.tile(np.array([0.9, 0.1]), (X.shape[0], 1))


class _Scaler:
    def transform(self, X: np.ndarray) -> np.ndarray:
        return X


class TestFeatureColumnResolution:
    def _bundle(self, configured: list[str]) -> Any:
        from types import SimpleNamespace

        preprocessor = SimpleNamespace(get_feature_columns=lambda: list(configured))
        return SimpleNamespace(
            config=SimpleNamespace(name="conn"),
            preprocessor=preprocessor,
        )

    def test_persisted_order_wins_over_config_order(self) -> None:
        from otalon_clas.main import _resolve_feature_columns
        from otalon_clas.runtime.module_bundle import InferenceModel

        bundle = self._bundle(["b", "a", "c"])
        model = InferenceModel(
            backend=_Backend(),
            scaler=_Scaler(),
            label_map={0: "benign"},
            feature_columns=("a", "b", "c"),
        )

        assert _resolve_feature_columns(bundle, model) == ["a", "b", "c"]

    def test_falls_back_to_config_for_legacy_artifacts(self) -> None:
        from otalon_clas.main import _resolve_feature_columns
        from otalon_clas.runtime.module_bundle import InferenceModel

        bundle = self._bundle(["a", "b"])
        model = InferenceModel(
            backend=_Backend(), scaler=_Scaler(), label_map={0: "benign"}
        )

        assert _resolve_feature_columns(bundle, model) == ["a", "b"]

    def test_unknown_persisted_column_is_a_hard_error(self) -> None:
        from otalon_clas.main import MLPredictionError, _resolve_feature_columns
        from otalon_clas.runtime.module_bundle import InferenceModel

        bundle = self._bundle(["a", "b"])
        model = InferenceModel(
            backend=_Backend(),
            scaler=_Scaler(),
            label_map={0: "benign"},
            feature_columns=("a", "gone"),
        )

        with pytest.raises(MLPredictionError, match="cannot produce"):
            _resolve_feature_columns(bundle, model)


class TestPredictionErrorsPropagate:
    """Structural faults must raise, not vanish into a silent ``None``."""

    def _bundle(self, preprocessed: pl.DataFrame, features: list[str]) -> Any:
        from types import SimpleNamespace

        preprocessor = SimpleNamespace(
            get_feature_columns=lambda: list(features),
            preprocess_for_prediction=lambda df: preprocessed,
        )
        return SimpleNamespace(
            config=SimpleNamespace(name="conn"),
            preprocessor=preprocessor,
            ml_pipeline=SimpleNamespace(
                _apply_threshold=lambda p, pr: (p, pr.max(axis=1))
            ),
        )

    def _model(self, features: tuple[str, ...] | None = None) -> Any:
        from otalon_clas.runtime.module_bundle import InferenceModel

        return InferenceModel(
            backend=_Backend(),
            scaler=_Scaler(),
            label_map={0: "benign"},
            feature_columns=features,
        )

    def test_missing_feature_column_raises(self) -> None:
        from otalon_clas.main import MLPredictionError, _run_ml_prediction

        df = pl.DataFrame({"uci": ["x"], "_bucket_epoch": [1], "a": [1.0]})
        bundle = self._bundle(df, ["a", "b", "c"])

        with pytest.raises(MLPredictionError, match="missing"):
            _run_ml_prediction(bundle, df, self._model())

    def test_absent_join_keys_raise(self) -> None:
        from otalon_clas.main import MLPredictionError, _run_ml_prediction

        df = pl.DataFrame({"a": [1.0], "b": [2.0], "c": [3.0]})
        bundle = self._bundle(df, ["a", "b", "c"])

        with pytest.raises(MLPredictionError, match="join keys"):
            _run_ml_prediction(bundle, df, self._model())

    def test_feature_width_mismatch_raises(self) -> None:
        from otalon_clas.main import MLPredictionError, _run_ml_prediction

        df = pl.DataFrame({"uci": ["x"], "_bucket_epoch": [1], "a": [1.0], "b": [2.0]})
        bundle = self._bundle(df, ["a", "b"])

        with pytest.raises(MLPredictionError, match="width mismatch"):
            _run_ml_prediction(bundle, df, self._model())

    def test_empty_input_is_not_an_error(self) -> None:
        from otalon_clas.main import _run_ml_prediction

        empty = pl.DataFrame({"uci": [], "_bucket_epoch": [], "a": [], "b": [], "c": []})
        bundle = self._bundle(empty, ["a", "b", "c"])

        assert _run_ml_prediction(bundle, empty, self._model()) is None

    def test_columns_are_selected_in_the_persisted_order(self) -> None:
        """The model must receive its own column order, not the config's."""
        from otalon_clas.main import _run_ml_prediction

        df = pl.DataFrame(
            {"uci": ["x"], "_bucket_epoch": [1], "a": [1.0], "b": [2.0], "c": [3.0]}
        )
        bundle = self._bundle(df, ["c", "b", "a"])
        model = self._model(features=("a", "b", "c"))

        _run_ml_prediction(bundle, df, model)

        assert model.backend.seen is not None
        np.testing.assert_array_equal(model.backend.seen[0], np.array([1.0, 2.0, 3.0]))


class TestDegradedState:
    def test_marking_degraded_then_publishing_a_model_clears_it(self) -> None:
        from otalon_clas.runtime.module_bundle import InferenceModel, ModuleBundle

        bundle = ModuleBundle.__new__(ModuleBundle)
        import threading

        bundle._model_lock = threading.RLock()
        bundle._inference_model = None
        bundle._ml_degraded_reason = None
        bundle.label_map = {}

        from types import SimpleNamespace

        bundle.ml_pipeline = SimpleNamespace(backend=None, scaler=None)

        bundle.mark_ml_degraded("boom")
        assert bundle.ml_degraded_reason == "boom"

        bundle.set_inference_model(
            InferenceModel(backend=_Backend(), scaler=_Scaler(), label_map={0: "x"})
        )
        assert bundle.ml_degraded_reason is None


# ── CLAS-04: ground-truth timezone handling ────────────────────────────


def _write_gt(tmp_path: Path, start: str, end: str) -> Path:
    path = tmp_path / "gt.json"
    path.write_text(
        json.dumps(
            [
                {
                    "module_name": "T0846/arp_scan",
                    "technical_method": "arp_scan",
                    "start_time": start,
                    "end_time": end,
                    "target_ip": ["192.168.0.20"],
                    "target_mac": [],
                    "protocol": "tcp",
                    "source_ip": "192.168.0.10",
                    "source_mac": "",
                }
            ]
        )
    )
    return path


class TestGroundTruthTimezone:
    def test_bounds_are_utc_aware(self, tmp_path: Path) -> None:
        labels = load_labels(_write_gt(tmp_path, "2026-03-06 21:08:31", "2026-03-06 21:08:33"))
        assert labels[0].start_time.tzinfo is not None
        assert labels[0].end_time.tzinfo is not None

    def test_local_ground_truth_matches_utc_data(self, tmp_path: Path) -> None:
        """A 21:08:31 CET entry must label the 20:08:31Z measurement row."""
        labels = load_labels(
            _write_gt(tmp_path, "2026-03-06 21:08:31", "2026-03-06 21:08:33"),
            time_margin_seconds=5,
        )
        df = pl.DataFrame(
            {
                "time": [pd.Timestamp("2026-03-06T20:08:32Z")],
                "uci": [
                    "aa:bb:cc:dd:ee:01/aa:bb:cc:dd:ee:02//IPv4/"
                    "192.168.0.10/192.168.0.20/1/2/Ethernet:IPv4:TCP"
                ],
            }
        )

        labeled = ConnectionLabeler(labels).apply_labels(df)

        assert labeled["label"].to_list() == ["T0846/arp_scan"]

    def test_the_pre_fix_naive_row_is_no_longer_matched(self, tmp_path: Path) -> None:
        """The old behaviour matched 21:08:32 naive; that is now an hour off."""
        labels = load_labels(
            _write_gt(tmp_path, "2026-03-06 21:08:31", "2026-03-06 21:08:33"),
            time_margin_seconds=5,
        )
        df = pl.DataFrame(
            {
                "time": [pd.Timestamp("2026-03-06T21:08:32Z")],
                "uci": [
                    "aa:bb:cc:dd:ee:01/aa:bb:cc:dd:ee:02//IPv4/"
                    "192.168.0.10/192.168.0.20/1/2/Ethernet:IPv4:TCP"
                ],
            }
        )

        labeled = ConnectionLabeler(labels).apply_labels(df)

        assert labeled["label"].to_list() == ["benign"]

    def test_naive_data_timestamps_are_treated_as_utc(self, tmp_path: Path) -> None:
        """A naive data column must not raise and must compare as UTC."""
        labels = load_labels(
            _write_gt(tmp_path, "2026-03-06 21:08:31", "2026-03-06 21:08:33"),
            time_margin_seconds=5,
        )
        df = pl.DataFrame(
            {
                "time": [pd.Timestamp("2026-03-06T20:08:32")],
                "uci": [
                    "aa:bb:cc:dd:ee:01/aa:bb:cc:dd:ee:02//IPv4/"
                    "192.168.0.10/192.168.0.20/1/2/Ethernet:IPv4:TCP"
                ],
            }
        )

        labeled = ConnectionLabeler(labels).apply_labels(df)

        assert labeled["label"].to_list() == ["T0846/arp_scan"]
