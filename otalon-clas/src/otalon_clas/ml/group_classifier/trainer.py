"""Train a Random-Forest classifier on aggregated alarm-group features.

Mirrors the workshop ``ml-baseline/train_evaluate.py`` pipeline:
StandardScaler + RandomForestClassifier with stratified k-fold cross
validation and out-of-fold reporting. The trained model is persisted
via :class:`GroupClassifierStore`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import numpy as np
from otalon_clas.common.settings import (
    GroupClassifierCrossValidationConfig, GroupClassifierRandomForestConfig)
from otalon_clas.ml.group_classifier.store import GroupClassifierStore
from loguru import logger
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, classification_report, f1_score,
                             precision_recall_fscore_support)
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import StandardScaler


@dataclass
class TrainResult:
    """Aggregate result returned by :meth:`GroupClassifierTrainer.train`."""

    accuracy_oof: float
    macro_f1_oof: float
    weighted_f1_oof: float
    fold_accuracies: list[float] = field(default_factory=list)
    fold_macro_f1: list[float] = field(default_factory=list)
    per_class: dict[str, dict[str, float]] = field(default_factory=dict)
    classification_report_text: str = ""
    n_samples: int = 0
    n_features: int = 0
    classes: list[str] = field(default_factory=list)


class GroupClassifierTrainer:
    """Train and persist the alarm-group Random-Forest classifier.

    Args:
        rf_config: Random-Forest hyperparameters.
        cv_config: Cross-validation configuration.
        store: Persistence layer for the trained model bundle.
    """

    def __init__(
        self,
        rf_config: GroupClassifierRandomForestConfig,
        cv_config: GroupClassifierCrossValidationConfig,
        store: GroupClassifierStore,
    ) -> None:
        """Initialize the trainer."""
        self._rf_config = rf_config
        self._cv_config = cv_config
        self._store = store

    def train(
        self,
        X: np.ndarray,
        y: np.ndarray,
        feature_names: list[str],
        extra_metadata: dict[str, Any] | None = None,
    ) -> TrainResult:
        """Run cross-validation, train the final estimator, and persist it.

        Args:
            X: Feature matrix of shape ``(n_samples, n_features)``.
            y: Label array of shape ``(n_samples,)`` containing string
                technical_method labels.
            feature_names: Ordered feature column names matching ``X``.
            extra_metadata: Optional metadata dict merged into the saved
                metadata JSON (training window, label distribution, etc).

        Returns:
            :class:`TrainResult` with per-fold and OOF metrics.

        Raises:
            ValueError: If ``X`` and ``y`` have inconsistent shapes or
                fewer than ``n_splits`` samples per class.
        """
        if X.ndim != 2 or X.shape[0] != y.shape[0]:
            msg = f"Inconsistent shapes: X={X.shape}, y={y.shape}"
            raise ValueError(msg)
        if X.shape[0] == 0:
            msg = "No samples to train on"
            raise ValueError(msg)

        unique_classes, class_counts = np.unique(y, return_counts=True)
        n_splits = self._effective_n_splits(class_counts)

        result = self._run_cross_validation(X, y, n_splits)

        final_model, final_scaler = self._fit_full_model(X, y)

        metadata = self._build_metadata(result, X, y, extra_metadata)
        self._store.save(
            model=final_model,
            scaler=final_scaler,
            feature_names=list(feature_names),
            classes=list(unique_classes),
            metadata=metadata,
        )

        result.classes = list(unique_classes)
        result.n_samples = int(X.shape[0])
        result.n_features = int(X.shape[1])
        return result

    def _effective_n_splits(self, class_counts: np.ndarray) -> int:
        """Cap ``n_splits`` so every class has at least one sample per fold."""
        configured = max(int(self._cv_config.n_splits), 2)
        min_class_count = int(class_counts.min())
        if min_class_count < configured:
            logger.warning(
                "GroupClassifierTrainer: smallest class has {} samples — "
                "lowering n_splits from {} to {}",
                min_class_count,
                configured,
                min_class_count,
            )
            return max(min_class_count, 2)
        return configured

    def _run_cross_validation(
        self,
        X: np.ndarray,
        y: np.ndarray,
        n_splits: int,
    ) -> TrainResult:
        """Run stratified k-fold and collect out-of-fold predictions.

        Args:
            X: Feature matrix.
            y: Label array.
            n_splits: Effective number of folds.

        Returns:
            :class:`TrainResult` populated with CV metrics.
        """
        skf = StratifiedKFold(
            n_splits=n_splits,
            shuffle=bool(self._cv_config.shuffle),
            random_state=int(self._cv_config.random_state),
        )

        oof_pred = np.empty_like(y, dtype=object)
        fold_accuracies: list[float] = []
        fold_f1_macros: list[float] = []

        for fold_idx, (train_idx, test_idx) in enumerate(skf.split(X, y), start=1):
            scaler = StandardScaler()
            X_train = scaler.fit_transform(X[train_idx])
            X_test = scaler.transform(X[test_idx])

            clf = self._build_estimator()
            clf.fit(X_train, y[train_idx])
            preds = clf.predict(X_test)
            oof_pred[test_idx] = preds

            acc = accuracy_score(y[test_idx], preds)
            f1m = f1_score(y[test_idx], preds, average="macro", zero_division=0)
            fold_accuracies.append(float(acc))
            fold_f1_macros.append(float(f1m))
            logger.info(
                "GroupClassifierTrainer: fold {}/{} acc={:.4f} macro-F1={:.4f}",
                fold_idx,
                n_splits,
                acc,
                f1m,
            )

        accuracy_oof = float(accuracy_score(y, oof_pred))
        macro_f1_oof = float(f1_score(y, oof_pred, average="macro", zero_division=0))
        weighted_f1_oof = float(
            f1_score(y, oof_pred, average="weighted", zero_division=0)
        )

        unique_present = sorted(set(y))
        prec, rec, f1, support = precision_recall_fscore_support(
            y, oof_pred, labels=unique_present, zero_division=0
        )
        per_class: dict[str, dict[str, float]] = {}
        for cls, p, r, f, s in zip(unique_present, prec, rec, f1, support):
            per_class[str(cls)] = {
                "precision": float(p),
                "recall": float(r),
                "f1": float(f),
                "support": int(s),
            }

        report_text = classification_report(
            y, oof_pred, labels=unique_present, zero_division=0, digits=4
        )

        return TrainResult(
            accuracy_oof=accuracy_oof,
            macro_f1_oof=macro_f1_oof,
            weighted_f1_oof=weighted_f1_oof,
            fold_accuracies=fold_accuracies,
            fold_macro_f1=fold_f1_macros,
            per_class=per_class,
            classification_report_text=report_text,
        )

    def _fit_full_model(
        self,
        X: np.ndarray,
        y: np.ndarray,
    ) -> tuple[RandomForestClassifier, StandardScaler]:
        """Fit a final model on all available data for inference.

        Args:
            X: Feature matrix.
            y: Label array.

        Returns:
            Tuple ``(model, scaler)`` for persistence.
        """
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        model = self._build_estimator()
        model.fit(X_scaled, y)
        logger.info(
            "GroupClassifierTrainer: trained final model on {} samples ({} classes)",
            X.shape[0],
            len(model.classes_),
        )
        return model, scaler

    def _build_estimator(self) -> RandomForestClassifier:
        """Instantiate a fresh estimator using the configured hyperparameters."""
        return RandomForestClassifier(
            n_estimators=int(self._rf_config.n_estimators),
            max_depth=self._rf_config.max_depth,
            min_samples_leaf=int(self._rf_config.min_samples_leaf),
            class_weight=self._rf_config.class_weight,
            random_state=int(self._rf_config.random_state),
            n_jobs=int(self._rf_config.n_jobs),
        )

    def _build_metadata(
        self,
        result: TrainResult,
        X: np.ndarray,
        y: np.ndarray,
        extra: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Build the metadata payload persisted alongside the model."""
        metadata: dict[str, Any] = {
            "trained_at": datetime.now(tz=timezone.utc).isoformat(),
            "n_samples": int(X.shape[0]),
            "n_features": int(X.shape[1]),
            "accuracy_oof": result.accuracy_oof,
            "macro_f1_oof": result.macro_f1_oof,
            "weighted_f1_oof": result.weighted_f1_oof,
            "fold_accuracies": result.fold_accuracies,
            "fold_macro_f1": result.fold_macro_f1,
            "per_class": result.per_class,
            "random_forest": self._rf_config.model_dump(),
            "cross_validation": self._cv_config.model_dump(),
            "classification_report": result.classification_report_text,
        }
        if extra:
            metadata.update(extra)
        return metadata
