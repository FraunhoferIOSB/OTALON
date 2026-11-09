"""Ensemble ML post-processing stage.

Takes outputs from all detection modules as meta-features and produces
ensemble-level anomaly classifications using a configurable ML backend.
"""

from __future__ import annotations

from typing import Any

import numpy as np
import polars as pl
from otalon_clas.pipeline.base import PostProcessingStage
from loguru import logger
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.preprocessing import StandardScaler

ENSEMBLE_ALGORITHMS: dict[str, type] = {
    "gradient_boosting": GradientBoostingClassifier,
    "random_forest": RandomForestClassifier,
}

DEFAULT_ALGORITHM: str = "gradient_boosting"
DEFAULT_N_ESTIMATORS: int = 100

META_FEATURE_COLUMNS: list[str] = [
    "confidence",
    "is_anomaly",
    "group_score",
    "group_interval_count",
]


class EnsembleMLStage(PostProcessingStage):
    """Ensemble ML stage combining multi-module detection outputs.

    Uses a configurable scikit-learn classifier (default: gradient boosting)
    trained on meta-features extracted from per-module detection results.

    Args:
        algorithm: Ensemble algorithm name (``gradient_boosting`` or ``random_forest``).
        params: Hyper-parameters passed to the estimator constructor.
        enabled: Whether this stage is active.
    """

    def __init__(
        self,
        algorithm: str = DEFAULT_ALGORITHM,
        params: dict[str, Any] | None = None,
        enabled: bool = False,
    ) -> None:
        """Initialize the ensemble ML stage.

        Args:
            algorithm: Ensemble algorithm key.
            params: Estimator hyper-parameters.
            enabled: Active flag.
        """
        self._enabled = enabled
        self._algorithm = algorithm
        self._params = params or {"n_estimators": DEFAULT_N_ESTIMATORS}
        self._model = self._create_model()
        self._scaler = StandardScaler()
        self._is_fitted = False

    def is_enabled(self) -> bool:
        """Return whether this stage is active.

        Returns:
            True if the stage should execute.
        """
        return self._enabled

    def process(self, anomalies: pl.DataFrame) -> pl.DataFrame:
        """Process anomalies through ensemble prediction.

        If the model is not fitted, returns the input unchanged with
        empty ensemble columns. When fitted, attaches ``ensemble_type``,
        ``ensemble_confidence``, and ``severity`` columns.

        Args:
            anomalies: Input anomaly DataFrame.

        Returns:
            DataFrame with ensemble prediction columns.
        """
        if anomalies.is_empty() or not self._is_fitted:
            return _append_ensemble_columns(anomalies)

        X = _extract_meta_features(anomalies)
        if X is None or X.shape[0] == 0:
            return _append_ensemble_columns(anomalies)

        return self._predict_and_attach(anomalies, X)

    def fit(self, anomalies: pl.DataFrame, labels: np.ndarray) -> None:
        """Train the ensemble model on labeled meta-features.

        Args:
            anomalies: DataFrame containing meta-feature columns.
            labels: Integer label array aligned with anomaly rows.
        """
        X = _extract_meta_features(anomalies)
        if X is None or X.shape[0] == 0:
            logger.warning("No meta-features available for ensemble training")
            return

        if len(labels) != X.shape[0]:
            logger.warning(
                "Label count ({}) does not match feature rows ({})",
                len(labels),
                X.shape[0],
            )
            return

        X_scaled = self._scaler.fit_transform(X)
        self._model.fit(X_scaled, labels)
        self._is_fitted = True
        logger.info(
            "Ensemble model trained ({}) on {} samples",
            self._algorithm,
            X.shape[0],
        )

    def _create_model(self) -> Any:
        """Instantiate the ensemble estimator from configuration.

        Returns:
            Scikit-learn estimator instance.
        """
        cls = ENSEMBLE_ALGORITHMS.get(self._algorithm)
        if cls is None:
            logger.warning(
                "Unknown ensemble algorithm '{}', falling back to {}",
                self._algorithm,
                DEFAULT_ALGORITHM,
            )
            cls = ENSEMBLE_ALGORITHMS[DEFAULT_ALGORITHM]
        return cls(**self._params)

    def _predict_and_attach(
        self,
        anomalies: pl.DataFrame,
        X: np.ndarray,
    ) -> pl.DataFrame:
        """Run ensemble prediction and attach result columns.

        Args:
            anomalies: Input anomaly DataFrame.
            X: Meta-feature matrix.

        Returns:
            DataFrame with ensemble columns.
        """
        X_scaled = self._scaler.transform(X)
        predictions = self._model.predict(X_scaled)
        probabilities = self._model.predict_proba(X_scaled)
        confidences = np.max(probabilities, axis=1) if probabilities.ndim > 1 else probabilities

        ensemble_types = [str(p) for p in predictions]
        severity_values = _compute_ensemble_severity(confidences)

        return anomalies.with_columns(
            pl.Series("ensemble_type", ensemble_types, dtype=pl.Utf8),
            pl.Series("ensemble_confidence", confidences.tolist(), dtype=pl.Float64),
            pl.Series("severity", severity_values, dtype=pl.Float64),
        )


def _extract_meta_features(df: pl.DataFrame) -> np.ndarray | None:
    """Extract meta-feature matrix from an anomaly DataFrame.

    Uses the intersection of available columns and ``META_FEATURE_COLUMNS``.

    Args:
        df: Input DataFrame.

    Returns:
        NumPy feature matrix or None if no features are available.
    """
    available = [c for c in META_FEATURE_COLUMNS if c in df.columns]
    if not available:
        return None

    feature_df = df.select(available)
    for col_name in feature_df.columns:
        if feature_df[col_name].dtype == pl.Boolean:
            feature_df = feature_df.with_columns(pl.col(col_name).cast(pl.Float64))
        elif feature_df[col_name].dtype == pl.Utf8:
            feature_df = feature_df.drop(col_name)

    if feature_df.is_empty() or len(feature_df.columns) == 0:
        return None

    return feature_df.fill_null(0.0).to_numpy()


def _compute_ensemble_severity(confidences: np.ndarray) -> list[float]:
    """Compute severity values from ensemble confidences.

    Maps confidence to severity: severity = confidence * 1.0 (capped at 1.0).

    Args:
        confidences: Confidence array.

    Returns:
        List of severity float values.
    """
    return [min(float(c), 1.0) for c in confidences]


def _append_ensemble_columns(df: pl.DataFrame) -> pl.DataFrame:
    """Append empty ensemble columns to a DataFrame.

    Args:
        df: Input DataFrame.

    Returns:
        DataFrame with added ensemble columns.
    """
    return df.with_columns(
        pl.lit("").alias("ensemble_type"),
        pl.lit(0.0).alias("ensemble_confidence"),
        pl.lit(0.0).alias("severity"),
    )
