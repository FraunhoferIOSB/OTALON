"""High-level ML pipeline: balancing, scaling, training, and prediction."""

from __future__ import annotations

from typing import Any

import numpy as np
from otalon_clas.ml.base import MLBackend
from loguru import logger
from sklearn.metrics import accuracy_score, f1_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

UNKNOWN_LABEL = -1


def _balance_classes(
    X: np.ndarray,
    y: np.ndarray,
    balance_per_class: int,
    rng: np.random.Generator,
) -> tuple[np.ndarray, np.ndarray]:
    """Under-/over-sample each class to exactly *balance_per_class* rows.

    Args:
        X: Feature matrix of shape ``(n_samples, n_features)``.
        y: Label vector of shape ``(n_samples,)``.
        balance_per_class: Target number of samples per class.
        rng: NumPy random generator for reproducibility.

    Returns:
        Tuple ``(X_balanced, y_balanced)`` with uniform class counts.
    """
    classes = np.unique(y)
    x_parts: list[np.ndarray] = []
    y_parts: list[np.ndarray] = []

    for cls in classes:
        mask = y == cls
        x_cls = X[mask]
        n_cls = x_cls.shape[0]
        indices = rng.choice(n_cls, size=balance_per_class, replace=n_cls < balance_per_class)
        x_parts.append(x_cls[indices])
        y_parts.append(np.full(balance_per_class, cls))

    return np.concatenate(x_parts), np.concatenate(y_parts)


class MLPipeline:
    """Orchestrates dataset balancing, scaling, training, and inference.

    Args:
        backend: A concrete :class:`MLBackend` instance.
        confidence_threshold: Minimum prediction confidence;
            samples below this threshold are labeled as *unknown* (``-1``).
    """

    def __init__(self, backend: MLBackend, confidence_threshold: float = 0.5) -> None:
        """Initialize the pipeline.

        Args:
            backend: Trained or untrained :class:`MLBackend` instance.
            confidence_threshold: Confidence floor for predictions.
        """
        self.backend = backend
        self.confidence_threshold = confidence_threshold
        self.scaler: StandardScaler | None = None

    def train(
        self,
        X: np.ndarray,
        y: np.ndarray,
        balance_per_class: int = 1000,
        random_seed: int = 2025,
    ) -> dict[str, Any]:
        """Balance, scale, train, and evaluate the backend.

        Args:
            X: Feature matrix of shape ``(n_samples, n_features)``.
            y: Label vector of shape ``(n_samples,)``.
            balance_per_class: Target sample count per class.
            random_seed: Seed for reproducibility.

        Returns:
            Dictionary with keys ``accuracy``, ``f1_weighted``,
            ``train_samples``, and ``test_samples``.
        """
        rng = np.random.default_rng(random_seed)
        X_bal, y_bal = _balance_classes(X, y, balance_per_class, rng)
        logger.info("Balanced dataset: {} samples across {} classes", X_bal.shape[0], len(np.unique(y_bal)))

        X_train, X_test, y_train, y_test = train_test_split(
            X_bal, y_bal, test_size=0.2, random_state=random_seed, stratify=y_bal
        )

        self.scaler = StandardScaler()
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)

        self.backend.fit(X_train_scaled, y_train)
        return self._evaluate(X_test_scaled, y_test, X_train.shape[0], X_test.shape[0])

    def _evaluate(
        self,
        X_test: np.ndarray,
        y_test: np.ndarray,
        train_samples: int,
        test_samples: int,
    ) -> dict[str, Any]:
        """Compute accuracy and F1 on the held-out test set.

        Args:
            X_test: Scaled test feature matrix.
            y_test: True labels for the test set.
            train_samples: Number of training samples (for reporting).
            test_samples: Number of test samples (for reporting).

        Returns:
            Metrics dictionary.
        """
        y_pred = self.backend.predict(X_test)
        acc = float(accuracy_score(y_test, y_pred))
        f1 = float(f1_score(y_test, y_pred, average="weighted", zero_division=0))
        logger.info("Evaluation — accuracy={:.4f}, f1_weighted={:.4f}", acc, f1)

        return {
            "accuracy": acc,
            "f1_weighted": f1,
            "train_samples": train_samples,
            "test_samples": test_samples,
        }

    def predict(self, X: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        """Scale, predict, and apply the confidence threshold.

        Samples whose maximum predicted probability falls below
        :attr:`confidence_threshold` receive the *unknown* label (``-1``).

        Args:
            X: Feature matrix of shape ``(n_samples, n_features)``.

        Returns:
            Tuple ``(predictions, confidences)`` where *predictions* has
            shape ``(n_samples,)`` and *confidences* has shape
            ``(n_samples,)``.

        Raises:
            RuntimeError: If the pipeline has not been trained yet.
        """
        if self.scaler is None:
            raise RuntimeError("Pipeline has not been trained; call train() first")

        X_scaled = self.scaler.transform(X)
        predictions = self.backend.predict(X_scaled)
        probabilities = self.backend.predict_proba(X_scaled)

        return self._apply_threshold(predictions, probabilities)

    def _apply_threshold(
        self,
        predictions: np.ndarray,
        probabilities: np.ndarray,
    ) -> tuple[np.ndarray, np.ndarray]:
        """Replace low-confidence predictions with the unknown label.

        Args:
            predictions: Raw class predictions.
            probabilities: Probability matrix or 1-D score array.

        Returns:
            Tuple ``(thresholded_predictions, confidences)``.
        """
        if probabilities.ndim == 1:
            confidences = probabilities
        else:
            confidences = np.max(probabilities, axis=1)

        low_confidence_mask = confidences < self.confidence_threshold
        thresholded = predictions.copy()
        thresholded[low_confidence_mask] = UNKNOWN_LABEL

        if np.any(low_confidence_mask):
            logger.debug(
                "{} of {} predictions below confidence threshold {:.2f}",
                int(np.sum(low_confidence_mask)),
                len(predictions),
                self.confidence_threshold,
            )

        return thresholded, confidences
