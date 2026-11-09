"""Isolation-forest backend for unsupervised anomaly detection.

Wraps :class:`sklearn.ensemble.IsolationForest` behind the common
:class:`~otalon_clas.ml.base.MLBackend` interface.  Because
isolation forests are unsupervised, :meth:`fit` ignores the label vector
and :meth:`predict_proba` synthesizes a ``[0, 1]`` anomaly score via
sigmoid normalization of the raw anomaly scores.
"""

import numpy as np
from otalon_clas.ml.base import MLBackend
from loguru import logger
from sklearn.ensemble import IsolationForest


def _sigmoid(x: np.ndarray) -> np.ndarray:
    """Apply the logistic sigmoid element-wise.

    Args:
        x: Input array.

    Returns:
        Sigmoid-transformed array with values in ``(0, 1)``.
    """
    return 1.0 / (1.0 + np.exp(-x))


class IsolationForestBackend(MLBackend):
    """Unsupervised anomaly-detection backend using an isolation forest.

    All keyword arguments are forwarded to
    :class:`sklearn.ensemble.IsolationForest`.
    """

    def __init__(self, **params: object) -> None:
        """Initialize the isolation-forest backend.

        Args:
            **params: Hyper-parameters forwarded to
                :class:`~sklearn.ensemble.IsolationForest`
                (e.g. ``n_estimators``, ``contamination``).
        """
        self._model = IsolationForest(**params)
        logger.debug("IsolationForestBackend initialized with params={}", params)

    def fit(self, X: np.ndarray, y: np.ndarray) -> None:
        """Train the isolation forest on *X* (unsupervised).

        The label vector *y* is accepted for interface compatibility but
        is not used during fitting.

        Args:
            X: Feature matrix of shape ``(n_samples, n_features)``.
            y: Ignored; present only for API compatibility.
        """
        logger.info("Fitting IsolationForest on {} samples (unsupervised)", X.shape[0])
        self._model.fit(X)

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Return anomaly predictions for *X*.

        Follows the scikit-learn convention: ``1`` for normal (inlier),
        ``-1`` for anomaly (outlier).

        Args:
            X: Feature matrix of shape ``(n_samples, n_features)``.

        Returns:
            Prediction array of shape ``(n_samples,)`` with values in
            ``{-1, 1}``.
        """
        return self._model.predict(X)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Return sigmoid-normalized anomaly scores for *X*.

        Raw anomaly scores from :meth:`~sklearn.ensemble.IsolationForest.score_samples`
        are negated and passed through a sigmoid so that the output lies in
        ``[0, 1]`` where **higher values indicate greater anomaly likelihood**.

        Args:
            X: Feature matrix of shape ``(n_samples, n_features)``.

        Returns:
            Anomaly-score array of shape ``(n_samples,)`` in ``[0, 1]``.
        """
        raw_scores = self._model.score_samples(X)
        return _sigmoid(-raw_scores)

    def get_params(self) -> dict:
        """Return the current hyper-parameters of the underlying estimator.

        Returns:
            Dictionary mapping parameter names to their values.
        """
        return self._model.get_params()
