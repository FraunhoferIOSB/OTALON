"""Random-forest backend wrapping :class:`sklearn.ensemble.RandomForestClassifier`."""

import numpy as np
from otalon_clas.ml.base import MLBackend
from loguru import logger
from sklearn.ensemble import RandomForestClassifier


class RandomForestBackend(MLBackend):
    """Supervised classification backend using a random forest ensemble.

    All keyword arguments are forwarded to
    :class:`sklearn.ensemble.RandomForestClassifier`.
    """

    def __init__(self, **params: object) -> None:
        """Initialize the random-forest backend.

        Args:
            **params: Hyper-parameters forwarded to
                :class:`~sklearn.ensemble.RandomForestClassifier`
                (e.g. ``n_estimators``, ``max_depth``).
        """
        self._model = RandomForestClassifier(**params)
        logger.debug("RandomForestBackend initialized with params={}", params)

    def fit(self, X: np.ndarray, y: np.ndarray) -> None:
        """Fit the random forest on *X* and *y*.

        Args:
            X: Feature matrix of shape ``(n_samples, n_features)``.
            y: Label vector of shape ``(n_samples,)``.
        """
        logger.info("Fitting RandomForestClassifier on {} samples", X.shape[0])
        self._model.fit(X, y)

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Return class predictions for *X*.

        Args:
            X: Feature matrix of shape ``(n_samples, n_features)``.

        Returns:
            Predicted labels of shape ``(n_samples,)``.
        """
        return self._model.predict(X)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Return class-probability estimates for *X*.

        Args:
            X: Feature matrix of shape ``(n_samples, n_features)``.

        Returns:
            Probability matrix of shape ``(n_samples, n_classes)``.
        """
        return self._model.predict_proba(X)

    def get_params(self) -> dict:
        """Return the current hyper-parameters of the underlying estimator.

        Returns:
            Dictionary mapping parameter names to their values.
        """
        return self._model.get_params()
