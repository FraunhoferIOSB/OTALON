"""Decision-tree backend wrapping :class:`sklearn.tree.DecisionTreeClassifier`."""

import numpy as np
from otalon_clas.ml.base import MLBackend
from loguru import logger
from sklearn.tree import DecisionTreeClassifier


class DecisionTreeBackend(MLBackend):
    """Supervised classification backend using a single decision tree.

    All keyword arguments are forwarded to
    :class:`sklearn.tree.DecisionTreeClassifier`.
    """

    def __init__(self, **params: object) -> None:
        """Initialize the decision-tree backend.

        Args:
            **params: Hyper-parameters forwarded to
                :class:`~sklearn.tree.DecisionTreeClassifier`
                (e.g. ``max_depth``, ``criterion``).
        """
        self._model = DecisionTreeClassifier(**params)
        logger.debug("DecisionTreeBackend initialized with params={}", params)

    def fit(self, X: np.ndarray, y: np.ndarray) -> None:
        """Fit the decision tree on *X* and *y*.

        Args:
            X: Feature matrix of shape ``(n_samples, n_features)``.
            y: Label vector of shape ``(n_samples,)``.
        """
        logger.info("Fitting DecisionTreeClassifier on {} samples", X.shape[0])
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
