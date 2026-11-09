"""Abstract base class defining the interface for all ML backends."""

from abc import ABC, abstractmethod

import numpy as np


class MLBackend(ABC):
    """Contract that every ML backend must fulfill.

    Subclasses wrap a concrete scikit-learn (or compatible) estimator and
    expose a uniform train / predict / inspect API consumed by
    :class:`~otalon_clas.ml.pipeline.MLPipeline`.
    """

    @abstractmethod
    def fit(self, X: np.ndarray, y: np.ndarray) -> None:
        """Train the model on feature matrix *X* and labels *y*.

        Args:
            X: Feature matrix of shape ``(n_samples, n_features)``.
            y: Label vector of shape ``(n_samples,)``.
        """
        ...

    @abstractmethod
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Return class predictions for *X*.

        Args:
            X: Feature matrix of shape ``(n_samples, n_features)``.

        Returns:
            Predicted labels of shape ``(n_samples,)``.
        """
        ...

    @abstractmethod
    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Return class-probability estimates for *X*.

        Args:
            X: Feature matrix of shape ``(n_samples, n_features)``.

        Returns:
            Probability matrix of shape ``(n_samples, n_classes)``.
        """
        ...

    @abstractmethod
    def get_params(self) -> dict:
        """Return the hyper-parameters currently set on the estimator.

        Returns:
            Dictionary mapping parameter names to their values.
        """
        ...
