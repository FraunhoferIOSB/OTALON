"""XGBoost backend wrapping :class:`xgboost.XGBClassifier`.

XGBoost is an optional dependency.  If the ``xgboost`` package is not
installed, importing this module succeeds but instantiating
:class:`XGBoostBackend` raises :exc:`ImportError` with an actionable message.
"""

from __future__ import annotations

import numpy as np
from otalon_clas.ml.base import MLBackend
from loguru import logger

try:
    from xgboost import XGBClassifier

    _XGBOOST_AVAILABLE = True
except ImportError:
    _XGBOOST_AVAILABLE = False


class XGBoostBackend(MLBackend):
    """Supervised classification backend using XGBoost gradient boosting.

    All keyword arguments are forwarded to :class:`xgboost.XGBClassifier`.

    Raises:
        ImportError: If the ``xgboost`` package is not installed.
    """

    def __init__(self, **params: object) -> None:
        """Initialize the XGBoost backend.

        Args:
            **params: Hyper-parameters forwarded to
                :class:`~xgboost.XGBClassifier`
                (e.g. ``n_estimators``, ``max_depth``, ``learning_rate``).

        Raises:
            ImportError: If ``xgboost`` is not installed.
        """
        if not _XGBOOST_AVAILABLE:
            raise ImportError(
                "The 'xgboost' package is required for XGBoostBackend. Install it with: pip install xgboost"
            )
        self._model = XGBClassifier(**params)
        logger.debug("XGBoostBackend initialized with params={}", params)

    def fit(self, X: np.ndarray, y: np.ndarray) -> None:
        """Fit the XGBoost classifier on *X* and *y*.

        Args:
            X: Feature matrix of shape ``(n_samples, n_features)``.
            y: Label vector of shape ``(n_samples,)``.
        """
        logger.info("Fitting XGBClassifier on {} samples", X.shape[0])
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
