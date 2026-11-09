"""Global registry mapping string keys to ML backend classes.

The registry is populated at import time with all built-in backends.
Third-party or experimental backends can be added at runtime via
:func:`register_backend`.
"""

from __future__ import annotations

from otalon_clas.ml.base import MLBackend
from loguru import logger

ML_BACKEND_REGISTRY: dict[str, type[MLBackend]] = {}


def register_backend(key: str, cls: type[MLBackend]) -> None:
    """Register an ML backend class under the given *key*.

    Args:
        key: Unique identifier used to look up the backend
            (e.g. ``"decision_tree"``).
        cls: A concrete :class:`MLBackend` subclass.

    Raises:
        ValueError: If *key* is already registered to a different class.
    """
    if key in ML_BACKEND_REGISTRY and ML_BACKEND_REGISTRY[key] is not cls:
        raise ValueError(
            f"Backend key '{key}' is already registered to "
            f"{ML_BACKEND_REGISTRY[key].__name__}; cannot re-register "
            f"to {cls.__name__}"
        )
    ML_BACKEND_REGISTRY[key] = cls
    logger.debug("Registered ML backend '{}' -> {}", key, cls.__name__)


def get_backend(key: str) -> type[MLBackend]:
    """Look up a registered ML backend class by *key*.

    Args:
        key: Identifier previously passed to :func:`register_backend`.

    Returns:
        The :class:`MLBackend` subclass registered under *key*.

    Raises:
        KeyError: If *key* has not been registered.
    """
    if key not in ML_BACKEND_REGISTRY:
        available = ", ".join(sorted(ML_BACKEND_REGISTRY)) or "(none)"
        raise KeyError(f"Unknown ML backend '{key}'. Available backends: {available}")
    return ML_BACKEND_REGISTRY[key]


def _register_builtins() -> None:
    """Register all built-in backends shipped with the package."""
    from otalon_clas.ml.backends.decision_tree import \
        DecisionTreeBackend
    from otalon_clas.ml.backends.isolation_forest import \
        IsolationForestBackend
    from otalon_clas.ml.backends.random_forest import \
        RandomForestBackend
    from otalon_clas.ml.backends.xgboost_backend import XGBoostBackend

    register_backend("decision_tree", DecisionTreeBackend)
    register_backend("random_forest", RandomForestBackend)
    register_backend("xgboost", XGBoostBackend)
    register_backend("isolation_forest", IsolationForestBackend)


_register_builtins()
