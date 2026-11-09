"""Preprocessor registry for resolving module configuration to implementations.

Maps string keys from ``PreprocessorConfig.type`` to concrete
``BasePreprocessor`` subclasses. Built-in preprocessors are registered
at module import time.
"""

from __future__ import annotations

from otalon_clas.preprocessing.base import BasePreprocessor
from loguru import logger

PREPROCESSOR_REGISTRY: dict[str, type[BasePreprocessor]] = {}
"""Global mapping of preprocessor type keys to their implementing classes."""


def register_preprocessor(key: str, cls: type[BasePreprocessor]) -> None:
    """Register a preprocessor class under a string key.

    Args:
        key: Unique string identifier (e.g., ``"conn_uci"``, ``"passthrough"``).
        cls: A ``BasePreprocessor`` subclass to associate with the key.

    Raises:
        ValueError: If the key is already registered with a different class.
    """
    if key in PREPROCESSOR_REGISTRY:
        existing = PREPROCESSOR_REGISTRY[key]
        if existing is not cls:
            msg = (
                f"Preprocessor key '{key}' is already registered to "
                f"{existing.__name__}, cannot re-register to {cls.__name__}"
            )
            raise ValueError(msg)
        return

    PREPROCESSOR_REGISTRY[key] = cls
    logger.debug("Registered preprocessor '{}' -> {}", key, cls.__name__)


def get_preprocessor(key: str) -> type[BasePreprocessor]:
    """Retrieve a registered preprocessor class by key.

    Args:
        key: The preprocessor type string from module configuration.

    Returns:
        The ``BasePreprocessor`` subclass registered under the given key.

    Raises:
        KeyError: If no preprocessor is registered for the given key.
    """
    if key not in PREPROCESSOR_REGISTRY:
        available = sorted(PREPROCESSOR_REGISTRY.keys())
        msg = f"Unknown preprocessor type '{key}'. Available: {available}"
        raise KeyError(msg)
    return PREPROCESSOR_REGISTRY[key]


def _register_builtins() -> None:
    """Register all built-in preprocessor implementations.

    Called once at module import time to populate the registry with
    the standard preprocessors: ``conn_uci``, ``passthrough``,
    ``tag_encoding``, ``sliding_window_5s``, and ``sliding_window_10s``.
    """
    from otalon_clas.preprocessing.connection import \
        ConnectionPreprocessor
    from otalon_clas.preprocessing.passthrough import \
        PassthroughPreprocessor
    from otalon_clas.preprocessing.sliding_window import \
        SlidingWindowPreprocessor
    from otalon_clas.preprocessing.tag_encoding import \
        TagEncodingPreprocessor

    register_preprocessor("conn_uci", ConnectionPreprocessor)
    register_preprocessor("passthrough", PassthroughPreprocessor)
    register_preprocessor("tag_encoding", TagEncodingPreprocessor)
    register_preprocessor("sliding_window_5s", SlidingWindowPreprocessor)
    register_preprocessor("sliding_window_10s", SlidingWindowPreprocessor)


_register_builtins()
