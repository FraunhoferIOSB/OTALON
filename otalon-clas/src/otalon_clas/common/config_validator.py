"""Configuration validation against known registry keys and data source references."""

from __future__ import annotations

from otalon_clas.common.settings import AppConfig
from loguru import logger

KNOWN_PREPROCESSOR_TYPES: frozenset[str] = frozenset(
    {
        "conn_uci",
        "passthrough",
        "sliding_window_5s",
        "sliding_window_10s",
    }
)

KNOWN_ML_ALGORITHMS: frozenset[str] = frozenset(
    {
        "decision_tree",
        "random_forest",
        "xgboost",
        "isolation_forest",
    }
)

KNOWN_STAGE_TYPES: frozenset[str] = frozenset(
    {
        "ensemble_ml",
        "rule_based",
    }
)


def validate_config(config: AppConfig) -> list[str]:
    """Validate configuration against known registry keys and constraints.

    Checks preprocessor types, ML algorithm keys, and post-processing
    stage types against their respective registries. Returns a list
    of validation error messages. An empty list means the config is valid.

    Args:
        config: The fully loaded and Pydantic-validated application config.

    Returns:
        List of human-readable validation error strings.
    """
    errors: list[str] = []

    for module in config.modules:
        _validate_module(module.name, module.preprocessor.type, errors)
        _validate_classification(module.name, module.classification.algorithm, errors)

    _validate_stages(config.pipeline_post_processing.stages, errors)

    for error in errors:
        logger.warning("Config validation: {}", error)

    return errors


def _validate_module(module_name: str, preprocessor_type: str, errors: list[str]) -> None:
    """Validate a module's preprocessor type against the registry."""
    if preprocessor_type not in KNOWN_PREPROCESSOR_TYPES:
        errors.append(
            f"Module '{module_name}': unknown preprocessor type '{preprocessor_type}'. "
            f"Known types: {sorted(KNOWN_PREPROCESSOR_TYPES)}"
        )


def _validate_classification(module_name: str, algorithm: str, errors: list[str]) -> None:
    """Validate a module's ML algorithm against the registry."""
    if algorithm not in KNOWN_ML_ALGORITHMS:
        errors.append(
            f"Module '{module_name}': unknown ML algorithm '{algorithm}'. "
            f"Known algorithms: {sorted(KNOWN_ML_ALGORITHMS)}"
        )


def _validate_stages(stages: list, errors: list[str]) -> None:
    """Validate post-processing stage types against the registry."""
    for i, stage in enumerate(stages):
        if stage.type not in KNOWN_STAGE_TYPES:
            errors.append(
                f"Pipeline stage [{i}]: unknown stage type '{stage.type}'. Known types: {sorted(KNOWN_STAGE_TYPES)}"
            )
