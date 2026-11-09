"""Canonical type constants and classification helpers."""

from otalon_common.types.anomaly_types import (
    BENIGN_TYPES,
    FREQUENCY_TYPES,
    AnomalyType,
    is_benign_type,
    is_frequency_type,
    is_ml_type,
)

__all__ = [
    "AnomalyType",
    "BENIGN_TYPES",
    "FREQUENCY_TYPES",
    "is_benign_type",
    "is_frequency_type",
    "is_ml_type",
]
