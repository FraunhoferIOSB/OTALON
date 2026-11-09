"""Canonical anomaly type constants and classification helpers.

PascalCase constants match the values stored in PostgreSQL by otalon-clas.
This eliminates the naming mismatch between ``"BoundViolation"`` (DB) and
``"Bound violation"`` (API) that caused dashboard signal-color bugs.
"""


class AnomalyType:
    """Canonical string constants for anomaly types in PostgreSQL."""

    BOUND_VIOLATION: str = "BoundViolation"
    NO_BOUNDS: str = "NoBounds"
    BENIGN: str = "benign"
    FREQUENCY_ANOMALY: str = "FrequencyAnomaly"
    ABSENCE_ANOMALY: str = "AbsenceAnomaly"


BENIGN_TYPES: frozenset[str] = frozenset(
    {
        AnomalyType.BOUND_VIOLATION,
        AnomalyType.NO_BOUNDS,
    }
)
"""Frozenset of anomaly types that come from rule-based detection
(bounds / frequency monitoring) and do not represent ML classifications."""

FREQUENCY_TYPES: frozenset[str] = frozenset(
    {
        AnomalyType.FREQUENCY_ANOMALY,
        AnomalyType.ABSENCE_ANOMALY,
    }
)
"""Frozenset of anomaly types produced by the frequency/presence monitor.

``FrequencyAnomaly`` is a verdict over observed inter-arrival intervals;
``AbsenceAnomaly`` states that expected data did not arrive at all. Both
are rule-based, never ML classifications, and neither carries per-feature
bound severities."""

NON_ML_TYPES: frozenset[str] = frozenset(
    {
        AnomalyType.BOUND_VIOLATION,
        AnomalyType.NO_BOUNDS,
        AnomalyType.BENIGN,
        AnomalyType.FREQUENCY_ANOMALY,
        AnomalyType.ABSENCE_ANOMALY,
        "",
    }
)
"""Frozenset of anomaly types that are NOT MITRE ATT&CK classifications.

Includes the bounds and frequency/absence anomaly types as well as the
explicit ``"benign"`` label produced by an ML classifier when no attack
pattern is recognized."""


def is_frequency_type(anomaly_type: str) -> bool:
    """Check whether an anomaly type comes from the frequency monitor.

    Args:
        anomaly_type: The anomaly type string to check.

    Returns:
        True if the type is ``FrequencyAnomaly`` or ``AbsenceAnomaly``.
    """
    return anomaly_type in FREQUENCY_TYPES


def is_benign_type(anomaly_type: str) -> bool:
    """Check whether an anomaly type is benign.

    Args:
        anomaly_type: The anomaly type string to check.

    Returns:
        True if the type is in BENIGN_TYPES.
    """
    return anomaly_type in BENIGN_TYPES


def is_ml_type(anomaly_type: str) -> bool:
    """Check whether an anomaly type is an ML-generated MITRE classification.

    ML types are MITRE ATT&CK technique labels (e.g. ``T0846/arp_scan``)
    produced by the classifier. Bounds / frequency anomaly types
    (``BoundViolation``, ``NoBounds``) and the explicit ``benign`` label
    do not count as ML attack classifications.

    Args:
        anomaly_type: The anomaly type string to check.

    Returns:
        True if the type is a MITRE classification.
    """
    return anomaly_type not in NON_ML_TYPES
