"""Runtime-configuration key declarations for otalon-clas."""

from __future__ import annotations

from otalon_common.runtime import (
    OTALON_CLAS_SERVICE,
    RuntimeKeySpec,
    bool_literal,
    float_interval,
    int_range,
    register,
    series_blacklist_syntax_validator,
)

_QUANTILE_VALIDATOR = float_interval(0.0, 0.5)
_INTERVAL_VALIDATOR = int_range(30, 86400)
_LOOKBACK_VALIDATOR = int_range(1, 168)
_CONFIRM_VALIDATOR = int_range(1, 10)
_MIN_SAMPLES_VALIDATOR = int_range(1, 100)
_ROTATION_VALIDATOR = int_range(1, 100)

SPECS: tuple[RuntimeKeySpec, ...] = (
    RuntimeKeySpec(
        service=OTALON_CLAS_SERVICE,
        key="detection.series_blacklist",
        value_type="list",
        validator=series_blacklist_syntax_validator,
        domain=(
            "JSON array of patterns: IPv4/IPv6 address (optional CIDR), MAC "
            "with trailing '*' octets, L3 token (IPv4/IPv6/ARP), protocol "
            "tag with optional trailing '*', or '/'-separated UCI pattern "
            "with '*' fields"
        ),
        description=("Series exclusion patterns (IP, MAC, protocol tag, UCI, * wildcards)."),
    ),
    RuntimeKeySpec(
        service=OTALON_CLAS_SERVICE,
        key="classification.training_enabled",
        value_type="bool",
        validator=bool_literal(),
        domain=None,
        description="Whether the classification training pipeline may run.",
    ),
    RuntimeKeySpec(
        service=OTALON_CLAS_SERVICE,
        key="training.default_quantile",
        value_type="float",
        validator=_QUANTILE_VALIDATOR,
        domain=_QUANTILE_VALIDATOR.domain,
        description="Default quantile used when deriving training bounds.",
    ),
    RuntimeKeySpec(
        service=OTALON_CLAS_SERVICE,
        key="training.retrain_paused",
        value_type="bool",
        validator=bool_literal(),
        domain=None,
        description="Whether retrain jobs are paused without stopping the supervisor.",
    ),
    RuntimeKeySpec(
        service=OTALON_CLAS_SERVICE,
        key="detection.conn.bounds_enabled",
        value_type="bool",
        validator=bool_literal(),
        domain=None,
        description="Whether live bounds detection is enabled for conn.",
    ),
    RuntimeKeySpec(
        service=OTALON_CLAS_SERVICE,
        key="detection.conn.classification_enabled",
        value_type="bool",
        validator=bool_literal(),
        domain=None,
        description="Whether live ML classification is enabled for conn.",
    ),
    RuntimeKeySpec(
        service=OTALON_CLAS_SERVICE,
        key="detection.conn.frequency_enabled",
        value_type="bool",
        validator=bool_literal(),
        domain=None,
        description="Whether live frequency and absence detection is enabled for conn.",
    ),
    RuntimeKeySpec(
        service=OTALON_CLAS_SERVICE,
        key="detection.mac_traffic.bounds_enabled",
        value_type="bool",
        validator=bool_literal(),
        domain=None,
        description="Whether live bounds detection is enabled for mac_traffic.",
    ),
    RuntimeKeySpec(
        service=OTALON_CLAS_SERVICE,
        key="detection.mac_traffic.classification_enabled",
        value_type="bool",
        validator=bool_literal(),
        domain=None,
        description="Whether live ML classification is enabled for mac_traffic.",
    ),
    RuntimeKeySpec(
        service=OTALON_CLAS_SERVICE,
        key="detection.mac_traffic.frequency_enabled",
        value_type="bool",
        validator=bool_literal(),
        domain=None,
        description="Whether live frequency and absence detection is enabled for mac_traffic.",
    ),
    RuntimeKeySpec(
        service=OTALON_CLAS_SERVICE,
        key="detection.proto_traffic.bounds_enabled",
        value_type="bool",
        validator=bool_literal(),
        domain=None,
        description="Whether live bounds detection is enabled for proto_traffic.",
    ),
    RuntimeKeySpec(
        service=OTALON_CLAS_SERVICE,
        key="detection.proto_traffic.classification_enabled",
        value_type="bool",
        validator=bool_literal(),
        domain=None,
        description="Whether live ML classification is enabled for proto_traffic.",
    ),
    RuntimeKeySpec(
        service=OTALON_CLAS_SERVICE,
        key="detection.proto_traffic.frequency_enabled",
        value_type="bool",
        validator=bool_literal(),
        domain=None,
        description="Whether live frequency and absence detection is enabled for proto_traffic.",
    ),
    RuntimeKeySpec(
        service=OTALON_CLAS_SERVICE,
        key="detection.conn.port_rule_refresh.enabled",
        value_type="bool",
        validator=bool_literal(),
        domain=None,
        description="Whether the background port-collapse rule refresh thread performs cycles.",
    ),
    RuntimeKeySpec(
        service=OTALON_CLAS_SERVICE,
        key="detection.conn.port_rule_refresh.interval_seconds",
        value_type="int",
        validator=_INTERVAL_VALIDATOR,
        domain=_INTERVAL_VALIDATOR.domain,
        description="Seconds between port-collapse rule refresh cycles.",
    ),
    RuntimeKeySpec(
        service=OTALON_CLAS_SERVICE,
        key="detection.conn.port_rule_refresh.lookback_hours",
        value_type="int",
        validator=_LOOKBACK_VALIDATOR,
        domain=_LOOKBACK_VALIDATOR.domain,
        description="Hours of InfluxDB history each refresh cycle recomputes rules over.",
    ),
    RuntimeKeySpec(
        service=OTALON_CLAS_SERVICE,
        key="detection.conn.port_rule_refresh.confirm_cycles",
        value_type="int",
        validator=_CONFIRM_VALIDATOR,
        domain=_CONFIRM_VALIDATOR.domain,
        description="Consecutive refresh cycles a candidate must persist before being confirmed.",
    ),
    RuntimeKeySpec(
        service=OTALON_CLAS_SERVICE,
        key="detection.conn.port_rule_refresh.min_samples",
        value_type="int",
        validator=_MIN_SAMPLES_VALIDATOR,
        domain=_MIN_SAMPLES_VALIDATOR.domain,
        description="Minimum InfluxDB rows a candidate base-key must have before confirmation.",
    ),
    RuntimeKeySpec(
        service=OTALON_CLAS_SERVICE,
        key="detection.conn.port_rule_refresh.rotation_distinct_ports",
        value_type="int",
        validator=_ROTATION_VALIDATOR,
        domain=_ROTATION_VALIDATOR.domain,
        description=(
            "Minimum distinct concrete ports on a single dimension that triggers "
            "a rotation candidate wildcarding that dimension."
        ),
    ),
)
"""The otalon-clas runtime key registrations."""


def register_runtime_keys() -> None:
    """Register otalon-clas runtime keys with the shared registry."""
    for spec in SPECS:
        register(spec)
