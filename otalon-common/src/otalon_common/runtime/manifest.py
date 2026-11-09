"""Static manifest of every known runtime-configuration key.

Services are deployed as separate container images and cannot import each
other's Python packages, so a consumer that must present or validate keys
belonging to another service reads this manifest instead. The manifest is pure
data: it carries no validator instances and no logic. Each service registers
the matching specifications at its own startup, and cross-check tests assert
that the manifest and the service-side registrations agree, so drift fails the
build rather than surfacing at runtime.
"""

from __future__ import annotations

from otalon_common.runtime.registry import RuntimeKeyDeclaration

OTALON_CLAS_SERVICE: str = "otalon-clas"
"""Service identifier used by OTALON-CLAS runtime-configuration rows."""

OTALON_SCAN_SERVICE: str = "otalon-scan"
"""Service identifier used by OTALON-SCAN runtime-configuration rows."""

OTALON_AI_SERVICE: str = "otalon-ai"
"""Service identifier used by OTALON-AI runtime-configuration rows (AI-045)."""

MANIFEST: tuple[RuntimeKeyDeclaration, ...] = (
    RuntimeKeyDeclaration(
        service=OTALON_CLAS_SERVICE,
        key="classification.training_enabled",
        value_type="bool",
        domain=None,
        description="Whether the classification training pipeline may run.",
    ),
    RuntimeKeyDeclaration(
        service=OTALON_CLAS_SERVICE,
        key="training.default_quantile",
        value_type="float",
        domain="(0, 0.5]",
        description="Default quantile used when deriving training bounds.",
    ),
    RuntimeKeyDeclaration(
        service=OTALON_CLAS_SERVICE,
        key="training.retrain_paused",
        value_type="bool",
        domain=None,
        description="Whether retrain jobs are paused without stopping the supervisor.",
    ),
    RuntimeKeyDeclaration(
        service=OTALON_CLAS_SERVICE,
        key="detection.conn.bounds_enabled",
        value_type="bool",
        domain=None,
        description="Whether live bounds detection is enabled for conn.",
    ),
    RuntimeKeyDeclaration(
        service=OTALON_CLAS_SERVICE,
        key="detection.conn.classification_enabled",
        value_type="bool",
        domain=None,
        description="Whether live ML classification is enabled for conn.",
    ),
    RuntimeKeyDeclaration(
        service=OTALON_CLAS_SERVICE,
        key="detection.conn.frequency_enabled",
        value_type="bool",
        domain=None,
        description="Whether live frequency and absence detection is enabled for conn.",
    ),
    RuntimeKeyDeclaration(
        service=OTALON_CLAS_SERVICE,
        key="detection.mac_traffic.bounds_enabled",
        value_type="bool",
        domain=None,
        description="Whether live bounds detection is enabled for mac_traffic.",
    ),
    RuntimeKeyDeclaration(
        service=OTALON_CLAS_SERVICE,
        key="detection.mac_traffic.classification_enabled",
        value_type="bool",
        domain=None,
        description="Whether live ML classification is enabled for mac_traffic.",
    ),
    RuntimeKeyDeclaration(
        service=OTALON_CLAS_SERVICE,
        key="detection.mac_traffic.frequency_enabled",
        value_type="bool",
        domain=None,
        description="Whether live frequency and absence detection is enabled for mac_traffic.",
    ),
    RuntimeKeyDeclaration(
        service=OTALON_CLAS_SERVICE,
        key="detection.proto_traffic.bounds_enabled",
        value_type="bool",
        domain=None,
        description="Whether live bounds detection is enabled for proto_traffic.",
    ),
    RuntimeKeyDeclaration(
        service=OTALON_CLAS_SERVICE,
        key="detection.proto_traffic.classification_enabled",
        value_type="bool",
        domain=None,
        description="Whether live ML classification is enabled for proto_traffic.",
    ),
    RuntimeKeyDeclaration(
        service=OTALON_CLAS_SERVICE,
        key="detection.proto_traffic.frequency_enabled",
        value_type="bool",
        domain=None,
        description="Whether live frequency and absence detection is enabled for proto_traffic.",
    ),
    RuntimeKeyDeclaration(
        service=OTALON_CLAS_SERVICE,
        key="detection.conn.port_rule_refresh.enabled",
        value_type="bool",
        domain=None,
        description="Whether the background port-collapse rule refresh thread performs cycles.",
    ),
    RuntimeKeyDeclaration(
        service=OTALON_CLAS_SERVICE,
        key="detection.conn.port_rule_refresh.interval_seconds",
        value_type="int",
        domain="[30, 86400]",
        description="Seconds between port-collapse rule refresh cycles.",
    ),
    RuntimeKeyDeclaration(
        service=OTALON_CLAS_SERVICE,
        key="detection.conn.port_rule_refresh.lookback_hours",
        value_type="int",
        domain="[1, 168]",
        description="Hours of InfluxDB history each refresh cycle recomputes rules over.",
    ),
    RuntimeKeyDeclaration(
        service=OTALON_CLAS_SERVICE,
        key="detection.conn.port_rule_refresh.confirm_cycles",
        value_type="int",
        domain="[1, 10]",
        description="Consecutive refresh cycles a candidate must persist before being confirmed.",
    ),
    RuntimeKeyDeclaration(
        service=OTALON_CLAS_SERVICE,
        key="detection.conn.port_rule_refresh.min_samples",
        value_type="int",
        domain="[1, 100]",
        description="Minimum InfluxDB rows a candidate base-key must have before confirmation.",
    ),
    RuntimeKeyDeclaration(
        service=OTALON_CLAS_SERVICE,
        key="detection.conn.port_rule_refresh.rotation_distinct_ports",
        value_type="int",
        domain="[1, 100]",
        description=(
            "Minimum distinct concrete ports on a single dimension that triggers "
            "a rotation candidate wildcarding that dimension."
        ),
    ),
    RuntimeKeyDeclaration(
        service=OTALON_CLAS_SERVICE,
        key="detection.series_blacklist",
        value_type="list",
        domain=(
            "JSON array of patterns: IPv4/IPv6 address (optional CIDR), MAC "
            "with trailing '*' octets, L3 token (IPv4/IPv6/ARP), protocol "
            "tag with optional trailing '*', or '/'-separated UCI pattern "
            "with '*' fields"
        ),
        description=(
            "Series exclusion patterns (IP, MAC, protocol tag, UCI, * wildcards)."
        ),
    ),
    RuntimeKeyDeclaration(
        service=OTALON_SCAN_SERVICE,
        key="enabled",
        value_type="bool",
        domain=None,
        description="Whether the passive seeder performs work or idles visibly.",
    ),
    RuntimeKeyDeclaration(
        service=OTALON_SCAN_SERVICE,
        key="poll_interval_s",
        value_type="int",
        domain="[10, 3600]",
        description="Seconds the passive seeder waits between poll cycles.",
    ),
    RuntimeKeyDeclaration(
        service=OTALON_SCAN_SERVICE,
        key="lookback_window_s",
        value_type="int",
        domain="[30, 86400]",
        description="Seconds of InfluxDB history each passive-seeder cycle reads.",
    ),
    RuntimeKeyDeclaration(
        service=OTALON_SCAN_SERVICE,
        key="drop_laa",
        value_type="bool",
        domain=None,
        description="Whether locally administered MAC addresses are dropped while seeding.",
    ),
    RuntimeKeyDeclaration(
        service=OTALON_AI_SERVICE,
        key="ai.provider",
        value_type="str",
        domain=None,
        description="AI model provider (AI-045). Non-secret connection setting.",
    ),
    RuntimeKeyDeclaration(
        service=OTALON_AI_SERVICE,
        key="ai.endpoint",
        value_type="str",
        domain=None,
        description="AI proxy base URL, e.g. http://host.docker.internal:4000/v1 (AI-045).",
    ),
    RuntimeKeyDeclaration(
        service=OTALON_AI_SERVICE,
        key="ai.chat_model",
        value_type="str",
        domain=None,
        description="Model used for interactive chat turns (AI-045).",
    ),
    RuntimeKeyDeclaration(
        service=OTALON_AI_SERVICE,
        key="ai.job_model",
        value_type="str",
        domain=None,
        description="Model used for background jobs (AI-045).",
    ),
    RuntimeKeyDeclaration(
        service=OTALON_AI_SERVICE,
        key="ai.context_window",
        value_type="int",
        domain="[4096, 1000000]",
        description="Maximum chat context window in tokens (AI-046). Was hard-coded to 128000.",
    ),
)
"""Every known ``(service, key)`` pair with its value type, domain, and description."""


def manifest_for_service(service: str) -> tuple[RuntimeKeyDeclaration, ...]:
    """Return the manifest slice belonging to *service*."""
    return tuple(entry for entry in MANIFEST if entry.service == service)


def manifest_entry(service: str, key: str) -> RuntimeKeyDeclaration | None:
    """Return the manifest entry for ``(service, key)`` or ``None``."""
    for entry in MANIFEST:
        if entry.service == service and entry.key == key:
            return entry
    return None
