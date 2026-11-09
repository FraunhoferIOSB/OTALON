"""Runtime-configuration key declarations for the passive asset seeder.

Declares the seeder's hot-reconfigurable ``(service, key)`` pairs and registers
them with the shared, dependency-free registry in ``otalon_common.runtime``
through :func:`register_runtime_keys`. Registration is idempotent because the
shared validator factories return comparable frozen dataclasses, so calling it
from more than one entry point cannot raise.

Only operating behaviour is hot. The InfluxDB token is a secret and is caught
by the registry's deny-list before any lookup; the InfluxDB URL and bucket
describe deployment topology and stay boot-only configuration.

Domain strings are taken from the validators themselves rather than typed by
hand, so the manifest cross-check in ``tests/unit/passive_source`` cannot pass
against a domain that the enforcing validator does not actually implement.
"""

from __future__ import annotations

from otalon_common.runtime import (
    OTALON_SCAN_SERVICE,
    RuntimeKeySpec,
    bool_literal,
    int_range,
    register,
)

KEY_ENABLED: str = "enabled"
"""Runtime key toggling whether the seeder performs work or idles visibly."""

KEY_POLL_INTERVAL_S: str = "poll_interval_s"
"""Runtime key carrying the seconds between consecutive poll cycles."""

KEY_LOOKBACK_WINDOW_S: str = "lookback_window_s"
"""Runtime key carrying the seconds of InfluxDB history each cycle reads."""

KEY_DROP_LAA: str = "drop_laa"
"""Runtime key toggling the locally-administered-address filter."""

HOT_KEYS: tuple[str, ...] = (
    KEY_ENABLED,
    KEY_POLL_INTERVAL_S,
    KEY_LOOKBACK_WINDOW_S,
    KEY_DROP_LAA,
)
"""Every key the seeder resolves at the top of a cycle."""

_POLL_INTERVAL_VALIDATOR = int_range(10, 3600)
_LOOKBACK_WINDOW_VALIDATOR = int_range(30, 86400)

SPECS: tuple[RuntimeKeySpec, ...] = (
    RuntimeKeySpec(
        service=OTALON_SCAN_SERVICE,
        key=KEY_ENABLED,
        value_type="bool",
        validator=bool_literal(),
        domain=None,
        description="Whether the passive seeder performs work or idles visibly.",
    ),
    RuntimeKeySpec(
        service=OTALON_SCAN_SERVICE,
        key=KEY_POLL_INTERVAL_S,
        value_type="int",
        validator=_POLL_INTERVAL_VALIDATOR,
        domain=_POLL_INTERVAL_VALIDATOR.domain,
        description="Seconds the passive seeder waits between poll cycles.",
    ),
    RuntimeKeySpec(
        service=OTALON_SCAN_SERVICE,
        key=KEY_LOOKBACK_WINDOW_S,
        value_type="int",
        validator=_LOOKBACK_WINDOW_VALIDATOR,
        domain=_LOOKBACK_WINDOW_VALIDATOR.domain,
        description="Seconds of InfluxDB history each passive-seeder cycle reads.",
    ),
    RuntimeKeySpec(
        service=OTALON_SCAN_SERVICE,
        key=KEY_DROP_LAA,
        value_type="bool",
        validator=bool_literal(),
        domain=None,
        description="Whether locally administered MAC addresses are dropped while seeding.",
    ),
)
"""The seeder's registration set, in manifest order."""


def register_runtime_keys() -> None:
    """Register every seeder key with the shared registry.

    Idempotent: re-registering an identical specification is a no-op, so
    calling this from more than one entry point is safe.
    """
    for spec in SPECS:
        register(spec)
