"""Regression tests for SUITE-046 — Runtime tab 500 on unmapped boot keys.

``GET /api/v1/operations/configuration/runtime`` returned HTTP 500 with
``KeyError ('otalon-clas', 'detection.conn.port_rule_refresh.enabled')``.
``_boot_value`` indexed its ``defaults`` dict directly, and the six
``port_rule_refresh.*`` keys added to the MANIFEST had never been mapped —
so one missing fallback took the entire page down.

Two things are pinned here:

* every MANIFEST key resolves a boot value (the specific bug), and the six
  port_rule_refresh values match otalon-clas' own defaults;
* an unmapped key degrades to a conservative per-type fallback instead of
  raising (the class of bug).

These deliberately need **no database**. The existing manifest coverage in
``test_runtime_configuration.py`` is ``requires_postgres``-gated and is
skipped on a machine without one, which is why this regression reached
production unnoticed.
"""

from __future__ import annotations

import pytest
from otalon_common.runtime import MANIFEST

from otalon_api.api.v1.operations_config import (
    _OTALON_SCAN_SERVICE,
    _TYPE_FALLBACKS,
    _boot_value,
    _manifest_value_type,
)

pytestmark = pytest.mark.unit

CLAS = "otalon-clas"
PREFIX = "detection.conn.port_rule_refresh"

# Boot defaults declared by otalon_clas.common.settings.PortRuleRefreshConfig
# (settings.py:443-448). config/config.json carries no port_rule_refresh
# block and no env override exists, so resolve() falls back to exactly these
# whenever no runtime_config row is present.
CLAS_PORT_RULE_REFRESH_DEFAULTS = {
    "enabled": "true",
    "interval_seconds": "300",
    "lookback_hours": "6",
    "confirm_cycles": "2",
    "min_samples": "2",
    "rotation_distinct_ports": "3",
}


class TestEveryManifestKeyResolves:
    """The specific defect: a manifest key with no default raised KeyError."""

    def test_no_manifest_key_raises(self) -> None:
        failures: list[tuple[str, str, str]] = []
        for entry in MANIFEST:
            try:
                _boot_value(entry.service, entry.key)
            except Exception as exc:  # noqa: BLE001 - the assertion is the point
                failures.append((entry.service, entry.key, type(exc).__name__))

        assert failures == [], f"boot value lookup raised for: {failures}"

    def test_manifest_has_the_expected_key_count(self) -> None:
        """Guards against a silent manifest shrink masking the check above.

        23 = 19 otalon-clas + 4 otalon-scan (SUITE-046) + 4 otalon-ai (AI-045).
        """
        assert len(MANIFEST) == 28

    def test_every_key_returns_a_string(self) -> None:
        for entry in MANIFEST:
            assert isinstance(_boot_value(entry.service, entry.key), str)

    def test_port_rule_refresh_keys_are_present_in_the_manifest(self) -> None:
        keys = {e.key for e in MANIFEST if e.service == CLAS}
        for suffix in CLAS_PORT_RULE_REFRESH_DEFAULTS:
            assert f"{PREFIX}.{suffix}" in keys


class TestPortRuleRefreshDefaultsMatchClas:
    """The boot fallback must mirror what otalon-clas actually boots with."""

    @pytest.mark.parametrize(
        ("suffix", "expected"), sorted(CLAS_PORT_RULE_REFRESH_DEFAULTS.items())
    )
    def test_value_matches_clas_default(self, suffix: str, expected: str) -> None:
        assert _boot_value(CLAS, f"{PREFIX}.{suffix}") == expected

    def test_enabled_is_a_bool_literal(self) -> None:
        assert _boot_value(CLAS, f"{PREFIX}.enabled") in {"true", "false"}

    @pytest.mark.parametrize(
        "suffix",
        [
            "interval_seconds",
            "lookback_hours",
            "confirm_cycles",
            "min_samples",
            "rotation_distinct_ports",
        ],
    )
    def test_int_keys_are_numeric_strings(self, suffix: str) -> None:
        assert _boot_value(CLAS, f"{PREFIX}.{suffix}").isdigit()

    def test_values_satisfy_their_manifest_domains(self) -> None:
        """A boot value outside its declared domain would be a latent bug."""
        from otalon_common.runtime import normalize_value

        for entry in MANIFEST:
            if PREFIX not in entry.key:
                continue
            normalize_value(
                entry.service, entry.key, _boot_value(entry.service, entry.key)
            )


class TestUnmappedKeyDegradesGracefully:
    """The class of defect: a future manifest key must not 500 the page."""

    def test_unmapped_bool_returns_false(self) -> None:
        assert _boot_value(CLAS, "detection.conn.bounds_enabled") == "unknown"
        # A key that exists in neither defaults nor the manifest:
        assert _boot_value(CLAS, "totally.unmapped.flag") == _TYPE_FALLBACKS["string"]

    def test_unmapped_key_does_not_raise(self) -> None:
        _boot_value("some-service", "no.such.key")

    def test_unmapped_key_logs_a_warning_naming_the_key(self, caplog) -> None:
        from otalon_api.api.v1 import operations_config

        handler_id = operations_config.logger.add(
            caplog.handler, format="{message}", level="WARNING"
        )
        try:
            _boot_value("some-service", "no.such.key")
        finally:
            operations_config.logger.remove(handler_id)

        messages = [record.getMessage() for record in caplog.records]
        assert any("no.such.key" in message for message in messages)
        assert any("no boot default mapped" in message for message in messages)

    def test_type_fallbacks_are_conservative(self) -> None:
        """A bool must never default to enabled, a number never to non-zero."""
        assert _TYPE_FALLBACKS["bool"] == "false"
        assert _TYPE_FALLBACKS["int"] == "0"
        assert _TYPE_FALLBACKS["float"] == "0.0"

    def test_manifest_value_type_lookup(self) -> None:
        assert _manifest_value_type(CLAS, f"{PREFIX}.enabled") == "bool"
        assert _manifest_value_type(CLAS, f"{PREFIX}.interval_seconds") == "int"

    def test_manifest_value_type_is_total(self) -> None:
        """An unknown key must not raise on the way to the fallback."""
        assert _manifest_value_type("nope", "nope") == "string"


class TestEnvOverrideStillWins:
    """The read path must keep honouring the mapped environment overrides."""

    def test_env_override_beats_the_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("PASSIVE_SEEDER_POLL_INTERVAL_S", "42")

        assert _boot_value(_OTALON_SCAN_SERVICE, "poll_interval_s") == "42"

    def test_default_applies_without_the_env(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("PASSIVE_SEEDER_POLL_INTERVAL_S", raising=False)

        assert _boot_value(_OTALON_SCAN_SERVICE, "poll_interval_s") == "60"

    def test_port_rule_refresh_has_no_env_override(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """clas reads these from runtime_config only — no PORT_RULE_REFRESH_* env."""
        monkeypatch.setenv("PORT_RULE_REFRESH_ENABLED", "false")

        assert _boot_value(CLAS, f"{PREFIX}.enabled") == "true"
