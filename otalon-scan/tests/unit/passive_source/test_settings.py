"""Unit tests for ``otalon_scan.passive_source.settings.PassiveSeederSettings``.

Covers the ``Environment Variables Contract`` requirement from
``openspec/changes/add-passive-asset-seeder/specs/``
``passive-asset-seeding/spec.md`` (defaults, missing-token error,
invalid-window error) and the ``Feature Flag Default-Off`` default
value.

The tests build settings from explicit constructor kwargs rather than
mutating ``os.environ``; pydantic-settings still reads the validation
aliases, so the call shape mirrors the env-var contract exactly.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from otalon_scan.passive_source.settings import PassiveSeederSettings


class TestDefaults:
    """Defaults of the contract — every value matches the spec."""

    def test_disabled_by_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """SCENARIO: Feature Flag Default-Off — default value is false."""
        # Strip any inherited env values so we observe model defaults.
        for var in [
            "PASSIVE_SEEDER_ENABLED",
            "PASSIVE_SEEDER_POLL_INTERVAL_S",
            "PASSIVE_SEEDER_LOOKBACK_WINDOW_S",
            "PASSIVE_SEEDER_INFLUX_URL",
            "PASSIVE_SEEDER_INFLUX_TOKEN",
            "PASSIVE_SEEDER_INFLUX_BUCKET",
            "PASSIVE_SEEDER_DROP_LAA",
        ]:
            monkeypatch.delenv(var, raising=False)
        s = PassiveSeederSettings()
        assert s.enabled is False
        assert s.poll_interval_s == 60
        assert s.lookback_window_s == 300
        assert s.influx_url == "http://influxdb3:8181"
        assert s.influx_token is None
        assert s.influx_bucket == "netcap"
        assert s.drop_laa is False


class TestValidation:
    """Cross-field validation rules from the contract."""

    def test_zero_interval_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """``PASSIVE_SEEDER_POLL_INTERVAL_S=0`` SHALL raise ValidationError."""
        monkeypatch.setenv("PASSIVE_SEEDER_POLL_INTERVAL_S", "0")
        with pytest.raises(ValidationError) as excinfo:
            PassiveSeederSettings()
        assert "POLL_INTERVAL_S" in str(excinfo.value)

    def test_window_smaller_than_interval_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """SCENARIO: Invalid window-to-interval ratio."""
        monkeypatch.setenv("PASSIVE_SEEDER_POLL_INTERVAL_S", "120")
        monkeypatch.setenv("PASSIVE_SEEDER_LOOKBACK_WINDOW_S", "60")
        with pytest.raises(ValidationError) as excinfo:
            PassiveSeederSettings()
        assert "LOOKBACK_WINDOW_S" in str(excinfo.value)

    def test_missing_token_when_enabled_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """SCENARIO: Missing Influx token while enabled."""
        monkeypatch.setenv("PASSIVE_SEEDER_ENABLED", "true")
        monkeypatch.delenv("PASSIVE_SEEDER_INFLUX_TOKEN", raising=False)
        with pytest.raises(ValidationError) as excinfo:
            PassiveSeederSettings()
        assert "INFLUX_TOKEN" in str(excinfo.value)

    def test_enabled_with_token_passes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Enabled + token + sensible defaults SHALL be valid."""
        monkeypatch.setenv("PASSIVE_SEEDER_ENABLED", "true")
        monkeypatch.setenv("PASSIVE_SEEDER_INFLUX_TOKEN", "test-token")
        s = PassiveSeederSettings()
        assert s.enabled is True
        assert s.influx_token == "test-token"
