"""Registry and manifest tests for the passive seeder's runtime keys.

Covers task C15 of ``passive-seeder-runtime-control``: the seeder-side
registrations and the static manifest slice for ``service="otalon-scan"``
must agree, so a domain or type change on one side fails the build rather than
surfacing as an api that advertises a range the seeder does not enforce.
"""

from __future__ import annotations

import pytest
from otalon_common.runtime import (
    OTALON_SCAN_SERVICE,
    all_specs,
    is_secret_key,
    lookup,
    manifest_for_service,
    validate_write,
)

from otalon_scan.passive_source.runtime_keys import HOT_KEYS, SPECS, register_runtime_keys


class TestManifestCrossCheck:
    """The registration set and the manifest slice must not drift."""

    def test_registrations_equal_manifest_slice(self) -> None:
        """Declarations of the registered specs equal the manifest slice."""
        registered = sorted(
            (spec.declaration() for spec in all_specs() if spec.service == OTALON_SCAN_SERVICE),
            key=lambda entry: entry.key,
        )
        expected = sorted(manifest_for_service(OTALON_SCAN_SERVICE), key=lambda entry: entry.key)
        assert registered == expected

    def test_every_hot_key_is_registered(self) -> None:
        """Each key the cycle resolves has a registration."""
        for key in HOT_KEYS:
            assert lookup(OTALON_SCAN_SERVICE, key) is not None

    def test_declared_keys_match_hot_keys(self) -> None:
        """``SPECS`` and ``HOT_KEYS`` describe the same key set."""
        assert {spec.key for spec in SPECS} == set(HOT_KEYS)

    def test_no_hot_key_trips_the_secret_denylist(self) -> None:
        """A registered key caught by the deny-list would be unwritable."""
        for key in HOT_KEYS:
            assert not is_secret_key(key)


class TestRegistrationIsIdempotent:
    """Re-registering the identical specification must not raise."""

    def test_double_registration_is_a_noop(self) -> None:
        """A second registration pass leaves the registry unchanged."""
        before = all_specs()
        register_runtime_keys()
        assert all_specs() == before


class TestDomainEnforcement:
    """The registered validators enforce the documented domains."""

    @pytest.mark.parametrize("value", ["10", "3600", "120"])
    def test_poll_interval_accepts_in_range(self, value: str) -> None:
        """Boundaries of ``[10, 3600]`` are inclusive."""
        validate_write(OTALON_SCAN_SERVICE, "poll_interval_s", value)

    @pytest.mark.parametrize("value", ["1", "9", "3601"])
    def test_poll_interval_rejects_out_of_range(self, value: str) -> None:
        """A value outside ``[10, 3600]`` is rejected."""
        with pytest.raises(ValueError, match="integer in"):
            validate_write(OTALON_SCAN_SERVICE, "poll_interval_s", value)

    @pytest.mark.parametrize("value", ["30", "86400"])
    def test_lookback_window_accepts_in_range(self, value: str) -> None:
        """Boundaries of ``[30, 86400]`` are inclusive."""
        validate_write(OTALON_SCAN_SERVICE, "lookback_window_s", value)

    def test_enabled_rejects_non_boolean(self) -> None:
        """``enabled`` only accepts recognized boolean literals."""
        with pytest.raises(ValueError, match="boolean literal"):
            validate_write(OTALON_SCAN_SERVICE, "enabled", "sometimes")

    def test_influx_token_is_denied_before_lookup(self) -> None:
        """The secret deny-list rejects the token regardless of registration."""
        with pytest.raises(ValueError, match="secret-looking"):
            validate_write(OTALON_SCAN_SERVICE, "PASSIVE_SEEDER_INFLUX_TOKEN", "x")

    def test_unknown_key_is_rejected(self) -> None:
        """A key outside the allow-list is rejected."""
        with pytest.raises(ValueError, match="allow-list"):
            validate_write(OTALON_SCAN_SERVICE, "influx_bucket", "netcap")
