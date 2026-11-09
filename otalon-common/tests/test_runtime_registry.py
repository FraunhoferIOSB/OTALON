"""Unit tests for the shared runtime-configuration registry.

Covers idempotent registration, conflicting-duplicate rejection, lookup of
unknown keys, the secret deny-list running ahead of registry lookup, and
enumeration across services.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from otalon_common.runtime import (
    RuntimeKeySpec,
    all_specs,
    bool_literal,
    int_range,
    is_secret_key,
    lookup,
    normalize_value,
    register,
    reset_registry,
    validate_write,
)

_SERVICE = "otalon-clas"
_OTHER_SERVICE = "otalon-scan"


@pytest.fixture(autouse=True)
def _isolated_registry() -> Iterator[None]:
    """Give every test an empty registry and restore emptiness afterwards."""
    reset_registry()
    yield
    reset_registry()


def _bool_spec(service: str, key: str) -> RuntimeKeySpec:
    """Build a boolean specification for *service* and *key*."""
    return RuntimeKeySpec(
        service=service,
        key=key,
        value_type="bool",
        validator=bool_literal(),
        domain=None,
        description=f"Test key {key}.",
    )


@pytest.mark.unit
def test_identical_reregistration_is_a_no_op() -> None:
    """Registering an identical specification twice changes nothing."""
    register(_bool_spec(_SERVICE, "training.retrain_paused"))
    register(_bool_spec(_SERVICE, "training.retrain_paused"))
    assert len(all_specs()) == 1


@pytest.mark.unit
def test_conflicting_duplicate_registration_raises() -> None:
    """A conflicting specification for the same pair fails loudly."""
    register(_bool_spec(_SERVICE, "training.default_quantile"))
    conflicting = RuntimeKeySpec(
        service=_SERVICE,
        key="training.default_quantile",
        value_type="int",
        validator=int_range(0, 1),
        domain="[0, 1]",
        description="Conflicting redeclaration.",
    )
    with pytest.raises(ValueError, match="conflicting specification"):
        register(conflicting)


@pytest.mark.unit
def test_conflicting_validator_alone_raises() -> None:
    """A differing validator is enough to make a duplicate conflicting."""
    register(_bool_spec(_OTHER_SERVICE, "poll_interval_s"))
    conflicting = RuntimeKeySpec(
        service=_OTHER_SERVICE,
        key="poll_interval_s",
        value_type="bool",
        validator=int_range(10, 3600),
        domain=None,
        description="Test key poll_interval_s.",
    )
    with pytest.raises(ValueError, match="conflicting specification"):
        register(conflicting)


@pytest.mark.unit
def test_lookup_of_unknown_key_returns_none() -> None:
    """An unregistered pair resolves to ``None`` rather than raising."""
    register(_bool_spec(_SERVICE, "training.retrain_paused"))
    assert lookup(_SERVICE, "training.some_typo") is None
    assert lookup("unknown-service", "training.retrain_paused") is None


@pytest.mark.unit
def test_lookup_returns_the_registered_spec() -> None:
    """A registered pair resolves to exactly the registered specification."""
    spec = _bool_spec(_SERVICE, "classification.training_enabled")
    register(spec)
    assert lookup(_SERVICE, "classification.training_enabled") == spec


@pytest.mark.unit
@pytest.mark.parametrize(
    "key",
    ["INFLUX_TOKEN", "POSTGRES_PASSWORD", "API_KEY", "CLIENT_SECRET", "influx_token"],
)
def test_secret_patterns_are_detected_case_insensitively(key: str) -> None:
    """Secret patterns match regardless of case."""
    assert is_secret_key(key) is True


@pytest.mark.unit
@pytest.mark.parametrize(
    "key", ["enabled", "poll_interval_s", "training.default_quantile"]
)
def test_non_secret_keys_are_not_flagged(key: str) -> None:
    """Ordinary configuration keys are not treated as secrets."""
    assert is_secret_key(key) is False


@pytest.mark.unit
def test_secret_check_precedes_registry_lookup() -> None:
    """A registered secret-looking key is still rejected."""
    register(_bool_spec(_SERVICE, "INFLUX_TOKEN"))
    assert lookup(_SERVICE, "INFLUX_TOKEN") is not None
    with pytest.raises(ValueError, match="secret-looking"):
        validate_write(_SERVICE, "INFLUX_TOKEN", "true")


@pytest.mark.unit
def test_secret_check_runs_without_any_registration() -> None:
    """The deny-list is callable independently of the registry contents."""
    assert all_specs() == ()
    assert is_secret_key("SERVICE_SECRET") is True


@pytest.mark.unit
def test_unregistered_write_is_rejected_with_allow_list_message() -> None:
    """An unknown key is rejected naming the allow-list."""
    with pytest.raises(ValueError, match="allow-list"):
        validate_write(_SERVICE, "training.some_typo", "true")


@pytest.mark.unit
def test_registered_write_passes_validation() -> None:
    """A registered key with an acceptable value validates successfully."""
    spec = _bool_spec(_SERVICE, "training.retrain_paused")
    register(spec)
    assert validate_write(_SERVICE, "training.retrain_paused", "true") == spec


@pytest.mark.unit
def test_registered_write_enforces_the_domain_validator() -> None:
    """A registered key with an invalid value is rejected by its validator."""
    register(_bool_spec(_SERVICE, "training.retrain_paused"))
    with pytest.raises(ValueError, match="boolean literal"):
        validate_write(_SERVICE, "training.retrain_paused", "sometimes")


@pytest.mark.unit
@pytest.mark.parametrize("value, expected", [("0", "false"), ("on", "true")])
def test_boolean_write_normalizes_to_canonical_literal(
    value: str, expected: str
) -> None:
    """Boolean aliases round-trip as the detector's canonical literals."""
    register(_bool_spec(_SERVICE, "training.retrain_paused"))

    assert normalize_value(_SERVICE, "training.retrain_paused", value) == expected


@pytest.mark.unit
def test_all_specs_enumerates_across_services_in_stable_order() -> None:
    """Enumeration spans services and is ordered by service then key."""
    register(_bool_spec(_OTHER_SERVICE, "enabled"))
    register(_bool_spec(_SERVICE, "training.retrain_paused"))
    register(_bool_spec(_SERVICE, "classification.training_enabled"))
    identities = [(spec.service, spec.key) for spec in all_specs()]
    assert identities == [
        (_SERVICE, "classification.training_enabled"),
        (_SERVICE, "training.retrain_paused"),
        (_OTHER_SERVICE, "enabled"),
    ]


@pytest.mark.unit
def test_spec_is_frozen() -> None:
    """A specification cannot be mutated after registration."""
    spec = _bool_spec(_SERVICE, "training.retrain_paused")
    register(spec)
    with pytest.raises(AttributeError):
        spec.key = "mutated"  # type: ignore[misc]
