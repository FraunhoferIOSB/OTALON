"""Unit tests for the static runtime-configuration manifest.

The manifest is the enumeration source for consumers that cannot import the
owning service's package. These tests pin its completeness, its internal
consistency (value type against domain notation), and its agreement with the
shared validator factories.
"""

from __future__ import annotations

import re

import pytest
from otalon_common.runtime import (
    MANIFEST,
    OTALON_AI_SERVICE,
    OTALON_CLAS_SERVICE,
    OTALON_SCAN_SERVICE,
    RuntimeKeyDeclaration,
    bool_literal,
    float_interval,
    int_range,
    is_secret_key,
    manifest_entry,
    manifest_for_service,
)

_INT_DOMAIN = re.compile(r"^\[-?\d+, -?\d+\]$")
_FLOAT_DOMAIN = re.compile(r"^\(-?\d+(?:\.\d+)?, -?\d+(?:\.\d+)?[\])]$")

_EXPECTED_IDENTITIES: tuple[tuple[str, str], ...] = (
    (OTALON_CLAS_SERVICE, "classification.training_enabled"),
    (OTALON_CLAS_SERVICE, "training.default_quantile"),
    (OTALON_CLAS_SERVICE, "training.retrain_paused"),
    (OTALON_CLAS_SERVICE, "detection.conn.bounds_enabled"),
    (OTALON_CLAS_SERVICE, "detection.conn.classification_enabled"),
    (OTALON_CLAS_SERVICE, "detection.conn.frequency_enabled"),
    (OTALON_CLAS_SERVICE, "detection.mac_traffic.bounds_enabled"),
    (OTALON_CLAS_SERVICE, "detection.mac_traffic.classification_enabled"),
    (OTALON_CLAS_SERVICE, "detection.mac_traffic.frequency_enabled"),
    (OTALON_CLAS_SERVICE, "detection.proto_traffic.bounds_enabled"),
    (OTALON_CLAS_SERVICE, "detection.proto_traffic.classification_enabled"),
    (OTALON_CLAS_SERVICE, "detection.proto_traffic.frequency_enabled"),
    (OTALON_CLAS_SERVICE, "detection.conn.port_rule_refresh.enabled"),
    (OTALON_CLAS_SERVICE, "detection.conn.port_rule_refresh.interval_seconds"),
    (OTALON_CLAS_SERVICE, "detection.conn.port_rule_refresh.lookback_hours"),
    (OTALON_CLAS_SERVICE, "detection.conn.port_rule_refresh.confirm_cycles"),
    (OTALON_CLAS_SERVICE, "detection.conn.port_rule_refresh.min_samples"),
    (OTALON_CLAS_SERVICE, "detection.conn.port_rule_refresh.rotation_distinct_ports"),
    (OTALON_CLAS_SERVICE, "detection.series_blacklist"),
    (OTALON_SCAN_SERVICE, "enabled"),
    (OTALON_SCAN_SERVICE, "poll_interval_s"),
    (OTALON_SCAN_SERVICE, "lookback_window_s"),
    (OTALON_SCAN_SERVICE, "drop_laa"),
    (OTALON_AI_SERVICE, "ai.provider"),
    (OTALON_AI_SERVICE, "ai.endpoint"),
    (OTALON_AI_SERVICE, "ai.chat_model"),
    (OTALON_AI_SERVICE, "ai.job_model"),
    (OTALON_AI_SERVICE, "ai.context_window"),
)


@pytest.mark.unit
def test_manifest_lists_exactly_the_known_keys() -> None:
    """The manifest holds nineteen OTALON-CLAS keys, four seeder keys and five otalon-ai keys (AI-045, AI-046)."""
    identities = tuple((entry.service, entry.key) for entry in MANIFEST)
    assert identities == _EXPECTED_IDENTITIES


@pytest.mark.unit
def test_manifest_identities_are_unique() -> None:
    """No ``(service, key)`` pair appears twice."""
    identities = [(entry.service, entry.key) for entry in MANIFEST]
    assert len(identities) == len(set(identities))


@pytest.mark.unit
@pytest.mark.parametrize("entry", MANIFEST, ids=lambda e: f"{e.service}:{e.key}")
def test_manifest_entry_is_internally_consistent(entry: RuntimeKeyDeclaration) -> None:
    """Value type, domain notation, and description agree for every entry."""
    assert entry.service and entry.key
    assert entry.description.strip()
    assert entry.value_type in {"bool", "int", "float", "str", "list"}
    if entry.value_type == "bool":
        assert entry.domain is None
    elif entry.value_type == "int":
        assert entry.domain is not None and _INT_DOMAIN.match(entry.domain)
    elif entry.value_type == "float":
        assert entry.domain is not None and _FLOAT_DOMAIN.match(entry.domain)
    elif entry.value_type == "list":
        assert entry.domain is not None and entry.domain.strip()


@pytest.mark.unit
def test_no_manifest_key_looks_like_a_secret() -> None:
    """The manifest never exposes a key the deny-list would reject."""
    assert [entry.key for entry in MANIFEST if is_secret_key(entry.key)] == []


@pytest.mark.unit
def test_manifest_domains_match_the_shared_validator_factories() -> None:
    """Each documented domain is reproducible from a validator factory."""
    domains = {(entry.service, entry.key): entry.domain for entry in MANIFEST}
    assert (
        domains[(OTALON_CLAS_SERVICE, "training.default_quantile")]
        == float_interval(0.0, 0.5).domain
    )
    assert (
        domains[(OTALON_SCAN_SERVICE, "poll_interval_s")] == int_range(10, 3600).domain
    )
    assert (
        domains[(OTALON_SCAN_SERVICE, "lookback_window_s")]
        == int_range(30, 86400).domain
    )


@pytest.mark.unit
def test_cyberclas_live_detection_entries_are_boolean_and_domainless() -> None:
    """All six live detection controls match the shared boolean contract."""
    live_keys = {
        "detection.conn.bounds_enabled",
        "detection.conn.classification_enabled",
        "detection.mac_traffic.bounds_enabled",
        "detection.mac_traffic.classification_enabled",
        "detection.proto_traffic.bounds_enabled",
        "detection.proto_traffic.classification_enabled",
    }
    entries = {
        entry.key: entry
        for entry in manifest_for_service(OTALON_CLAS_SERVICE)
        if entry.key in live_keys
    }
    assert set(entries) == live_keys
    assert {(entry.value_type, entry.domain) for entry in entries.values()} == {
        ("bool", None)
    }


@pytest.mark.unit
def test_manifest_for_service_returns_only_that_service() -> None:
    """Slicing by service yields that service's keys and no others."""
    seeder_keys = {entry.key for entry in manifest_for_service(OTALON_SCAN_SERVICE)}
    assert seeder_keys == {
        "enabled",
        "poll_interval_s",
        "lookback_window_s",
        "drop_laa",
    }
    assert len(manifest_for_service(OTALON_CLAS_SERVICE)) == 19
    assert manifest_for_service("unknown-service") == ()


@pytest.mark.unit
def test_manifest_entry_lookup() -> None:
    """A single entry is retrievable and unknown pairs resolve to ``None``."""
    entry = manifest_entry(OTALON_SCAN_SERVICE, "poll_interval_s")
    assert entry is not None
    assert entry.value_type == "int"
    assert manifest_entry(OTALON_SCAN_SERVICE, "nope") is None


@pytest.mark.unit
def test_manifest_bool_entries_accept_boolean_literals() -> None:
    """Every bool-typed manifest key validates against the bool factory."""
    validator = bool_literal()
    for entry in MANIFEST:
        if entry.value_type == "bool":
            validator("true")
            validator("false")


@pytest.mark.unit
def test_manifest_entries_are_frozen() -> None:
    """Manifest entries are immutable so consumers cannot corrupt them."""
    with pytest.raises(AttributeError):
        MANIFEST[0].key = "mutated"  # type: ignore[misc]
