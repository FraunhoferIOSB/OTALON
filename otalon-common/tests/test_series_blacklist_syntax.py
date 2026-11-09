"""Unit tests for the series-blacklist list value type (CLAS-071, D6/D7).

Pins every accepted entry form of the ``detection.series_blacklist``
runtime key, the indexed rejection contract (``entry[N]: …``, mapped to
HTTP 422 by otalon-api), the canonical persisted JSON form, and that the
secret deny-list / allow-list leave the new key writable while all
other registry semantics stay intact.
"""

from __future__ import annotations

import json

import pytest
from otalon_common.runtime import (
    OTALON_CLAS_SERVICE,
    ListEntryValidationError,
    RuntimeKeySpec,
    is_secret_key,
    lookup,
    manifest_entry,
    normalize_value,
    register,
    series_blacklist_syntax_validator,
    validate_write,
)

_SERVICE = OTALON_CLAS_SERVICE
_KEY = "detection.series_blacklist"

_ACCEPTED_ENTRIES = [
    "192.168.0.1",
    "8.8.8.8",
    "fe80::1",
    "fe80::1/64",
    "10.0.0.0/8",
    "7c:cb:e2:ea:0d:65",
    "ff:ff:ff:ff:ff:ff",
    "33:33:00:00:00:01",
    "33:33:*",
    "33:33:00:*",
    "01:00:5e:*",
    "01:80:c2:*",
    "IPv4",
    "IPv6",
    "ARP",
    "ipv6",
    "Ethernet:ARP",
    "Ethernet:IPv4:TCP:DNS",
    "Ethernet:IPv4:*",
    "33:33:00:00:00:01/a8:74:1d:18:c6:96//IPv4/192.168.0.77/*/*/*/*",
    "mac/*/*/*/*/*/*/*/*",
]

_REJECTED_ENTRIES = [
    "33:33:zz",
    "33:33",
    "*:33:33",
    "33:*:33",
    "*:*",
    "not!! a pattern",
    "IPv4x",
    ":IPv4",
    "Ethernet:",
    "Ethernet:*:TCP",
    "zz",
    "mac/extra/fields/*/*/*/*/*/*/*/*/*",
    "  ",
]


def _spec() -> RuntimeKeySpec:
    """Build the series-blacklist specification under test."""
    return RuntimeKeySpec(
        service=_SERVICE,
        key=_KEY,
        value_type="list",
        validator=series_blacklist_syntax_validator,
        domain="entry forms",
        description="Series exclusion patterns (IP, MAC, protocol tag, UCI, * wildcards).",
    )


@pytest.fixture(name="blacklist_key")
def _blacklist_key() -> RuntimeKeySpec:
    """Register the series-blacklist key and drop it after the test."""
    spec = _spec()
    register(spec)
    yield spec
    from otalon_common.runtime import reset_registry

    reset_registry()


def _value(entries: list[str]) -> str:
    """Serialize *entries* as the JSON-array value text."""
    return json.dumps(entries)


@pytest.mark.unit
@pytest.mark.parametrize("entry", _ACCEPTED_ENTRIES)
def test_every_accepted_entry_form_validates(entry: str) -> None:
    """Each declared entry form passes the shared syntax validator."""
    series_blacklist_syntax_validator(_value([entry]))


@pytest.mark.unit
def test_spec_scenario_entries_validate_together() -> None:
    """The spec's one-of-each-form array validates as a whole."""
    series_blacklist_syntax_validator(_value(_ACCEPTED_ENTRIES))


@pytest.mark.unit
@pytest.mark.parametrize("entry", _REJECTED_ENTRIES)
def test_each_malformed_form_is_rejected_with_its_index(entry: str) -> None:
    """A malformed entry is rejected naming its 0-based index."""
    with pytest.raises(ListEntryValidationError, match=r"entry\[1\]"):
        series_blacklist_syntax_validator(_value(["ff:ff:ff:ff:ff:ff", entry]))


@pytest.mark.unit
def test_malformed_mac_rejection_matches_spec_scenario() -> None:
    """The spec's ``["33:33:*", "33:33:zz"]`` case names entry index 1."""
    with pytest.raises(ListEntryValidationError, match=r"entry\[1\]"):
        series_blacklist_syntax_validator(_value(["33:33:*", "33:33:zz"]))


@pytest.mark.unit
@pytest.mark.parametrize("value", ['"nope"', "42", '{"a": 1}', "null", "not json", ""])
def test_non_array_input_is_rejected_without_entry_index(value: str) -> None:
    """Structural non-array failures carry no entry index and are ValueErrors."""
    with pytest.raises(ValueError, match="expected a JSON array") as exc_info:
        series_blacklist_syntax_validator(value)
    assert not isinstance(exc_info.value, ListEntryValidationError)


@pytest.mark.unit
@pytest.mark.parametrize("value", ["[1]", '["ok", 2]', '[["nested"]]', "[null]"])
def test_non_string_entries_are_rejected_without_entry_index(value: str) -> None:
    """Non-string array elements are structural failures, not entry failures."""
    with pytest.raises(ValueError, match="array of strings") as exc_info:
        series_blacklist_syntax_validator(value)
    assert not isinstance(exc_info.value, ListEntryValidationError)


@pytest.mark.unit
def test_empty_array_is_valid() -> None:
    """An empty blacklist is a legitimate configuration."""
    series_blacklist_syntax_validator("[]")


@pytest.mark.unit
def test_valid_write_via_registry_and_canonicalization() -> None:
    """Valid writes pass validate_write; canonical form is compact JSON."""
    register(_spec())
    value = '["ipv6","ff:ff:ff:ff:ff:ff"]'
    assert validate_write(_SERVICE, _KEY, value) == lookup(_SERVICE, _KEY)
    assert normalize_value(_SERVICE, _KEY, value) == value


@pytest.mark.unit
def test_whitespace_variants_converge_to_one_persisted_text() -> None:
    """Whitespace-padded input persists as one canonical compact JSON text."""
    register(_spec())
    a = normalize_value(_SERVICE, _KEY, ' [ "IPv6" ,  "FF:FF:FF:FF:FF:FF" ] ')
    b = normalize_value(_SERVICE, _KEY, '["IPv6","FF:FF:FF:FF:FF:FF"]')
    assert a == '["ipv6","ff:ff:ff:ff:ff:ff"]'
    assert a == b


@pytest.mark.unit
def test_canonicalization_lowercases_strips_and_deduplicates_in_order() -> None:
    """Entries are lowercased, stripped, de-duplicated, order preserved."""
    register(_spec())
    canonical = normalize_value(
        _SERVICE, _KEY, '[ " IPv6 " , "ipv6", "ARP", "  arp ", " 8.8.8.8 "]'
    )
    assert canonical == '["ipv6","arp","8.8.8.8"]'


@pytest.mark.unit
def test_invalid_entry_write_is_rejected_with_index_via_registry() -> None:
    """validate_write surfaces the entry-level failure with its index."""
    register(_spec())
    with pytest.raises(ListEntryValidationError, match=r"entry\[1\]"):
        normalize_value(_SERVICE, _KEY, _value(["33:33:*", "bad!!"]))


@pytest.mark.unit
def test_secret_deny_does_not_block_the_series_blacklist_key() -> None:
    """The key name matches no secret pattern and stays writable."""
    assert is_secret_key(_KEY) is False
    register(_spec())
    assert lookup(_SERVICE, _KEY) is not None
    normalize_value(_SERVICE, _KEY, "[]")


@pytest.mark.unit
def test_manifest_declares_the_series_blacklist_key() -> None:
    """The static manifest carries the list-typed key for other services."""
    entry = manifest_entry(_SERVICE, _KEY)
    assert entry is not None
    assert entry.value_type == "list"
    assert entry.domain is not None and "MAC" in entry.domain
    assert entry.description.startswith("Series exclusion patterns")


@pytest.mark.unit
def test_allow_list_still_rejects_unknown_keys() -> None:
    """An unregistered key is rejected naming the allow-list."""
    with pytest.raises(ValueError, match="allow-list"):
        validate_write(_SERVICE, "detection.series_typo", "[]")


@pytest.mark.unit
def test_secret_deny_still_blocks_other_secret_keys() -> None:
    """Secret-looking keys keep being denied ahead of any registration."""
    with pytest.raises(ValueError, match="secret-looking"):
        validate_write(_SERVICE, "detection.token", "[]")


@pytest.mark.unit
@pytest.mark.parametrize(
    "value", ['"nope"', "42", '{"a": 1}', "null", "not json", "[1,2]"]
)
def test_validate_write_enforces_array_guard_for_registered_key(
    blacklist_key: RuntimeKeySpec, value: str
) -> None:
    """The structural guard in validate_write rejects non-array list values.

    The per-key validator alone would not catch every structural case through
    the registry path; this pins the guard on the real write path.
    """
    with pytest.raises(ValueError):
        validate_write(_SERVICE, _KEY, value)
