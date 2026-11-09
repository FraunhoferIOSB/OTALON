"""Unit tests for :func:`otalon_scan.core.auth.parse_allowed_keys`.

Phase 5 / scan--api-auth. Verifies the allow-list parser handles empty
input, malformed entries, duplicate-name rotation, and whitespace
robustness exactly as specified.
"""

from __future__ import annotations

import pytest

from otalon_scan.core.auth import parse_allowed_keys

# ---- Happy path ----


def test_parse_single_entry() -> None:
    result = parse_allowed_keys("ui-prod:viewer:abcd1234")
    assert result == {"abcd1234": ("ui-prod", "viewer")}


def test_parse_multiple_entries() -> None:
    raw = "ui-prod:viewer:k1,mcp-prod:operator:k2,ui-stage:viewer:k3"
    result = parse_allowed_keys(raw)
    assert result == {
        "k1": ("ui-prod", "viewer"),
        "k2": ("mcp-prod", "operator"),
        "k3": ("ui-stage", "viewer"),
    }


def test_parse_supports_both_roles() -> None:
    result = parse_allowed_keys("a:viewer:k1,b:operator:k2")
    assert result["k1"][1] == "viewer"
    assert result["k2"][1] == "operator"


# ---- Rotation: same name across multiple keys ----


def test_duplicate_name_for_rotation_is_allowed() -> None:
    """Two entries with the same ``name`` SHALL produce two allow-list entries."""
    raw = "mcp-prod:operator:OLDKEY,mcp-prod:operator:NEWKEY"
    result = parse_allowed_keys(raw)
    assert result == {
        "OLDKEY": ("mcp-prod", "operator"),
        "NEWKEY": ("mcp-prod", "operator"),
    }


def test_duplicate_key_last_wins() -> None:
    """The same opaque key listed twice collapses to the last entry.

    This is not a spec-mandated behaviour but a property of using the
    key as a dict key. Documented here so future changes notice.
    """
    raw = "old:viewer:SAMEKEY,new:operator:SAMEKEY"
    result = parse_allowed_keys(raw)
    assert result == {"SAMEKEY": ("new", "operator")}


# ---- Whitespace handling ----


def test_whitespace_around_entries_is_stripped() -> None:
    raw = "  ui-prod:viewer:k1  ,   mcp-prod:operator:k2  "
    result = parse_allowed_keys(raw)
    assert result == {
        "k1": ("ui-prod", "viewer"),
        "k2": ("mcp-prod", "operator"),
    }


def test_whitespace_around_fields_is_stripped() -> None:
    raw = " ui-prod : viewer : k1 "
    result = parse_allowed_keys(raw)
    assert result == {"k1": ("ui-prod", "viewer")}


def test_trailing_and_consecutive_commas_are_tolerated() -> None:
    raw = "ui-prod:viewer:k1,,mcp-prod:operator:k2,"
    result = parse_allowed_keys(raw)
    assert result == {
        "k1": ("ui-prod", "viewer"),
        "k2": ("mcp-prod", "operator"),
    }


# ---- Rejection cases ----


@pytest.mark.parametrize("raw", ["", "   ", "\n", "\t  \n"])
def test_empty_or_whitespace_input_raises(raw: str) -> None:
    with pytest.raises(ValueError, match="empty"):
        parse_allowed_keys(raw)


def test_purely_commas_raises() -> None:
    with pytest.raises(ValueError, match="no usable entries"):
        parse_allowed_keys(",,,")


def test_entry_without_colons_raises() -> None:
    with pytest.raises(ValueError, match="malformed.*expected exactly three"):
        parse_allowed_keys("justakey")


def test_entry_with_two_colons_only_raises() -> None:
    with pytest.raises(ValueError, match="malformed.*expected exactly three"):
        parse_allowed_keys("name:viewer")


def test_entry_with_four_colons_raises() -> None:
    with pytest.raises(ValueError, match="malformed.*expected exactly three"):
        parse_allowed_keys("name:viewer:key:extra")


def test_unknown_role_raises() -> None:
    with pytest.raises(ValueError, match="role must be one of"):
        parse_allowed_keys("name:admin:key")


def test_empty_name_raises() -> None:
    with pytest.raises(ValueError, match="empty name"):
        parse_allowed_keys(":viewer:key")


def test_empty_key_raises() -> None:
    with pytest.raises(ValueError, match="empty key"):
        parse_allowed_keys("name:viewer:")


def test_first_malformed_entry_aborts_parsing() -> None:
    """A malformed entry SHALL abort parsing, not be silently skipped.

    Operators rely on the fail-fast behaviour: a typo in any single
    entry must surface as a startup failure, not as a partially-loaded
    allow-list where some keys silently never authenticate.
    """
    with pytest.raises(ValueError):
        parse_allowed_keys("good:viewer:k1,broken-entry-no-colons,other:operator:k2")


# ---- verify_api_key programmer-error guard ----


def test_verify_api_key_rejects_unknown_required_role() -> None:
    """Calling ``verify_api_key`` with an unsupported role SHALL raise at import time.

    This is a programmer-error guard: passing a string outside the
    ``{"viewer", "operator"}`` set is a typo in route wiring and must
    surface immediately, not silently fail closed at request time.
    """
    from otalon_scan.core.auth import verify_api_key

    with pytest.raises(ValueError, match="required_role must be 'viewer' or 'operator'"):
        verify_api_key("admin")  # type: ignore[arg-type]
