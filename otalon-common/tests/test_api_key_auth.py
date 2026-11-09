"""Security tests for shared API-key authentication."""

import hmac
import subprocess
import sys

import pytest

import otalon_common.auth.api_key as auth


def test_core_module_imports_without_web_framework() -> None:
    """The pure core imports with no FastAPI/Starlette dependency (spec 29-32)."""
    code = (
        "import sys\n"
        "import otalon_common.auth.api_key\n"
        "assert 'fastapi' not in sys.modules, 'fastapi leaked into core import'\n"
        "assert 'starlette' not in sys.modules, 'starlette leaked into core import'\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_parse_and_resolve_roles() -> None:
    entries = auth.parse_allowed_keys("read:viewer:VIEW,write:operator:OP")
    assert entries[0].role is auth.KeyRole.VIEWER
    operator = auth.KeyRegistry(tuple(entries)).verify("OP")
    assert operator is not None
    assert operator.role is auth.KeyRole.OPERATOR


@pytest.mark.parametrize(
    "raw", ["bad", "name:unknown:key", "name:viewer:", ":viewer:key", "a:viewer:k:b"]
)
def test_parse_rejects_malformed_entries(raw: str) -> None:
    with pytest.raises(ValueError):
        auth.parse_allowed_keys(raw)


def test_rotation_accepts_duplicate_name_keys() -> None:
    registry = auth.KeyRegistry(
        tuple(auth.parse_allowed_keys("svc:operator:OLD,svc:operator:NEW"))
    )
    old = registry.verify("OLD")
    new = registry.verify("NEW")
    assert old is not None and new is not None
    assert old.name == "svc"
    assert new.name == "svc"


def test_wrong_and_empty_keys_are_rejected_with_compare_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[bytes, bytes]] = []
    original = hmac.compare_digest

    def recording(left: bytes, right: bytes) -> bool:
        calls.append((left, right))
        return original(left, right)

    monkeypatch.setattr(hmac, "compare_digest", recording)
    registry = auth.KeyRegistry(tuple(auth.parse_allowed_keys("svc:operator:SECRET")))
    assert registry.verify("") is None
    assert registry.verify("WRONG") is None
    assert calls == [(b"", b"SECRET"), (b"WRONG", b"SECRET")]


@pytest.mark.parametrize(
    "presented",
    ["Schlüssel", "ключ", "秘密", "key\U0001f512", "SECRET\u00e9"],
)
def test_non_ascii_key_is_rejected_without_exception(presented: str) -> None:
    """Non-ASCII keys must mismatch cleanly instead of raising TypeError."""
    registry = auth.KeyRegistry(tuple(auth.parse_allowed_keys("svc:operator:SECRET")))
    assert registry.verify(presented) is None
    assert auth.constant_time_equals(presented, "SECRET") is False


def test_non_ascii_key_matches_itself() -> None:
    """A configured non-ASCII key still authenticates its exact value."""
    registry = auth.KeyRegistry(
        tuple(auth.parse_allowed_keys("svc:operator:Schlüssel"))
    )
    entry = registry.verify("Schlüssel")
    assert entry is not None
    assert entry.name == "svc"
    assert registry.verify("Schlussel") is None


def test_lone_surrogate_key_is_rejected_without_exception() -> None:
    """Surrogate code points survive encoding and mismatch cleanly."""
    assert auth.constant_time_equals("\ud800", "SECRET") is False
    assert auth.constant_time_equals("\ud800", "\ud800") is True


def test_ascii_key_still_matches() -> None:
    """Valid ASCII keys authenticate exactly as before the encoding fix."""
    registry = auth.KeyRegistry(tuple(auth.parse_allowed_keys("svc:operator:SECRET")))
    entry = registry.verify("SECRET")
    assert entry is not None
    assert entry.role is auth.KeyRole.OPERATOR
    assert registry.verify("secret") is None


def test_from_env_unset_fails_closed_and_repr_redacts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("MISSING_ALLOWED_KEYS", raising=False)
    registry = auth.KeyRegistry.from_env("MISSING_ALLOWED_KEYS")
    assert registry.on_missing is auth.OnMissing.FAIL_CLOSED
    assert registry.verify("SECRET") is None
    assert "SECRET" not in repr(registry)
