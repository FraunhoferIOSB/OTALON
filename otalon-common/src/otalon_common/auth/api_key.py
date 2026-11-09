"""Framework-independent API-key parsing and verification."""

from __future__ import annotations

import hmac
import os
from dataclasses import dataclass
from enum import StrEnum


class KeyRole(StrEnum):
    """Authorization roles supported by service API keys."""

    VIEWER = "viewer"
    OPERATOR = "operator"


class OnMissing(StrEnum):
    """Behavior when an allowed-key environment variable is empty."""

    FAIL_CLOSED = "fail_closed"
    WARN_OPEN = "warn_open"


def _encode_key(value: str) -> bytes:
    """Return ``value`` as bytes suitable for a constant-time comparison.

    ``hmac.compare_digest`` refuses ``str`` operands holding a non-ASCII
    character. Starlette decodes request headers as latin-1, so any byte above
    0x7F in ``X-API-Key`` produced such a string and raised ``TypeError``
    instead of answering 401 (audit V4/QUA-C5).

    Args:
        value: The supplied or configured key as decoded by Starlette.

    Returns:
        The UTF-8 encoding of ``value``; lone surrogates are preserved.
    """
    return value.encode("utf-8", "surrogatepass")


def constant_time_equals(presented: str, expected: str) -> bool:
    """Return whether two keys are equal, comparing them in constant time.

    Both operands are encoded the same way, so every input stays comparable
    without discarding information and without short-circuiting on length: the
    comparison remains constant-time for equal-length candidates and a
    non-ASCII key yields a clean mismatch instead of an exception.

    Args:
        presented: The key supplied by the caller.
        expected: The configured key to compare against.

    Returns:
        ``True`` when both keys are byte-identical, ``False`` otherwise.
    """
    return hmac.compare_digest(_encode_key(presented), _encode_key(expected))


@dataclass(frozen=True, repr=False)
class KeyEntry:
    """Named API key and its minimum authorization role."""

    name: str
    role: KeyRole
    key: str

    def __repr__(self) -> str:
        """Return a representation that cannot disclose the key."""
        return f"KeyEntry(name={self.name!r}, role={self.role!r}, key=<redacted>)"


def parse_allowed_keys(raw: str) -> list[KeyEntry]:
    """Parse comma-separated ``name:role:key`` entries."""
    if not raw.strip():
        return []
    entries: list[KeyEntry] = []
    for item in raw.split(","):
        parts = item.split(":")
        if len(parts) != 3 or not all(parts):
            raise ValueError("allowed key entries must have name:role:key format")
        name, role_text, key = parts
        try:
            role = KeyRole(role_text)
        except ValueError as exc:
            raise ValueError("allowed key role must be viewer or operator") from exc
        entries.append(KeyEntry(name=name, role=role, key=key))
    return entries


@dataclass(frozen=True, repr=False)
class KeyRegistry:
    """Collection of API keys with explicit missing-key behavior."""

    entries: tuple[KeyEntry, ...] = ()
    on_missing: OnMissing = OnMissing.FAIL_CLOSED

    @classmethod
    def from_env(
        cls, var: str, *, on_missing: OnMissing = OnMissing.FAIL_CLOSED
    ) -> KeyRegistry:
        """Build registry from an environment variable without exposing its value."""
        return cls(tuple(parse_allowed_keys(os.environ.get(var, ""))), on_missing)

    def verify(self, presented: str) -> KeyEntry | None:
        """Return matching entry, using constant-time comparison for every key."""
        matched: KeyEntry | None = None
        for entry in self.entries:
            if constant_time_equals(presented, entry.key) and matched is None:
                matched = entry
        return matched

    @property
    def configured(self) -> bool:
        """Return whether at least one key is configured."""
        return bool(self.entries)

    def __repr__(self) -> str:
        """Return a representation that cannot disclose configured keys."""
        return (
            f"KeyRegistry(entries={len(self.entries)}, on_missing={self.on_missing!r})"
        )
