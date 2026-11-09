"""Key-structured redaction of sensitive fields for operations jobs/audit.

Job ``params``/``log`` and audit free-text (``detail``/``reason``/``target``/
``action``) payloads are persisted and surfaced in the UI. Any producer
(Wave B service-lifecycle today; C/D/E/F later) that passes a
credential-bearing value should not leak it into the durable row, the SSE
stream, the DOM or a verification artifact. This module provides a single
deterministic redactor applied at the service boundary.

**Scope (honest):** redaction is **key-structured**, not arbitrary
value scanning. :func:`redact_sensitive` redacts a dict entry when its
**key** matches a sensitive marker (recursively through nested dicts and
lists). :func:`redact_text` redacts the value in a ``key=value`` / ``key:
value`` token pair when the **key** matches a marker — it does **not**
inspect free-standing values for secret-shaped content. A bare secret in an
unlabelled string (e.g. a lone token with no key) is therefore *not*
detected; producers remain responsible for not emitting such values.
Value-pattern scrubbing is deliberately out of scope until free-form
producers land (tracked follow-up).
"""

from __future__ import annotations

import re
from typing import Any

REDACTED = "***REDACTED***"

# Substrings that mark a key as sensitive (matched case-insensitively).
SENSITIVE_KEY_MARKERS: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "x-api-key",
        "authorization",
        "auth",
        "credential",
        "private_key",
        "access_key",
        "session",
        "cookie",
        "bearer",
    }
)

_MAX_DEPTH = 12


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(marker in lowered for marker in SENSITIVE_KEY_MARKERS)


def redact_sensitive(value: Any, _depth: int = 0) -> Any:
    """Return a copy of *value* with sensitive keys recursively redacted.

    Dict keys matching any :data:`SENSITIVE_KEY_MARKERS` marker have their
    value replaced with :data:`REDACTED`; lists/tuples are traversed
    element-wise. Non-container values are returned unchanged. Recursion is
    bounded by :data:`_MAX_DEPTH` to avoid pathological nesting.

    Args:
        value: Arbitrary JSON-compatible payload (dict/list/scalar).
        _depth: Internal recursion guard; callers pass nothing.

    Returns:
        A redacted deep copy safe to persist and surface.
    """
    if _depth >= _MAX_DEPTH:
        return value
    if isinstance(value, dict):
        redacted: dict[Any, Any] = {}
        for key, item in value.items():
            if isinstance(key, str) and _is_sensitive_key(key):
                redacted[key] = REDACTED
            else:
                redacted[key] = redact_sensitive(item, _depth + 1)
        return redacted
    if isinstance(value, (list, tuple)):
        return [redact_sensitive(item, _depth + 1) for item in value]
    return value


def _marker_pattern(marker: str) -> str:
    """Build a regex fragment for a marker treating ``_``/``-`` as equivalent.

    ``api_key`` then also matches ``api-key`` and ``apikey`` so a
    hyphenated or run-together key in free text is still detected.
    """
    return re.escape(marker).replace("_", "[_-]?").replace(r"\-", "[_-]?")


# Matches a ``sensitive_key = value`` or ``sensitive_key: value`` token pair.
# The key alternation is built from the markers (``_``/``-`` insensitive); the
# value is the following quoted string or non-separator run. This is still
# key-structured: it only fires when a recognised sensitive KEY precedes the
# value, never on a free-standing value.
_TEXT_KEY_ALTERNATION = "|".join(_marker_pattern(marker) for marker in sorted(SENSITIVE_KEY_MARKERS))
_TEXT_SECRET_RE = re.compile(
    rf"(?P<key>[\w.]*(?:{_TEXT_KEY_ALTERNATION})[\w.]*)"
    r"(?P<sep>\s*[:=]\s*)"
    r"(?P<val>\"[^\"]*\"|'[^']*'|[^\s,;&]+)",
    flags=re.IGNORECASE,
)


def redact_text(value: str | None) -> str | None:
    """Redact ``key=value`` pairs in free-text where the key is sensitive.

    Applied to audit free-text fields (``detail``/``reason``/``target``/
    ``action``) at the service boundary. Only the value in a
    ``<sensitive-key><sep><value>`` pair is replaced with :data:`REDACTED`;
    the surrounding text and the key itself are preserved so the audit row
    stays legible. Consistent with :func:`redact_sensitive`, detection is
    **key-structured** — a value with no sensitive key in front of it is left
    untouched (see the module docstring for the deliberate scope limit).

    Args:
        value: Free-text audit field, or ``None``.

    Returns:
        The redacted string, or ``None`` when *value* is ``None``.
    """
    if value is None:
        return None

    def _replace(match: "re.Match[str]") -> str:
        return f"{match.group('key')}{match.group('sep')}{REDACTED}"

    return _TEXT_SECRET_RE.sub(_replace, value)


# IPv4 (with optional CIDR), IPv6, and DNS-style hostnames. Value-pattern based
# — deliberately scoped to the Support Bundle payload (see
# :func:`redact_network_identifiers`), which advertises hostname/IP redaction in
# its privacy preview (design Decision 5). This is intentionally NOT applied to
# the shared audit redactor, whose key-structured scope keeps audit rows
# legible; scrubbing free-standing identifiers there is a separate concern.
REDACTED_HOST = "***REDACTED-HOST***"
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:/\d{1,2})?\b")
_IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}\b")
# A dotted DNS hostname of at least two labels ending in an alphabetic TLD; local
# filesystem paths (leading ``/``) and bare version numbers are excluded because
# the TLD label must be alphabetic and 2+ chars.
_HOSTNAME_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")


def redact_network_identifiers(value: Any, _depth: int = 0) -> Any:
    """Return a copy of *value* with hostnames and IP addresses redacted.

    Recursively scrubs IPv4/IPv6 addresses and DNS-style hostnames from string
    values inside dicts/lists so the Support Bundle honours the hostname/IP
    redaction it advertises (design Decision 5). Dict keys and non-string
    scalars are left structurally intact; only string *values* are rewritten.

    Args:
        value: Arbitrary JSON-compatible payload (dict/list/scalar).
        _depth: Internal recursion guard; callers pass nothing.

    Returns:
        A copy with network identifiers replaced by :data:`REDACTED_HOST`.
    """
    if _depth >= _MAX_DEPTH:
        return value
    if isinstance(value, dict):
        return {key: redact_network_identifiers(item, _depth + 1) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_network_identifiers(item, _depth + 1) for item in value]
    if isinstance(value, str):
        scrubbed = _IPV4_RE.sub(REDACTED_HOST, value)
        scrubbed = _IPV6_RE.sub(REDACTED_HOST, scrubbed)
        return _HOSTNAME_RE.sub(REDACTED_HOST, scrubbed)
    return value
