"""API-key authentication for the CyberScan-ICS REST surface.

Implements the ``scan--api-auth`` spec of the
``harden-otalon-scan-security`` OpenSpec change (Phase 5):

- Allow-list parsing from the ``OTALON_SCAN_ALLOWED_KEYS`` environment variable.
- A FastAPI dependency factory :func:`verify_api_key` that enforces the
  ``X-API-Key`` header and the caller's role on every protected route.
- Constant-time key comparison via :func:`hmac.compare_digest`.
- Structured audit logging on every accept and reject via ``loguru``
  (matching the rest of otalon-scan; ``otalon-scan`` is a
  loguru-based subproject per ``AGENTS.md``).

Role model (spec ``scan--api-auth``):

- ``viewer``  — read-only endpoints
- ``operator`` — read-only + mutating endpoints (super-set of ``viewer``)

The allow-list itself is stored at module level via :func:`set_allowed_keys`,
which the API server calls exactly once at startup after parsing the
environment. Tests may override the allow-list via the same function (and
should restore the previous value with :func:`get_allowed_keys`).
"""

from __future__ import annotations

import hmac
from typing import Callable, Literal, Optional

from fastapi import HTTPException, Request, status
from loguru import logger

__all__ = [
    "AllowedKey",
    "Role",
    "parse_allowed_keys",
    "set_allowed_keys",
    "get_allowed_keys",
    "verify_api_key",
    "KEY_PREFIX_LEN",
]

# Type aliases.
Role = Literal["viewer", "operator"]

# Allow-list entry: ``key -> (name, role)``.
AllowedKey = tuple[str, Role]

# Number of leading characters of a rejected key that we log. The full key
# is NEVER logged.
KEY_PREFIX_LEN: int = 8

# Role precedence: an ``operator`` key satisfies a ``viewer`` requirement,
# but not vice-versa.
_ROLE_RANK: dict[str, int] = {"viewer": 0, "operator": 1}

# Module-level allow-list. Populated by the API server at startup via
# :func:`set_allowed_keys`. Empty by default so that any accidental
# import without explicit setup denies every request.
_ALLOWED_KEYS: dict[str, AllowedKey] = {}


def parse_allowed_keys(raw: str) -> dict[str, AllowedKey]:
    """Parse the ``OTALON_SCAN_ALLOWED_KEYS`` allow-list.

    Accepts a comma-separated list of ``name:role:key`` triples:

        ``ui-prod:viewer:abcd...,mcp-prod:operator:efgh...``

    Whitespace around entries and around individual fields is stripped.
    Empty entries (produced by trailing or consecutive commas) are
    skipped silently.

    Multiple entries with the same ``name`` are permitted — this is the
    rotation mechanism described in the spec. Each distinct ``key``
    becomes a separate entry in the returned mapping.

    Args:
    raw: The raw value of the ``OTALON_SCAN_ALLOWED_KEYS`` environment
            variable (or any equivalent string).

    Returns:
        A mapping ``key -> (name, role)`` keyed by the opaque API key.

    Raises:
        ValueError: If ``raw`` is empty (or whitespace-only), if any
            non-empty entry does not match the ``name:role:key`` shape,
            if the role is not one of ``"viewer"`` / ``"operator"``,
            or if any field (``name`` / ``role`` / ``key``) is empty after
            stripping whitespace. The error message identifies the offending
            entry so the operator can fix the configuration.
    """
    if raw is None or not raw.strip():
        raise ValueError(
            "OTALON_SCAN_ALLOWED_KEYS is empty; the otalon-scan auth layer "
            "requires at least one entry of the form name:role:key"
        )

    result: dict[str, AllowedKey] = {}
    for raw_entry in raw.split(","):
        entry = raw_entry.strip()
        if not entry:
            # Trailing comma or consecutive commas: skip silently.
            continue

        parts = entry.split(":")
        if len(parts) != 3:
            raise ValueError(
                f"malformed OTALON_SCAN_ALLOWED_KEYS entry {entry!r}: "
                f"expected exactly three colon-separated fields name:role:key, "
                f"got {len(parts)}"
            )

        name = parts[0].strip()
        role_raw = parts[1].strip()
        key = parts[2].strip()

        if not name:
            raise ValueError(f"malformed OTALON_SCAN_ALLOWED_KEYS entry {entry!r}: empty name field")
        if not key:
            raise ValueError(f"malformed OTALON_SCAN_ALLOWED_KEYS entry {entry!r}: empty key field")
        if role_raw not in _ROLE_RANK:
            raise ValueError(
                f"malformed OTALON_SCAN_ALLOWED_KEYS entry {entry!r}: "
                f"role must be one of 'viewer' or 'operator', got {role_raw!r}"
            )

        # mypy: role_raw is now provably one of the literal values.
        role: Role = "operator" if role_raw == "operator" else "viewer"
        result[key] = (name, role)

    if not result:
        # Pure whitespace / pure commas — same failure mode as truly empty input.
        raise ValueError(
            "OTALON_SCAN_ALLOWED_KEYS contained no usable entries; expected " "at least one name:role:key triple"
        )

    return result


def set_allowed_keys(keys: dict[str, AllowedKey]) -> None:
    """Install the active allow-list.

    Called once at service startup with the result of
    :func:`parse_allowed_keys`. Tests may invoke this directly to drive
    the auth dependency without going through ``os.environ``.
    """
    global _ALLOWED_KEYS
    _ALLOWED_KEYS = dict(keys)


def get_allowed_keys() -> dict[str, AllowedKey]:
    """Return a shallow copy of the current allow-list.

    Mainly useful for tests that want to save/restore state across cases.
    """
    return dict(_ALLOWED_KEYS)


def _truncate_key(presented: Optional[str]) -> str:
    """Truncate a presented key for safe inclusion in an audit log.

    - ``None`` / empty → ``"(empty)"``.
    - Anything longer than :data:`KEY_PREFIX_LEN` → first prefix + ``"..."``.
    - Anything else → the value unchanged. The full key is NEVER logged
      for accepted requests either; callers use the caller's ``name``.
    """
    if not presented:
        return "(empty)"
    if len(presented) > KEY_PREFIX_LEN:
        return f"{presented[:KEY_PREFIX_LEN]}..."
    return presented


def _lookup(presented: str) -> Optional[AllowedKey]:
    """Constant-time lookup of ``presented`` in the active allow-list.

    Compares the presented key against every entry with
    :func:`hmac.compare_digest`. We accept the resulting linear scan
    because it preserves constant-time semantics versus the trivial
    ``dict.get`` (which would short-circuit on key length / hash and
    leak timing information about which prefix matches).

    Returns the ``(name, role)`` tuple for the matching key or ``None``
    if no key matched.
    """
    match: Optional[AllowedKey] = None
    presented_bytes = presented.encode("utf-8")
    for candidate, info in _ALLOWED_KEYS.items():
        if hmac.compare_digest(candidate.encode("utf-8"), presented_bytes):
            match = info
            # Do not break: keep the loop body uniform so total time
            # depends on allow-list size, not on early match position.
    return match


def verify_api_key(required_role: Role) -> Callable[[Request], None]:
    """Return a FastAPI dependency that enforces auth + role for one route.

    Usage::

        @app.get("/scans/running", dependencies=[Depends(verify_api_key("viewer"))])
        async def list_running(): ...

        @app.post("/scans/start", dependencies=[Depends(verify_api_key("operator"))])
        async def start(): ...

    On each invocation the returned dependency:

    1. Reads the ``X-API-Key`` request header. Missing or empty header →
       HTTP 401, ``event=auth.reject reason=missing`` audit log.
    2. Looks the presented key up in the allow-list with constant-time
       comparison. No match → HTTP 401, ``event=auth.reject reason=invalid``.
    3. Compares the caller's role against ``required_role``. Insufficient
       role → HTTP 403,
       ``event=auth.reject reason=insufficient_role caller=… role=… required_role=…``.
    4. On accept: ``event=auth.accept name=… role=… path=… key_prefix=…``
       at INFO level. The ``key_prefix`` field is the truncated form of
       the presented key, matching the prefix used on reject so log
       readers can correlate accept/reject events without ever seeing
       the full key.

    The full API key never appears in any log line.
    """
    if required_role not in _ROLE_RANK:
        # This is a programmer error, surface it loudly at import time.
        raise ValueError(f"verify_api_key: required_role must be 'viewer' or 'operator', " f"got {required_role!r}")

    required_rank = _ROLE_RANK[required_role]

    def _dependency(request: Request) -> None:
        path = request.url.path
        method = request.method
        presented: Optional[str] = request.headers.get("x-api-key")

        if not presented:
            logger.warning(
                "event=auth.reject reason=missing method={method} path={path} " "key_prefix={key_prefix}",
                method=method,
                path=path,
                key_prefix=_truncate_key(presented),
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="missing X-API-Key header",
            )

        info = _lookup(presented)
        if info is None:
            logger.warning(
                "event=auth.reject reason=invalid method={method} path={path} " "key_prefix={key_prefix}",
                method=method,
                path=path,
                key_prefix=_truncate_key(presented),
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid API key",
            )

        name, role = info
        if _ROLE_RANK[role] < required_rank:
            logger.warning(
                "event=auth.reject reason=insufficient_role caller={name} "
                "role={role} required_role={required_role} method={method} path={path}",
                name=name,
                role=role,
                required_role=required_role,
                method=method,
                path=path,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"role {role!r} cannot access endpoint requiring {required_role!r}",
            )

        logger.info(
            "event=auth.accept name={name} role={role} method={method} path={path} " "key_prefix={key_prefix}",
            name=name,
            role=role,
            method=method,
            path=path,
            key_prefix=_truncate_key(presented),
        )

    return _dependency
