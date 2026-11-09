"""Repositories for product users and opaque server-side sessions."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from loguru import logger
from otalon_common.auth import (
    UserRole,
    dummy_password_hash,
    hash_password,
    verify_password,
)
from psycopg2.extras import RealDictCursor

from otalon_api.repositories.postgres_repo import PostgresRepository

SESSION_TTL = timedelta(hours=24)
"""Sliding lifetime applied to every validated product session."""


class LastActiveAdminError(Exception):
    """Raised when an identity change would remove the last active admin."""


@dataclass(frozen=True)
class UserEntry:
    """User identity loaded from the product identity store."""

    id: int
    username: str
    password_hash: str
    role: UserRole
    must_change_password: bool
    disabled: bool
    last_login_at: datetime | None
    created_at: datetime | None = None


def _user_from_row(row: dict[str, Any]) -> UserEntry:
    """Convert one PostgreSQL row into a typed user entry."""
    return UserEntry(
        id=int(row["id"]),
        username=str(row["username"]),
        password_hash=str(row["password_hash"]),
        role=UserRole(str(row["role"])),
        must_change_password=bool(row["must_change_password"]),
        disabled=bool(row["disabled"]),
        last_login_at=row.get("last_login_at"),
        created_at=row.get("created_at"),
    )


class UserRepository:
    """Database access for product user records and password lifecycle."""

    def __init__(self, postgres_repo: PostgresRepository) -> None:
        """Initialize repository over shared PostgreSQL access."""
        self._postgres = postgres_repo

    def find_by_username(self, username: str) -> UserEntry | None:
        """Return user matching username, or ``None`` when absent."""
        rows = self._postgres._execute_query(
            "SELECT id, username, password_hash, role, must_change_password, "
            "disabled, last_login_at, created_at FROM users WHERE username = %(username)s",
            {"username": username},
        )
        return _user_from_row(rows[0]) if rows else None

    def authenticate(self, username: str, password: str) -> UserEntry | None:
        """Verify known and unknown usernames through one Argon2 code path."""
        user = self.find_by_username(username)
        password_hash = user.password_hash if user is not None else dummy_password_hash()
        verified = verify_password(password, password_hash)
        if user is None or user.disabled or not verified:
            return None
        return user

    def count_users(self) -> int:
        """Return number of product users."""
        rows = self._postgres._execute_query("SELECT COUNT(*) AS count FROM users")
        return int(rows[0]["count"]) if rows else 0

    def list_users(self) -> list[UserEntry]:
        """Return all product users ordered by creation ID."""
        rows = self._postgres._execute_query(
            "SELECT id, username, password_hash, role, must_change_password, "
            "disabled, last_login_at, created_at FROM users ORDER BY id"
        )
        return [_user_from_row(row) for row in rows]

    def find_by_id(self, user_id: int) -> UserEntry | None:
        """Return one product user by numeric identifier."""
        rows = self._postgres._execute_query(
            "SELECT id, username, password_hash, role, must_change_password, "
            "disabled, last_login_at, created_at FROM users WHERE id=%(id)s",
            {"id": user_id},
        )
        return _user_from_row(rows[0]) if rows else None

    def create_user(self, username: str, role: UserRole, password: str) -> UserEntry:
        """Create a forced-change user with a newly hashed password."""
        rows = self._postgres._execute_query(
            "INSERT INTO users (username, password_hash, role, must_change_password) "
            "VALUES (%(username)s, %(password_hash)s, %(role)s, true) "
            "RETURNING id, username, password_hash, role, must_change_password, "
            "disabled, last_login_at, created_at",
            {
                "username": username,
                "password_hash": hash_password(password),
                "role": role.value,
            },
        )
        if not rows:
            raise RuntimeError("User creation returned no row")
        return _user_from_row(rows[0])

    def update_user(self, user_id: int, role: UserRole | None, disabled: bool | None) -> UserEntry | None:
        """Update supplied role and disabled fields, preserving omitted fields."""
        with self._postgres.connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("LOCK TABLE users IN SHARE ROW EXCLUSIVE MODE")
                cur.execute(
                    "SELECT id, username, password_hash, role, must_change_password, "
                    "disabled, last_login_at, created_at FROM users WHERE id=%(id)s",
                    {"id": user_id},
                )
                current = cur.fetchone()
                if current is None:
                    conn.commit()
                    return None
                if (
                    current["role"] == UserRole.ADMIN.value
                    and not current["disabled"]
                    and (role is not None and role != UserRole.ADMIN or disabled is True)
                ):
                    cur.execute(
                        "SELECT COUNT(*) AS count FROM users " "WHERE role='admin' AND disabled=false AND id <> %(id)s",
                        {"id": user_id},
                    )
                    if int(cur.fetchone()["count"]) == 0:
                        raise LastActiveAdminError
                cur.execute(
                    "UPDATE users SET role=COALESCE(%(role)s, role), "
                    "disabled=COALESCE(%(disabled)s, disabled), updated_at=now() "
                    "WHERE id=%(id)s RETURNING id, username, password_hash, role, "
                    "must_change_password, disabled, last_login_at, created_at",
                    {
                        "id": user_id,
                        "role": role.value if role is not None else None,
                        "disabled": disabled,
                    },
                )
                row = cur.fetchone()
            conn.commit()
        rows = [dict(row)] if row is not None else []
        return _user_from_row(rows[0]) if rows else None

    def delete_user(self, user_id: int) -> bool:
        """Delete one user; PostgreSQL cascades deletion to their sessions."""
        with self._postgres.connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("LOCK TABLE users IN SHARE ROW EXCLUSIVE MODE")
                cur.execute(
                    "SELECT role, disabled FROM users WHERE id=%(id)s",
                    {"id": user_id},
                )
                current = cur.fetchone()
                if current is None:
                    conn.commit()
                    return False
                if current["role"] == UserRole.ADMIN.value and not current["disabled"]:
                    cur.execute(
                        "SELECT COUNT(*) AS count FROM users " "WHERE role='admin' AND disabled=false AND id <> %(id)s",
                        {"id": user_id},
                    )
                    if int(cur.fetchone()["count"]) == 0:
                        raise LastActiveAdminError
                cur.execute("DELETE FROM users WHERE id=%(id)s", {"id": user_id})
                deleted = cur.rowcount > 0
            conn.commit()
        return deleted

    def reset_password(self, user_id: int, password: str) -> bool:
        """Replace password hash and force a change, returning target existence."""
        return (
            self._postgres._execute_update(
                "UPDATE users SET password_hash=%(password_hash)s, "
                "must_change_password=true, updated_at=now() WHERE id=%(id)s",
                {"id": user_id, "password_hash": hash_password(password)},
            )
            > 0
        )

    def create_bootstrap_admin(self, password: str) -> bool:
        """Create one forced-change admin only while the user table is empty."""
        with self._postgres.connection() as conn:
            with conn.cursor() as cur:
                cur.execute("LOCK TABLE users IN SHARE ROW EXCLUSIVE MODE")
                cur.execute("SELECT COUNT(*) FROM users")
                count = int(cur.fetchone()[0])
                if count:
                    conn.commit()
                    return False
                cur.execute(
                    "INSERT INTO users (username, password_hash, role, must_change_password) "
                    "VALUES (%(username)s, %(password_hash)s, 'admin', true)",
                    {"username": "admin", "password_hash": hash_password(password)},
                )
            conn.commit()
        return True

    def update_password(self, user_id: int, password: str) -> None:
        """Replace password hash and clear forced-change state."""
        self._postgres._execute_command(
            "UPDATE users SET password_hash=%(password_hash)s, "
            "must_change_password=false, updated_at=now() WHERE id=%(id)s",
            {"id": user_id, "password_hash": hash_password(password)},
        )

    def mark_login(self, user_id: int) -> None:
        """Record successful login time without exposing credentials."""
        self._postgres._execute_command(
            "UPDATE users SET last_login_at=now(), updated_at=now() WHERE id=%(id)s",
            {"id": user_id},
        )


class SessionRepository:
    """Database access for opaque, revocable, sliding sessions."""

    def __init__(self, postgres_repo: PostgresRepository) -> None:
        """Initialize repository over shared PostgreSQL access."""
        self._postgres = postgres_repo

    def create(self, user_id: int, ip: str | None, user_agent: str | None) -> str:
        """Create a fresh 256-bit opaque session and return its ID."""
        session_id = secrets.token_hex(32)
        self._postgres._execute_command(
            "INSERT INTO sessions (session_id, user_id, expires_at, ip, user_agent) "
            "VALUES (%(session_id)s, %(user_id)s, now() + interval '24 hours', %(ip)s, %(user_agent)s)",
            {
                "session_id": session_id,
                "user_id": user_id,
                "ip": ip,
                "user_agent": user_agent,
            },
        )
        return session_id

    def validate_and_touch(self, session_id: str) -> UserEntry | None:
        """Validate session/user state and extend valid session by 24 hours."""
        with self._postgres.connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    "SELECT u.id, u.username, u.password_hash, u.role, "
                    "u.must_change_password, u.disabled, u.last_login_at "
                    "FROM sessions s JOIN users u ON u.id=s.user_id "
                    "WHERE s.session_id=%(session_id)s AND s.revoked_at IS NULL "
                    "AND s.expires_at > now() AND u.disabled=false FOR UPDATE",
                    {"session_id": session_id},
                )
                row = cur.fetchone()
                if row is None:
                    conn.commit()
                    return None
                cur.execute(
                    "UPDATE sessions SET last_seen_at=now(), expires_at=now() + "
                    "interval '24 hours' WHERE session_id=%(session_id)s",
                    {"session_id": session_id},
                )
            conn.commit()
        return _user_from_row(dict(row))

    def revoke(self, session_id: str) -> None:
        """Revoke one session without logging its opaque identifier."""
        self._postgres._execute_command(
            "UPDATE sessions SET revoked_at=COALESCE(revoked_at, now()) " "WHERE session_id=%(session_id)s",
            {"session_id": session_id},
        )

    def revoke_for_user(self, user_id: int) -> None:
        """Revoke all sessions belonging to one user."""
        self._postgres._execute_command(
            "UPDATE sessions SET revoked_at=COALESCE(revoked_at, now()) "
            "WHERE user_id=%(user_id)s AND revoked_at IS NULL",
            {"user_id": user_id},
        )


def generate_bootstrap_password() -> str:
    """Generate a one-time password for admin-created/reset user accounts."""
    return secrets.token_urlsafe(24)


BOOTSTRAP_DEFAULT_PASSWORD = "OTALON-Setup!"
"""Fixed first-boot admin password. Operator MUST change it on first login
(enforced by ``must_change_password=true``); no secret is generated or logged.
A per-installation random admin password is planned for the future installer
flow (see `.dev/todo/TODO_otalon-api.md`), which will replace this fixed
value without changing the forced-change contract. Not used for admin-created
or reset accounts — those still use ``generate_bootstrap_password()``.
"""


def bootstrap_identity(postgres_repo: PostgresRepository) -> bool:
    """Seed empty identity storage with one forced-change admin account.

    Uses a fixed, documented first-boot password rather than a randomly
    generated one: operators previously had to dig it out of container
    startup logs, which is unusable in practice. Security is preserved by
    ``must_change_password=true``, which blocks all product routes until the
    password is changed.

    Args:
        postgres_repo: Shared PostgreSQL repository.

    Returns:
        ``True`` when a new bootstrap account was inserted.
    """
    inserted = UserRepository(postgres_repo).create_bootstrap_admin(BOOTSTRAP_DEFAULT_PASSWORD)
    if inserted:
        logger.warning(
            "Product identity bootstrap account created with the fixed default "
            "password (see documentation) — change it immediately on first login."
        )
    return inserted
