"""Idempotent PostgreSQL schema bootstrap for product identities."""

from __future__ import annotations

from psycopg2.extras import RealDictCursor

from otalon_api.repositories.postgres_repo import PostgresRepository

USERS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id                  BIGSERIAL PRIMARY KEY,
    username            TEXT NOT NULL UNIQUE,
    password_hash       TEXT NOT NULL,
    role                TEXT NOT NULL CHECK (role IN ('admin','operator','viewer')),
    must_change_password BOOLEAN NOT NULL DEFAULT true,
    disabled            BOOLEAN NOT NULL DEFAULT false,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at       TIMESTAMPTZ
);
"""

SESSIONS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id      TEXT PRIMARY KEY,
    user_id         BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ,
    ip              TEXT,
    user_agent      TEXT
);
"""

DASHBOARD_USER_STATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS dashboard_user_state (
    user_id        BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    layout         JSONB,
    tour_completed JSONB,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
"""

IDENTITY_INDEXES_SQL = """
CREATE INDEX IF NOT EXISTS ix_sessions_user_id ON sessions (user_id);
CREATE INDEX IF NOT EXISTS ix_sessions_expires_at ON sessions (expires_at)
    WHERE revoked_at IS NULL;
"""


def ensure_identity_schema(postgres_repo: PostgresRepository) -> None:
    """Create product identity tables and indexes idempotently.

    Args:
        postgres_repo: Shared PostgreSQL repository backed by a connection pool.
    """
    with postgres_repo.connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SET statement_timeout = '30s'")
            cur.execute(USERS_TABLE_SQL)
            cur.execute(SESSIONS_TABLE_SQL)
            cur.execute(DASHBOARD_USER_STATE_TABLE_SQL)
            cur.execute(IDENTITY_INDEXES_SQL)
        conn.commit()
