"""Shared database access.

The chat surface (`chat/session_store.py`) and the jobs surface
(`jobs/repositories/postgres_repo.py`, inherited) BOTH need PostgreSQL access
against the same ``otalon-clas`` database. The inherited jobs code uses
SQLAlchemy; the chat surface uses raw psycopg2 because the message payload is
a single JSONB column and an ORM adds no value.

This module exposes a single :class:`Database` helper that owns:

- one SQLAlchemy engine (consumed by the jobs surface)
- one psycopg2 connection pool (consumed by the chat surface)

Both point at the same DSN. They are deliberately separate handles so that
neither surface can starve the other.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator, Optional

import psycopg2
from loguru import logger
from psycopg2.extensions import connection as PgConnection
from psycopg2.pool import ThreadedConnectionPool


class Database:
    """Connection holder shared by chat and jobs surfaces."""

    def __init__(self, dsn: str, *, chat_pool_minconn: int = 1, chat_pool_maxconn: int = 8) -> None:
        if not dsn:
            raise ValueError("Database: dsn is required")
        self.dsn = dsn
        self._chat_pool: Optional[ThreadedConnectionPool] = None
        self._chat_pool_minconn = chat_pool_minconn
        self._chat_pool_maxconn = chat_pool_maxconn

    # --- chat-side: raw psycopg2 pool ----------------------------------

    def _ensure_chat_pool(self) -> ThreadedConnectionPool:
        if self._chat_pool is None:
            self._chat_pool = ThreadedConnectionPool(
                minconn=self._chat_pool_minconn,
                maxconn=self._chat_pool_maxconn,
                dsn=self.dsn,
            )
            logger.debug(
                "Database: chat psycopg2 pool initialised (min={}, max={})",
                self._chat_pool_minconn,
                self._chat_pool_maxconn,
            )
        return self._chat_pool

    @contextmanager
    def chat_connection(self) -> Iterator[PgConnection]:
        """Yield a pooled psycopg2 connection for the chat surface."""
        pool = self._ensure_chat_pool()
        conn = pool.getconn()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            pool.putconn(conn)

    # --- migrations: ad-hoc, non-pooled --------------------------------

    @contextmanager
    def admin_connection(self) -> Iterator[PgConnection]:
        """Yield a fresh non-pooled connection for migrations / one-shots."""
        conn = psycopg2.connect(self.dsn)
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def close(self) -> None:
        """Release pool resources at shutdown."""
        if self._chat_pool is not None:
            self._chat_pool.closeall()
            self._chat_pool = None
            logger.debug("Database: chat psycopg2 pool closed")
