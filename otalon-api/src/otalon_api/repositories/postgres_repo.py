"""PostgreSQL repository for metadata, anomaly, bounds, alarm, and device queries.

Wraps ``psycopg2`` with parameterized queries for SQL-injection-safe access
to the OTALON PostgreSQL database.  Uses a ``ThreadedConnectionPool``
for safe concurrent access from multiple threads.  Every public query
method returns ``list[dict]`` for easy downstream conversion to Pydantic
models.
"""

from __future__ import annotations

import json
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from time import perf_counter
from typing import Any, Iterator, List, Optional, Sequence

import pandas as pd
import psycopg2
import psycopg2.extensions
import psycopg2.extras
from loguru import logger
from otalon_common import calculate_bounds_correction
from psycopg2 import sql as psql
from psycopg2.pool import ThreadedConnectionPool


class BoundsCorrectionConflict(Exception):
    """Raised when a bounds correction's ``before`` snapshot is stale.

    Signals that the current locked bounds no longer match the snapshot the
    client previewed, so the correction must be rejected as a conflict-safe
    client error (HTTP 409) rather than silently overwriting newer state.
    """


class RhythmCorrectionConflict(Exception):
    """Raised when a rhythm correction's ``before_snapshot`` is stale.

    The frequency-profile counterpart of :class:`BoundsCorrectionConflict`:
    the locked ``frequency_profiles`` row no longer carries the override
    values the client previewed, so the correction is rejected as HTTP 409
    with neither the profile nor the audit history mutated.
    """


class FrequencyProfileNotFound(Exception):
    """Raised when a frequency correction targets a series without a profile.

    Corrections tune a learned cadence; a series the frequency monitor has
    never trained has nothing to tune, so this is a 404 rather than an
    implicit profile creation.
    """


FREQUENCY_NOTIFY_CHANNEL: str = "frequency_profile_changed"
"""PostgreSQL channel otalon-clas LISTENs on for profile invalidation.

Must match ``frequency_monitor.notify_channel`` in
``otalon-clas/config/config.json``; the payload shape
``{"module": ..., "series_id": ...}`` is what
``FrequencyProfileInvalidator._dispatch_payload`` parses.
"""


DB_TABLE_ALLOWLIST: frozenset[str] = frozenset(
    {
        "anomalies",
        "alarms",
        "bounds",
        "scan_results",
        "devices",
        "ports",
    }
)

DEFAULT_MIN_CONNECTIONS = 1
DEFAULT_MAX_CONNECTIONS = 20


class PostgresRepository:
    """Thread-safe wrapper around a psycopg2 connection pool.

    Uses ``ThreadedConnectionPool`` so that multiple threads (e.g.
    from FastAPI's thread-pool executor) can safely execute queries
    concurrently.  ``RealDictCursor`` is used so that all query
    results are returned as dictionaries keyed by column name.
    """

    def __init__(
        self,
        host: str,
        port: int,
        user: str,
        password: str,
        database: str,
        min_connections: int = DEFAULT_MIN_CONNECTIONS,
        max_connections: int = DEFAULT_MAX_CONNECTIONS,
    ) -> None:
        """Initialize the PostgreSQL repository with connection-pool settings.

        The pool is created lazily on first use so that construction
        never raises even when the database is temporarily unavailable.

        Args:
            host: PostgreSQL server hostname.
            port: PostgreSQL server port.
            user: Database user.
            password: Database password.
            database: Target database name.
            min_connections: Minimum number of pooled connections.
            max_connections: Maximum number of pooled connections.
        """
        self._dsn: dict[str, Any] = {
            "host": host,
            "port": port,
            "user": user,
            "password": password,
            "dbname": database,
        }
        self._pool: Optional[ThreadedConnectionPool] = None
        self._pool_lock = threading.Lock()
        self._min_conn = min_connections
        self._max_conn = max_connections
        logger.debug(
            "PostgresRepository initialized for {}:{}/{} (pool {}-{})",
            host,
            port,
            database,
            min_connections,
            max_connections,
        )

    def _get_pool(self) -> ThreadedConnectionPool:
        """Return a live connection pool, creating it if necessary.

        Uses a threading lock to prevent race conditions when multiple
        threads attempt to create the pool simultaneously.

        Returns:
            An open ``ThreadedConnectionPool``.

        Raises:
            psycopg2.Error: If the pool cannot be created.
        """
        if self._pool is None or self._pool.closed:
            with self._pool_lock:
                if self._pool is None or self._pool.closed:
                    self._pool = ThreadedConnectionPool(self._min_conn, self._max_conn, **self._dsn)
                    logger.debug("PostgresRepository: new connection pool established")
        return self._pool

    @contextmanager
    def connection(self) -> Iterator[Any]:
        """Yield a pooled connection with autocommit=False for multi-statement transactions.

        The caller is responsible for ``conn.commit()``. On exception the
        connection is rolled back and discarded; on normal exit it is
        returned to the pool. As defense-in-depth, a connection that a caller
        left mid-transaction on normal exit is rolled back before it re-enters
        the pool, so a forgotten ``commit()``/``rollback()`` (e.g. an early
        ``return`` after ``SELECT ... FOR UPDATE``) can never hand back an
        ``idle in transaction`` connection that pins a snapshot and exhausts
        the pool.
        """
        pool = self._get_pool()
        conn = pool.getconn()
        conn.autocommit = False
        try:
            yield conn
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            try:
                pool.putconn(conn, close=True)
            except Exception:
                pass
            raise
        else:
            self._reset_open_transaction(conn)
            pool.putconn(conn)

    @staticmethod
    def _reset_open_transaction(conn: Any) -> None:
        """Roll back a connection left mid-transaction on normal CM exit."""
        try:
            if conn.get_transaction_status() != psycopg2.extensions.TRANSACTION_STATUS_IDLE:
                conn.rollback()
        except Exception:
            logger.warning("PostgresRepository: failed to reset lingering transaction on pooled connection")

    def _execute_query(self, sql: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """Execute a parameterized SQL query and return rows as dicts.

        Borrows a connection from the pool, executes the query, and
        returns the connection afterwards.  Broken connections are
        discarded automatically.

        Args:
            sql: SQL query string with ``%(name)s`` placeholders.
            params: Parameter dict for placeholder substitution.

        Returns:
            List of row dictionaries.

        Raises:
            psycopg2.Error: On database errors after logging.
        """
        perf_start = perf_counter()
        pool = self._get_pool()
        conn = None
        try:
            conn = pool.getconn()
            conn.autocommit = True
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(sql, params)
                rows: list[dict[str, Any]] = [dict(row) for row in cur.fetchall()]
            duration_ms = round((perf_counter() - perf_start) * 1000.0, 3)
            logger.debug("PostgresRepository query OK: {} rows, {:.1f}ms", len(rows), duration_ms)
            return rows
        except psycopg2.Error as exc:
            duration_ms = round((perf_counter() - perf_start) * 1000.0, 3)
            logger.error(
                "PostgresRepository query FAILED ({:.1f}ms): {} | SQL: {}",
                duration_ms,
                exc,
                sql,
            )
            if conn is not None:
                try:
                    pool.putconn(conn, close=True)
                except Exception:
                    pass
                conn = None
            raise
        finally:
            if conn is not None:
                pool.putconn(conn)

    def _execute_command(self, sql: str, params: dict[str, Any] | None = None) -> None:
        """Execute a parameterized mutation without expecting result rows."""
        pool = self._get_pool()
        conn = None
        try:
            conn = pool.getconn()
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute(sql, params)
        except psycopg2.Error:
            if conn is not None:
                pool.putconn(conn, close=True)
                conn = None
            raise
        finally:
            if conn is not None:
                pool.putconn(conn)

    def _execute_query_with_timeout(
        self,
        sql: str,
        params: dict[str, Any] | None = None,
        timeout_seconds: int = 10,
    ) -> list[dict[str, Any]]:
        """Execute a query with a per-statement timeout to prevent runaway queries.

        Sets ``statement_timeout`` on the connection before executing the query
        and resets it afterwards.  The timeout is session-scoped and does not
        persist beyond this call.

        Args:
            sql: SQL query string with ``%(name)s`` placeholders.
            params: Parameter dict for placeholder substitution.
            timeout_seconds: Maximum execution time in seconds.

        Returns:
            List of row dictionaries.

        Raises:
            psycopg2.OperationalError: When the statement timeout is exceeded.
            psycopg2.Error: On other database errors after logging.
        """
        perf_start = perf_counter()
        pool = self._get_pool()
        conn = None
        rows: list[dict[str, Any]] = []
        try:
            conn = pool.getconn()
            conn.autocommit = True
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(f"SET statement_timeout = '{timeout_seconds}s'")
                cur.execute(sql, params)
                rows = [dict(row) for row in cur.fetchall()]
            duration_ms = round((perf_counter() - perf_start) * 1000.0, 3)
            logger.debug(
                "PostgresRepository query OK (timeout={}s): {} rows, {:.1f}ms",
                timeout_seconds,
                len(rows),
                duration_ms,
            )
            return rows
        except psycopg2.Error as exc:
            duration_ms = round((perf_counter() - perf_start) * 1000.0, 3)
            logger.error(
                "PostgresRepository query FAILED (timeout={}s, {:.1f}ms): {} | SQL: {}",
                timeout_seconds,
                duration_ms,
                exc,
                sql,
            )
            if conn is not None:
                try:
                    pool.putconn(conn, close=True)
                except Exception:
                    pass
                conn = None
            raise
        finally:
            if conn is not None:
                try:
                    with conn.cursor() as cur:
                        cur.execute("SET statement_timeout = 0")
                except Exception:
                    pass
                pool.putconn(conn)

    def _execute_update(self, sql: str, params: dict[str, Any] | None = None) -> int:
        """Execute a parameterized DML statement and return affected row count.

        Borrows a connection from the pool, executes the statement, and
        returns the connection afterwards.  Broken connections are
        discarded automatically.

        Args:
            sql: SQL statement with ``%(name)s`` placeholders.
            params: Parameter dict for placeholder substitution.

        Returns:
            Number of rows affected.

        Raises:
            psycopg2.Error: On database errors after logging.
        """
        perf_start = perf_counter()
        pool = self._get_pool()
        conn = None
        try:
            conn = pool.getconn()
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute(sql, params)
                rowcount = int(cur.rowcount) if cur.rowcount is not None else 0
            duration_ms = round((perf_counter() - perf_start) * 1000.0, 3)
            logger.debug(
                "PostgresRepository update OK: {} rows affected, {:.1f}ms",
                rowcount,
                duration_ms,
            )
            return rowcount
        except psycopg2.Error as exc:
            duration_ms = round((perf_counter() - perf_start) * 1000.0, 3)
            logger.error(
                "PostgresRepository update FAILED ({:.1f}ms): {} | SQL: {}",
                duration_ms,
                exc,
                sql,
            )
            if conn is not None:
                try:
                    pool.putconn(conn, close=True)
                except Exception:
                    pass
                conn = None
            raise
        finally:
            if conn is not None:
                pool.putconn(conn)

    def health_check(self) -> bool:
        """Check whether the PostgreSQL connection pool is alive.

        Returns:
            ``True`` if the database is reachable, ``False`` otherwise.
        """
        try:
            self._execute_query("SELECT 1")
            return True
        except Exception as exc:
            logger.error("PostgreSQL health check failed: {}", exc)
            return False

    def ensure_indexes(self) -> None:
        """Create performance indexes on alarms and anomalies if they do not exist.

        Indexes are created with ``IF NOT EXISTS`` so the method is safe
        to call on every startup.  A single connection is borrowed from
        the pool and all statements execute in one transaction block.

        Raises:
            psycopg2.Error: If any index creation statement fails.
        """
        index_statements = [
            "CREATE INDEX IF NOT EXISTS idx_alarms_start_ts ON alarms (start_timestamp DESC)",
            "CREATE INDEX IF NOT EXISTS idx_alarms_time_range ON alarms (start_timestamp, end_timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_alarms_module ON alarms (module)",
            "CREATE INDEX IF NOT EXISTS idx_anomalies_series_id ON anomalies (series_id)",
            "CREATE INDEX IF NOT EXISTS idx_anomalies_start_ts ON anomalies (start_ts DESC)",
        ]
        pool = self._get_pool()
        conn = pool.getconn()
        try:
            conn.autocommit = False
            with conn.cursor() as cur:
                for stmt in index_statements:
                    cur.execute(stmt)
            conn.commit()
            logger.info("PostgresRepository: performance indexes ensured")
        except psycopg2.Error as exc:
            conn.rollback()
            logger.error("PostgresRepository: failed to ensure indexes: {}", exc)
            try:
                pool.putconn(conn, close=True)
            except Exception:
                pass
            conn = None
            raise
        finally:
            if conn is not None:
                pool.putconn(conn)

    _BOUNDS_MODULE_ALIASES: dict[str, list[str]] = {
        "netcap": ["conn"],
        "conn": ["netcap"],
    }

    def snapshot_bounds_to_history(self, module: str, reason: str) -> int:
        """Copy all current ``bounds`` rows for *module* into ``bounds_history``.

        Atomic snapshot used by the boundary-retraining orchestrator before
        otalon-clas overwrites ``bounds`` during boot-training (per
        OpenSpec change ``add-chat-triggered-boundary-retraining`` § 1.4 /
        spec scenario "A pre-training snapshot row is written").

        Each ``bounds`` row is reproduced in ``bounds_history`` with
        ``action='snapshot'`` and the supplied *reason* (so the FP-remediation
        audit trail can distinguish pre-training snapshots from
        operator-driven mutations). Because the snapshot captures the
        productive envelope *as-is*, ``old_lower == new_lower`` and
        ``old_upper == new_upper`` for every snapshot row (a no-op payload
        that can be restored verbatim if training fails).

        Note: ``snapshot_bounds_to_history`` is module-aliased the same way
        as :meth:`query_bounds` — if *module* yields zero rows but an alias
        (``"conn"`` ↔ ``"netcap"``) has rows, the snapshot follows the
        alias so we never silently snapshot an empty set.

        Args:
            module: Detection module (e.g. ``"conn"`` or ``"netcap"``).
            reason: Human-readable note written verbatim to
                ``bounds_history.reason``; required and non-empty.

        Returns:
            Number of rows copied into ``bounds_history``.

        Raises:
            ValueError: If *reason* is empty.
            psycopg2.Error: On database errors.
        """
        if not reason or not reason.strip():
            raise ValueError("reason must be a non-empty string")

        effective_module = module
        rows = self._query_bounds_single(effective_module, None)
        if not rows:
            for alias in self._BOUNDS_MODULE_ALIASES.get(module, []):
                alias_rows = self._query_bounds_single(alias, None)
                if alias_rows:
                    effective_module = alias
                    rows = alias_rows
                    break

        if not rows:
            logger.warning(
                "snapshot_bounds_to_history: no bounds rows found for module={} "
                "(or its aliases); nothing to snapshot",
                module,
            )
            return 0

        insert_sql = (
            "INSERT INTO bounds_history "
            "(id, module, series_id, action, old_lower, old_upper, "
            " new_lower, new_upper, reason) "
            "VALUES (%(id)s, %(module)s, %(series_id)s, 'snapshot', "
            " %(old_lower)s, %(old_upper)s, %(new_lower)s, %(new_upper)s, "
            " %(reason)s)"
        )

        import uuid as _uuid

        pool = self._get_pool()
        conn = pool.getconn()
        inserted = 0
        try:
            conn.autocommit = False
            with conn.cursor() as cur:
                for row in rows:
                    lower = row.get("lower_bounds")
                    upper = row.get("upper_bounds")
                    lower_json = json.dumps(lower) if not isinstance(lower, str) else lower
                    upper_json = json.dumps(upper) if not isinstance(upper, str) else upper
                    cur.execute(
                        insert_sql,
                        {
                            "id": _uuid.uuid4().hex,
                            "module": effective_module,
                            "series_id": str(row.get("series_id", "")),
                            "old_lower": lower_json,
                            "old_upper": upper_json,
                            "new_lower": lower_json,
                            "new_upper": upper_json,
                            "reason": reason,
                        },
                    )
                    inserted += 1
            conn.commit()
            logger.info(
                "PostgresRepository: snapshot_bounds_to_history copied {} rows " "(module={}, reason={!r})",
                inserted,
                effective_module,
                reason,
            )
            return inserted
        except psycopg2.Error as exc:
            conn.rollback()
            logger.error(
                "PostgresRepository: snapshot_bounds_to_history FAILED " "(module={}, copied={}): {}",
                effective_module,
                inserted,
                exc,
            )
            try:
                pool.putconn(conn, close=True)
            except Exception:
                pass
            conn = None
            raise
        finally:
            if conn is not None:
                pool.putconn(conn)

    def query_bounds(self, module: str, series_id: str | None = None) -> list[dict[str, Any]]:
        """Load bounds for a module, optionally filtered by series_id.

        When no rows are found under the requested module, the method
        automatically falls back to well-known aliases. This ensures
        compatibility between legacy (``module='netcap'``) and
        otalon-clas (``module='conn'``) bounds.

        Args:
            module: Detection module name (e.g. ``"netcap"`` or ``"conn"``).
            series_id: Optional UCI / series identifier to filter by.

        Returns:
            List of bound row dicts with keys like ``module``, ``series_id``,
            ``lower_bounds``, ``upper_bounds``.
        """
        rows = self._query_bounds_single(module, series_id)
        if rows:
            return rows

        for alias in self._BOUNDS_MODULE_ALIASES.get(module, []):
            rows = self._query_bounds_single(alias, series_id)
            if rows:
                return rows

        return []

    def query_bound_violations(
        self,
        module: str,
        series_id: str,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> list[dict[str, Any]]:
        """Return persisted BoundViolation anomaly rows for one series.

        Affected features live in the real ``violated_features`` JSON column
        (and ``violated_feature_details`` JSON map), not a scalar ``feature``
        column. The optional ``[since, until)`` window is applied server-side
        as a strict half-open interval so an event exactly at ``until`` is
        excluded.
        """
        clauses = [
            "module = %(module)s",
            "series_id = %(series_id)s",
            "anomaly_type = 'BoundViolation'",
        ]
        params: dict[str, Any] = {"module": module, "series_id": series_id}
        if since is not None:
            clauses.append("start_ts >= %(since)s")
            params["since"] = since
        if until is not None:
            clauses.append("start_ts < %(until)s")
            params["until"] = until
        return self._execute_query(
            "SELECT start_ts AS event_ts, start_ts, end_ts, anomaly_type, "
            "violated_features, violated_feature_details FROM anomalies WHERE "
            + " AND ".join(clauses)
            + " ORDER BY start_ts DESC",
            params,
        )

    def preview_bounds_correction(
        self,
        module: str,
        series_id: str,
        action: str,
        lower_bounds: dict[str, Any],
        upper_bounds: dict[str, Any],
        before: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Calculate correction result without writing PostgreSQL state."""
        if action not in {"expand", "replace", "create"}:
            raise ValueError(f"unsupported bounds action: {action}")
        current = self.query_bounds(module, series_id)
        existing = current[0] if current else None
        old_lower = dict((existing or {}).get("lower_bounds") or {})
        old_upper = dict((existing or {}).get("upper_bounds") or {})
        if before is not None and before != {
            "lower_bounds": old_lower,
            "upper_bounds": old_upper,
        }:
            raise ValueError("before does not match current bounds")
        correction = calculate_bounds_correction(
            action,
            old_lower or None,
            old_upper or None,
            lower_bounds,
            upper_bounds,
            required_features=(
                (set(old_lower) | set(old_upper)) if action in {"expand", "replace"} and existing else None
            ),
        )
        return {
            "module": module,
            "series_id": series_id,
            "action": action,
            "prior": {
                "lower_bounds": old_lower or None,
                "upper_bounds": old_upper or None,
            },
            "lower_bounds": correction.lower,
            "upper_bounds": correction.upper,
        }

    def correct_bounds(
        self,
        module: str,
        series_id: str,
        action: str,
        lower_bounds: dict[str, Any],
        upper_bounds: dict[str, Any],
        reason: str,
        actor: str,
        before: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Apply bounds correction, history, and detector invalidation atomically.

        Successful writes queue exactly one PostgreSQL ``NOTIFY`` on channel
        ``cyberclas_bounds_invalidation`` with JSON payload
        ``{"module": "<module>", "series_id": "<series_id>"}``.
        PostgreSQL delivers that notification only when this transaction
        commits, so conflicts and rollbacks do not notify the detector.

        When ``before`` is supplied it is compared against the bounds row
        under ``SELECT ... FOR UPDATE`` inside the same transaction. A
        mismatch raises :class:`BoundsCorrectionConflict` and leaves all
        bounds, history, and audit state untouched, so a concurrent
        mutation between preview and apply cannot be overwritten by a
        stale snapshot.
        """
        reason = reason or ""
        if action not in {"expand", "replace", "create"}:
            raise ValueError(f"unsupported bounds action: {action}")
        import uuid

        pool = self._get_pool()
        conn = pool.getconn()
        failed = False
        try:
            conn.autocommit = False
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT lower_bounds, upper_bounds FROM bounds "
                    "WHERE module=%(module)s AND series_id=%(series_id)s FOR UPDATE",
                    {"module": module, "series_id": series_id},
                )
                existing = cur.fetchone()
                old_lower = dict(existing["lower_bounds"]) if existing else None
                old_upper = dict(existing["upper_bounds"]) if existing else None
                if before is not None and before != {
                    "lower_bounds": old_lower or {},
                    "upper_bounds": old_upper or {},
                }:
                    raise BoundsCorrectionConflict("bounds changed since preview; correction rejected as stale")
                correction = calculate_bounds_correction(
                    action,
                    old_lower,
                    old_upper,
                    lower_bounds,
                    upper_bounds,
                    required_features=(
                        (set(old_lower or {}) | set(old_upper or {}))
                        if action in {"expand", "replace"} and existing is not None
                        else None
                    ),
                )
                lower_bounds = correction.lower
                upper_bounds = correction.upper
                now = datetime.now(timezone.utc)
                if existing is None:
                    cur.execute(
                        "INSERT INTO bounds "
                        "(module, series_id, lower_bounds, upper_bounds, trained_at) "
                        "VALUES (%(module)s, %(series_id)s, %(lower)s::jsonb, "
                        "%(upper)s::jsonb, %(now)s)",
                        {
                            "module": module,
                            "series_id": series_id,
                            "lower": json.dumps(lower_bounds),
                            "upper": json.dumps(upper_bounds),
                            "now": now,
                        },
                    )
                else:
                    cur.execute(
                        "UPDATE bounds SET lower_bounds=%(lower)s::jsonb, "
                        "upper_bounds=%(upper)s::jsonb, trained_at=%(now)s "
                        "WHERE module=%(module)s AND series_id=%(series_id)s",
                        {
                            "module": module,
                            "series_id": series_id,
                            "lower": json.dumps(lower_bounds),
                            "upper": json.dumps(upper_bounds),
                            "now": now,
                        },
                    )
                history_id = uuid.uuid4().hex
                cur.execute(
                    "INSERT INTO bounds_history "
                    "(id,module,series_id,action,old_lower,old_upper,new_lower,"
                    "new_upper,reason,actor) VALUES (%(id)s,%(module)s,%(series_id)s,"
                    "%(action)s,%(old_lower)s::jsonb,%(old_upper)s::jsonb,"
                    "%(new_lower)s::jsonb,%(new_upper)s::jsonb,%(reason)s,%(actor)s)",
                    {
                        "id": history_id,
                        "module": module,
                        "series_id": series_id,
                        "action": action,
                        "old_lower": (json.dumps(old_lower) if old_lower is not None else None),
                        "old_upper": (json.dumps(old_upper) if old_upper is not None else None),
                        "new_lower": json.dumps(lower_bounds),
                        "new_upper": json.dumps(upper_bounds),
                        "reason": reason,
                        "actor": actor,
                    },
                )
                cur.execute(
                    "SELECT pg_notify(%(channel)s, %(payload)s)",
                    {
                        "channel": "cyberclas_bounds_invalidation",
                        "payload": json.dumps({"module": module, "series_id": series_id}),
                    },
                )
            conn.commit()
            return {
                "history_id": history_id,
                "module": module,
                "series_id": series_id,
                "action": action,
                "lower_bounds": lower_bounds,
                "upper_bounds": upper_bounds,
                "prior": {"lower_bounds": old_lower, "upper_bounds": old_upper},
            }
        except Exception:
            failed = True
            conn.rollback()
            raise
        finally:
            if failed:
                pool.putconn(conn, close=True)
            else:
                pool.putconn(conn)

    def _query_bounds_single(self, module: str, series_id: str | None) -> list[dict[str, Any]]:
        """Execute a bounds query for exactly one module name.

        Args:
            module: Detection module name.
            series_id: Optional series identifier filter.

        Returns:
            List of bound row dicts.
        """
        if series_id is not None:
            sql = """
                SELECT *
                FROM bounds
                WHERE module = %(module)s
                  AND series_id = %(series_id)s
            """
            params: dict[str, Any] = {"module": module, "series_id": series_id}
        else:
            sql = """
                SELECT *
                FROM bounds
                WHERE module = %(module)s
            """
            params = {"module": module}
        return self._execute_query(sql, params)

    def query_frequency_profiles(
        self,
        module: str,
        series_ids: Sequence[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Load frequency profiles for a module, optionally filtered by series.

        Unlike ``query_bounds`` this method does NOT apply the
        ``netcap``→``conn`` alias fallback: ``frequency_profiles`` is
        written exclusively by otalon-clas, which always uses the
        canonical module names, so a legacy alias here would silently
        return a different module's cadence.

        Args:
            module: Detection module name (``conn``, ``mac_traffic``,
                ``proto_traffic``).
            series_ids: Optional series filter. ``None`` returns the
                whole module; an empty sequence returns nothing.

        Returns:
            List of profile row dicts.
        """
        if series_ids is not None and len(series_ids) == 0:
            return []

        sql = """
            SELECT module, series_id, mean_interval, std_interval,
                   last_seen, trained_at,
                   tolerance_factor_override, absence_factor_override
            FROM frequency_profiles
            WHERE module = %(module)s
        """
        params: dict[str, Any] = {"module": module}
        if series_ids is not None:
            sql += " AND series_id = ANY(%(series_ids)s)"
            params["series_ids"] = list(series_ids)
        return self._execute_query(sql, params)

    def query_profiled_series_ids(self, series_ids: Sequence[str]) -> set[str]:
        """Return requested conn series having bounds or rhythm profiles."""
        if not series_ids:
            return set()
        sql = """
            SELECT series_id FROM bounds
            WHERE module = 'conn' AND series_id = ANY(%(series_ids)s)
            UNION
            SELECT series_id FROM frequency_profiles
            WHERE module = 'conn' AND series_id = ANY(%(series_ids)s)
        """
        rows = self._execute_query(sql, {"series_ids": list(series_ids)})
        return {str(row["series_id"]) for row in rows}

    def query_all_profiled_series_ids(self, module: str) -> set[str]:
        """Return every series with bounds or a frequency profile for a module."""
        sql = """
            SELECT series_id FROM bounds WHERE module = %(module)s
            UNION
            SELECT series_id FROM frequency_profiles WHERE module = %(module)s
        """
        rows = self._execute_query(sql, {"module": module})
        return {str(row["series_id"]) for row in rows}

    def query_open_frequency_anomaly(
        self,
        module: str,
        series_id: str,
    ) -> dict[str, Any] | None:
        """Return the most recent frequency/absence anomaly for one series.

        Used to report the detector's current verdict alongside the
        profile. Only the two frequency-monitor types are considered;
        bounds and ML verdicts are a different question and are already
        served by the anomalies endpoints.

        Args:
            module: Detection module name.
            series_id: Series identifier.

        Returns:
            The newest matching anomaly row, or ``None``.
        """
        sql = """
            SELECT anomaly_type, start_ts, end_ts, confidence
            FROM anomalies
            WHERE module = %(module)s
              AND series_id = %(series_id)s
              AND anomaly_type IN ('FrequencyAnomaly', 'AbsenceAnomaly')
            ORDER BY end_ts DESC
            LIMIT 1
        """
        rows = self._execute_query(sql, {"module": module, "series_id": series_id})
        return rows[0] if rows else None

    def query_frequency_profile_row(self, module: str, series_id: str) -> dict[str, Any] | None:
        """Return one ``frequency_profiles`` row, or ``None`` when untrained.

        Args:
            module: Detection module name.
            series_id: Series identifier.

        Returns:
            The profile row dict, or ``None`` if the series has no profile.
        """
        rows = self.query_frequency_profiles(module, [series_id])
        return rows[0] if rows else None

    def count_recent_absence_anomalies(
        self,
        module: str,
        series_ids: Sequence[str],
        since: datetime,
    ) -> dict[str, int]:
        """Count absence episodes per series from an inclusive start instant.

        Args:
            module: Detection module name.
            series_ids: Series identifiers to aggregate.
            since: Inclusive lower bound applied to ``start_ts``.

        Returns:
            Mapping from series identifier to episode count.
        """
        if not series_ids:
            return {}
        sql = """
            SELECT series_id, COUNT(*) AS absence_count
            FROM anomalies
            WHERE module = %(module)s
              AND anomaly_type = 'AbsenceAnomaly'
              AND start_ts >= %(since)s
              AND series_id = ANY(%(series_ids)s)
            GROUP BY series_id
        """
        rows = self._execute_query(
            sql,
            {"module": module, "since": since, "series_ids": list(series_ids)},
        )
        return {str(row["series_id"]): int(row["absence_count"]) for row in rows}

    def count_recent_frequency_anomalies(
        self,
        module: str,
        series_ids: Sequence[str],
        since: datetime,
    ) -> dict[str, int]:
        """Count frequency-anomaly episodes per series from an inclusive instant.

        Args:
            module: Detection module name.
            series_ids: Series identifiers to aggregate.
            since: Inclusive lower bound applied to ``start_ts``.

        Returns:
            Mapping from series identifier to episode count.
        """
        if not series_ids:
            return {}
        sql = """
            SELECT series_id, COUNT(*) AS frequency_count
            FROM anomalies
            WHERE module = %(module)s
              AND anomaly_type = 'FrequencyAnomaly'
              AND start_ts >= %(since)s
              AND series_id = ANY(%(series_ids)s)
            GROUP BY series_id
        """
        rows = self._execute_query(
            sql,
            {"module": module, "since": since, "series_ids": list(series_ids)},
        )
        return {str(row["series_id"]): int(row["frequency_count"]) for row in rows}

    def query_frequency_events(
        self,
        module: str,
        series_id: str,
        since: datetime,
    ) -> list[dict[str, Any]]:
        """Return persisted frequency/absence anomalies since an instant.

        These rows are the server-side evidence a rhythm suggestion is
        derived from. The window is a half-open ``[since, now)`` interval
        applied on ``start_ts`` so an event exactly at the boundary is
        included once.

        Args:
            module: Detection module name.
            series_id: Series identifier.
            since: Inclusive lower bound of the lookback window.

        Returns:
            Matching anomaly rows ordered oldest first.
        """
        sql = """
            SELECT anomaly_type, start_ts, end_ts, value, confidence
            FROM anomalies
            WHERE module = %(module)s
              AND series_id = %(series_id)s
              AND anomaly_type IN ('FrequencyAnomaly', 'AbsenceAnomaly')
              AND start_ts >= %(since)s
            ORDER BY start_ts ASC
        """
        return self._execute_query(sql, {"module": module, "series_id": series_id, "since": since})

    def query_recent_frequency_events(
        self,
        module: str,
        series_id: str,
        since: datetime | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Return the newest rhythm anomaly episodes for one series.

        Distinct from :meth:`query_frequency_events`, which is unbounded
        evidence for the suggestion arithmetic. This read backs an
        operator-facing timeline, so it is ordered newest first and hard
        bounded: a series with thousands of absence episodes must not
        turn a drawer open into a multi-megabyte response.

        ``since`` is optional on purpose. The Rhythm Review "All" range
        has no lower bound, and returning nothing for it would be a lie
        about a series that demonstrably had episodes.

        Args:
            module: Detection module name.
            series_id: Series identifier.
            since: Optional inclusive lower bound applied to ``start_ts``.
            limit: Maximum number of episodes to return.

        Returns:
            Matching anomaly rows ordered newest first.
        """
        clauses = [
            "module = %(module)s",
            "series_id = %(series_id)s",
            "anomaly_type IN ('FrequencyAnomaly', 'AbsenceAnomaly')",
        ]
        params: dict[str, Any] = {"module": module, "series_id": series_id, "limit": limit}
        if since is not None:
            clauses.append("start_ts >= %(since)s")
            params["since"] = since
        where_str = " AND ".join(clauses)
        sql = f"""
            SELECT anomaly_type, start_ts, end_ts, confidence
            FROM anomalies
            WHERE {where_str}
            ORDER BY start_ts DESC
            LIMIT %(limit)s
        """
        return self._execute_query(sql, params)

    def query_frequency_history(
        self,
        module: str,
        series_id: str,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        """Return the correction-audit rows for exactly one series.

        Scoped strictly to ``(module, series_id)``: the drawer's History
        tab must never surface another series' corrections.

        Ordered newest first, deliberately. The spec requirement
        (``openspec/changes/ui101-rhythm-review-tab/specs/
        api--frequency-profile-corrections/spec.md``) asks for
        "chronological order" without naming a direction, and reverse
        chronological is what an audit trail wants: the state an operator
        must reason about before correcting again is the *last* one, and
        ``LIMIT`` then keeps the most recent rows rather than the oldest.
        This also matches the sibling audit list
        (``operations_audit_repo.py``: ``ORDER BY at DESC``). The one
        ``ASC`` query there is a backfill import, where insertion order
        matters — a different job. Do not flip this without changing the
        drawer's timeline rendering too.

        Args:
            module: Detection module name.
            series_id: Series identifier.
            limit: Maximum number of rows to return.

        Returns:
            List of ``frequency_profile_history`` row dicts.
        """
        sql = """
            SELECT id, module, series_id, action, old_tolerance, new_tolerance,
                   old_absence, new_absence, reason, actor, changed_at
            FROM frequency_profile_history
            WHERE module = %(module)s AND series_id = %(series_id)s
            ORDER BY changed_at DESC
            LIMIT %(limit)s
        """
        return self._execute_query(
            sql,
            {"module": module, "series_id": series_id, "limit": max(1, int(limit))},
        )

    def correct_frequency_overrides(
        self,
        module: str,
        series_id: str,
        tolerance_override: float | None,
        absence_override: float | None,
        before_snapshot: dict[str, Any],
        reason: str,
        actor: str,
        action: str = "update",
    ) -> dict[str, Any]:
        """Apply override correction, audit row, and invalidation atomically.

        The profile row is locked with ``SELECT ... FOR UPDATE`` and its
        two override columns are compared against ``before_snapshot``
        inside the same transaction, so a writer that changed them
        between Preview and Apply produces a
        :class:`RhythmCorrectionConflict` instead of a silent overwrite.

        On success the transaction writes exactly three things: the two
        override columns, one ``frequency_profile_history`` row, and one
        queued ``pg_notify`` on
        :data:`FREQUENCY_NOTIFY_CHANNEL`. PostgreSQL delivers that
        notification only at commit, so a conflict or a rollback notifies
        nothing and the detector never reloads a state that was not
        persisted.

        Learned cadence columns (``mean_interval``, ``std_interval``,
        ``last_seen``, ``trained_at``) are deliberately untouched — this
        path corrects operator tuning, not training output.

        Args:
            module: Detection module name.
            series_id: Series identifier.
            tolerance_override: New ``tolerance_factor.override``; ``None``
                clears it back to the global default.
            absence_override: New ``absence_factor.override``; ``None``
                clears it back to the global default.
            before_snapshot: Mapping with the two override values as read
                by the immediately preceding Preview.
            reason: Non-empty audited operator reason.
            actor: Audited operator identity.
            action: History action label.

        Returns:
            Dict with the audit ``history_id``, the committed override
            values, the prior values, and ``notified``.

        Raises:
            FrequencyProfileNotFound: When the series carries no profile.
            RhythmCorrectionConflict: When the locked overrides differ from
                ``before_snapshot``.
        """
        import uuid

        pool = self._get_pool()
        conn = pool.getconn()
        failed = False
        try:
            conn.autocommit = False
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT tolerance_factor_override, absence_factor_override "
                    "FROM frequency_profiles "
                    "WHERE module=%(module)s AND series_id=%(series_id)s FOR UPDATE",
                    {"module": module, "series_id": series_id},
                )
                existing = cur.fetchone()
                if existing is None:
                    raise FrequencyProfileNotFound(f"no frequency profile for {module}:{series_id}")
                old_tolerance = _as_optional_float(existing["tolerance_factor_override"])
                old_absence = _as_optional_float(existing["absence_factor_override"])
                if not _snapshot_matches(before_snapshot, old_tolerance, old_absence):
                    raise RhythmCorrectionConflict(
                        "frequency profile changed since preview; correction rejected as stale"
                    )
                history_id = uuid.uuid4().hex
                cur.execute(
                    "UPDATE frequency_profiles SET tolerance_factor_override=%(tolerance)s, "
                    "absence_factor_override=%(absence)s "
                    "WHERE module=%(module)s AND series_id=%(series_id)s",
                    {
                        "module": module,
                        "series_id": series_id,
                        "tolerance": tolerance_override,
                        "absence": absence_override,
                    },
                )
                cur.execute(
                    "INSERT INTO frequency_profile_history "
                    "(id, module, series_id, action, old_tolerance, old_absence, "
                    "new_tolerance, new_absence, reason, actor, changed_at) "
                    "VALUES (%(id)s, %(module)s, %(series_id)s, %(action)s, "
                    "%(old_tolerance)s, %(old_absence)s, %(new_tolerance)s, "
                    "%(new_absence)s, %(reason)s, %(actor)s, %(now)s)",
                    {
                        "id": history_id,
                        "module": module,
                        "series_id": series_id,
                        "action": action,
                        "old_tolerance": old_tolerance,
                        "old_absence": old_absence,
                        "new_tolerance": tolerance_override,
                        "new_absence": absence_override,
                        "reason": reason,
                        "actor": actor,
                        "now": datetime.now(timezone.utc),
                    },
                )
                cur.execute(
                    "SELECT pg_notify(%(channel)s, %(payload)s)",
                    {
                        "channel": FREQUENCY_NOTIFY_CHANNEL,
                        "payload": json.dumps({"module": module, "series_id": series_id}),
                    },
                )
            conn.commit()
            return {
                "history_id": history_id,
                "module": module,
                "series_id": series_id,
                "action": action,
                "tolerance_factor_override": tolerance_override,
                "absence_factor_override": absence_override,
                "prior": {
                    "tolerance_factor_override": old_tolerance,
                    "absence_factor_override": old_absence,
                },
                "notified": True,
            }
        except Exception:
            failed = True
            conn.rollback()
            raise
        finally:
            if failed:
                pool.putconn(conn, close=True)
            else:
                pool.putconn(conn)

    def query_anomalies(
        self,
        module: str,
        series_id: str | None = None,
        time_range: tuple[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """Query anomaly intervals, optionally filtered by series and time.

        Args:
            module: Detection module name.
            series_id: Optional series/UCI identifier.
            time_range: Optional ``(start, stop)`` ISO-8601 timestamp tuple.

        Returns:
            List of anomaly row dicts ordered by ``start_ts`` ascending.
        """
        clauses: List[str] = ["module = %(module)s"]
        params: dict[str, Any] = {"module": module}

        if series_id is not None:
            clauses.append("series_id = %(series_id)s")
            params["series_id"] = series_id

        if time_range is not None:
            clauses.append("start_ts <= %(stop)s AND end_ts >= %(start)s")
            params["start"] = time_range[0]
            params["stop"] = time_range[1]

        where_str = " AND ".join(clauses)
        sql = f"SELECT * FROM anomalies WHERE {where_str} ORDER BY start_ts ASC"
        return self._execute_query(sql, params)

    def query_anomaly_groups(
        self,
        module: str | None = None,
        time_range: tuple[str, str] | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Query alarm groups with optional module and time-range filters.

        The ``anomaly_type_stats`` and ``series_ids`` JSON columns are
        automatically deserialized by psycopg2.

        Args:
            module: Optional module filter (e.g. ``"netcap"``).
            time_range: Optional ``(start, stop)`` ISO-8601 tuple.
            limit: Maximum number of groups to return (default 50).
            offset: Number of groups to skip for pagination (default 0).

        Returns:
            List of alarm group dicts ordered by ``start_timestamp`` descending.
        """
        clauses: List[str] = []
        params: dict[str, Any] = {"limit": limit, "offset": offset}

        if module is not None:
            clauses.append("module = %(module)s")
            params["module"] = module

        if time_range is not None:
            clauses.append("start_timestamp <= %(stop)s AND end_timestamp >= %(start)s")
            params["start"] = time_range[0]
            params["stop"] = time_range[1]

        where_str = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"""
            SELECT id, module, start_timestamp, end_timestamp, series_ids,
                   primary_type, confirmed, is_active, anomaly_type_stats, multi_type,
                   enrichment
            FROM alarms
            {where_str}
            ORDER BY start_timestamp DESC
            LIMIT %(limit)s
            OFFSET %(offset)s
        """
        rows = self._execute_query_with_timeout(sql, params, timeout_seconds=10)
        return self._deserialize_json_columns(rows)

    def count_anomaly_groups(
        self,
        module: str | None = None,
        time_range: tuple[str, str] | None = None,
    ) -> int:
        """Count total alarm groups matching the given filters (ignores limit/offset).

        Args:
            module: Optional module filter.
            time_range: Optional ``(start, stop)`` ISO-8601 tuple.

        Returns:
            Total number of matching alarm groups.
        """
        clauses: List[str] = []
        params: dict[str, Any] = {}

        if module is not None:
            clauses.append("module = %(module)s")
            params["module"] = module

        if time_range is not None:
            clauses.append("start_timestamp <= %(stop)s AND end_timestamp >= %(start)s")
            params["start"] = time_range[0]
            params["stop"] = time_range[1]

        where_str = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"SELECT COUNT(*) FROM alarms {where_str}"
        rows = self._execute_query_with_timeout(sql, params, timeout_seconds=10)
        return int(rows[0]["count"]) if rows else 0

    def query_anomaly_group_series(self, group_id: str) -> list[dict[str, Any]]:
        """Query individual anomaly records belonging to an alarm group.

        Matches anomalies whose ``series_id`` is contained in the alarm
        group's ``series_ids`` array and whose time range overlaps the
        alarm group's active window.

        Args:
            group_id: The alarm group UUID.

        Returns:
            List of anomaly dicts for the given group, ordered by ``start_ts``.
        """
        sql = """
            SELECT a.*
            FROM anomalies a
            JOIN alarms ag ON ag.id = %(group_id)s::uuid
            WHERE a.series_id = ANY(
                SELECT jsonb_array_elements_text(ag.series_ids::jsonb)
            )
            AND a.start_ts >= ag.start_timestamp
            AND a.start_ts <= COALESCE(ag.end_timestamp, NOW())
            ORDER BY a.start_ts ASC
        """
        return self._execute_query(sql, {"group_id": group_id})

    def query_alarm_details_since(self, since: str) -> list[dict[str, Any]]:
        """Query alarm groups with anomaly counts since a given timestamp.

        Anomaly counts are computed by matching anomalies whose
        ``series_id`` is contained in the alarm's ``series_ids`` array
        and whose start time falls within the alarm's active window.

        Args:
            since: ISO-8601 timestamp string.

        Returns:
            List of alarm group dicts augmented with ``anomaly_count``.
        """
        sql = """
            SELECT
                ag.*,
                (
                    SELECT COUNT(a.id)
                    FROM anomalies a
                    WHERE a.series_id = ANY(
                        SELECT jsonb_array_elements_text(ag.series_ids::jsonb)
                    )
                    AND a.start_ts >= ag.start_timestamp
                    AND a.start_ts <= COALESCE(ag.end_timestamp, NOW())
                ) AS anomaly_count
            FROM alarms ag
            WHERE ag.start_timestamp >= %(since)s
            ORDER BY ag.start_timestamp DESC
        """
        rows = self._execute_query(sql, {"since": since})
        return self._deserialize_json_columns(rows)

    def query_dashboard_kpis(self, since: str) -> dict[str, Any]:
        """Aggregate dashboard KPI values since a given timestamp.

        Alarm group counts are computed directly from the ``alarms``
        table.  Anomaly counts and affected series are derived via a
        correlated subquery that matches anomalies through the alarm's
        ``series_ids`` JSON array and time window overlap.

        To prevent runaway queries on large datasets, the anomaly
        subqueries are limited to the most recent 10,000 anomalies
        within the time window. When this limit is hit, a warning
        flag is set in the result.

        Args:
            since: ISO-8601 timestamp string.

        Returns:
            Dict with keys ``active_alarm_groups``, ``total_alarm_groups``,
            ``total_anomalies``, ``affected_series_count``, ``last_alarm_timestamp``,
            and ``anomaly_limit_reached`` (bool).
        """
        # Limit anomalies to prevent runaway queries
        max_anomalies = 10000
        sql = """
            WITH limited_anomalies AS (
                SELECT id, series_id, start_ts
                FROM anomalies
                WHERE start_ts >= %(since)s
                ORDER BY start_ts DESC
                LIMIT %(max_anomalies)s
            )
            SELECT
                COUNT(*) FILTER (WHERE ag.is_active = true) AS active_alarm_groups,
                COUNT(*) AS total_alarm_groups,
                COALESCE((
                    SELECT COUNT(DISTINCT a.id)
                    FROM limited_anomalies a
                    JOIN alarms ag2 ON a.series_id = ANY(
                        SELECT jsonb_array_elements_text(ag2.series_ids::jsonb)
                    )
                    AND a.start_ts >= ag2.start_timestamp
                    AND a.start_ts <= COALESCE(ag2.end_timestamp, NOW())
                    WHERE ag2.end_timestamp > %(since)s  -- API-069: overlap, not start-only
                ), 0) AS total_anomalies,
                COALESCE((
                    SELECT COUNT(DISTINCT a.series_id)
                    FROM limited_anomalies a
                    JOIN alarms ag2 ON a.series_id = ANY(
                        SELECT jsonb_array_elements_text(ag2.series_ids::jsonb)
                    )
                    AND a.start_ts >= ag2.start_timestamp
                    AND a.start_ts <= COALESCE(ag2.end_timestamp, NOW())
                    WHERE ag2.end_timestamp > %(since)s  -- API-069: overlap, not start-only
                ), 0) AS affected_series_count,
                MAX(ag.start_timestamp) AS last_alarm_timestamp,
                (SELECT COUNT(*) FROM limited_anomalies) >= %(max_anomalies)s AS anomaly_limit_reached
            FROM alarms ag
            WHERE ag.end_timestamp > %(since)s  -- API-069: overlap, not start-only
        """
        rows = self._execute_query(sql, {"since": since, "max_anomalies": max_anomalies})
        if rows:
            return dict(rows[0])
        return {
            "active_alarm_groups": 0,
            "total_alarm_groups": 0,
            "total_anomalies": 0,
            "affected_series_count": 0,
            "last_alarm_timestamp": None,
            "anomaly_limit_reached": False,
        }

    def get_anomaly_group_by_id(self, alarm_id: str) -> dict[str, Any] | None:
        """Fetch a single alarm group by its UUID.

        Args:
            alarm_id: The alarm group UUID.

        Returns:
            Alarm group dict, or ``None`` if not found.
        """
        sql = "SELECT * FROM alarms WHERE id = %(alarm_id)s LIMIT 1"
        rows = self._execute_query(sql, {"alarm_id": alarm_id})
        if not rows:
            return None
        deserialized = self._deserialize_json_columns(rows)
        return deserialized[0]

    def update_alarm_group_confirmed(self, alarm_id: str, confirmed: bool) -> bool:
        """Update the confirmed status of an alarm group.

        Args:
            alarm_id: The alarm group UUID.
            confirmed: New confirmed status.

        Returns:
            ``True`` if exactly one row was updated.
        """
        sql = "UPDATE alarms SET confirmed = %(confirmed)s WHERE id = %(alarm_id)s"
        rowcount = self._execute_update(sql, {"confirmed": confirmed, "alarm_id": alarm_id})
        return rowcount == 1

    def update_alarm_group_primary_type(self, alarm_id: str, primary_type: str) -> bool:
        """Override the ``primary_type`` of an alarm group.

        Used by the *Adopt Subagent Classification* operator action: the
        operator can replace the supervised-ML attack-method label with the
        zero-shot LLM subagent's Step-1 ``technical_method``.

        ``primary_type`` is stored as ``json``; we wrap the string in a JSON
        string literal so the value remains a single-type alarm. ``multi_type``
        is set to ``false`` because adoption replaces the multi-label set
        with one operator-confirmed label.

        Args:
            alarm_id: The alarm group ID.
            primary_type: New attack-method label, free-form string.

        Returns:
            ``True`` if exactly one row was updated.
        """
        sql = (
            "UPDATE alarms " "SET primary_type = %(primary_type)s::json, multi_type = FALSE " "WHERE id = %(alarm_id)s"
        )
        rowcount = self._execute_update(
            sql,
            {
                "primary_type": json.dumps(primary_type),
                "alarm_id": alarm_id,
            },
        )
        return rowcount == 1

    def query_device_count(self) -> int:
        """Count distinct devices from the current inventory tables.

        Returns:
            Number of known devices, or 0 if no compatible table exists.
        """
        try:
            rows = self._execute_query("SELECT COUNT(*) AS cnt FROM devices")
            return int(rows[0]["cnt"]) if rows else 0
        except psycopg2.Error:
            try:
                rows = self._execute_query("SELECT COUNT(DISTINCT ip_address) AS cnt FROM scan_results")
                return int(rows[0]["cnt"]) if rows else 0
            except psycopg2.Error:
                return 0

    def query_connection_count(self) -> int:
        """Count distinct connections (UCIs) from bounds.

        Returns:
            Number of unique series_id values, or 0 on error.
        """
        try:
            rows = self._execute_query("SELECT COUNT(DISTINCT series_id) AS cnt FROM bounds")
            return int(rows[0]["cnt"]) if rows else 0
        except psycopg2.Error:
            return 0

    def query_vulnerability_summary(self) -> dict[str, Any]:
        """Aggregate vulnerability observation data for the dashboard widget.

        Returns:
            Dict with keys ``affected_device_count``, ``total_cve_count``,
            ``severity_breakdown``, and ``top_cves``.
        """
        try:
            total_row = self._execute_query(
                "SELECT COUNT(DISTINCT device_id) AS affected_devices, COUNT(*) AS total_cves "
                "FROM vulnerability_observations"
            )
            total = total_row[0] if total_row else {"affected_devices": 0, "total_cves": 0}

            severity_rows = self._execute_query(
                "SELECT severity, COUNT(*) AS cnt FROM vulnerability_observations "
                "GROUP BY severity ORDER BY cnt DESC"
            )
            severity_breakdown: dict[str, int] = {}
            for row in severity_rows:
                sev = row.get("severity") or "unknown"
                severity_breakdown[str(sev)] = int(row.get("cnt", 0) or 0)

            top_rows = self._execute_query(
                "SELECT vuln_id, severity, COUNT(*) AS cnt FROM vulnerability_observations "
                "GROUP BY vuln_id, severity ORDER BY cnt DESC, severity DESC LIMIT 5"
            )
            top_cves = [
                {
                    "vuln_id": str(row.get("vuln_id", "")),
                    "severity": str(row.get("severity", "") or "unknown"),
                    "count": int(row.get("cnt", 0) or 0),
                }
                for row in top_rows
            ]

            return {
                "affected_device_count": int(total.get("affected_devices", 0) or 0),
                "total_cve_count": int(total.get("total_cves", 0) or 0),
                "severity_breakdown": severity_breakdown,
                "top_cves": top_cves,
            }
        except psycopg2.Error:
            return {
                "affected_device_count": 0,
                "total_cve_count": 0,
                "severity_breakdown": {},
                "top_cves": [],
            }

    def query_last_anomaly_time(self) -> datetime | None:
        """Return the most recent ``start_ts`` timestamp in ``anomalies``.

        Returns:
            A timezone-aware UTC datetime, or ``None`` when no anomalies
            exist or the query fails.
        """
        query = "SELECT MAX(start_ts) AS last_cycle FROM anomalies"
        perf_start = perf_counter()
        try:
            rows = self._execute_query(query)
            if not rows or rows[0].get("last_cycle") is None:
                return None
            ts = rows[0]["last_cycle"]
            if isinstance(ts, datetime):
                if ts.tzinfo is None:
                    return ts.replace(tzinfo=timezone.utc)
                return ts
            dt = pd.to_datetime(ts)
            if dt.tz is None:
                dt = dt.tz_localize("UTC")
            return dt.to_pydatetime()  # type: ignore[no-any-return]
        except psycopg2.Error as exc:
            duration_ms = round((perf_counter() - perf_start) * 1000.0, 3)
            logger.warning(
                "query_last_anomaly_time FAILED ({:.1f}ms): {} | SQL: {}",
                duration_ms,
                exc,
                query,
            )
            return None

    def query_recent_anomaly_series_count(self, since: datetime, until: datetime) -> int | None:
        """Count distinct ``series_id`` values in a recent anomaly window.

        Args:
            since: Inclusive window start (``start_ts >= since``).
            until: Inclusive window end (``start_ts <= until``).

        Returns:
            Distinct series count, or ``None`` on query failure.
        """
        query = (
            "SELECT COUNT(DISTINCT series_id) AS cnt FROM anomalies "
            "WHERE start_ts >= %(since)s AND start_ts <= %(until)s"
        )
        perf_start = perf_counter()
        try:
            rows = self._execute_query(query, {"since": since, "until": until})
            if not rows:
                return None
            return int(rows[0].get("cnt") or 0)
        except psycopg2.Error as exc:
            duration_ms = round((perf_counter() - perf_start) * 1000.0, 3)
            logger.warning(
                "query_recent_anomaly_series_count FAILED ({:.1f}ms): {} | SQL: {}",
                duration_ms,
                exc,
                query,
            )
            return None

    def close(self) -> None:
        """Close all connections in the pool."""
        try:
            if self._pool and not self._pool.closed:
                self._pool.closeall()
                logger.debug("PostgresRepository: connection pool closed")
        except Exception:
            logger.warning("Failed to close PostgreSQL connection pool", exc_info=True)

    def query_devices(
        self,
        limit: int | None = None,
        offset: int | None = None,
    ) -> list[dict[str, Any]]:
        """Load device rows from the ``devices`` table.

        Args:
            limit: Maximum number of rows to return.  ``None`` returns all.
            offset: Row offset for pagination.  ``None`` starts at the beginning.

        Returns:
            List of device row dicts.
        """
        sql = "SELECT * FROM devices ORDER BY id ASC"
        params: dict[str, Any] = {}
        if limit is not None:
            sql += " LIMIT %(limit)s"
            params["limit"] = limit
        if offset is not None:
            sql += " OFFSET %(offset)s"
            params["offset"] = offset
        return self._execute_query(sql, params or None)

    def query_device_by_id(self, device_id: int) -> dict[str, Any] | None:
        """Fetch a single device row by its primary key.

        Args:
            device_id: The device ``id``.

        Returns:
            Device dict, or ``None`` if not found.
        """
        rows = self._execute_query(
            "SELECT * FROM devices WHERE id = %(device_id)s LIMIT 1",
            {"device_id": device_id},
        )
        return rows[0] if rows else None

    def query_network_interfaces_for_devices(self, device_ids: list[int]) -> dict[int, list[dict[str, Any]]]:
        """Fetch all network interfaces for a list of device IDs in one query.

        Args:
            device_ids: List of device primary keys.

        Returns:
            Dict mapping each device ID to its list of interface row dicts.
            Devices with no interfaces map to an empty list.
        """
        if not device_ids:
            return {}
        # F-01: ``open_ports_summary`` jsonb cache was dropped. The
        # aggregated array is now served by ``network_interface_ports_view``
        # — see :meth:`query_network_interface_ports_view`.
        sql = (
            "SELECT id, device_id, mac_address, ipv4_address, ipv6_address, "
            "subnet, last_scan_at, notes, source "
            "FROM network_interfaces WHERE device_id = ANY(%(ids)s) "
            "ORDER BY device_id ASC, id ASC"
        )
        rows = self._execute_query(sql, {"ids": device_ids})
        result: dict[int, list[dict[str, Any]]] = {dev_id: [] for dev_id in device_ids}
        for row in rows:
            dev_id = row.get("device_id")
            if dev_id is None:
                continue
            result.setdefault(int(dev_id), []).append(row)
        return result

    def query_device_topology_view(self, device_ids: Sequence[int]) -> dict[int, list[dict[str, Any]]]:
        """Read aggregated active vulnerabilities per device from the view.

        ``device_topology_view`` (created by F-01 migration
        ``0001_initial_view_and_upserts``) emits one row per device with
        a ``vulnerabilities`` jsonb array filtered to ``status='active'``.
        This helper translates the result into a ``{device_id: [...]}``
        lookup so :class:`TopologyService` can populate per-device
        ``vulnerabilities`` fields without re-aggregating in Python.

        Args:
            device_ids: List of device primary keys to fetch.

        Returns:
            Dict mapping device IDs to their ``vulnerabilities`` array
            (always a list — never ``None``). Devices with zero active
            CVEs map to ``[]``.
        """
        if not device_ids:
            return {}
        sql = "SELECT id, vulnerabilities FROM device_topology_view " "WHERE id = ANY(%(ids)s)"
        rows = self._execute_query(sql, {"ids": list(device_ids)})
        result: dict[int, list[dict[str, Any]]] = {int(d): [] for d in device_ids}
        for row in rows:
            dev_id = row.get("id")
            if dev_id is None:
                continue
            vulns = row.get("vulnerabilities") or []
            if isinstance(vulns, list):
                result[int(dev_id)] = vulns
        return result

    def query_network_interface_ports_view(
        self,
        interface_ids: Sequence[int],
    ) -> dict[int, list[dict[str, Any]]]:
        """Read aggregated open-port summaries per interface from the view.

        ``network_interface_ports_view`` (created by F-01 migration
        ``0001_initial_view_and_upserts``) emits one row per interface
        with an ``open_ports_summary`` jsonb array aggregated from
        ``service_observations``.

        Args:
            interface_ids: List of interface primary keys to fetch.

        Returns:
            Dict mapping interface IDs to the open-ports array.
            Interfaces with no observations map to ``[]``.
        """
        if not interface_ids:
            return {}
        sql = (
            "SELECT interface_id, open_ports_summary FROM network_interface_ports_view "
            "WHERE interface_id = ANY(%(ids)s)"
        )
        rows = self._execute_query(sql, {"ids": list(interface_ids)})
        result: dict[int, list[dict[str, Any]]] = {int(i): [] for i in interface_ids}
        for row in rows:
            iface_id = row.get("interface_id")
            if iface_id is None:
                continue
            ports = row.get("open_ports_summary") or []
            if isinstance(ports, list):
                result[int(iface_id)] = ports
        return result

    def query_devices_total_count(self) -> int:
        """Return the total number of rows in the ``devices`` table.

        Used by paginated list endpoints so the UI can render a correct
        total irrespective of the current page slice.
        """
        rows = self._execute_query("SELECT COUNT(*) AS cnt FROM devices", None)
        if not rows:
            return 0
        return int(rows[0].get("cnt", 0) or 0)

    def query_passive_discovery_summary(self) -> dict[str, Any]:
        """Aggregate persisted passive-discovery inventory from PostgreSQL.

        Reads the ``network_interfaces`` rows tagged ``source='passive'``
        (written by the ``otalon-scan-passive-seeder`` container) and
        returns a single aggregate row describing the observed passive
        inventory. This is a pure read of already-persisted producer
        facts — it never inspects the seeder process, container health,
        or generic API liveness.

        Returns:
            Dict with ``observed_interface_count`` (passive interface
            rows), ``observed_asset_count`` (distinct devices carrying a
            passive interface), ``latest_seen_at`` (most recent
            ``last_seen_passive_at``) and ``first_seen_at`` (earliest
            ``first_seen_passive_at``). Timestamps are returned as
            timezone-aware ``datetime`` or ``None`` when no passive rows
            exist.
        """
        sql = (
            "SELECT "
            "COUNT(*) AS observed_interface_count, "
            "COUNT(DISTINCT device_id) AS observed_asset_count, "
            "MAX(last_seen_passive_at) AS latest_seen_at, "
            "MIN(first_seen_passive_at) AS first_seen_at "
            "FROM network_interfaces WHERE source = 'passive'"
        )
        rows = self._execute_query(sql, None)
        if not rows:
            return {
                "observed_interface_count": 0,
                "observed_asset_count": 0,
                "latest_seen_at": None,
                "first_seen_at": None,
            }
        row = rows[0]
        return {
            "observed_interface_count": int(row.get("observed_interface_count", 0) or 0),
            "observed_asset_count": int(row.get("observed_asset_count", 0) or 0),
            "latest_seen_at": row.get("latest_seen_at"),
            "first_seen_at": row.get("first_seen_at"),
        }

    def truncate_table(self, table_name: str, cascade: bool = False) -> None:
        """Truncate a table, restricted to the configured allowlist.

        Uses ``psycopg2.sql.Identifier`` for safe SQL-identifier escaping.

        Args:
            table_name: Name of the table to truncate.
            cascade: Whether to add ``CASCADE``.

        Raises:
            ValueError: If *table_name* is not in :data:`DB_TABLE_ALLOWLIST`.
            psycopg2.Error: On database errors.
        """
        if table_name not in DB_TABLE_ALLOWLIST:
            raise ValueError(f"Table '{table_name}' is not in the allowed table list: {sorted(DB_TABLE_ALLOWLIST)}")
        stmt = psql.SQL("TRUNCATE TABLE {}").format(psql.Identifier(table_name))
        if cascade:
            stmt = psql.SQL("TRUNCATE TABLE {} CASCADE").format(psql.Identifier(table_name))
        perf_start = perf_counter()
        pool = self._get_pool()
        conn = pool.getconn()
        try:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute(stmt)
            duration_ms = round((perf_counter() - perf_start) * 1000.0, 3)
            logger.info(
                "PostgresRepository TRUNCATE '{}' OK ({:.1f}ms)",
                table_name,
                duration_ms,
            )
        except psycopg2.Error as exc:
            duration_ms = round((perf_counter() - perf_start) * 1000.0, 3)
            logger.error(
                "PostgresRepository TRUNCATE '{}' FAILED ({:.1f}ms): {}",
                table_name,
                duration_ms,
                exc,
            )
            try:
                pool.putconn(conn, close=True)
            except Exception:
                pass
            conn = None
            raise
        finally:
            if conn is not None:
                pool.putconn(conn)

    def delete_all_rows(self, table_name: str) -> int:
        """Delete all rows from a table, restricted to the configured allowlist.

        Uses ``psycopg2.sql.Identifier`` for safe SQL-identifier escaping.

        Args:
            table_name: Name of the table to delete from.

        Returns:
            Number of deleted rows.

        Raises:
            ValueError: If *table_name* is not in :data:`DB_TABLE_ALLOWLIST`.
            psycopg2.Error: On database errors.
        """
        if table_name not in DB_TABLE_ALLOWLIST:
            raise ValueError(f"Table '{table_name}' is not in the allowed table list: {sorted(DB_TABLE_ALLOWLIST)}")
        stmt = psql.SQL("DELETE FROM {}").format(psql.Identifier(table_name))
        perf_start = perf_counter()
        pool = self._get_pool()
        conn = pool.getconn()
        try:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute(stmt)
                rowcount = int(cur.rowcount) if cur.rowcount is not None else 0
            duration_ms = round((perf_counter() - perf_start) * 1000.0, 3)
            logger.info(
                "PostgresRepository DELETE FROM '{}': {} rows ({:.1f}ms)",
                table_name,
                rowcount,
                duration_ms,
            )
            return rowcount
        except psycopg2.Error as exc:
            duration_ms = round((perf_counter() - perf_start) * 1000.0, 3)
            logger.error(
                "PostgresRepository DELETE FROM '{}' FAILED ({:.1f}ms): {}",
                table_name,
                duration_ms,
                exc,
            )
            try:
                pool.putconn(conn, close=True)
            except Exception:
                pass
            conn = None
            raise
        finally:
            if conn is not None:
                pool.putconn(conn)

    def delete_all_rows_batch(self, table_names: tuple[str, ...]) -> dict[str, int]:
        """Delete allowlisted tables in one transaction, rolling back on error."""
        if any(table not in DB_TABLE_ALLOWLIST for table in table_names):
            raise ValueError("Batch contains a table outside the allowed table list")
        pool = self._get_pool()
        conn = pool.getconn()
        try:
            conn.autocommit = False
            deleted: dict[str, int] = {}
            with conn.cursor() as cur:
                for table_name in table_names:
                    cur.execute(psql.SQL("DELETE FROM {}").format(psql.Identifier(table_name)))
                    deleted[table_name] = int(cur.rowcount or 0)
            conn.commit()
            return deleted
        except Exception:
            conn.rollback()
            raise
        finally:
            pool.putconn(conn)

    @staticmethod
    def _deserialize_json_columns(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Ensure JSON/JSONB columns are deserialized to Python objects.

        psycopg2 normally handles JSONB automatically, but text-typed JSON
        columns may arrive as strings.  This method normalizes both cases.

        Args:
            rows: List of row dicts from a query.

        Returns:
            The same list with ``anomaly_type_stats`` and ``series_ids``
            deserialized if they were strings.
        """
        json_fields = ("anomaly_type_stats", "series_ids", "enrichment")
        for row in rows:
            for field in json_fields:
                val = row.get(field)
                if isinstance(val, str):
                    try:
                        row[field] = json.loads(val)
                    except (json.JSONDecodeError, TypeError):
                        pass
        return rows


def _as_optional_float(value: Any) -> float | None:
    """Coerce a nullable DB numeric to ``float | None``.

    Args:
        value: Raw column value (``None``, ``Decimal``, ``float``, ...).

    Returns:
        The float value, or ``None`` when the column is NULL or unusable.
    """
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _snapshot_matches(
    snapshot: dict[str, Any],
    old_tolerance: float | None,
    old_absence: float | None,
) -> bool:
    """Compare a client ``before_snapshot`` against the locked override state.

    Both override fields participate; a missing key in the snapshot is
    read as ``None`` so an omitted field cannot silently match any
    persisted value.

    Args:
        snapshot: Client-supplied before-state.
        old_tolerance: Locked ``tolerance_factor_override``.
        old_absence: Locked ``absence_factor_override``.

    Returns:
        ``True`` when the snapshot matches the locked row exactly.
    """
    claimed_tolerance = _as_optional_float(snapshot.get("tolerance_factor_override"))
    claimed_absence = _as_optional_float(snapshot.get("absence_factor_override"))
    return claimed_tolerance == old_tolerance and claimed_absence == old_absence
