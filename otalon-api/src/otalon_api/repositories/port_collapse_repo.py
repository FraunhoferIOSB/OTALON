"""Read-only repository for port-collapse rules from PostgreSQL.

Provides cached access to the ``port_collapse_rules`` table written by
otalon-clas during training.  Uses ``psycopg2`` directly
(consistent with ``postgres_repo.py``) and ``cachetools.TTLCache`` for
in-memory caching with a 120-second TTL.
"""

from __future__ import annotations

from typing import Optional, cast

import polars as pl
import psycopg2
import psycopg2.extras
from cachetools import TTLCache
from loguru import logger

_RULES_QUERY = """\
SELECT src_mac, dst_mac, vlan, ip_proto, src_ip, dst_ip, protocols,
       normalized_uci, wildcard_src_port, wildcard_dst_port, bucket_seconds
FROM port_collapse_rules WHERE module = %s
"""

_DEFAULT_TTL = 120
_DEFAULT_MAXSIZE = 16
_SENTINEL = object()


class PortCollapseRepository:
    """Cached, read-only access to port-collapse rules in PostgreSQL.

    Rules are loaded once per module and cached for ``ttl`` seconds.
    The repository gracefully handles missing tables (fresh databases)
    by returning ``None`` so callers can fall back to stateless
    aggregation.
    """

    def __init__(self, dsn: str, ttl: int = _DEFAULT_TTL) -> None:
        """Initialize the port-collapse repository.

        Args:
            dsn: PostgreSQL connection string (libpq-style).
            ttl: Cache time-to-live in seconds.
        """
        self._dsn = dsn
        self._cache: TTLCache[str, Optional[pl.DataFrame]] = TTLCache(maxsize=_DEFAULT_MAXSIZE, ttl=ttl)

    def _connect(self) -> psycopg2.extensions.connection:
        """Open a new psycopg2 connection.

        Returns:
            A psycopg2 connection object.
        """
        return psycopg2.connect(self._dsn)

    def get_rules(self, module: str) -> Optional[pl.DataFrame]:
        """Load port-collapse rules for a given module.

        Returns a Polars DataFrame compatible with
        ``otalon_common.connection.rule_engine.apply_port_rules()``.
        Results are cached by module name with TTL-based expiry.

        Args:
            module: The module name (e.g. ``"conn"``).

        Returns:
            A Polars DataFrame with rule columns, or ``None`` if no
            rules exist or the table is missing.
        """
        cached = self._cache.get(module, _SENTINEL)
        if cached is not _SENTINEL:
            return cast(Optional[pl.DataFrame], cached)

        try:
            result = self._fetch_rules(module)
        except (psycopg2.errors.UndefinedTable, psycopg2.ProgrammingError):
            logger.warning("port_collapse_rules table not found — returning None")
            self._cache[module] = None
            return None
        except psycopg2.Error:
            logger.exception("Failed to load port-collapse rules for module={}", module)
            return None

        self._cache[module] = result
        return result

    def _fetch_rules(self, module: str) -> Optional[pl.DataFrame]:
        """Execute the rules query and convert to a Polars DataFrame.

        Args:
            module: The module name to query.

        Returns:
            A Polars DataFrame, or ``None`` if no rows match.
        """
        conn = self._connect()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(_RULES_QUERY, (module,))
                rows = cur.fetchall()
        finally:
            conn.close()

        if not rows:
            return None

        return pl.DataFrame([dict(row) for row in rows])

    def get_normalized_ucis(self, module: str) -> list[str]:
        """Return a sorted list of unique normalized UCI strings from rules.

        Useful for topology/station-list endpoints that need the
        canonical UCI set without loading the full rules DataFrame.

        Args:
            module: The module name (e.g. ``"conn"``).

        Returns:
            A sorted list of distinct normalized UCI strings, or an
            empty list if no rules exist.
        """
        rules = self.get_rules(module)
        if rules is None:
            return []

        ucis = rules["normalized_uci"].unique().to_list()
        return sorted(ucis)

    def invalidate_cache(self, module: str | None = None) -> None:
        """Clear cached rules.

        Args:
            module: Module name to invalidate, or ``None`` to clear
                all cached modules.
        """
        if module is None:
            self._cache.clear()
        else:
            self._cache.pop(module, None)
