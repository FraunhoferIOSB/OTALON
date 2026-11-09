# src/repositories/postgres_repo.py
from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
from loguru import logger
from otalon_common import calculate_bounds_correction
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker

VERBOSE = False

_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

READABLE_TABLES: frozenset[str] = frozenset(
    {
        "alarms",
        "anomalies",
        "anomaly_suppression",
        "bounds",
        "bounds_history",
        "devices",
        "frequency_profiles",
        "frequency_profile_history",
        "network_interfaces",
        "port_collapse_rules",
        "retrain_jobs",
        "runtime_config",
        "service_observations",
        "vulnerability_observations",
    }
)
"""Tables that the read-only ``query_table`` helper may target.

The MCP tool surface is driven by an LLM, so the table name must never be
free-form: an allow-list is the only thing standing between a crafted tool
argument and an arbitrary-table read (audit MCP-01).
"""


def _require_identifier(value: str, kind: str) -> str:
    """Return ``value`` when it is a bare SQL identifier, else raise.

    Args:
        value: Candidate identifier (table or column name).
        kind: Human-readable label used in the error message.

    Returns:
        The validated identifier, unchanged.

    Raises:
        ValueError: When ``value`` is not a plain ``[A-Za-z_][A-Za-z0-9_]*``
            identifier and therefore cannot be safely inlined into SQL.
    """
    candidate = str(value or "").strip()
    if not _IDENTIFIER_RE.match(candidate):
        raise ValueError(f"invalid {kind}: {value!r}")
    return candidate


def _is_sqlite(engine: Engine) -> bool:
    """Return True if the SQLAlchemy engine is backed by SQLite."""
    return engine.dialect.name == "sqlite"


def _json_param(value: Any) -> Any:
    """Coerce a JSON-able value for parameterized SQL across dialects.

    SQLAlchemy's psycopg2 driver accepts dicts directly for JSON columns;
    SQLite (used in tests) requires a serialised JSON string. Encoding
    as JSON on both sides keeps the call sites uniform.
    """
    if value is None:
        return None
    return json.dumps(value)


def _json_load(value: Any) -> Dict[str, Any]:
    """Decode a JSON column value into a plain Python dict.

    Tolerates pre-decoded dicts (psycopg2 path) and JSON-encoded strings
    (SQLite path). Non-dict payloads collapse to an empty dict.
    """
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8")
    try:
        decoded = json.loads(value)
    except (TypeError, ValueError):
        return {}
    return decoded if isinstance(decoded, dict) else {}


class PostgresRepo:
    def __init__(self, dsn: str) -> None:
        self.dsn = dsn
        self.engine = create_engine(self.dsn)
        self._Session = sessionmaker(bind=self.engine)

    def list_tables(self) -> List[str]:
        inspector = inspect(self.engine)
        return inspector.get_table_names()

    def list_columns(self, table: str) -> List[str]:
        inspector = inspect(self.engine)
        col_ret = [col["name"] for col in inspector.get_columns(table)]
        logger.debug(f"Read {table} from PostgresDB - received: {col_ret}")
        return col_ret

    def query_table(
        self,
        table: str,
        columns: Optional[List[str]] = None,
        where: Optional[str] = None,
        params: Optional[Dict[str, Any]] = None,
        limit: Optional[int] = None,
    ) -> pd.DataFrame:
        """Run an allow-listed, parameterised SELECT and return a DataFrame.

        ``table`` must be a member of :data:`READABLE_TABLES` and every
        entry of ``columns`` must be a bare SQL identifier. ``where`` is a
        SQL fragment that may ONLY reference bind parameters (``:name``)
        for its values — callers pass the values through ``params``, never
        by string interpolation (audit MCP-01).

        Args:
            table: Allow-listed table name.
            columns: Optional explicit column list; ``None`` selects ``*``.
            where: Optional WHERE fragment using ``:name`` bind markers.
            params: Bind parameter values referenced by ``where``.
            limit: Optional row limit (coerced to ``int``).

        Returns:
            The query result as a DataFrame.

        Raises:
            ValueError: When the table is not allow-listed, a column is not
                a bare identifier, or ``where`` contains a quote character
                (which would indicate an inlined literal).
            Exception: Any database error is propagated so the tool layer
                reports a failure instead of a silent empty result
                (audit MCP-06).
        """
        safe_table = _require_identifier(table, "table name")
        if safe_table not in READABLE_TABLES:
            raise ValueError(f"table {safe_table!r} is not readable; allowed: {sorted(READABLE_TABLES)}")
        if columns:
            safe_columns = [_require_identifier(c, "column name") for c in columns]
            col_str = ", ".join(f'"{c}"' for c in safe_columns)
        else:
            col_str = "*"

        sql = f'SELECT {col_str} FROM "{safe_table}"'
        if where:
            if "'" in where or '"' in where:
                raise ValueError("where fragment must use bind parameters (:name), not inlined literals")
            sql += f" WHERE {where}"
        if limit:
            sql += f" LIMIT {int(limit)}"

        if VERBOSE:
            logger.debug(f"Postgres query_table from {self.dsn} executing: {sql}")
        df = pd.read_sql(text(sql), self.engine, params=dict(params or {}))
        if VERBOSE:
            logger.debug(f"Postgres query_table from {self.dsn} returned {len(df)} rows and df:\n{df}")
        return df

    def query_bounds(
        self,
        module: str,
        series_id: Optional[str] = None,
        features: Optional[List[str]] = None,
    ) -> pd.DataFrame:
        where = "module = :module"
        params: Dict[str, Any] = {"module": module}
        if series_id is not None:
            where += " AND series_id = :series_id"
            params["series_id"] = series_id
        df = self.query_table("bounds", where=where, params=params)
        if df is None or df.empty:
            return pd.DataFrame()

        lower_raw = df["lower_bounds"] if "lower_bounds" in df.columns else pd.Series([{}] * len(df), dtype="object")
        upper_raw = df["upper_bounds"] if "upper_bounds" in df.columns else pd.Series([{}] * len(df), dtype="object")
        lower_df = pd.json_normalize(lower_raw.to_list())
        upper_df = pd.json_normalize(upper_raw.to_list())

        if features:
            keep_lb = [c for c in features if c in lower_df.columns]
            keep_ub = [c for c in features if c in upper_df.columns]
            lower_df = lower_df[keep_lb] if keep_lb else pd.DataFrame(index=lower_df.index)
            upper_df = upper_df[keep_ub] if keep_ub else pd.DataFrame(index=upper_df.index)

        lower_df.columns = [f"lb_{c.split('.')[-1]}" for c in lower_df.columns]
        upper_df.columns = [f"ub_{c.split('.')[-1]}" for c in upper_df.columns]

        drop_meta = [
            "lower_bounds",
            "upper_bounds",
            "trained_at",
            "first_ts",
            "last_ts",
        ]
        meta = df.drop(columns=drop_meta, errors="ignore").reset_index(drop=True)
        bounds = pd.concat([lower_df.reset_index(drop=True), upper_df.reset_index(drop=True)], axis=1)
        result = pd.concat([meta, bounds], axis=1)
        return result

    # ── bounds write / expand / replace ─────────────────────────────────
    #
    # All three mutators share the same shape:
    #   * Single SQLAlchemy transaction (``engine.begin()``).
    #   * UPSERT/INSERT into ``bounds`` + INSERT into ``bounds_history``.
    #   * Both rows commit together or both roll back.
    #   * Return ``{"ok": True, ...}`` on success, ``{"ok": False, ...}``
    #     on failure.
    # The ``bounds_history`` table is owned by ``otalon-clas`` (ORM
    # ``BoundsHistory`` in ``otalon_clas.common.postgres_connector``);
    # MCP assumes it already exists.

    def _fetch_bounds_row(
        self, conn: Any, module: str, series_id: str
    ) -> Optional[Tuple[Dict[str, Any], Dict[str, Any]]]:
        """Return ``(lower, upper)`` for an existing row, or ``None``."""
        row = conn.execute(
            text("SELECT lower_bounds, upper_bounds FROM bounds WHERE module = :m AND series_id = :s"),
            {"m": module, "s": series_id},
        ).fetchone()
        if row is None:
            return None
        return _json_load(row[0]), _json_load(row[1])

    def _insert_history(
        self,
        conn: Any,
        *,
        module: str,
        series_id: str,
        action: str,
        old_lower: Optional[Dict[str, Any]],
        old_upper: Optional[Dict[str, Any]],
        new_lower: Dict[str, Any],
        new_upper: Dict[str, Any],
        reason: str,
    ) -> str:
        """Insert a row into ``bounds_history`` and return the new id."""
        history_id = uuid.uuid4().hex
        conn.execute(
            text(
                "INSERT INTO bounds_history "
                "(id, module, series_id, action, old_lower, old_upper, "
                " new_lower, new_upper, reason) "
                "VALUES (:id, :module, :series_id, :action, "
                " :old_lower, :old_upper, :new_lower, :new_upper, :reason)"
            ),
            {
                "id": history_id,
                "module": module,
                "series_id": series_id,
                "action": action,
                "old_lower": _json_param(old_lower),
                "old_upper": _json_param(old_upper),
                "new_lower": _json_param(new_lower),
                "new_upper": _json_param(new_upper),
                "reason": reason,
            },
        )
        return history_id

    def write_bounds(
        self,
        module: str,
        series_id: str,
        lower_bounds: Dict[str, Any],
        upper_bounds: Dict[str, Any],
        reason: str,
    ) -> Dict[str, Any]:
        """Create a new bounds row for ``(module, series_id)``.

        Raises if a row already exists — callers should use ``expand_bounds``
        or ``replace_bounds`` instead. The bounds row and the
        ``bounds_history`` row are written in a single transaction.
        """
        if not reason or not reason.strip():
            return {"ok": False, "error": "reason must be a non-empty string"}
        try:
            now = datetime.now(timezone.utc)
            with self.engine.begin() as conn:
                existing = self._fetch_bounds_row(conn, module, series_id)
                if existing is not None:
                    raise ValueError(
                        f"bounds already exist for module={module!r}, series_id={series_id!r}; "
                        "use expand_bounds or replace_bounds instead"
                    )
                conn.execute(
                    text(
                        "INSERT INTO bounds (module, series_id, lower_bounds, upper_bounds, trained_at) "
                        "VALUES (:m, :s, :lb, :ub, :ts)"
                    ),
                    {
                        "m": module,
                        "s": series_id,
                        "lb": _json_param(lower_bounds),
                        "ub": _json_param(upper_bounds),
                        "ts": now,
                    },
                )
                history_id = self._insert_history(
                    conn,
                    module=module,
                    series_id=series_id,
                    action="write",
                    old_lower=None,
                    old_upper=None,
                    new_lower=lower_bounds,
                    new_upper=upper_bounds,
                    reason=reason,
                )
            return {
                "ok": True,
                "module": module,
                "series_id": series_id,
                "action": "write",
                "history_id": history_id,
            }
        except Exception as exc:
            logger.exception(
                "write_bounds failed: module={}, series_id={}, exc={}",
                module,
                series_id,
                exc,
            )
            return {"ok": False, "error": str(exc)}

    def expand_bounds(
        self,
        module: str,
        series_id: str,
        lower_bounds: Dict[str, Any],
        upper_bounds: Dict[str, Any],
        reason: str,
    ) -> Dict[str, Any]:
        """Widen existing bounds per-feature.

        For each feature ``f``:

        * ``lower[f] = min(old_lower[f], new_lower[f])``
        * ``upper[f] = max(old_upper[f], new_upper[f])``

        Features present in the old row but missing from the new payload
        keep their old value. Features present only in the new payload
        are added. If no bounds row exists for ``(module, series_id)``
        the call fails — the caller should use ``write_bounds`` first.
        """
        if not reason or not reason.strip():
            return {"ok": False, "error": "reason must be a non-empty string"}
        try:
            now = datetime.now(timezone.utc)
            with self.engine.begin() as conn:
                existing = self._fetch_bounds_row(conn, module, series_id)
                if existing is None:
                    raise ValueError(
                        f"no bounds row exists for module={module!r}, series_id={series_id!r}; "
                        "use write_bounds to create one"
                    )
                old_lower, old_upper = existing
                correction = calculate_bounds_correction("expand", old_lower, old_upper, lower_bounds, upper_bounds)
                merged_lower = correction.lower
                merged_upper = correction.upper
                conn.execute(
                    text(
                        "UPDATE bounds SET lower_bounds = :lb, upper_bounds = :ub, trained_at = :ts "
                        "WHERE module = :m AND series_id = :s"
                    ),
                    {
                        "lb": _json_param(merged_lower),
                        "ub": _json_param(merged_upper),
                        "ts": now,
                        "m": module,
                        "s": series_id,
                    },
                )
                history_id = self._insert_history(
                    conn,
                    module=module,
                    series_id=series_id,
                    action="expand",
                    old_lower=old_lower,
                    old_upper=old_upper,
                    new_lower=merged_lower,
                    new_upper=merged_upper,
                    reason=reason,
                )
            return {
                "ok": True,
                "module": module,
                "series_id": series_id,
                "action": "expand",
                "history_id": history_id,
            }
        except Exception as exc:
            logger.exception(
                "expand_bounds failed: module={}, series_id={}, exc={}",
                module,
                series_id,
                exc,
            )
            return {"ok": False, "error": str(exc)}

    def replace_bounds(
        self,
        module: str,
        series_id: str,
        lower_bounds: Dict[str, Any],
        upper_bounds: Dict[str, Any],
        reason: str,
    ) -> Dict[str, Any]:
        """Fully overwrite ``lower_bounds`` and ``upper_bounds``.

        Creates the row if it does not exist (acting like ``write_bounds``).
        This operation can NARROW bounds and is destructive — callers
        should expose it only when the operator explicitly says "replace".
        """
        if not reason or not reason.strip():
            return {"ok": False, "error": "reason must be a non-empty string"}
        try:
            now = datetime.now(timezone.utc)
            with self.engine.begin() as conn:
                existing = self._fetch_bounds_row(conn, module, series_id)
                if existing is None:
                    conn.execute(
                        text(
                            "INSERT INTO bounds (module, series_id, lower_bounds, upper_bounds, trained_at) "
                            "VALUES (:m, :s, :lb, :ub, :ts)"
                        ),
                        {
                            "m": module,
                            "s": series_id,
                            "lb": _json_param(lower_bounds),
                            "ub": _json_param(upper_bounds),
                            "ts": now,
                        },
                    )
                    old_lower: Optional[Dict[str, Any]] = None
                    old_upper: Optional[Dict[str, Any]] = None
                else:
                    old_lower, old_upper = existing
                correction = calculate_bounds_correction("replace", old_lower, old_upper, lower_bounds, upper_bounds)
                lower_bounds = correction.lower
                upper_bounds = correction.upper
                if existing is not None:
                    conn.execute(
                        text(
                            "UPDATE bounds SET lower_bounds = :lb, upper_bounds = :ub, trained_at = :ts "
                            "WHERE module = :m AND series_id = :s"
                        ),
                        {
                            "lb": _json_param(lower_bounds),
                            "ub": _json_param(upper_bounds),
                            "ts": now,
                            "m": module,
                            "s": series_id,
                        },
                    )
                history_id = self._insert_history(
                    conn,
                    module=module,
                    series_id=series_id,
                    action="replace",
                    old_lower=old_lower,
                    old_upper=old_upper,
                    new_lower=lower_bounds,
                    new_upper=upper_bounds,
                    reason=reason,
                )
            return {
                "ok": True,
                "module": module,
                "series_id": series_id,
                "action": "replace",
                "history_id": history_id,
            }
        except Exception as exc:
            logger.exception(
                "replace_bounds failed: module={}, series_id={}, exc={}",
                module,
                series_id,
                exc,
            )
            return {"ok": False, "error": str(exc)}

    # ── anomaly suppression CRUD ──────────────────────────────────────────
    #
    # Shape mirrors the otalon-clas ``anomaly_suppression`` ORM table.
    # The table is created by otalon-clas on startup via
    # ``Base.metadata.create_all()``; this helper bootstraps the table if
    # the MCP server is invoked before otalon-clas has had a chance to
    # create it, so MCP write tools never fail with "table missing".

    def _ensure_anomaly_suppression_table(self) -> None:
        """Create ``anomaly_suppression`` if not already present.

        The Postgres branch uses native ``TEXT[]`` and partial indexes; the
        SQLite branch (test only) collapses arrays to a comma-separated
        TEXT column. The schema mirrors the otalon-clas ORM model.
        """
        if _is_sqlite(self.engine):
            ddl = (
                "CREATE TABLE IF NOT EXISTS anomaly_suppression ("
                " id INTEGER PRIMARY KEY AUTOINCREMENT,"
                " series_id TEXT NOT NULL UNIQUE,"
                " suppressed_types TEXT NOT NULL,"
                " reason TEXT NOT NULL,"
                " created_by TEXT,"
                " created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,"
                " expires_at TIMESTAMP"
                ")"
            )
            idx_series = (
                "CREATE INDEX IF NOT EXISTS ix_anomaly_suppression_series_id " "ON anomaly_suppression (series_id)"
            )
            idx_expires = (
                "CREATE INDEX IF NOT EXISTS ix_anomaly_suppression_expires_at " "ON anomaly_suppression (expires_at)"
            )
        else:
            ddl = (
                "CREATE TABLE IF NOT EXISTS anomaly_suppression ("
                " id BIGSERIAL PRIMARY KEY,"
                " series_id TEXT NOT NULL UNIQUE,"
                " suppressed_types TEXT[] NOT NULL,"
                " reason TEXT NOT NULL,"
                " created_by TEXT,"
                " created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),"
                " expires_at TIMESTAMPTZ,"
                " CONSTRAINT ck_anomaly_suppression_types_nonempty "
                "  CHECK (cardinality(suppressed_types) > 0)"
                ")"
            )
            idx_series = (
                "CREATE INDEX IF NOT EXISTS ix_anomaly_suppression_series_id " "ON anomaly_suppression (series_id)"
            )
            idx_expires = (
                "CREATE INDEX IF NOT EXISTS ix_anomaly_suppression_expires_at "
                "ON anomaly_suppression (expires_at) WHERE expires_at IS NOT NULL"
            )
        with self.engine.begin() as conn:
            conn.execute(text(ddl))
            conn.execute(text(idx_series))
            conn.execute(text(idx_expires))

    @staticmethod
    def _normalize_types(types: List[str]) -> List[str]:
        """Return ``types`` with empty/None entries dropped and unique-preserved."""
        seen: Dict[str, None] = {}
        for t in types or []:
            if t is None:
                continue
            t_str = str(t).strip()
            if not t_str:
                continue
            if t_str not in seen:
                seen[t_str] = None
        return list(seen.keys())

    def _types_to_param(self, types: List[str]) -> Any:
        """Encode types for the active dialect (list for psycopg2, CSV for sqlite)."""
        if _is_sqlite(self.engine):
            return ",".join(types)
        return list(types)

    def _types_from_row(self, raw: Any) -> List[str]:
        """Decode a ``suppressed_types`` column value into a list of strings."""
        if raw is None:
            return []
        if isinstance(raw, list):
            return [str(x) for x in raw if x is not None and str(x).strip()]
        if isinstance(raw, str):
            if not raw.strip():
                return []
            return [p.strip() for p in raw.split(",") if p.strip()]
        return []

    def add_suppression(
        self,
        series_id: str,
        suppressed_types: List[str],
        reason: str,
        created_by: Optional[str] = None,
        expires_at: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Insert or update the suppression row for ``series_id``.

        ``suppressed_types`` is a list of anomaly types (e.g.
        ``["arp_scan", "arp_spoofing"]``); the row holds the union of the
        existing types and the new ones (idempotent — passing the same
        list twice is a no-op). ``reason`` is mandatory. ``expires_at`` is
        an optional ISO-8601 timestamp.

        Returns ``{"ok": True, "id": <pk>, "action": "create"|"update",
        "suppressed_types": [...], "series_id": ...}`` on success.
        """
        if not series_id or not series_id.strip():
            return {"ok": False, "error": "series_id must be a non-empty string"}
        if not reason or not reason.strip():
            return {"ok": False, "error": "reason must be a non-empty string"}
        normalized = self._normalize_types(suppressed_types or [])
        if not normalized:
            return {
                "ok": False,
                "error": "suppressed_types must contain at least one non-empty value",
            }
        expires_dt: Optional[datetime] = None
        if expires_at:
            try:
                expires_dt = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
            except ValueError:
                return {"ok": False, "error": f"invalid expires_at: {expires_at!r}"}
        try:
            self._ensure_anomaly_suppression_table()
            with self.engine.begin() as conn:
                existing = conn.execute(
                    text("SELECT id, suppressed_types FROM anomaly_suppression " "WHERE series_id = :s"),
                    {"s": series_id},
                ).fetchone()
                if existing is None:
                    res = conn.execute(
                        (
                            text(
                                "INSERT INTO anomaly_suppression "
                                "(series_id, suppressed_types, reason, created_by, expires_at) "
                                "VALUES (:s, :t, :r, :cb, :exp) RETURNING id"
                            )
                            if not _is_sqlite(self.engine)
                            else text(
                                "INSERT INTO anomaly_suppression "
                                "(series_id, suppressed_types, reason, created_by, expires_at) "
                                "VALUES (:s, :t, :r, :cb, :exp)"
                            )
                        ),
                        {
                            "s": series_id,
                            "t": self._types_to_param(normalized),
                            "r": reason,
                            "cb": created_by,
                            "exp": expires_dt,
                        },
                    )
                    new_id: Optional[int]
                    if _is_sqlite(self.engine):
                        new_id = int(getattr(res, "lastrowid", 0) or 0)
                    else:
                        row = res.fetchone()
                        new_id = int(row[0]) if row else None
                    return {
                        "ok": True,
                        "id": new_id,
                        "series_id": series_id,
                        "suppressed_types": normalized,
                        "action": "create",
                    }
                old_id = int(existing[0])
                old_types = self._types_from_row(existing[1])
                merged = self._normalize_types(list(old_types) + list(normalized))
                conn.execute(
                    text(
                        "UPDATE anomaly_suppression "
                        "SET suppressed_types = :t, reason = :r, "
                        "    created_by = COALESCE(:cb, created_by), "
                        "    expires_at = :exp "
                        "WHERE id = :id"
                    ),
                    {
                        "t": self._types_to_param(merged),
                        "r": reason,
                        "cb": created_by,
                        "exp": expires_dt,
                        "id": old_id,
                    },
                )
                return {
                    "ok": True,
                    "id": old_id,
                    "series_id": series_id,
                    "suppressed_types": merged,
                    "action": "update",
                }
        except Exception as exc:
            logger.exception("add_suppression failed: series_id={}, exc={}", series_id, exc)
            return {"ok": False, "error": str(exc)}

    def list_suppressions(
        self,
        series_id: Optional[str] = None,
        include_expired: bool = False,
    ) -> Dict[str, Any]:
        """List suppression rows, optionally filtered by series_id.

        ``include_expired=False`` (default) filters rows whose
        ``expires_at`` lies in the past. Returns ``{"ok": True,
        "records": [{...}, ...], "count": N}``.
        """
        try:
            self._ensure_anomaly_suppression_table()
            params: Dict[str, Any] = {}
            where: List[str] = []
            if series_id:
                where.append("series_id = :s")
                params["s"] = series_id
            if not include_expired:
                where.append("(expires_at IS NULL OR expires_at > :now)")
                params["now"] = datetime.now(timezone.utc)
            where_str = (" WHERE " + " AND ".join(where)) if where else ""
            sql = (
                "SELECT id, series_id, suppressed_types, reason, created_by, "
                "       created_at, expires_at "
                "FROM anomaly_suppression" + where_str + " ORDER BY created_at DESC"
            )
            with self.engine.connect() as conn:
                rows = conn.execute(text(sql), params).fetchall()
            records: List[Dict[str, Any]] = []
            for r in rows:
                records.append(
                    {
                        "id": int(r[0]),
                        "series_id": str(r[1]),
                        "suppressed_types": self._types_from_row(r[2]),
                        "reason": str(r[3]) if r[3] is not None else "",
                        "created_by": (str(r[4]) if r[4] is not None else None),
                        "created_at": (r[5].isoformat() if hasattr(r[5], "isoformat") else str(r[5])),
                        "expires_at": (
                            r[6].isoformat()
                            if r[6] is not None and hasattr(r[6], "isoformat")
                            else (str(r[6]) if r[6] is not None else None)
                        ),
                    }
                )
            return {"ok": True, "records": records, "count": len(records)}
        except Exception as exc:
            logger.exception("list_suppressions failed: exc={}", exc)
            return {"ok": False, "error": str(exc)}

    def remove_suppression(
        self,
        series_id: str,
        suppressed_types: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Remove suppression(s) for ``series_id``.

        * ``suppressed_types=None`` deletes the row outright (the operator
          asked to lift the suppression entirely).
        * Non-empty ``suppressed_types`` removes those types from the row's
          set. If the resulting set is empty, the row is deleted; otherwise
          it is updated in place.

        Returns ``{"ok": True, "action": "delete"|"update"|"noop",
        "remaining_types": [...]}``. Missing rows return ``"noop"``.
        """
        if not series_id or not series_id.strip():
            return {"ok": False, "error": "series_id must be a non-empty string"}
        try:
            self._ensure_anomaly_suppression_table()
            with self.engine.begin() as conn:
                existing = conn.execute(
                    text("SELECT id, suppressed_types FROM anomaly_suppression " "WHERE series_id = :s"),
                    {"s": series_id},
                ).fetchone()
                if existing is None:
                    return {
                        "ok": True,
                        "action": "noop",
                        "series_id": series_id,
                        "remaining_types": [],
                    }
                row_id = int(existing[0])
                if suppressed_types is None:
                    conn.execute(
                        text("DELETE FROM anomaly_suppression WHERE id = :id"),
                        {"id": row_id},
                    )
                    return {
                        "ok": True,
                        "action": "delete",
                        "series_id": series_id,
                        "remaining_types": [],
                    }
                drop_set = {t.strip() for t in suppressed_types if t and t.strip()}
                if not drop_set:
                    return {
                        "ok": False,
                        "error": "suppressed_types must be None or a non-empty list",
                    }
                old_types = self._types_from_row(existing[1])
                remaining = [t for t in old_types if t not in drop_set]
                if not remaining:
                    conn.execute(
                        text("DELETE FROM anomaly_suppression WHERE id = :id"),
                        {"id": row_id},
                    )
                    return {
                        "ok": True,
                        "action": "delete",
                        "series_id": series_id,
                        "remaining_types": [],
                    }
                conn.execute(
                    text("UPDATE anomaly_suppression SET suppressed_types = :t " "WHERE id = :id"),
                    {"t": self._types_to_param(remaining), "id": row_id},
                )
                return {
                    "ok": True,
                    "action": "update",
                    "series_id": series_id,
                    "remaining_types": remaining,
                }
        except Exception as exc:
            logger.exception("remove_suppression failed: series_id={}, exc={}", series_id, exc)
            return {"ok": False, "error": str(exc)}

    def query_anomalies(
        self,
        module: str,
        series_id: Optional[str | int] = None,
        metric: Optional[str] = None,
        time_range: Optional[Tuple[str, str]] = None,
    ) -> pd.DataFrame:
        where: List[str] = ["module = :module"]
        params: Dict[str, Any] = {"module": module}
        if series_id is not None:
            where.append("series_id = :series_id")
            params["series_id"] = str(series_id)
        if metric is not None:
            where.append("metric = :metric")
            params["metric"] = metric
        if time_range is not None:
            start, stop = time_range
            where.append("start_ts <= :stop AND end_ts >= :start")
            params["start"] = start
            params["stop"] = stop
        where_str = " AND ".join(where)
        return self.query_table("anomalies", where=where_str, params=params)

    def query_anomaly_groups(
        self,
        module: Optional[str] = None,
        type_: Optional[str] = None,
        confirmed: Optional[bool] = None,
        time_range: Optional[Tuple[str, str]] = None,
        limit: Optional[int] = None,
    ) -> pd.DataFrame:
        """Read alarm rows with optional filters.

        ``type_`` filters on ``alarms.primary_type``, which is a JSON
        column holding a bare JSON string (e.g. ``"tcp_flood"``), NOT a
        ``type`` column — the previous name never matched and silently
        returned every row (audit MCP-08). The comparison unwraps the JSON
        scalar via ``#>> '{}'`` so callers keep passing the plain label.
        """
        where: List[str] = []
        params: Dict[str, Any] = {}
        if module:
            where.append("module = :module")
            params["module"] = module
        if type_:
            where.append(self._primary_type_predicate())
            params["primary_type"] = type_
        if confirmed is not None:
            where.append("confirmed = :confirmed")
            params["confirmed"] = bool(confirmed)
        if time_range:
            start, stop = time_range
            where.append("start_timestamp <= :stop AND end_timestamp >= :start")
            params["start"] = start
            params["stop"] = stop
        where_str = " AND ".join(where) if where else None
        return self.query_table("alarms", where=where_str, params=params, limit=limit)

    def _primary_type_predicate(self) -> str:
        """Return the dialect-appropriate ``primary_type`` equality fragment.

        PostgreSQL stores ``primary_type`` as ``json`` holding a bare JSON
        string, so its text form is wrapped in double quotes. Unwrapping
        with ``#>> '{}'`` would need a quoted literal, which
        :meth:`query_table` forbids; encoding the bind parameter with
        ``to_json`` instead keeps the fragment literal-free and compares
        like-for-like. ``CAST(... AS text)`` is used rather than the
        ``::text`` shorthand because ``:param::text`` collides with the
        bind-parameter syntax.

        SQLite (tests) keeps the value as a plain string column, so a
        direct comparison applies.
        """
        if _is_sqlite(self.engine):
            return "primary_type = :primary_type"
        return "CAST(primary_type AS text) = " "CAST(to_json(CAST(:primary_type AS text)) AS text)"

    def get_anomaly_group_by_id(self, alarm_id: str) -> pd.DataFrame:
        """Return the single alarm row with ``id == alarm_id``.

        Database errors propagate to the caller so a lookup failure is
        reported as an error rather than as "alarm not found"
        (audit MCP-06).
        """
        return self.query_table(
            "alarms",
            where="id = :alarm_id",
            params={"alarm_id": str(alarm_id)},
            limit=1,
        )

    def update_anomaly_group_confirmed(self, alarm_id: str, confirmed: bool) -> bool:
        try:
            stmt = text("UPDATE alarms SET confirmed = :confirmed WHERE id = :id")
            with self.engine.begin() as conn:
                res = conn.execute(stmt, {"confirmed": bool(confirmed), "id": str(alarm_id)})
                return bool(res.rowcount and res.rowcount > 0)
        except Exception as exc:
            logger.exception(f"update_anomaly_group_confirmed failed: {exc}")
            return False

    def list_whitelisted_tables_present(self, whitelist: Optional[List[str]] = None) -> List[str]:
        try:
            insp = inspect(self.engine)
            present = set(insp.get_table_names() or [])
            if whitelist is None:
                return sorted(present)
            return [t for t in (whitelist or []) if t in present]
        except Exception as exc:
            logger.error(f"list_whitelisted_tables_present failed: {exc}")
            return []

    def _require_destructive_target(self, table: str, allowlist: Optional[List[str]]) -> str:
        """Return the quotable table name for a destructive statement, else raise.

        The two callers (:meth:`truncate_table`, :meth:`delete_all_rows`)
        inline the table name into a ``TRUNCATE`` / ``DELETE`` statement,
        so it must clear three hurdles before it becomes SQL: it is a bare
        identifier, the caller supplied a non-empty allow-list, and the
        name is a member of it. The previous guard was
        ``isinstance(allowlist, list) and table not in allowlist``, which
        skipped entirely when the caller passed ``None`` — the default —
        and left a mere ``get_table_names()`` membership test in front of
        the only two destructive statements in the repository
        (audit MCP-016). Fail-closed replaces the guard-skip: no
        allow-list means no destruction.

        Args:
            table: Candidate table name.
            allowlist: Table names the caller permits; ``None`` or empty
                rejects every table.

        Returns:
            The validated identifier, safe to quote into the statement.

        Raises:
            ValueError: When the allow-list is empty/missing, the name is
                not a bare identifier, or it is not allow-listed.
        """
        if not allowlist:
            raise ValueError(f"Tabelle '{table}' ist nicht in der Whitelist erlaubt: keine Allowlist angegeben.")
        safe_table = _require_identifier(table, "table name")
        safe_allowlist = {str(entry).strip() for entry in allowlist}
        if safe_table not in safe_allowlist:
            raise ValueError(f"Tabelle '{table}' ist nicht in der Whitelist erlaubt.")
        return safe_table

    def truncate_table(
        self,
        table: str,
        cascade: bool = False,
        allowlist: Optional[List[str]] = None,
    ) -> Tuple[bool, str]:
        """Empty an allow-listed table with ``TRUNCATE``.

        Args:
            table: Table to truncate; must be a bare identifier that is
                both allow-listed and present in the database.
            cascade: Append ``CASCADE`` to follow foreign keys.
            allowlist: Table names the caller permits. ``None`` or empty
                rejects the call (audit MCP-016).

        Returns:
            ``(True, "ok")`` on success, otherwise ``(False, reason)``.
        """
        try:
            safe_table = self._require_destructive_target(table, allowlist)
            insp = inspect(self.engine)
            if safe_table not in (insp.get_table_names() or []):
                return False, f"Tabelle '{table}' existiert nicht."
            sql = f'TRUNCATE TABLE "{safe_table}" {"CASCADE" if cascade else ""}'.strip()
            with self.engine.begin() as conn:
                conn.execute(text(sql))
            return True, "ok"
        except Exception as exc:
            logger.exception(f"truncate_table failed: table={table}, cascade={cascade}, exc={exc}")
            return False, str(exc)

    def delete_all_rows(self, table: str, allowlist: Optional[List[str]] = None) -> Tuple[int, str]:
        """Delete every row of an allow-listed table.

        Args:
            table: Table to empty; must be a bare identifier that is both
                allow-listed and present in the database.
            allowlist: Table names the caller permits. ``None`` or empty
                rejects the call (audit MCP-016).

        Returns:
            ``(rowcount, "ok")`` on success, otherwise ``(-1, reason)``.
        """
        try:
            safe_table = self._require_destructive_target(table, allowlist)
            insp = inspect(self.engine)
            if safe_table not in (insp.get_table_names() or []):
                return -1, f"Tabelle '{table}' existiert nicht."
            sql = f'DELETE FROM "{safe_table}"'
            with self.engine.begin() as conn:
                res = conn.execute(text(sql))
                rc = int(getattr(res, "rowcount", 0) or 0)
            return rc, "ok"
        except Exception as exc:
            logger.exception(f"delete_all_rows failed: table={table}, exc={exc}")
            return -1, str(exc)

    def get_pk_columns(self, table: str) -> List[str]:
        try:
            insp = inspect(self.engine)
            pk = insp.get_pk_constraint(table) or {}
            cols = pk.get("constrained_columns") or []
            return [str(c) for c in cols]
        except Exception as exc:
            logger.exception(f"get_pk_columns failed: table={table}, exc={exc}")
            return []

    def update_rows(
        self,
        table: str,
        rows: List[Dict[str, Any]],
        pk_cols: Optional[List[str]] = None,
    ) -> int:
        if not rows:
            return 0
        try:
            from sqlalchemy import MetaData, Table, and_

            md = MetaData()
            tbl = Table(table, md, autoload_with=self.engine)

            if not pk_cols:
                pk_cols = [c.name for c in tbl.primary_key.columns] or []

            if not pk_cols:
                raise ValueError(f"Keine Primary-Key-Spalten für Tabelle '{table}' gefunden.")

            updated = 0
            with self.engine.begin() as conn:
                for rec in rows:
                    missing = [pk for pk in pk_cols if pk not in rec]
                    if missing:
                        raise ValueError(f"PK-Spalten {missing} fehlen im Datensatz für Tabelle '{table}'.")

                    clauses = [tbl.c[pk] == rec[pk] for pk in pk_cols]
                    values = {k: v for k, v in rec.items() if k not in pk_cols}
                    if not values:
                        continue

                    stmt = tbl.update().where(and_(*clauses)).values(**values)
                    res = conn.execute(stmt)
                    updated += int(getattr(res, "rowcount", 0) or 0)
            return updated
        except Exception as exc:
            logger.exception(f"update_rows failed: table={table}, rows={len(rows)}, exc={exc}")
            return 0

    # ── devices / network_interfaces CRUD ────────────────────────────
    #
    # Schema reference (canonical, see otalon-scan
    # ``src/repositories/models.py``):
    #
    # ``devices``: id (int PK, autoincrement), primary_mac (text,
    #   nullable, lowercased colon-separated MAC), vendor, device_family,
    #   device_type, description, article_number, device_role,
    #   firmware_version, update_available (bool, default false),
    #   last_scan_at, notes, created_at, updated_at. NO `source` column,
    #   NO `hostname` column.
    #
    # ``network_interfaces``: id (int PK, autoincrement), device_id (FK
    #   devices.id ON DELETE SET NULL, nullable), mac_address (UQ),
    #   ipv4_address (INET, UQ), ipv6_address (INET, UQ), subnet (CIDR),
    #   last_scan_at, notes, source (text, NOT NULL, default 'active'),
    #   first_seen_passive_at, last_seen_passive_at, created_at,
    #   updated_at.

    _DEVICE_WRITE_COLUMNS = (
        "primary_mac",
        "vendor",
        "device_family",
        "device_type",
        "description",
        "article_number",
        "device_role",
        "firmware_version",
        "update_available",
        "notes",
    )

    _INTERFACE_WRITE_COLUMNS = (
        "device_id",
        "mac_address",
        "ipv4_address",
        "ipv6_address",
        "subnet",
        "notes",
        "source",
    )

    def list_devices(self, limit: int = 200, offset: int = 0) -> List[Dict[str, Any]]:
        """Return a paginated list of devices ordered by id ASC."""
        sql = "SELECT * FROM devices ORDER BY id ASC LIMIT :lim OFFSET :off"
        try:
            with self.engine.begin() as conn:
                rows = conn.execute(text(sql), {"lim": int(limit), "off": int(offset)}).mappings().all()
            return [dict(row) for row in rows]
        except Exception as exc:
            logger.exception(f"list_devices failed: {exc}")
            raise

    def get_device(self, device_id: int) -> Optional[Dict[str, Any]]:
        """Return a single device row by id, or None when not found."""
        try:
            with self.engine.begin() as conn:
                row = (
                    conn.execute(
                        text("SELECT * FROM devices WHERE id = :id"),
                        {"id": int(device_id)},
                    )
                    .mappings()
                    .first()
                )
            return dict(row) if row else None
        except Exception as exc:
            logger.exception(f"get_device failed: device_id={device_id} exc={exc}")
            raise

    def add_device(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Insert a new device row and return the persisted row.

        Only columns declared in ``_DEVICE_WRITE_COLUMNS`` are accepted;
        unknown keys are rejected with ``ValueError`` so we never silently
        ignore caller intent. ``id``, ``created_at`` and ``updated_at``
        are server-assigned. The ``devices`` table has NO ``source`` and
        NO ``hostname`` columns; the seeder-style provenance marker lives
        on ``network_interfaces`` instead.
        """
        unknown = [k for k in payload.keys() if k not in self._DEVICE_WRITE_COLUMNS]
        if unknown:
            raise ValueError(
                f"add_device rejected unknown columns: {unknown}. " f"Allowed: {list(self._DEVICE_WRITE_COLUMNS)}"
            )
        cols = list(payload.keys())
        if not cols:
            # Insert with all defaults — devices table tolerates empty
            # body (everything is nullable or has a server default).
            sql = "INSERT INTO devices DEFAULT VALUES"
            params: Dict[str, Any] = {}
        else:
            placeholders = ", ".join(f":{c}" for c in cols)
            sql = f"INSERT INTO devices ({', '.join(cols)}) VALUES ({placeholders})"
            params = dict(payload)

        try:
            with self.engine.begin() as conn:
                if _is_sqlite(self.engine):
                    res = conn.execute(text(sql), params)
                    new_id = int(getattr(res, "lastrowid", 0) or 0)
                else:
                    res = conn.execute(text(sql + " RETURNING id"), params)
                    new_id = int(res.scalar_one())
                row = (
                    conn.execute(
                        text("SELECT * FROM devices WHERE id = :id"),
                        {"id": new_id},
                    )
                    .mappings()
                    .first()
                )
            return dict(row) if row else {"id": new_id}
        except Exception as exc:
            logger.exception(f"add_device failed: payload={payload} exc={exc}")
            raise

    def update_device(self, device_id: int, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Partial update: writes only the keys present in ``payload``.

        Returns the refreshed row, or ``None`` when ``device_id`` does
        not exist. Unknown columns raise ``ValueError``. An empty
        ``payload`` is a no-op (returns the existing row unchanged).
        """
        unknown = [k for k in payload.keys() if k not in self._DEVICE_WRITE_COLUMNS]
        if unknown:
            raise ValueError(
                f"update_device rejected unknown columns: {unknown}. " f"Allowed: {list(self._DEVICE_WRITE_COLUMNS)}"
            )
        try:
            with self.engine.begin() as conn:
                if payload:
                    assignments = ", ".join(f"{c} = :{c}" for c in payload.keys())
                    params = dict(payload)
                    params["id"] = int(device_id)
                    res = conn.execute(
                        text(f"UPDATE devices SET {assignments} WHERE id = :id"),
                        params,
                    )
                    if not (res.rowcount and res.rowcount > 0):
                        return None
                row = (
                    conn.execute(
                        text("SELECT * FROM devices WHERE id = :id"),
                        {"id": int(device_id)},
                    )
                    .mappings()
                    .first()
                )
            return dict(row) if row else None
        except Exception as exc:
            logger.exception(f"update_device failed: device_id={device_id} payload={payload} exc={exc}")
            raise

    def delete_device(self, device_id: int, cascade_interfaces: bool = False) -> Dict[str, Any]:
        """Hard-delete a device row.

        When ``cascade_interfaces`` is ``False`` (the default), child
        ``network_interfaces`` keep their rows but their ``device_id``
        is set to ``NULL`` via the table-level FK ``ON DELETE SET NULL``
        rule. When ``True``, all interfaces owned by the device are
        deleted first; service- and vulnerability-observations bound to
        those interfaces cascade via their own FK definitions.

        Returns ``{"ok": True, "deleted_device_id": id,
        "deleted_interfaces": n, "orphaned_interfaces": n}`` on success;
        ``{"ok": False, "error": "device not found"}`` when the row is
        missing.
        """
        try:
            with self.engine.begin() as conn:
                row = conn.execute(
                    text("SELECT id FROM devices WHERE id = :id"),
                    {"id": int(device_id)},
                ).first()
                if row is None:
                    return {"ok": False, "error": f"device {device_id} not found"}
                deleted_iface = 0
                orphaned_iface = 0
                if cascade_interfaces:
                    res = conn.execute(
                        text("DELETE FROM network_interfaces WHERE device_id = :id"),
                        {"id": int(device_id)},
                    )
                    deleted_iface = int(res.rowcount or 0)
                else:
                    # Count interfaces that will be orphaned (set to NULL).
                    orphaned_iface = int(
                        conn.execute(
                            text("SELECT COUNT(*) FROM network_interfaces " "WHERE device_id = :id"),
                            {"id": int(device_id)},
                        ).scalar_one()
                    )
                conn.execute(
                    text("DELETE FROM devices WHERE id = :id"),
                    {"id": int(device_id)},
                )
            return {
                "ok": True,
                "deleted_device_id": int(device_id),
                "deleted_interfaces": deleted_iface,
                "orphaned_interfaces": orphaned_iface,
                "cascade_interfaces": bool(cascade_interfaces),
            }
        except Exception as exc:
            logger.exception(f"delete_device failed: device_id={device_id} exc={exc}")
            raise

    def list_interfaces(
        self,
        device_id: Optional[int] = None,
        limit: int = 200,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Return a paginated list of network interfaces.

        Set ``device_id`` to narrow the query to one device's interfaces.
        Pass ``device_id=0`` to query the orphan set (interfaces with
        ``device_id IS NULL`` — useful after a non-cascade delete_device).
        """
        try:
            with self.engine.begin() as conn:
                if device_id is None:
                    rows = (
                        conn.execute(
                            text("SELECT * FROM network_interfaces " "ORDER BY id ASC LIMIT :lim OFFSET :off"),
                            {"lim": int(limit), "off": int(offset)},
                        )
                        .mappings()
                        .all()
                    )
                elif int(device_id) == 0:
                    rows = (
                        conn.execute(
                            text(
                                "SELECT * FROM network_interfaces "
                                "WHERE device_id IS NULL "
                                "ORDER BY id ASC LIMIT :lim OFFSET :off"
                            ),
                            {"lim": int(limit), "off": int(offset)},
                        )
                        .mappings()
                        .all()
                    )
                else:
                    rows = (
                        conn.execute(
                            text(
                                "SELECT * FROM network_interfaces "
                                "WHERE device_id = :did "
                                "ORDER BY id ASC LIMIT :lim OFFSET :off"
                            ),
                            {
                                "did": int(device_id),
                                "lim": int(limit),
                                "off": int(offset),
                            },
                        )
                        .mappings()
                        .all()
                    )
            return [dict(row) for row in rows]
        except Exception as exc:
            logger.exception(f"list_interfaces failed: device_id={device_id} exc={exc}")
            raise

    def get_interface(self, interface_id: int) -> Optional[Dict[str, Any]]:
        try:
            with self.engine.begin() as conn:
                row = (
                    conn.execute(
                        text("SELECT * FROM network_interfaces WHERE id = :id"),
                        {"id": int(interface_id)},
                    )
                    .mappings()
                    .first()
                )
            return dict(row) if row else None
        except Exception as exc:
            logger.exception(f"get_interface failed: interface_id={interface_id} exc={exc}")
            raise

    def add_interface(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Insert a new network_interfaces row and return the persisted row.

        Defaults ``source`` to ``"manual"`` when the caller does not
        supply one so MCP-originated rows are clearly distinguishable
        from active-scan / passive-seeder rows in audits. Unknown
        columns raise ``ValueError``.
        """
        unknown = [k for k in payload.keys() if k not in self._INTERFACE_WRITE_COLUMNS]
        if unknown:
            raise ValueError(
                f"add_interface rejected unknown columns: {unknown}. " f"Allowed: {list(self._INTERFACE_WRITE_COLUMNS)}"
            )
        body = dict(payload)
        body.setdefault("source", "manual")
        cols = list(body.keys())
        placeholders = ", ".join(f":{c}" for c in cols)
        sql = f"INSERT INTO network_interfaces ({', '.join(cols)}) " f"VALUES ({placeholders})"
        try:
            with self.engine.begin() as conn:
                if _is_sqlite(self.engine):
                    res = conn.execute(text(sql), body)
                    new_id = int(getattr(res, "lastrowid", 0) or 0)
                else:
                    res = conn.execute(text(sql + " RETURNING id"), body)
                    new_id = int(res.scalar_one())
                row = (
                    conn.execute(
                        text("SELECT * FROM network_interfaces WHERE id = :id"),
                        {"id": new_id},
                    )
                    .mappings()
                    .first()
                )
            return dict(row) if row else {"id": new_id}
        except Exception as exc:
            logger.exception(f"add_interface failed: payload={payload} exc={exc}")
            raise

    def update_interface(self, interface_id: int, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        unknown = [k for k in payload.keys() if k not in self._INTERFACE_WRITE_COLUMNS]
        if unknown:
            raise ValueError(
                f"update_interface rejected unknown columns: {unknown}. "
                f"Allowed: {list(self._INTERFACE_WRITE_COLUMNS)}"
            )
        try:
            with self.engine.begin() as conn:
                if payload:
                    assignments = ", ".join(f"{c} = :{c}" for c in payload.keys())
                    params = dict(payload)
                    params["id"] = int(interface_id)
                    res = conn.execute(
                        text(f"UPDATE network_interfaces SET {assignments} " f"WHERE id = :id"),
                        params,
                    )
                    if not (res.rowcount and res.rowcount > 0):
                        return None
                row = (
                    conn.execute(
                        text("SELECT * FROM network_interfaces WHERE id = :id"),
                        {"id": int(interface_id)},
                    )
                    .mappings()
                    .first()
                )
            return dict(row) if row else None
        except Exception as exc:
            logger.exception(f"update_interface failed: interface_id={interface_id} " f"payload={payload} exc={exc}")
            raise

    def delete_interface(self, interface_id: int) -> Dict[str, Any]:
        """Hard-delete a network_interfaces row.

        Service- and vulnerability-observations bound to the interface
        cascade automatically (their FKs use ON DELETE CASCADE).
        """
        try:
            with self.engine.begin() as conn:
                row = conn.execute(
                    text("SELECT id FROM network_interfaces WHERE id = :id"),
                    {"id": int(interface_id)},
                ).first()
                if row is None:
                    return {"ok": False, "error": f"interface {interface_id} not found"}
                conn.execute(
                    text("DELETE FROM network_interfaces WHERE id = :id"),
                    {"id": int(interface_id)},
                )
            return {"ok": True, "deleted_interface_id": int(interface_id)}
        except Exception as exc:
            logger.exception(f"delete_interface failed: interface_id={interface_id} exc={exc}")
            raise

    def close(self) -> None:
        try:
            self.engine.dispose()
        except Exception:
            pass
