"""Repository for the immutable Change Audit log."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from otalon_api.domain.operations import (
    AuditQueryFilters,
    OperationsAuditAppend,
    OperationsAuditEntry,
    OperationsAuditImport,
)
from otalon_api.repositories.postgres_repo import PostgresRepository


class OperationsAuditRepository:
    """Append-only provenance-aware audit repository."""

    def __init__(self, postgres_repo: PostgresRepository) -> None:
        self._pg = postgres_repo

    def _row_to_model(self, row: dict[str, Any]) -> OperationsAuditEntry:
        return OperationsAuditEntry.model_validate(row)

    def append(
        self,
        entry: OperationsAuditAppend,
        at: datetime | None = None,
    ) -> OperationsAuditEntry:
        """Insert a native operations audit row."""
        sql = """
            INSERT INTO operations_audit (at, category, actor, action, target, reason, detail)
            VALUES (%(at)s, %(category)s, %(actor)s, %(action)s, %(target)s, %(reason)s, %(detail)s)
            RETURNING *
        """
        params = entry.model_dump(mode="json")
        params["at"] = (at or datetime.now(timezone.utc)).isoformat()
        rows = self._pg._execute_query(sql, params)
        if not rows:
            raise RuntimeError("operations_audit insert returned no row")
        return self._row_to_model(rows[0])

    def import_row(self, entry: OperationsAuditImport) -> OperationsAuditEntry | None:
        """Idempotently import an audit row from an external source.

        Uses ``ON CONFLICT (source, source_id) DO NOTHING`` so repeated
        imports of the same origin row return ``None`` instead of duplicating.
        """
        sql = """
            INSERT INTO operations_audit
                (at, category, actor, action, target, reason, detail, source, source_id)
            VALUES (%(at)s, %(category)s, %(actor)s, %(action)s, %(target)s,
                    %(reason)s, %(detail)s, %(source)s, %(source_id)s)
            ON CONFLICT (source, source_id) DO NOTHING
            RETURNING *
        """
        data = entry.model_dump(mode="json")
        data["at"] = (entry.at or datetime.now(timezone.utc)).isoformat()
        rows = self._pg._execute_query(sql, data)
        return self._row_to_model(rows[0]) if rows else None

    def query(self, filters: AuditQueryFilters, limit: int = 1000) -> list[OperationsAuditEntry]:
        """Return audit entries most-recent first."""
        clauses: list[str] = []
        params: dict[str, Any] = {"limit": limit}

        if filters.category:
            clauses.append("category = %(category)s")
            params["category"] = filters.category
        if filters.actor:
            clauses.append("actor ILIKE %(actor)s")
            params["actor"] = f"%{filters.actor}%"
        if filters.since:
            clauses.append("at >= %(since)s")
            params["since"] = filters.since.isoformat()
        if filters.q:
            clauses.append("(action ILIKE %(q)s OR target ILIKE %(q)s)")
            params["q"] = f"%{filters.q}%"

        where = " AND ".join(clauses)
        sql = f"""
            SELECT * FROM operations_audit
            {f"WHERE {where}" if where else ""}
            ORDER BY at DESC
            LIMIT %(limit)s
        """
        return [self._row_to_model(r) for r in self._pg._execute_query(sql, params)]

    def get(self, entry_id: int) -> OperationsAuditEntry | None:
        """Return one immutable audit entry by database identifier."""
        rows = self._pg._execute_query("SELECT * FROM operations_audit WHERE id = %(id)s", {"id": entry_id})
        return self._row_to_model(rows[0]) if rows else None

    def delete_by_source(self, source: str) -> int:
        """Delete only rows created under an explicit non-native ``source``.

        This is the deterministic test/systemtest isolation primitive: rows
        seeded with an ownership marker (a dedicated ``source`` such as
        ``systemtest`` or a per-run token) can be removed without ever
        touching native operator history. The native ``"operations"`` source
        is refused so no live audit trail can be deleted through this path.

        Args:
            source: The ownership marker to scope the delete to.

        Returns:
            The number of rows removed for that source.

        Raises:
            ValueError: If ``source`` is empty or the native operations source.
        """
        marker = (source or "").strip()
        if not marker or marker == "operations":
            raise ValueError("delete_by_source refuses empty or native 'operations' source")
        rows = self._pg._execute_query(
            "DELETE FROM operations_audit WHERE source = %(source)s RETURNING id",
            {"source": marker},
        )
        return len(rows)

    def backfill_bounds_history(
        self,
        source: str = "bounds_history",
        actor_fallback: str = "operator",
        limit: int = 10_000,
    ) -> int:
        """One-time backfill of historical bounds_history rows.

        Inserts an ``operations_audit`` row for every ``bounds_history`` row
        that does not already have a provenance row. The ``UNIQUE`` index
        on ``(source, source_id)`` makes the operation idempotent. When the
        ``bounds_history`` table does not exist yet (otalon-clas has not
        bootstrapped), the method is a safe no-op returning ``0``.
        """
        exists = self._pg._execute_query("SELECT to_regclass('public.bounds_history') AS reg")
        if not exists or exists[0].get("reg") is None:
            return 0

        select = """
            SELECT
                id::text AS source_id,
                changed_at AS at,
                module || ':' || series_id AS target,
                action,
                reason,
                COALESCE(actor, %(actor_fallback)s) AS actor
            FROM bounds_history
            WHERE NOT EXISTS (
                SELECT 1 FROM operations_audit
                WHERE operations_audit.source = %(source)s
                  AND operations_audit.source_id = bounds_history.id::text
            )
            ORDER BY changed_at ASC
            LIMIT %(limit)s
        """
        rows = self._pg._execute_query(
            select,
            {"source": source, "actor_fallback": actor_fallback, "limit": limit},
        )
        if not rows:
            return 0

        inserted = 0
        for row in rows:
            imported = self.import_row(
                OperationsAuditImport(
                    source=source,
                    source_id=row["source_id"],
                    at=row["at"],
                    category="bounds",
                    actor=row["actor"],
                    action=row["action"],
                    target=row["target"],
                    reason=row["reason"],
                    detail="Historical bounds correction imported from bounds_history",
                )
            )
            if imported:
                inserted += 1
        return inserted
