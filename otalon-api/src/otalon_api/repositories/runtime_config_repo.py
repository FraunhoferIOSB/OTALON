"""Row-level access to shared runtime configuration tables."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

import psycopg2.extras

from otalon_api.domain.operations import OperationsAuditAppend
from otalon_api.repositories.postgres_repo import PostgresRepository


class RuntimeConfigRepo:
    """Read and write ``runtime_config`` rows without owning its DDL."""

    def __init__(self, postgres_repo: PostgresRepository) -> None:
        """Initialize repository with shared PostgreSQL access."""
        self._repo = postgres_repo

    def list_rows(self) -> list[dict[str, Any]]:
        """Return all persisted runtime configuration rows."""
        return self._repo._execute_query(
            """
            SELECT service, key, value, value_prev, updated_at, updated_by
            FROM runtime_config
            ORDER BY service, key
            """
        )

    def get(self, service: str, key: str) -> dict[str, Any] | None:
        """Return one persisted runtime row, if present."""
        rows = self._repo._execute_query(
            """
            SELECT service, key, value, value_prev, updated_at, updated_by
            FROM runtime_config
            WHERE service = %(service)s AND key = %(key)s
            """,
            {"service": service, "key": key},
        )
        return rows[0] if rows else None

    def upsert(self, service: str, key: str, value: str, updated_by: str) -> None:
        """Persist one value and move its previous value to ``value_prev``."""
        self._repo._execute_update(
            """
            INSERT INTO runtime_config
                (service, key, value, value_prev, updated_at, updated_by)
            VALUES (%(service)s, %(key)s, %(value)s, NULL, now(), %(updated_by)s)
            ON CONFLICT (service, key) DO UPDATE SET
                value_prev = runtime_config.value,
                value = EXCLUDED.value,
                updated_at = EXCLUDED.updated_at,
                updated_by = EXCLUDED.updated_by
            """,
            {"service": service, "key": key, "value": value, "updated_by": updated_by},
        )

    def upsert_with_audit(
        self,
        service: str,
        key: str,
        value: str,
        updated_by: str,
        audit: OperationsAuditAppend,
    ) -> dict[str, Any] | None:
        """Persist runtime value and audit row in one PostgreSQL transaction."""
        with self._repo.connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT pg_advisory_xact_lock(hashtext(%(lock_key)s))",
                    {"lock_key": f"runtime_config:{service}:{key}"},
                )
                cur.execute(
                    """
                    SELECT service, key, value, value_prev, updated_at, updated_by
                    FROM runtime_config
                    WHERE service = %(service)s AND key = %(key)s
                    FOR UPDATE
                    """,
                    {"service": service, "key": key},
                )
                rows = cur.fetchall()
                prior = dict(rows[0]) if rows else None
                cur.execute(
                    """
                    INSERT INTO runtime_config
                        (service, key, value, value_prev, updated_at, updated_by)
                    VALUES (%(service)s, %(key)s, %(value)s, NULL, now(), %(updated_by)s)
                    ON CONFLICT (service, key) DO UPDATE SET
                        value_prev = runtime_config.value,
                        value = EXCLUDED.value,
                        updated_at = EXCLUDED.updated_at,
                        updated_by = EXCLUDED.updated_by
                    """,
                    {
                        "service": service,
                        "key": key,
                        "value": value,
                        "updated_by": updated_by,
                    },
                )
                params = audit.model_dump(mode="json")
                detail = json.loads(params["detail"] or "{}")
                if not detail.get("sensitive"):
                    detail["prior_value"] = prior["value"] if prior else None
                params["detail"] = json.dumps(detail)
                params["at"] = datetime.now(timezone.utc).isoformat()
                cur.execute(
                    """
                    INSERT INTO operations_audit
                        (at, category, actor, action, target, reason, detail)
                    VALUES (%(at)s, %(category)s, %(actor)s, %(action)s, %(target)s, %(reason)s, %(detail)s)
                    """,
                    params,
                )
            conn.commit()
        return prior


class PassiveSeederStatusRepo:
    """Read the passive-seeder status row owned by otalon-scan."""

    def __init__(self, postgres_repo: PostgresRepository) -> None:
        """Initialize repository with shared PostgreSQL access."""
        self._repo = postgres_repo

    def get(self, service: str) -> dict[str, Any] | None:
        """Return persisted status for *service*, or ``None`` if absent."""
        rows = self._repo._execute_query(
            """
            SELECT service, state, last_cycle_at, last_error, rows_seeded,
                   poll_interval_s, updated_at
            FROM passive_seeder_status
            WHERE service = %(service)s
            """,
            {"service": service},
        )
        return rows[0] if rows else None


RuntimeConfigRepository = RuntimeConfigRepo
"""Compatibility name matching the repository's domain terminology."""

PassiveSeederStatusRepository = PassiveSeederStatusRepo
"""Compatibility name for the passive-seeder status repository."""
