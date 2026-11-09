"""Idempotent PostgreSQL migrations for operations tables."""

from __future__ import annotations

from loguru import logger
from psycopg2 import errors
from psycopg2.extras import RealDictCursor

from otalon_api.repositories.postgres_repo import PostgresRepository

OPERATIONS_JOBS_TABLE_SQL = """
CREATE SEQUENCE IF NOT EXISTS operations_jobs_display_seq;

CREATE TABLE IF NOT EXISTS operations_jobs (
    id              BIGSERIAL PRIMARY KEY,
    display_id      TEXT NOT NULL UNIQUE DEFAULT ('J-' || nextval('operations_jobs_display_seq')),
    type            TEXT NOT NULL
                    CHECK (type IN ('training','ingest','backup','service','maintenance','detection_gate_change')),
    title           TEXT NOT NULL,
    state           TEXT NOT NULL DEFAULT 'queued'
                    CHECK (state IN ('queued','running','cancelling','completed','failed','cancelled','rejected')),
    trigger         TEXT NOT NULL,
    actor           TEXT,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at        TIMESTAMPTZ,
    phase_current   INT,
    phase_total     INT,
    phase_label     TEXT,
    latest_event    TEXT,
    params          JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(params) = 'object'),
    log             JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(log) = 'array'),
    error           TEXT,
    result          TEXT,
    can_cancel      BOOLEAN NOT NULL DEFAULT false,
    can_retry       BOOLEAN NOT NULL DEFAULT false,
    retried_as_id   BIGINT UNIQUE REFERENCES operations_jobs(id),
    idempotency_key TEXT UNIQUE
);
"""


OPERATIONS_AUDIT_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS operations_audit (
    id          BIGSERIAL PRIMARY KEY,
    at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    category    TEXT NOT NULL CHECK (category IN ('config','bounds','reset','service','job','access')),
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    target      TEXT NOT NULL,
    reason      TEXT,
    detail      TEXT,
    source      TEXT NOT NULL DEFAULT 'operations',
    source_id   TEXT,
    UNIQUE (source, source_id)
);
"""

HEALTH_INCIDENTS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS health_incidents (
    id                  UUID PRIMARY KEY,
    service             TEXT NOT NULL,
    owning_service      TEXT NOT NULL DEFAULT '',
    probe_target        TEXT NOT NULL DEFAULT '',
    category            TEXT NOT NULL,
    cause               TEXT NOT NULL,
    status              TEXT NOT NULL CHECK (status IN ('active', 'recovered')),
    first_seen          TIMESTAMPTZ NOT NULL,
    last_seen           TIMESTAMPTZ NOT NULL,
    recovered_at        TIMESTAMPTZ,
    sample_count        INTEGER NOT NULL DEFAULT 0,
    failure_count       INTEGER NOT NULL DEFAULT 0,
    consecutive_successes INTEGER NOT NULL DEFAULT 0,
    latency_budget_ms   DOUBLE PRECISION NOT NULL,
    worst_latency_ms    DOUBLE PRECISION NOT NULL,
    samples             JSONB NOT NULL DEFAULT '[]'::jsonb,
    acknowledged_at    TIMESTAMPTZ,
    acknowledged_by    TEXT
);

ALTER TABLE health_incidents ADD COLUMN IF NOT EXISTS owning_service TEXT NOT NULL DEFAULT '';
ALTER TABLE health_incidents ADD COLUMN IF NOT EXISTS probe_target TEXT NOT NULL DEFAULT '';
ALTER TABLE health_incidents ADD COLUMN IF NOT EXISTS acknowledged_at TIMESTAMPTZ;
ALTER TABLE health_incidents ADD COLUMN IF NOT EXISTS acknowledged_by TEXT;
"""

HEALTH_INCIDENTS_DUPLICATE_MIGRATION_SQL = """
WITH ranked AS (
    SELECT id, service,
           row_number() OVER (PARTITION BY service ORDER BY first_seen ASC, id ASC) AS rank
    FROM health_incidents
    WHERE status = 'active'
), duplicates AS (
     SELECT service, (array_agg(id ORDER BY rank))[1] AS keep_id
    FROM ranked
    GROUP BY service
    HAVING count(*) > 1
), stats AS (
    SELECT d.keep_id,
           min(h.first_seen) AS first_seen,
           max(h.last_seen) AS last_seen,
           sum(h.sample_count)::integer AS sample_count,
           sum(h.failure_count)::integer AS failure_count,
           max(h.worst_latency_ms) AS worst_latency_ms,
           max(h.latency_budget_ms) AS latency_budget_ms,
           max(h.consecutive_successes) FILTER (WHERE h.id = d.keep_id) AS consecutive_successes
    FROM duplicates d
    JOIN health_incidents h ON h.service = d.service AND h.status = 'active'
    GROUP BY d.keep_id
), samples AS (
    SELECT d.keep_id,
           jsonb_path_query_array(
               COALESCE(jsonb_agg(elements.value ORDER BY h.last_seen ASC, h.id ASC)
                   FILTER (WHERE elements.value IS NOT NULL), '[]'::jsonb),
               '$[last - 9 to last]'
           ) AS samples
    FROM duplicates d
    JOIN health_incidents h ON h.service = d.service AND h.status = 'active'
    LEFT JOIN LATERAL jsonb_array_elements(
        CASE WHEN jsonb_typeof(h.samples) = 'array' THEN h.samples ELSE '[]'::jsonb END
    ) AS elements(value) ON true
    GROUP BY d.keep_id
), merged AS (
    SELECT stats.*, samples.samples
    FROM stats
    JOIN samples USING (keep_id)
)
UPDATE health_incidents h
SET first_seen = m.first_seen,
    last_seen = m.last_seen,
    sample_count = m.sample_count,
    failure_count = m.failure_count,
    worst_latency_ms = m.worst_latency_ms,
    latency_budget_ms = m.latency_budget_ms,
    consecutive_successes = COALESCE(m.consecutive_successes, 0),
    samples = COALESCE(m.samples, '[]'::jsonb)
FROM merged m
WHERE h.id = m.keep_id;

DELETE FROM health_incidents h
USING (
    SELECT service, (array_agg(id ORDER BY first_seen ASC, id ASC))[1] AS keep_id
    FROM health_incidents
    WHERE status = 'active'
    GROUP BY service
    HAVING count(*) > 1
) duplicates
WHERE h.service = duplicates.service
  AND h.status = 'active'
  AND h.id <> duplicates.keep_id;
"""

HEALTH_INCIDENTS_REQUIRED_COLUMNS = frozenset(
    {
        "id",
        "service",
        "owning_service",
        "probe_target",
        "category",
        "cause",
        "status",
        "first_seen",
        "last_seen",
        "recovered_at",
        "sample_count",
        "failure_count",
        "consecutive_successes",
        "latency_budget_ms",
        "worst_latency_ms",
        "samples",
        "acknowledged_at",
        "acknowledged_by",
    }
)

OPERATIONS_INDEXES_SQL = """
CREATE INDEX IF NOT EXISTS ix_operations_jobs_state_started
    ON operations_jobs (state, started_at DESC);
CREATE INDEX IF NOT EXISTS ix_operations_jobs_type_started
    ON operations_jobs (type, started_at DESC);
CREATE INDEX IF NOT EXISTS ix_operations_jobs_actor_started
    ON operations_jobs (actor, started_at DESC);
CREATE INDEX IF NOT EXISTS ix_operations_audit_at
    ON operations_audit (at DESC);
CREATE INDEX IF NOT EXISTS ix_operations_audit_category_at
    ON operations_audit (category, at DESC);
CREATE INDEX IF NOT EXISTS ix_health_incidents_status_last_seen
    ON health_incidents (status, last_seen DESC);
CREATE INDEX IF NOT EXISTS ix_health_incidents_service_last_seen
    ON health_incidents (service, last_seen DESC);
CREATE UNIQUE INDEX IF NOT EXISTS uq_health_incidents_active_service
    ON health_incidents (service) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS ix_health_incidents_unack_active
    ON health_incidents (last_seen DESC)
    WHERE status = 'active' AND acknowledged_at IS NULL;
"""

BOUNDS_HISTORY_ACTOR_COLUMN = """
ALTER TABLE bounds_history ADD COLUMN IF NOT EXISTS actor TEXT;
"""

FREQUENCY_HISTORY_ACTOR_COLUMN = """
ALTER TABLE frequency_profile_history ADD COLUMN IF NOT EXISTS actor TEXT;
"""

# `ADD COLUMN ... DEFAULT NULL` is metadata-only in PostgreSQL 11+ and so is
# fast in itself, but it still needs an ACCESS EXCLUSIVE lock. Behind a
# long-running reader (or an idle-in-transaction session) on the same table
# the ALTER would queue indefinitely *and* block every subsequent query on
# that table behind it, stalling API bootstrap. A short `lock_timeout` makes
# the migration fail fast instead: the caller treats the timeout as
# non-fatal and the additive column is retried on the next boot.
MIGRATION_LOCK_TIMEOUT = "3s"
MIGRATION_STATEMENT_TIMEOUT = "10s"

OPERATIONS_JOBS_REJECTED_MIGRATION_SQL = """
ALTER TABLE operations_jobs DROP CONSTRAINT IF EXISTS operations_jobs_state_check;
ALTER TABLE operations_jobs ADD CONSTRAINT operations_jobs_state_check
    CHECK (state IN ('queued','running','cancelling','completed','failed','cancelled','rejected'));
UPDATE operations_jobs
SET state = 'rejected', can_retry = false, can_cancel = false
WHERE state = 'failed' AND error = 'runtime retrain cooldown active';
"""

# UI-080 R3: "Change detection modes" records a `detection_gate_change` job.
# `CREATE TABLE IF NOT EXISTS` cannot widen the type constraint on an
# already-deployed database, so every Apply died with
# `psycopg2.errors.CheckViolation` on `operations_jobs_type_check` and
# surfaced as a bare HTTP 500. The explicit drop/add below widens the
# constraint on existing volumes; the CREATE TABLE definition above keeps
# fresh volumes in sync. Both lists must stay equal to
# `otalon_api.domain.operations.job.JobType`.
OPERATIONS_JOBS_TYPE_MIGRATION_SQL = """
ALTER TABLE operations_jobs DROP CONSTRAINT IF EXISTS operations_jobs_type_check;
ALTER TABLE operations_jobs ADD CONSTRAINT operations_jobs_type_check
    CHECK (type IN ('training','ingest','backup','service','maintenance','detection_gate_change'));
"""


def ensure_operations_schema(postgres_repo: PostgresRepository) -> None:
    """Create the operations tables/indexes owned by otalon-api.

    Uses ``IF NOT EXISTS`` throughout so the call is idempotent. The
    ``operations_jobs`` and ``operations_audit`` tables are owned by
    otalon-api and always created here. The additive
    ``bounds_history.actor`` column is handled **separately** by
    :func:`ensure_bounds_history_actor` because ``bounds_history`` is a
    otalon-clas-owned table that may not exist when otalon-api
    bootstraps; folding its ``ALTER`` into this transaction would roll back
    the operations tables if the table were missing.

    Args:
        postgres_repo: Shared PostgresRepository backed by a connection pool.
    """
    with postgres_repo.connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SET statement_timeout = '30s'")
            cur.execute(OPERATIONS_JOBS_TABLE_SQL)
            cur.execute(OPERATIONS_JOBS_REJECTED_MIGRATION_SQL)
            cur.execute(OPERATIONS_JOBS_TYPE_MIGRATION_SQL)
            cur.execute(OPERATIONS_AUDIT_TABLE_SQL)
            cur.execute(HEALTH_INCIDENTS_TABLE_SQL)
            cur.execute(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_schema = 'public' AND table_name = 'health_incidents'"
            )
            columns = {row["column_name"] for row in cur.fetchall()}
            missing = sorted(HEALTH_INCIDENTS_REQUIRED_COLUMNS - columns)
            if missing:
                raise RuntimeError(f"Unsupported health_incidents schema; missing columns: {missing}")
            cur.execute(HEALTH_INCIDENTS_DUPLICATE_MIGRATION_SQL)
            cur.execute(OPERATIONS_INDEXES_SQL)
        conn.commit()

    # Best-effort, order-independent: add the attribution columns only when
    # the otalon-clas-owned tables already exist. Each runs in its own
    # transaction so a missing table never aborts the operations schema.
    ensure_bounds_history_actor(postgres_repo)
    ensure_frequency_history_actor(postgres_repo)


def bootstrap_bounds_history_backfill(postgres_repo: PostgresRepository) -> int:
    """Idempotently backfill historical ``bounds_history`` rows at bootstrap.

    Task 3.2 requires historical pre-WAVE-D bound corrections to *surface*
    in Change Audit, not merely be reachable through a callable helper. This
    runs the one-time idempotent backfill once the operations tables exist so
    the rows appear without operator intervention.

    The underlying repository method is a **safe no-op** when the
    otalon-clas-owned ``bounds_history`` table is absent (guarded by
    ``to_regclass``), so calling this before otalon-clas has bootstrapped
    simply imports nothing and returns ``0``. It is idempotent via the
    ``UNIQUE (source, source_id)`` constraint, so repeated boots never
    duplicate rows.

    Args:
        postgres_repo: Shared PostgresRepository backed by a connection pool.

    Returns:
        The number of historical rows imported on this call (``0`` when the
        table is absent or everything is already imported).
    """
    # Imported lazily to avoid a circular import at module load time
    # (operations_audit_repo imports the domain package, not this module).
    from otalon_api.repositories.operations_audit_repo import OperationsAuditRepository

    imported = OperationsAuditRepository(postgres_repo).backfill_bounds_history()
    if imported:
        logger.info(
            "Backfilled {} historical bounds_history rows into operations_audit",
            imported,
        )
    return imported


def _ensure_history_actor_column(
    postgres_repo: PostgresRepository,
    *,
    table: str,
    ddl: str,
    absent_reason: str,
) -> bool:
    """Run one additive ``actor`` column migration under a short lock timeout.

    Shared by the ``bounds_history`` and ``frequency_profile_history``
    migrations. Both target otalon-clas-owned tables, so a missing table
    is a normal outcome rather than an error. Both also run during API
    bootstrap while the rest of the stack may already be querying those
    tables, so the DDL is bounded by ``lock_timeout``: a blocked ALTER
    fails fast and is retried on the next boot instead of holding an
    ACCESS EXCLUSIVE lock request that queues every later reader behind it.

    Args:
        postgres_repo: Shared PostgresRepository backed by a connection pool.
        table: Unqualified table name in the ``public`` schema.
        ddl: The additive ``ALTER TABLE`` statement to run.
        absent_reason: Explanation logged when the table does not exist yet.

    Returns:
        ``True`` if the column exists after the call, ``False`` if the table
        was absent or the migration timed out waiting for its lock.
    """
    with postgres_repo.connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT to_regclass(%(table)s) AS reg", {"table": f"public.{table}"})
            row = cur.fetchone()
            if not row or row["reg"] is None:
                conn.commit()
                logger.info("{} not present yet; skipping actor column ({})", table, absent_reason)
                return False
            cur.execute(f"SET LOCAL lock_timeout = '{MIGRATION_LOCK_TIMEOUT}'")
            cur.execute(f"SET LOCAL statement_timeout = '{MIGRATION_STATEMENT_TIMEOUT}'")
            try:
                cur.execute(ddl)
            except (errors.LockNotAvailable, errors.QueryCanceled) as exc:
                conn.rollback()
                logger.warning(
                    "{}.actor migration could not acquire its lock within {} "
                    "and was skipped; it retries on the next boot: {}",
                    table,
                    MIGRATION_LOCK_TIMEOUT,
                    exc,
                )
                return False
        conn.commit()
    return True


def ensure_bounds_history_actor(postgres_repo: PostgresRepository) -> bool:
    """Add the nullable ``bounds_history.actor`` column when the table exists.

    ``bounds_history`` is owned by otalon-clas (``create_tables``). This
    migration is additive and safe to run repeatedly. If the table has not
    been created yet, the call is a no-op and returns ``False`` so the
    caller (and otalon-clas' own additive path) remain the source of
    truth for creation order.

    Args:
        postgres_repo: Shared PostgresRepository backed by a connection pool.

    Returns:
        ``True`` if the column exists after the call, ``False`` if the
        table was absent, or the DDL could not take its lock in time.
    """
    return _ensure_history_actor_column(
        postgres_repo,
        table="bounds_history",
        ddl=BOUNDS_HISTORY_ACTOR_COLUMN,
        absent_reason="otalon-clas owns creation, column is additive there too",
    )


def ensure_frequency_history_actor(postgres_repo: PostgresRepository) -> bool:
    """Add the nullable ``frequency_profile_history.actor`` column when present.

    ``frequency_profile_history`` is owned by otalon-clas
    (``create_tables``) and predates the UI-101 correction contract, which
    requires attributing each correction to an operator. The column is
    additive and nullable, so the migration is safe to run repeatedly and
    does not change what otalon-clas writes. It follows the same
    order-independent pattern as :func:`ensure_bounds_history_actor`: when
    the table has not been created yet the call is a no-op.

    Args:
        postgres_repo: Shared PostgresRepository backed by a connection pool.

    Returns:
        ``True`` if the column exists after the call, ``False`` if the
        table was absent, or the DDL could not take its lock in time.
    """
    return _ensure_history_actor_column(
        postgres_repo,
        table="frequency_profile_history",
        ddl=FREQUENCY_HISTORY_ACTOR_COLUMN,
        absent_reason="otalon-clas owns creation, column is additive",
    )
