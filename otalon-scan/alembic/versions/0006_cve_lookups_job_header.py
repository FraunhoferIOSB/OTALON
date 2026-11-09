"""cve_lookups_job_header

Sixth Alembic migration for otalon-scan; introduced as part of the
``SCAN-026`` change (CVE-Lookup als verfolgbarer Job — Welle A).

The CVE lookup is being promoted from a synchronous proxy call into a
tracked async **job** (design.md § D1-D3). This migration adds the job
**header** table ``cve_lookups`` — one row per triggered lookup carrying
its scope/parameters, lifecycle status, an aggregated ``summary`` and an
optional ``error``. The CVE hits themselves continue to live in
``vulnerability_observations`` (Feature 3); ``cve_lookups`` is purely the
job record, mirroring the existing ``scans`` job-record pattern.

This migration is **strictly additive and reversible**. It creates:

1. the Postgres enum type ``cve_lookup_status`` with the values
   ``pending`` / ``running`` / ``completed`` / ``failed`` (the
   ``ScanStatus`` vocabulary, design.md § D1 — kept as its own enum so
   the two job tables stay decoupled);
2. the ``cve_lookups`` table with columns
   ``id`` (uuid PK / job_id), ``scope``, ``device_id``, ``source``,
   ``api_key_used``, ``status``, ``summary`` (jsonb), ``error``,
   ``started_at`` / ``finished_at``, ``created_at`` / ``updated_at``;
3. an index ``ix_cve_lookups_started_at`` supporting the
   newest-first Recent-Lookups list (Welle B).

NO existing table is touched (no ALTER / DROP / TRUNCATE / DELETE) — the
hits stay in ``vulnerability_observations`` unchanged. ``downgrade`` drops
exactly the table and the enum type it created.

Revision ID: 0006
Revises: 0005
Create Date: 2026-06-21

Refs:
- ``openspec/changes/cve-lookup-job/design.md`` decision D1
- ``.dev/concepts/cve-lookup-job/CONCEPT.md`` §6 / §7 Fork 1a
- ``.dev/todo/TODO_otalon-scan.md`` item SCAN-026
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0006"
down_revision: Union[str, None] = "0005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Apply the SCAN-026 CVE-lookup job-header schema delta.

    Creates the ``cve_lookup_status`` enum type and the additive
    ``cve_lookups`` job-header table plus its newest-first index. Every
    statement is idempotent (``IF NOT EXISTS`` / guarded ``DO`` block) so
    a partially-applied upgrade can be safely re-run. No existing table
    is modified.
    """
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_type WHERE typname = 'cve_lookup_status'
            ) THEN
                CREATE TYPE cve_lookup_status AS ENUM (
                    'pending', 'running', 'completed', 'failed'
                );
            END IF;
        END$$;
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS cve_lookups (
            id uuid PRIMARY KEY,
            scope text NOT NULL,
            device_id integer NULL,
            source text NOT NULL DEFAULT 'nvd',
            api_key_used boolean NOT NULL DEFAULT false,
            status cve_lookup_status NOT NULL DEFAULT 'pending',
            summary jsonb NULL,
            error text NULL,
            started_at timestamptz NOT NULL DEFAULT now(),
            finished_at timestamptz NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            updated_at timestamptz NULL
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_cve_lookups_started_at ON cve_lookups (started_at)")


def downgrade() -> None:
    """Reverse the SCAN-026 schema delta.

    Drops the ``cve_lookups`` table and the ``cve_lookup_status`` enum
    type created by :func:`upgrade`. Any job-header rows recorded since
    the upgrade are discarded; the CVE hits in
    ``vulnerability_observations`` are untouched.
    """
    op.execute("DROP INDEX IF EXISTS ix_cve_lookups_started_at")
    op.execute("DROP TABLE IF EXISTS cve_lookups")
    op.execute("DROP TYPE IF EXISTS cve_lookup_status")
