"""passive_source_marker

Third Alembic migration for otalon-scan; introduced as part of the
``add-passive-asset-seeder`` OpenSpec change.

This migration ships the schema delta required by the passive asset
seeder. See ``openspec/changes/add-passive-asset-seeder/design.md``
decision ``D-SCHEMA-DELTA`` for the rationale and the precedence table
in ``D-MERGE-RULE`` for the runtime contract the new columns enable.

It is **additive only**:

1. Adds ``network_interfaces.source TEXT NOT NULL DEFAULT 'active'`` so
   every existing row (all of which originate from active scans per the
   post-F-03 invariant) automatically inherits ``source='active'`` via
   the column DEFAULT without requiring a back-fill UPDATE.
2. Adds ``CHECK (source IN ('active', 'passive'))`` constraint
   ``ck_network_interfaces_source`` as the runtime safety net for any
   caller that bypasses the helper's ``Literal["active","passive"]``
   type hint.
3. Adds ``network_interfaces.first_seen_passive_at TIMESTAMPTZ NULL``
   and ``network_interfaces.last_seen_passive_at TIMESTAMPTZ NULL``.
   Both default to NULL on every existing row (legacy rows were never
   observed passively); the passive seeder populates them on first
   passive observation and refreshes ``last_seen_passive_at`` on every
   subsequent passive observation.

No column is added to ``devices``: per Fork 2 = b (operator decision
2026-05-19), device-level ``source`` is derived in the UI by
aggregating over the interfaces linked via ``device_id``.

``downgrade`` drops the two timestamp columns, drops the CHECK
constraint, and finally drops the ``source`` column. Any provenance
markers populated since the upgrade are discarded; they are
regenerable on re-upgrade from the next passive poll cycle so no
permanent data is lost.

Revision ID: 0003
Revises: 0002
Create Date: 2026-05-20

Refs:
- ``openspec/changes/add-passive-asset-seeder/proposal.md``
- ``openspec/changes/add-passive-asset-seeder/design.md``
  decisions ``D-SCHEMA-DELTA`` and ``D-MERGE-RULE``
- ``openspec/changes/add-passive-asset-seeder/specs/``
  ``scan--persistence-ownership/spec.md`` ADDED requirement
  ``Source Provenance Marker on Network Interfaces``
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Apply the passive-source schema delta.

    Steps run in this order so each statement is valid against the
    schema state produced by the previous step:

    1. Add ``source TEXT NOT NULL DEFAULT 'active'``. All existing rows
       inherit ``source='active'`` automatically via the DEFAULT.
    2. Add ``ck_network_interfaces_source`` CHECK constraint. Passes
       immediately because every existing row carries the defaulted
       value ``'active'``, which is admitted by the constraint.
    3. Add the two nullable timestamp columns
       ``first_seen_passive_at`` and ``last_seen_passive_at``. Legacy
       rows keep NULL on both.
    """
    op.execute("ALTER TABLE network_interfaces " "ADD COLUMN source TEXT NOT NULL DEFAULT 'active'")
    op.execute(
        "ALTER TABLE network_interfaces "
        "ADD CONSTRAINT ck_network_interfaces_source "
        "CHECK (source IN ('active', 'passive'))"
    )
    op.execute("ALTER TABLE network_interfaces " "ADD COLUMN first_seen_passive_at TIMESTAMPTZ NULL")
    op.execute("ALTER TABLE network_interfaces " "ADD COLUMN last_seen_passive_at TIMESTAMPTZ NULL")


def downgrade() -> None:
    """Reverse the passive-source schema delta.

    Drops the two timestamp columns, drops the CHECK constraint, and
    finally drops the ``source`` column. Any passive provenance
    markers populated since the upgrade are discarded; they are
    regenerable on re-upgrade from the next passive poll cycle so no
    permanent data is lost outside the new columns themselves.
    """
    op.execute("ALTER TABLE network_interfaces " "DROP COLUMN IF EXISTS last_seen_passive_at")
    op.execute("ALTER TABLE network_interfaces " "DROP COLUMN IF EXISTS first_seen_passive_at")
    op.execute("ALTER TABLE network_interfaces " "DROP CONSTRAINT IF EXISTS ck_network_interfaces_source")
    op.execute("ALTER TABLE network_interfaces " "DROP COLUMN IF EXISTS source")
