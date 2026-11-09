"""manual_identity_fields

Seventh Alembic migration for otalon-scan; introduced as part of the
``SCAN-023`` change (operator manual override of asset identity fields
that survives a re-scan).

``ScannerPostgresRepo.upsert_device`` overwrites the identity fields
(``vendor`` / ``device_family`` / ``device_type`` / ``article_number`` /
``firmware_version`` / ``product_name`` / ``hw_version`` / ``sw_version``)
on every scan via the NULL-skipping COALESCE merge. That clobbers a value
an operator manually corrected. This migration adds a per-device
provenance marker so a manually-set value is protected.

Lock-mechanism choice (design): a single nullable-free JSONB array column
``devices.manual_identity_fields`` listing the identity-field names the
operator has locked (e.g. ``["vendor", "firmware_version"]``) is preferred
over eight ``*_locked`` boolean columns because:

1. it is ONE additive column instead of eight;
2. it extends to future identity fields with NO further migration (the
   set of lockable fields is data, not schema);
3. it mirrors the provenance-marker style already used on
   ``network_interfaces`` (the ``source`` column / revision 0003).

This migration is **additive and reversible**. It adds:

1. ``devices.manual_identity_fields JSONB NOT NULL DEFAULT '[]'``

The ``NOT NULL DEFAULT '[]'`` server-default back-fills every existing
row with an empty lock set (no field locked), so legacy rows keep the
unchanged scan-overwrite behaviour. No data migration is required.

``downgrade`` drops exactly this column. Any operator locks recorded
since the upgrade are discarded (the manual *values* themselves stay in
their own identity columns; only the lock marker is removed).

Revision ID: 0007
Revises: 0006
Create Date: 2026-06-21

Refs:
- ``.dev/todo/TODO_otalon-scan.md`` item SCAN-023
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0007"
down_revision: Union[str, None] = "0006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Apply the SCAN-023 manual-identity-lock schema delta.

    Adds the additive ``devices.manual_identity_fields`` JSONB column with
    a ``'[]'`` server-default so every existing row back-fills to an empty
    lock set. The statement is idempotent via ``IF NOT EXISTS`` so a
    partially-applied upgrade can be safely re-run. No existing column is
    altered or dropped.
    """
    op.execute(
        "ALTER TABLE devices " "ADD COLUMN IF NOT EXISTS manual_identity_fields JSONB NOT NULL DEFAULT '[]'::jsonb"
    )


def downgrade() -> None:
    """Reverse the SCAN-023 schema delta.

    Drops exactly the ``manual_identity_fields`` column added by
    :func:`upgrade`. Operator lock markers recorded since the upgrade are
    discarded; the manually-set identity *values* themselves remain in
    their own columns.
    """
    op.execute("ALTER TABLE devices DROP COLUMN IF EXISTS manual_identity_fields")
