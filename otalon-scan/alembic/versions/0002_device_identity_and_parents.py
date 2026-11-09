"""device_identity_and_parents

Second Alembic migration for otalon-scan; introduced as part of
``refactor-otalon-scan-device-network-ownership-v1`` (F-03).

This migration ships the **device-identity natural key** that F-01
explicitly deferred to F-03 (see F-01 design.md § D-F03-PREREQ and the
F-03 design decision ``D-DEVICE-KEY``). It:

1. Adds ``devices.primary_mac TEXT NULL`` (nullable so legacy rows
   without a known MAC keep working).
2. Adds a partial UNIQUE index ``uq_devices_primary_mac`` on
   ``devices(primary_mac) WHERE primary_mac IS NOT NULL`` so all new
   rows from :meth:`ScannerPostgresRepo.upsert_device` deduplicate on
   the natural key while legacy rows with ``primary_mac IS NULL`` can
   coexist.
3. Adds a CHECK constraint ``ck_devices_primary_mac_format`` enforcing
   canonical lowercase colon-separated MAC format
   (``^[0-9a-f]{2}(:[0-9a-f]{2}){5}$``) on non-NULL values.
4. Best-effort back-fill: copies the lowercased ``mac_address`` of each
   device's first (smallest-id) MAC-bearing ``network_interfaces`` row
   into ``devices.primary_mac`` (per F-03 design.md § D-MIGRATION-PLAN).

``downgrade`` drops the CHECK, the partial UNIQUE index, and the column
in inverse order. Note: downgrade DISCARDS any ``primary_mac`` values
that have been populated since the upgrade; they are regenerable on
re-upgrade via the same back-fill query, so no permanent data is lost
for rows whose ``network_interfaces`` parent still carries the MAC.

Revision ID: 0002
Revises: 0001
Create Date: 2026-05-18

Refs:
- ``openspec/changes/refactor-otalon-scan-device-network-ownership-v1/``
  ``proposal.md`` / ``design.md`` / ``tasks.md``
- ``openspec/specs/scan--persistence-ownership/spec.md`` (delta from
  this change)
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_PRIMARY_MAC_REGEX: str = r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$"


def upgrade() -> None:
    """Apply the F-03 device-identity schema delta.

    Steps run in this order so each statement is valid against the
    schema state produced by the previous step:

    1. Add the nullable ``primary_mac`` column.
    2. Add the CHECK constraint (passes immediately because all existing
       rows have ``primary_mac IS NULL`` and the CHECK admits NULLs).
    3. Add the partial UNIQUE index.
    4. Back-fill ``primary_mac`` from each device's first MAC-bearing
       interface — runs last so the CHECK and UNIQUE are already in
       place and reject any malformed legacy data instead of silently
       admitting it.
    """
    # 1) Add column.
    op.execute("ALTER TABLE devices ADD COLUMN primary_mac TEXT NULL")

    # 2) Add CHECK constraint (CHECK is parsed against existing data,
    #    which is all-NULL, so it succeeds).
    op.execute(
        f"ALTER TABLE devices ADD CONSTRAINT ck_devices_primary_mac_format "
        f"CHECK (primary_mac IS NULL OR primary_mac ~ '{_PRIMARY_MAC_REGEX}')"
    )

    # 3) Add partial UNIQUE index.
    op.execute("CREATE UNIQUE INDEX uq_devices_primary_mac " "ON devices (primary_mac) WHERE primary_mac IS NOT NULL")

    # 4) Best-effort back-fill from each device's first MAC-bearing
    #    interface. Per F-03 design.md § D-MIGRATION-PLAN: rows whose
    #    interfaces have no MAC stay primary_mac IS NULL — the partial
    #    UNIQUE accepts those. The lower() defends against any
    #    pre-existing uppercase MAC strings.
    op.execute(
        """
        UPDATE devices d
        SET primary_mac = lower(ni.mac_address)
        FROM network_interfaces ni
        WHERE ni.device_id = d.id
          AND d.primary_mac IS NULL
          AND ni.mac_address IS NOT NULL
          AND ni.id = (
              SELECT MIN(ni2.id)
              FROM network_interfaces ni2
              WHERE ni2.device_id = d.id
                AND ni2.mac_address IS NOT NULL
          )
        """
    )


def downgrade() -> None:
    """Reverse the F-03 device-identity schema delta.

    Drops the CHECK, the partial UNIQUE index, and the column in
    inverse order. Any ``primary_mac`` values populated since the
    upgrade are discarded; they are regenerable on re-upgrade via the
    back-fill in :func:`upgrade` so no permanent data is lost.
    """
    op.execute("DROP INDEX IF EXISTS uq_devices_primary_mac")
    op.execute("ALTER TABLE devices DROP CONSTRAINT IF EXISTS ck_devices_primary_mac_format")
    op.execute("ALTER TABLE devices DROP COLUMN IF EXISTS primary_mac")
