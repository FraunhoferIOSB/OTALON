"""snmp_asset_enrichment

Fifth Alembic migration for otalon-scan; introduced as part of the
``SCAN-018`` change (SNMP asset-data enrichment).

The SNMP walker already collects ~17 asset fields per device, but the
persistence pipeline only stored ``vendor`` / ``device_family`` /
``device_type`` / ``article_number`` / ``device_role`` /
``firmware_version``. The asset-inventory-relevant fields
``product_name`` / ``hw_version`` / ``sw_version`` / ``serial_number``
were dropped during the Walker -> ``DeviceFinding`` -> ``devices`` mapping.

This migration is **additive and reversible**. It adds four nullable
columns to the ``devices`` asset master-data table (operator decision D1:
the new fields are device-scoped master-data, one value per device, no
observation-scoped scan history):

1. ``devices.product_name TEXT NULL``
2. ``devices.hw_version TEXT NULL``
3. ``devices.sw_version TEXT NULL``
4. ``devices.serial_number TEXT NULL``

No back-fill is required: legacy rows keep NULL on all four columns and
the values are populated on the next SNMP scan (operator decision D5:
an active SNMP scan overwrites existing values, mirroring the
NULL-skipping COALESCE merge rule already used by ``upsert_device``).

Per operator decision D2, the SNMP ``product_family`` value is mapped
onto the **existing** ``device_family`` column — no new column is added
for it. Per D3, ``firmware_version`` is retained alongside the new
``hw_version`` / ``sw_version`` columns (no replace).

``downgrade`` drops exactly these four columns. Any SNMP asset data
populated since the upgrade is discarded; it is regenerable on the next
SNMP scan so no permanent data is lost outside the new columns
themselves.

Revision ID: 0005
Revises: 0004
Create Date: 2026-06-15

Refs:
- ``.dev/concepts/snmp-asset-enrichment/CONCEPT.md`` decisions D1-D5
- ``.dev/todo/TODO_otalon-scan.md`` item SCAN-018
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0005"
down_revision: Union[str, None] = "0004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_NEW_COLUMNS: tuple[str, ...] = (
    "product_name",
    "hw_version",
    "sw_version",
    "serial_number",
)


def upgrade() -> None:
    """Apply the SCAN-018 SNMP asset-enrichment schema delta.

    Adds four nullable ``TEXT`` columns to ``devices``. All existing
    rows keep NULL on every new column; the SNMP scan populates them on
    the next walk. Each statement is idempotent via ``IF NOT EXISTS`` so
    a partially-applied upgrade can be safely re-run.
    """
    for column in _NEW_COLUMNS:
        op.execute(f"ALTER TABLE devices ADD COLUMN IF NOT EXISTS {column} TEXT NULL")


def downgrade() -> None:
    """Reverse the SCAN-018 schema delta.

    Drops exactly the four columns added by :func:`upgrade`. Any SNMP
    asset data populated since the upgrade is discarded; it is
    regenerable on the next SNMP scan so no permanent data is lost
    outside the new columns themselves.
    """
    for column in reversed(_NEW_COLUMNS):
        op.execute(f"ALTER TABLE devices DROP COLUMN IF EXISTS {column}")
