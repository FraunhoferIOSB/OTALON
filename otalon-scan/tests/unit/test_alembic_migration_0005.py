"""Schema-shape tests for the ``0005_snmp_asset_enrichment`` migration.

SCAN-018 adds four additive nullable columns to ``devices``
(``product_name`` / ``hw_version`` / ``sw_version`` / ``serial_number``).
These tests read from ``information_schema`` so they are side-effect-free
against the live ``otalon-clas`` database and skip when ``POSTGRES_DSN`` is
unset.

Maps to operator decisions in
``.dev/concepts/snmp-asset-enrichment/CONCEPT.md``:

- D1: the new fields live on ``devices`` (asset master-data).
- D2: no ``product_family`` column is added (mapped onto ``device_family``).
- D3: ``firmware_version`` is retained alongside ``hw_version`` /
  ``sw_version``.
"""

from __future__ import annotations

import os
from typing import AsyncIterator

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from testsupport import requires_postgres

# Drives real PostgreSQL (schema/migrations/SQL); a mock would not
# exercise what these assert. Skipped (not deleted) when no database is
# reachable, so the suite is green-or-explicit (SUITE-034).
pytestmark = requires_postgres


def _to_async_dsn(dsn: str) -> str:
    if dsn.startswith("postgresql+asyncpg://"):
        return dsn
    if dsn.startswith("postgresql+psycopg2://"):
        return "postgresql+asyncpg://" + dsn[len("postgresql+psycopg2://") :]
    if dsn.startswith("postgresql://"):
        return "postgresql+asyncpg://" + dsn[len("postgresql://") :]
    return dsn


@pytest.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    raw = os.environ.get("POSTGRES_DSN")
    if not raw:
        pytest.skip("POSTGRES_DSN not set; cannot run 0005 schema tests")
    eng = create_async_engine(_to_async_dsn(raw), pool_pre_ping=True)
    try:
        yield eng
    finally:
        await eng.dispose()


async def test_alembic_head_at_least_0005(engine: AsyncEngine) -> None:
    """The DB SHALL be migrated at or past the SCAN-018 revision ``"0005"``.

    SCAN-026 added revision ``0006`` on top of this one; the SCAN-018
    columns asserted below are additive and remain present regardless of
    the exact head, so this guard only requires the schema to be at least
    at the ``0005`` baseline (string compare is safe for the zero-padded
    numeric revision ids).
    """
    async with engine.connect() as conn:
        res = await conn.exec_driver_sql("SELECT version_num FROM alembic_version")
        row = res.first()
    assert row is not None
    assert row[0] >= "0005"


@pytest.mark.parametrize(
    "column",
    ["product_name", "hw_version", "sw_version", "serial_number"],
)
async def test_new_asset_column_exists_nullable_text(engine: AsyncEngine, column: str) -> None:
    """Each SCAN-018 column SHALL exist as a nullable TEXT column on ``devices``."""
    async with engine.connect() as conn:
        res = await conn.exec_driver_sql(
            "SELECT data_type, is_nullable "
            "FROM information_schema.columns "
            f"WHERE table_name = 'devices' AND column_name = '{column}'"
        )
        row = res.first()
    assert row is not None, f"devices.{column} column missing"
    assert row[0] == "text"
    assert row[1] == "YES"


async def test_no_product_family_column_added(engine: AsyncEngine) -> None:
    """D2: no ``product_family`` column SHALL be added (mapped to device_family)."""
    async with engine.connect() as conn:
        res = await conn.exec_driver_sql(
            """
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = 'devices' AND column_name = 'product_family'
            """
        )
        rows = res.fetchall()
    assert rows == [], "devices.product_family must NOT exist (D2: use device_family)"


async def test_firmware_version_retained(engine: AsyncEngine) -> None:
    """D3: ``firmware_version`` SHALL remain present alongside the new columns."""
    async with engine.connect() as conn:
        res = await conn.exec_driver_sql(
            """
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = 'devices' AND column_name = 'firmware_version'
            """
        )
        row = res.first()
    assert row is not None, "devices.firmware_version must be retained (D3)"
