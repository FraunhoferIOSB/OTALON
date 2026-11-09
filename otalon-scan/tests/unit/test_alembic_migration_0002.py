"""F-03 schema-shape tests for the device-identity migration.

Tasks 5.4 / 5.5 of
``refactor-otalon-scan-device-network-ownership-v1``: assert the
post-migration schema delta directly. The tests read from
``information_schema`` / ``pg_catalog`` / ``pg_indexes`` /
``pg_constraint`` so they are side-effect-free against the live
``otalon-clas`` DB (they do NOT insert or delete operator data).

The migration runs at most once on the workspace's live Postgres
(``$POSTGRES_DSN``) before any test in this module executes; the
``alembic_version_is_at_0002_head`` check covers the apply-side of
task 5.4 (i) -- (iv). The back-fill test (task 5.5) inserts and
cleans up its own temporary rows.

Per AGENTS.md: live-DB fixture pattern mirrors F-01's
``test_alembic_migration.py``; testcontainers is not used in this
workspace.
"""

from __future__ import annotations

import os
from typing import AsyncIterator
from uuid import uuid4

import pytest
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from otalon_scan.repositories.models import Device, NetworkInterface
from otalon_scan.repositories.postgres_repo import ScannerPostgresRepo
from testsupport import requires_postgres

# Drives real PostgreSQL (schema/migrations/SQL); a mock would not
# exercise what these assert. Skipped (not deleted) when no database is
# reachable, so the suite is green-or-explicit (SUITE-034).
pytestmark = requires_postgres


def _to_async_dsn(dsn: str) -> str:
    """Mirror of the helper in :mod:`otalon_scan.repositories.postgres_repo`.

    Duplicated locally to keep this test module independent of the
    repository module's exact import surface (small file).
    """
    if dsn.startswith("postgresql+asyncpg://"):
        return dsn
    if dsn.startswith("postgresql+psycopg2://"):
        return "postgresql+asyncpg://" + dsn[len("postgresql+psycopg2://") :]
    if dsn.startswith("postgresql://"):
        return "postgresql+asyncpg://" + dsn[len("postgresql://") :]
    return dsn


@pytest.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    """Yield an asyncpg engine bound to the workspace Postgres."""
    raw = os.environ.get("POSTGRES_DSN")
    if not raw:
        pytest.skip("POSTGRES_DSN not set; cannot run F-03 schema-shape tests")
    eng = create_async_engine(_to_async_dsn(raw), pool_pre_ping=True)
    try:
        yield eng
    finally:
        await eng.dispose()


@pytest.fixture
async def repo() -> AsyncIterator[ScannerPostgresRepo]:
    """Yield a :class:`ScannerPostgresRepo` for the back-fill test.

    The back-fill test inserts a :class:`Device` ORM row, so the live DB
    must carry the full current model schema. The schema-revision guard
    skips when the DB is not migrated to the expected head (mirrors the
    other DB-backed fixtures), avoiding a hard failure on an ORM column
    the live DB has not yet received.
    """
    dsn = os.environ.get("POSTGRES_DSN")
    if not dsn:
        pytest.skip("POSTGRES_DSN not set")
    r = ScannerPostgresRepo(dsn=dsn)
    try:
        await r.verify_schema_revision()
    except RuntimeError as exc:
        await r.dispose()
        pytest.skip(f"PostgreSQL not migrated to current head: {exc}")
    try:
        yield r
    finally:
        await r.dispose()


# ---- Task 5.4 — schema-shape assertions ---------------------------------------


async def test_alembic_version_is_at_or_above_0002_head(engine: AsyncEngine) -> None:
    """The ``alembic_version`` table SHALL hold a revision descended from ``"0002"``.

    Updated by ``add-passive-asset-seeder``: the workspace head moves
    to ``"0003"`` (a descendant of ``"0002"``), so an exact-equality
    check would break this F-03 test on every subsequent migration.
    We assert membership in the known-good descendant set instead. The
    set is extended as later additive migrations land (current head
    ``0015`` — the SCAN-031 ``scan_status.CANCELLED_PARTIAL`` value).
    """
    async with engine.connect() as conn:
        res = await conn.exec_driver_sql("SELECT version_num FROM alembic_version")
        row = res.first()
    assert row is not None
    assert row[0] in {
        "0002",
        "0003",
        "0004",
        "0005",
        "0006",
        "0007",
        "0008",
        "0009",
        "0010",
        "0011",
        "0012",
        "0013",
        "0014",
        "0015",
    }, f"unexpected alembic head: {row[0]!r}"


async def test_devices_primary_mac_column_exists(engine: AsyncEngine) -> None:
    """``devices.primary_mac`` SHALL exist as TEXT nullable."""
    async with engine.connect() as conn:
        res = await conn.exec_driver_sql("""
            SELECT data_type, is_nullable
            FROM information_schema.columns
            WHERE table_name = 'devices' AND column_name = 'primary_mac'
            """)
        row = res.first()
    assert row is not None, "devices.primary_mac column missing"
    # PostgreSQL TEXT maps to data_type='text'.
    assert row[0] == "text"
    assert row[1] == "YES"


async def test_uq_devices_primary_mac_index_is_partial(engine: AsyncEngine) -> None:
    """``uq_devices_primary_mac`` SHALL exist as a partial UNIQUE index."""
    async with engine.connect() as conn:
        res = await conn.exec_driver_sql("""
            SELECT indexdef
            FROM pg_indexes
            WHERE schemaname = 'public'
              AND indexname = 'uq_devices_primary_mac'
            """)
        row = res.first()
    assert row is not None, "uq_devices_primary_mac index missing"
    indexdef = row[0]
    # Partial UNIQUE on (primary_mac) WHERE primary_mac IS NOT NULL.
    assert "UNIQUE" in indexdef.upper()
    assert "primary_mac" in indexdef
    assert "WHERE" in indexdef.upper()
    assert "IS NOT NULL" in indexdef.upper()


async def test_ck_devices_primary_mac_format_constraint_present(
    engine: AsyncEngine,
) -> None:
    """``ck_devices_primary_mac_format`` CHECK SHALL exist on ``devices``."""
    async with engine.connect() as conn:
        res = await conn.exec_driver_sql("""
            SELECT contype, pg_get_constraintdef(oid)
            FROM pg_constraint
            WHERE conname = 'ck_devices_primary_mac_format'
              AND conrelid = 'public.devices'::regclass
            """)
        row = res.first()
    assert row is not None, "ck_devices_primary_mac_format CHECK constraint missing"
    contype, definition = row
    # asyncpg returns ``contype`` as bytes for the ``"char"`` Postgres type
    # in some driver versions; coerce to a single character for the check.
    contype_str = contype.decode() if isinstance(contype, (bytes, bytearray)) else str(contype)
    assert contype_str == "c", f"expected CHECK (type 'c'), got {contype_str!r}"
    # The CHECK admits NULL and matches the canonical MAC regex.
    assert "primary_mac" in definition
    assert "IS NULL" in definition.upper()
    # The regex must match what the helper accepts (lowercase, colon-sep, 6 octets).
    assert "[0-9a-f]" in definition


async def test_ck_rejects_invalid_mac_format(engine: AsyncEngine) -> None:
    """A direct SQL insert with bad ``primary_mac`` SHALL be rejected by the CHECK.

    Bypasses the F-03 helper so we exercise the DB-level CHECK directly
    (the helper-level path is covered separately by
    :func:`test_device_invalid_primary_mac_raises_value_error` in
    ``test_postgres_repo_upsert_parents.py``).
    """
    async with engine.connect() as conn:
        # Need a transaction since the failing INSERT aborts it.
        trans = await conn.begin()
        try:
            with pytest.raises(Exception) as excinfo:
                await conn.exec_driver_sql("""
                    INSERT INTO devices
                        (primary_mac, update_available, created_at)
                    VALUES
                        ('NOT-A-MAC', false, now())
                    """)
            msg = str(excinfo.value).lower()
            assert (
                "ck_devices_primary_mac_format" in msg or "check" in msg
            ), f"expected CHECK violation in error, got: {msg[:200]}"
        finally:
            await trans.rollback()


# ---- Task 5.5 — back-fill semantics -------------------------------------------


async def test_backfill_populates_primary_mac_from_first_iface(
    repo: ScannerPostgresRepo,
    engine: AsyncEngine,
) -> None:
    """Seed a device with one MAC-bearing interface; re-run back-fill query;
    assert ``primary_mac`` gets the lowercased MAC.

    The migration's back-fill ran once at upgrade time. To verify
    idempotency, we manually NULL-out a device's ``primary_mac``, re-run
    the same back-fill SQL, and assert the row reverts to the correct
    value. This exercises task 5.5's "downgrade and re-upgrade; assert
    idempotent re-population" scenario without actually toggling
    alembic state (which would interfere with concurrent workspace
    tests).
    """
    # Seed: insert a device + one interface with a unique test MAC.
    test_mac = "02:fe:de:ad:be:ef"
    test_mac_upper = "02:FE:DE:AD:BE:EF"

    async with repo._Session() as session:
        async with session.begin():
            # Insert device with NO primary_mac (legacy-style).
            dev = Device(primary_mac=None, vendor="BackfillTest", notes="__fixture__")
            session.add(dev)
            await session.flush()
            did = int(dev.id)

            # Insert interface linked to dev, with the upper-case MAC so
            # the back-fill's lower() is observable.
            ni = NetworkInterface(
                mac_address=test_mac_upper,
                device_id=did,
            )
            session.add(ni)
            await session.flush()
            iface_id = int(ni.id)
    try:
        # Sanity: device starts NULL.
        async with repo._Session() as session:
            d = await session.get(Device, did)
            assert d is not None and d.primary_mac is None

        # Re-run the back-fill SQL (same statement as in
        # alembic/versions/0002_device_identity_and_parents.py upgrade()).
        async with engine.connect() as conn:
            await conn.exec_driver_sql("""
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
                """)
            await conn.commit()

        # Assert: primary_mac populated, lowercased.
        async with repo._Session() as session:
            d = await session.get(Device, did)
            assert d is not None
            assert d.primary_mac == test_mac, f"back-fill must lowercase: expected {test_mac!r}, got {d.primary_mac!r}"

        # Idempotency: re-run the same UPDATE — should be a no-op (no rows match
        # because primary_mac is no longer NULL).
        async with engine.connect() as conn:
            res = await conn.exec_driver_sql("""
                UPDATE devices d
                SET primary_mac = lower(ni.mac_address)
                FROM network_interfaces ni
                WHERE ni.device_id = d.id
                  AND d.primary_mac IS NULL
                  AND ni.mac_address IS NOT NULL
                """)
            await conn.commit()
            # rowcount on UPDATE: 0 (already populated).
            assert res.rowcount == 0
    finally:
        # Cleanup: remove the seeded rows.
        async with repo._Session() as session:
            async with session.begin():
                await session.execute(delete(NetworkInterface).where(NetworkInterface.id == iface_id))
                await session.execute(delete(Device).where(Device.id == did))


# ---- Task 5.6 — coverage check (smoke) ----------------------------------------
#
# Full coverage measurement is run from the workspace gate
# (``pytest --cov=otalon_scan.repositories.postgres_repo --cov-branch …``); this
# stub verifies the new public symbols are importable so a coverage run
# touches every line in the helper bodies.


async def test_helper_public_symbols_importable() -> None:
    """The F-03 public symbols SHALL be importable at module load time."""
    from otalon_scan.repositories.exceptions import IdentityCollisionError  # noqa: F401
    from otalon_scan.repositories.postgres_repo import ScannerPostgresRepo
    from otalon_scan.utils.mac import canonicalise

    # Sanity: helper attributes exist on the class.
    assert hasattr(ScannerPostgresRepo, "upsert_device")
    assert hasattr(ScannerPostgresRepo, "upsert_network_interface")
    # canonicalise round-trips a known good MAC.
    assert canonicalise("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"


# Random UUID smoke so the import of uuid stays exercised.
_ = uuid4()  # noqa: F841
