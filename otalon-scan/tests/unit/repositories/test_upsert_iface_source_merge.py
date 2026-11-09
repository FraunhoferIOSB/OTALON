"""Tests for the active-vs-passive merge rule on ``upsert_network_interface``.

Implements task 5.6 of ``add-passive-asset-seeder/tasks.md``: covers
the six rows of the precedence table from design.md ``D-MERGE-RULE``
and the corresponding spec scenarios in
``openspec/changes/add-passive-asset-seeder/specs/``
``scan--persistence-ownership/spec.md``:

- ``New row from active scan defaults to active`` (row 1)
- ``New row from passive seeder`` (row 2)
- ``Repeated call with same MAC refreshes last_scan_at`` (row 3, F-03 wording)
- ``Active never downgrades to passive`` (row 4)
- ``Passive upgrades to active`` (row 5)
- ``Passive idempotent re-observation`` (row 6)
- ``Default source argument preserves F-03 backwards compatibility``

Plus two additional checks pinned by the
``Source Provenance Marker on Network Interfaces`` ADDED requirement:

- ``CHECK constraint rejects unknown source value``
- ``Devices table carries no source column``

Live-Postgres fixture pattern mirrors F-03's ``test_postgres_repo_upsert_parents.py``.
"""

from __future__ import annotations

import os
from typing import AsyncIterator

import pytest
from sqlalchemy import delete, select

from otalon_scan.repositories.models import NetworkInterface
from otalon_scan.repositories.postgres_repo import ScannerPostgresRepo
from testsupport import requires_postgres

# Drives real PostgreSQL (schema/migrations/SQL); a mock would not
# exercise what these assert. Skipped (not deleted) when no database is
# reachable, so the suite is green-or-explicit (SUITE-034).
pytestmark = requires_postgres


@pytest.fixture
async def repo() -> AsyncIterator[ScannerPostgresRepo]:
    """Provide a repo bound to the workspace Postgres at the 0003 head."""
    dsn = os.environ.get("POSTGRES_DSN")
    if not dsn:
        pytest.skip("POSTGRES_DSN not set; cannot run merge-rule tests")
    r = ScannerPostgresRepo(dsn=dsn)
    try:
        await r.verify_schema_revision()
    except RuntimeError as exc:
        await r.dispose()
        pytest.skip(f"PostgreSQL not at 0003 head: {exc}")
    try:
        yield r
    finally:
        await r.dispose()


def _random_mac() -> str:
    """Return a unique LAA-prefixed MAC so concurrent tests do not collide."""
    suffix = os.urandom(3).hex()
    return f"02:fa:00:{suffix[0:2]}:{suffix[2:4]}:{suffix[4:6]}"


async def _cleanup(repo: ScannerPostgresRepo, mac: str) -> None:
    async with repo._Session() as session:
        async with session.begin():
            await session.execute(delete(NetworkInterface).where(NetworkInterface.mac_address == mac))


async def _fetch(repo: ScannerPostgresRepo, mac: str) -> NetworkInterface:
    async with repo._Session() as session:
        res = await session.execute(select(NetworkInterface).where(NetworkInterface.mac_address == mac))
        row = res.scalar_one()
    return row


# ---- Precedence-table row 1 — fresh active ------------------------------------


async def test_row1_fresh_active_inserts_active(repo: ScannerPostgresRepo) -> None:
    """SCENARIO: New row from active scan defaults to active."""
    mac = _random_mac()
    try:
        await repo.upsert_network_interface(mac=mac)
        row = await _fetch(repo, mac)
        assert row.source == "active"
        assert row.first_seen_passive_at is None
        assert row.last_seen_passive_at is None
        assert row.last_scan_at is not None
    finally:
        await _cleanup(repo, mac)


# ---- Precedence-table row 2 — fresh passive -----------------------------------


async def test_row2_fresh_passive_inserts_passive(repo: ScannerPostgresRepo) -> None:
    """SCENARIO: New row from passive seeder."""
    mac = _random_mac()
    try:
        await repo.upsert_network_interface(mac=mac, source="passive")
        row = await _fetch(repo, mac)
        assert row.source == "passive"
        assert row.first_seen_passive_at is not None
        assert row.last_seen_passive_at is not None
        assert row.last_scan_at is None
        assert row.device_id is None
    finally:
        await _cleanup(repo, mac)


# ---- Precedence-table row 3 — active + active = idempotent --------------------


async def test_row3_active_plus_active_is_idempotent(repo: ScannerPostgresRepo) -> None:
    """SCENARIO: Repeated call with same MAC refreshes last_scan_at."""
    mac = _random_mac()
    try:
        await repo.upsert_network_interface(mac=mac)
        first = await _fetch(repo, mac)
        first_last_scan = first.last_scan_at

        # Sleep to let the wall-clock advance past the millisecond
        # boundary so equality comparisons are meaningful.
        import asyncio

        await asyncio.sleep(0.01)
        await repo.upsert_network_interface(mac=mac)
        second = await _fetch(repo, mac)

        assert second.source == "active"
        assert second.last_scan_at is not None
        assert second.last_scan_at >= first_last_scan  # advances (or equals)
        assert second.first_seen_passive_at is None
    finally:
        await _cleanup(repo, mac)


# ---- Precedence-table row 4 — active + passive = active (NO DOWNGRADE) --------


async def test_row4_active_plus_passive_no_downgrade(repo: ScannerPostgresRepo) -> None:
    """SCENARIO: Active never downgrades to passive."""
    mac = _random_mac()
    try:
        await repo.upsert_network_interface(mac=mac, source="active")
        first = await _fetch(repo, mac)
        first_last_scan = first.last_scan_at

        import asyncio

        await asyncio.sleep(0.01)
        await repo.upsert_network_interface(mac=mac, source="passive")
        second = await _fetch(repo, mac)

        assert second.source == "active"  # NO DOWNGRADE
        assert second.last_seen_passive_at is not None  # passive ts refreshed
        # last_scan_at preserved on a passive call (no refresh).
        assert second.last_scan_at == first_last_scan
    finally:
        await _cleanup(repo, mac)


# ---- Precedence-table row 5 — passive + active = active (UPGRADE) -------------


async def test_row5_passive_plus_active_upgrades(repo: ScannerPostgresRepo) -> None:
    """SCENARIO: Passive upgrades to active."""
    mac = _random_mac()
    try:
        await repo.upsert_network_interface(mac=mac, source="passive")
        first = await _fetch(repo, mac)
        first_passive_first = first.first_seen_passive_at
        first_passive_last = first.last_seen_passive_at

        import asyncio

        await asyncio.sleep(0.01)
        await repo.upsert_network_interface(mac=mac, source="active")
        second = await _fetch(repo, mac)

        assert second.source == "active"  # UPGRADE
        assert second.last_scan_at is not None
        # Passive timestamps preserved.
        assert second.first_seen_passive_at == first_passive_first
        assert second.last_seen_passive_at == first_passive_last
    finally:
        await _cleanup(repo, mac)


# ---- Precedence-table row 6 — passive + passive = idempotent ------------------


async def test_row6_passive_plus_passive_is_idempotent(
    repo: ScannerPostgresRepo,
) -> None:
    """SCENARIO: Passive idempotent re-observation."""
    mac = _random_mac()
    try:
        await repo.upsert_network_interface(mac=mac, source="passive")
        first = await _fetch(repo, mac)
        first_first_seen = first.first_seen_passive_at
        first_last_seen = first.last_seen_passive_at

        import asyncio

        await asyncio.sleep(0.01)
        await repo.upsert_network_interface(mac=mac, source="passive")
        second = await _fetch(repo, mac)

        assert second.source == "passive"
        # first_seen_passive_at is immutable after first passive call.
        assert second.first_seen_passive_at == first_first_seen
        # last_seen_passive_at advances.
        assert second.last_seen_passive_at is not None
        assert second.last_seen_passive_at >= first_last_seen
        # last_scan_at remains NULL on a passive-only row.
        assert second.last_scan_at is None
    finally:
        await _cleanup(repo, mac)


# ---- Backwards compatibility — default source is 'active' ---------------------


async def test_default_source_is_active(repo: ScannerPostgresRepo) -> None:
    """SCENARIO: Default source argument preserves F-03 backwards compatibility.

    F-03-era callers omit ``source`` and SHALL behave exactly as
    before: ``source='active'``, ``last_scan_at`` refreshed, passive
    columns untouched.
    """
    mac = _random_mac()
    try:
        # Call without the source kwarg.
        await repo.upsert_network_interface(mac=mac)
        row = await _fetch(repo, mac)
        assert row.source == "active"
        assert row.first_seen_passive_at is None
        assert row.last_seen_passive_at is None
    finally:
        await _cleanup(repo, mac)


# ---- Source column constraint -------------------------------------------------


async def test_check_constraint_rejects_unknown_source(
    repo: ScannerPostgresRepo,
) -> None:
    """SCENARIO: CHECK constraint rejects unknown source value.

    Bypass the helper's ``Literal`` type-hint and issue raw SQL so
    we exercise the DB-level CHECK directly.
    """
    async with repo._Session() as session:
        async with session.begin():
            with pytest.raises(Exception) as excinfo:
                await session.execute(
                    NetworkInterface.__table__.insert().values(
                        mac_address=_random_mac(),
                        source="bogus",
                    )
                )
            msg = str(excinfo.value).lower()
            assert (
                "ck_network_interfaces_source" in msg or "check" in msg or "constraint" in msg
            ), f"expected CHECK violation, got: {msg[:200]}"
            # Rollback so the failed insert does not leak.
            await session.rollback()


async def test_devices_table_has_no_source_column(
    repo: ScannerPostgresRepo,
) -> None:
    """SCENARIO: Devices table carries no source column."""
    async with repo._Session() as session:
        res = await session.execute(select(NetworkInterface))  # type: ignore[arg-type]  # placeholder
        _ = res.first()
        # Real probe via information_schema.
        res2 = await session.execute(NetworkInterface.__table__.select().limit(0))
        _ = res2.first()
    # information_schema lookup via raw SQL.
    async with repo.engine.connect() as conn:
        res3 = await conn.exec_driver_sql(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name='devices' AND column_name IN "
            "('source','first_seen_passive_at','last_seen_passive_at')"
        )
        rows = res3.fetchall()
    assert rows == [], f"devices should have no source-related columns, got {rows}"
