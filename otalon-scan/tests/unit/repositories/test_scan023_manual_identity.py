"""Tests for the SCAN-023 operator manual-identity override + lock.

Two tiers:

1. **Pure-unit (no DB)** — proves the lock-aware ON CONFLICT update map
   and the ``set_manual_identity`` field-validation logic without a
   PostgreSQL instance, so the lock semantics are verified in the
   ``not integration`` tier (the live stack DSN is intentionally unset
   during SCAN-023 development). These render the compiled SQL of
   :func:`_identity_update_set` and assert that each identity field is
   wrapped in a ``CASE WHEN manual_identity_fields ? '<field>' THEN
   devices.<field> ELSE coalesce(EXCLUDED.<field>, devices.<field>)``
   branch — i.e. a locked field keeps its stored value, an unlocked one
   keeps the NULL-skipping merge.

2. **DB-backed (skips without ``POSTGRES_DSN``)** — proves end-to-end
   that ``upsert_device`` does NOT overwrite a locked field but DOES
   fill an unlocked/empty one, and that ``set_manual_identity`` writes
   the value AND records the lock. Mirrors the SCAN-018 merge-test
   fixture pattern (``test_scan018_snmp_asset_merge.py``). These require
   the schema migrated to the SCAN-023 head (revision 0007); they skip
   cleanly otherwise.
"""

from __future__ import annotations

import os
from typing import AsyncIterator

import pytest
from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.sql.elements import Case

from otalon_scan.repositories.models import Device
from otalon_scan.repositories.postgres_repo import (
    MANUAL_IDENTITY_FIELDS,
    ScannerPostgresRepo,
    _identity_update_set,
)
from testsupport import requires_postgres

# Drives real PostgreSQL (schema/SQL); a mock would not exercise what
# these assert. Skipped (not deleted) when no database is reachable, so
# the suite is green-or-explicit (SUITE-034).
pytestmark = requires_postgres

# ---------------------------------------------------------------------------
# Tier 1 — pure-unit (no DB)
# ---------------------------------------------------------------------------


class TestIdentityUpdateSet:
    """The lock-aware ON CONFLICT update map (structural inspection)."""

    def test_covers_exactly_the_eight_identity_fields(self) -> None:
        """The map SHALL key on exactly the lockable identity fields."""
        stmt = pg_insert(Device)
        update_set = _identity_update_set(stmt)
        assert set(update_set) == set(MANUAL_IDENTITY_FIELDS)
        assert "description" not in update_set
        assert "device_role" not in update_set
        assert "serial_number" not in update_set

    def test_each_field_is_a_case_keyed_on_the_lock_marker(self) -> None:
        """Each branch SHALL be a ``CASE`` guarded by the lock marker.

        A locked field returns the stored ``devices.<field>``; an unlocked
        one falls back to the COALESCE merge. The structural assertions
        (``CASE`` type + the rendered ``manual_identity_fields`` lock guard
        keyed on the field name + a ``coalesce`` fallback) prove the
        lock-aware shape without a live PostgreSQL connection.
        """
        stmt = pg_insert(Device)
        update_set = _identity_update_set(stmt)
        for field, expr in update_set.items():
            assert isinstance(expr, Case), f"{field}: expected a CASE expression"
            sql = str(expr).lower()
            assert "manual_identity_fields" in sql, f"{field}: missing lock guard"
            assert field in sql, f"{field}: lock guard not keyed on field name"
            assert "coalesce" in sql, f"{field}: missing COALESCE fallback"


class TestSetManualIdentityValidation:
    """``set_manual_identity`` argument validation (no DB touched).

    The validation runs before any session is opened, so these assertions
    exercise the guard clauses without a live PostgreSQL connection.
    """

    @pytest.fixture
    def repo(self) -> ScannerPostgresRepo:
        """A repo bound to an unreachable DSN — never connects here."""
        return ScannerPostgresRepo(dsn="postgresql+asyncpg://unused@127.0.0.1:1/none")

    async def test_empty_fields_rejected(self, repo: ScannerPostgresRepo) -> None:
        """An empty field map SHALL raise ValueError before any DB call."""
        with pytest.raises(ValueError, match="no identity fields"):
            await repo.set_manual_identity(1, {})

    async def test_unknown_field_rejected(self, repo: ScannerPostgresRepo) -> None:
        """A non-identity field SHALL raise ValueError before any DB call."""
        with pytest.raises(ValueError, match="not lockable identity fields"):
            await repo.set_manual_identity(1, {"description": "x"})


# ---------------------------------------------------------------------------
# Tier 2 — DB-backed (skips without POSTGRES_DSN / SCAN-023 head)
# ---------------------------------------------------------------------------


@pytest.fixture
async def repo() -> AsyncIterator[ScannerPostgresRepo]:
    """Provide a repo bound to the workspace Postgres at the SCAN-023 head."""
    dsn = os.environ.get("POSTGRES_DSN")
    if not dsn:
        pytest.skip("POSTGRES_DSN not set; cannot run SCAN-023 DB merge tests")
    r = ScannerPostgresRepo(dsn=dsn)
    try:
        await r.verify_schema_revision()
    except RuntimeError as exc:
        await r.dispose()
        pytest.skip(f"PostgreSQL not at SCAN-023 head: {exc}")
    try:
        yield r
    finally:
        await r.dispose()


def _random_mac() -> str:
    """Return a unique LAA-prefixed MAC so concurrent tests do not collide."""
    suffix = os.urandom(3).hex()
    return f"02:23:00:{suffix[0:2]}:{suffix[2:4]}:{suffix[4:6]}"


async def _cleanup(repo: ScannerPostgresRepo, mac: str) -> None:
    async with repo._Session() as session:
        async with session.begin():
            await session.execute(delete(Device).where(Device.primary_mac == mac))


async def _fetch(repo: ScannerPostgresRepo, mac: str) -> Device:
    async with repo._Session() as session:
        res = await session.execute(select(Device).where(Device.primary_mac == mac))
        return res.scalar_one()


async def test_set_manual_identity_sets_value_and_lock(repo: ScannerPostgresRepo) -> None:
    """Acceptance (b): ``set_manual_identity`` sets value AND locks field."""
    mac = _random_mac()
    try:
        device_id = await repo.upsert_device(primary_mac=mac, vendor="AutoVendor")
        updated = await repo.set_manual_identity(device_id, {"vendor": "OperatorVendor"})
        assert updated is not None
        assert updated.vendor == "OperatorVendor"
        assert "vendor" in updated.manual_identity_fields
        row = await _fetch(repo, mac)
        assert row.vendor == "OperatorVendor"
        assert "vendor" in row.manual_identity_fields
    finally:
        await _cleanup(repo, mac)


async def test_upsert_does_not_overwrite_locked_field(repo: ScannerPostgresRepo) -> None:
    """Acceptance (a): a locked field survives a re-scan."""
    mac = _random_mac()
    try:
        device_id = await repo.upsert_device(primary_mac=mac, vendor="AutoVendor")
        await repo.set_manual_identity(device_id, {"vendor": "OperatorVendor"})
        # Simulate a later scan that resolved a (wrong) vendor again.
        await repo.upsert_device(primary_mac=mac, vendor="AutoVendorV2")
        row = await _fetch(repo, mac)
        assert row.vendor == "OperatorVendor"  # locked → preserved
    finally:
        await _cleanup(repo, mac)


async def test_upsert_fills_unlocked_empty_field(repo: ScannerPostgresRepo) -> None:
    """Acceptance (a): an unlocked/empty field IS auto-filled by a scan."""
    mac = _random_mac()
    try:
        device_id = await repo.upsert_device(primary_mac=mac, vendor="AutoVendor")
        # Lock vendor only; firmware_version stays unlocked + empty.
        await repo.set_manual_identity(device_id, {"vendor": "OperatorVendor"})
        await repo.upsert_device(primary_mac=mac, firmware_version="V9.9", vendor="ignored")
        row = await _fetch(repo, mac)
        assert row.vendor == "OperatorVendor"  # locked → preserved
        assert row.firmware_version == "V9.9"  # unlocked + empty → filled
    finally:
        await _cleanup(repo, mac)


async def test_set_manual_identity_missing_device_returns_none(
    repo: ScannerPostgresRepo,
) -> None:
    """A non-existent device id returns None (caller → 404)."""
    assert await repo.set_manual_identity(999_999_999, {"vendor": "X"}) is None
