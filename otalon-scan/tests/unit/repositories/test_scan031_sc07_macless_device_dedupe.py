"""Tests for SC-07 (SUITE-031 audit): the MAC-less device branch of
:meth:`ScannerPostgresRepo.save_findings_batch` blind-INSERTed a new
``devices`` row on every scan and bypassed the SCAN-023 identity lock.

Fix: the branch now correlates the finding's interface (IPv4/IPv6) to its
linked device and merges into that row with the NULL-skipping, lock-aware
semantics of the canonical ``primary_mac`` UPSERT path; only a genuinely
unknown interface yields an INSERT.

Runs against the workspace Postgres at the 0015 head; skips when
``POSTGRES_DSN`` is unset/unreachable, mirroring the neighbouring
``test_scan018_snmp_asset_merge.py`` fixture pattern.
"""

from __future__ import annotations

import os
from typing import AsyncIterator
from uuid import uuid4

import pytest
from sqlalchemy import cast, delete, select
from sqlalchemy.dialects.postgresql import INET

from otalon_scan.core.models import DeviceFinding
from otalon_scan.repositories.models import Device, NetworkInterface
from otalon_scan.repositories.postgres_repo import ScannerPostgresRepo

_MARKER = "__sc07_fixture__"


@pytest.fixture
async def repo() -> AsyncIterator[ScannerPostgresRepo]:
    """Provide a repo bound to the workspace Postgres at the 0015 head."""
    dsn = os.environ.get("POSTGRES_DSN")
    if not dsn:
        pytest.skip("POSTGRES_DSN not set; cannot run SC-07 dedupe tests")
    r = ScannerPostgresRepo(dsn=dsn)
    try:
        await r.verify_schema_revision()
    except Exception as exc:
        await r.dispose()
        pytest.skip(f"PostgreSQL unreachable or unmigrated: {exc}")
    try:
        yield r
    finally:
        await r.dispose()


def _unique_ipv4() -> str:
    """Unique documentation-range IPv4 so concurrent suites never collide."""
    return f"192.0.2.{uuid4().int % 250 + 1}"


async def _devices_for_ipv4(repo: ScannerPostgresRepo, ipv4: str) -> list[Device]:
    """All devices linked to the interface carrying ``ipv4`` plus any
    duplicate rows this fixture's marker produced."""
    async with repo._Session() as session:
        res = await session.execute(
            select(Device)
            .join(NetworkInterface, NetworkInterface.device_id == Device.id)
            .where(NetworkInterface.ipv4_address == cast(ipv4, INET))
        )
        linked = list(res.scalars().all())
        res2 = await session.execute(select(Device).where(Device.notes == _MARKER))
        marked = list(res2.scalars().all())
    seen: dict[int, Device] = {d.id: d for d in linked + marked}
    return list(seen.values())


async def _cleanup(repo: ScannerPostgresRepo, ipv4: str) -> None:
    async with repo._Session() as session:
        async with session.begin():
            await session.execute(delete(NetworkInterface).where(NetworkInterface.ipv4_address == cast(ipv4, INET)))
            await session.execute(delete(Device).where(Device.notes == _MARKER))


async def test_macless_finding_dedupes_across_rescans(repo: ScannerPostgresRepo) -> None:
    """Two scans of the same MAC-less host SHALL yield ONE device row, not
    one duplicate per scan."""
    ipv4 = _unique_ipv4()
    vendor = f"SC07-{uuid4().hex[:8]}"
    try:
        for _ in range(2):
            await repo.save_findings_batch(
                uuid4(),
                [DeviceFinding(ipv4=ipv4, vendor=vendor, product_name="Switch", notes=_MARKER)],
            )
        devices = await _devices_for_ipv4(repo, ipv4)
        dupes = [d for d in devices if d.vendor == vendor]
        assert len(dupes) == 1, f"expected 1 deduped device row, got {len(dupes)} (SC-07 blind INSERT)"
    finally:
        await _cleanup(repo, ipv4)


async def test_macless_merge_honours_identity_lock(repo: ScannerPostgresRepo) -> None:
    """A locked identity field SHALL survive a re-scan of a MAC-less host;
    unlocked fields keep the NULL-skipping merge."""
    ipv4 = _unique_ipv4()
    vendor = f"SC07-{uuid4().hex[:8]}"
    try:
        await repo.save_findings_batch(
            uuid4(),
            [DeviceFinding(ipv4=ipv4, vendor=vendor, product_name="Switch", notes=_MARKER)],
        )
        devices = await _devices_for_ipv4(repo, ipv4)
        assert len(devices) == 1
        device_id = devices[0].id

        locked = await repo.set_manual_identity(device_id, {"vendor": "LockedVendor"})
        assert locked is not None

        await repo.save_findings_batch(
            uuid4(),
            [
                DeviceFinding(
                    ipv4=ipv4,
                    vendor="ScanOverwriteVendor",
                    product_name="Switch-Gen2",
                    notes=_MARKER,
                )
            ],
        )

        devices = await _devices_for_ipv4(repo, ipv4)
        assert len(devices) == 1, f"re-scan created a duplicate device row (SC-07): {len(devices)}"
        row = devices[0]
        assert row.id == device_id
        assert row.vendor == "LockedVendor", "identity lock bypassed by MAC-less merge (SC-07)"
        assert row.product_name == "Switch-Gen2"
    finally:
        await _cleanup(repo, ipv4)


async def test_macless_finding_without_any_address_still_inserts(repo: ScannerPostgresRepo) -> None:
    """Guard: a device-attrs-only finding (no MAC/IP at all) has no dedupe
    key and keeps the legacy single INSERT behaviour."""
    vendor = f"SC07-{uuid4().hex[:8]}"
    try:
        await repo.save_findings_batch(
            uuid4(),
            [DeviceFinding(vendor=vendor, product_name="MysteryBox", notes=_MARKER)],
        )
        devices = await _devices_for_ipv4(repo, "0.0.0.0")  # marker-only lookup
        assert any(d.vendor == vendor for d in devices)
    finally:
        async with repo._Session() as session:
            async with session.begin():
                await session.execute(delete(Device).where(Device.notes == _MARKER))
