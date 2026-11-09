"""B-E1 tests for the device-scoped reads and the vulnerability patch.

Covers the three upstream methods added to close B-E1 (the
``otalon-api`` proxy advertised them but ``otalon-scan`` returned
a route-miss 404):

- :meth:`ScannerPostgresRepo.list_device_scans` — scans that touched a
  device (via its interfaces' service observations or device-scoped
  vulnerability observations).
- :meth:`ScannerPostgresRepo.list_device_observations` — service
  observations for a device's interfaces.
- :meth:`ScannerPostgresRepo.update_vulnerability` — patch the mutable
  triage fields of a vulnerability observation.
- :meth:`ScannerPostgresRepo.device_exists` — existence probe the
  endpoints use to surface a fachliche 404.

Each method is exercised on its happy path and its empty / not-found
path. The tests use the workspace Postgres reachable via
``$POSTGRES_DSN`` (seeded by ``tests/conftest.py``); they ``pytest.skip``
when it is unreachable, and clean up every row they create.
"""

from __future__ import annotations

import os
from typing import AsyncIterator
from uuid import UUID

import pytest
from sqlalchemy import delete, select

from otalon_scan.repositories.models import (
    NetworkInterface,
    Scan,
    ServiceObservation,
    VulnerabilityObservation,
    VulnStatus,
)
from otalon_scan.repositories.postgres_repo import ScannerPostgresRepo
from testsupport import requires_postgres

# Drives real PostgreSQL (schema/migrations/SQL); a mock would not
# exercise what these assert. Skipped (not deleted) when no database is
# reachable, so the suite is green-or-explicit (SUITE-034).
pytestmark = requires_postgres


@pytest.fixture
async def repo() -> AsyncIterator[ScannerPostgresRepo]:
    """Provide a ScannerPostgresRepo bound to the workspace Postgres.

    Skips when ``$POSTGRES_DSN`` is missing or unreachable. The engine is
    disposed at teardown so the pool does not leak.
    """
    dsn = os.environ.get("POSTGRES_DSN")
    if not dsn:
        pytest.skip("POSTGRES_DSN not set; cannot run B-E1 device/vuln tests")
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


async def _make_device(repo: ScannerPostgresRepo) -> int:
    """Create a throwaway device row and return its PK."""
    suffix = os.urandom(3).hex()
    dev = await repo.upsert_device_legacy(
        vendor=f"BE1TestVendor-{suffix}",
        device_type=f"BE1TestPLC-{suffix}",
        notes="__be1_fixture__",
    )
    return int(dev.id)


async def _make_interface(repo: ScannerPostgresRepo, device_id: int) -> int:
    """Create an interface linked to ``device_id`` and return its PK."""
    suffix = os.urandom(3).hex()
    mac = f"02:0b:e1:{suffix[0:2]}:{suffix[2:4]}:{suffix[4:6]}"
    iface = await repo.upsert_interface_legacy(mac=mac)
    await repo.link_interface_to_device(int(iface.id), device_id)
    return int(iface.id)


async def _cleanup(repo: ScannerPostgresRepo, scan_id: UUID, device_id: int) -> None:
    """Remove every row created by a test, in FK-safe order."""
    async with repo._Session() as session:
        async with session.begin():
            await session.execute(delete(ServiceObservation).where(ServiceObservation.scan_id == scan_id))
            await session.execute(delete(VulnerabilityObservation).where(VulnerabilityObservation.scan_id == scan_id))
            await session.execute(delete(Scan).where(Scan.id == scan_id))
            await session.execute(delete(NetworkInterface).where(NetworkInterface.device_id == device_id))
    await repo.delete_device(device_id)


# ---- device_exists ----


async def test_device_exists_true_and_false(repo: ScannerPostgresRepo) -> None:
    """``device_exists`` is True for a real device, False for a phantom id."""
    device_id = await _make_device(repo)
    try:
        assert await repo.device_exists(device_id) is True
        assert await repo.device_exists(999_999_999) is False
    finally:
        await repo.delete_device(device_id)


# ---- list_device_scans ----


async def test_list_device_scans_happy_path(repo: ScannerPostgresRepo) -> None:
    """A scan that wrote an observation for the device is listed."""
    device_id = await _make_device(repo)
    iface_id = await _make_interface(repo, device_id)
    scan_id = await repo.start_scan(module_name="_be1_unit_dev_scans")
    try:
        await repo.upsert_service_observation(
            scan_id=scan_id,
            interface_id=iface_id,
            port=502,
            transport="tcp",
            service_name="modbus",
        )
        rows = await repo.list_device_scans(device_id)
        assert [str(r.id) for r in rows] == [str(scan_id)]
    finally:
        await _cleanup(repo, scan_id, device_id)


async def test_list_device_scans_empty_for_untouched_device(
    repo: ScannerPostgresRepo,
) -> None:
    """An existing device with no observations returns an empty list."""
    device_id = await _make_device(repo)
    try:
        assert await repo.list_device_scans(device_id) == []
    finally:
        await repo.delete_device(device_id)


# ---- list_device_observations ----


async def test_list_device_observations_happy_path(
    repo: ScannerPostgresRepo,
) -> None:
    """Service observations on the device's interfaces are returned."""
    device_id = await _make_device(repo)
    iface_id = await _make_interface(repo, device_id)
    scan_id = await repo.start_scan(module_name="_be1_unit_dev_obs")
    try:
        await repo.upsert_service_observation(
            scan_id=scan_id,
            interface_id=iface_id,
            port=44818,
            transport="tcp",
            service_name="ethernet-ip",
        )
        rows = await repo.list_device_observations(device_id)
        assert len(rows) == 1
        assert rows[0].port == 44818
        assert rows[0].service_name == "ethernet-ip"
    finally:
        await _cleanup(repo, scan_id, device_id)


async def test_list_device_observations_empty(repo: ScannerPostgresRepo) -> None:
    """An existing device with no observations returns an empty list."""
    device_id = await _make_device(repo)
    try:
        assert await repo.list_device_observations(device_id) == []
    finally:
        await repo.delete_device(device_id)


# ---- update_vulnerability ----


async def test_update_vulnerability_happy_path(repo: ScannerPostgresRepo) -> None:
    """Patching status stamps ``status_changed_at`` and persists fields."""
    device_id = await _make_device(repo)
    scan_id = await repo.start_scan(module_name="_be1_unit_vuln_patch")
    try:
        await repo.upsert_vulnerability_observation(
            scan_id=scan_id,
            device_id=device_id,
            vuln_id="CVE-2024-0001",
            severity="HIGH",
            summary="initial",
        )
        async with repo._Session() as session:

            res = await session.execute(
                select(VulnerabilityObservation).where(VulnerabilityObservation.device_id == device_id)
            )
            seeded = res.scalar_one()
            vuln_pk = int(seeded.id)
            assert seeded.status == VulnStatus.ACTIVE
            assert seeded.status_changed_at is None

        updated = await repo.update_vulnerability(
            vuln_pk,
            status=VulnStatus.MITIGATED,
            summary="patched",
            status_changed_by="operator-1",
        )
        assert updated is not None
        assert updated.status == VulnStatus.MITIGATED
        assert updated.summary == "patched"
        assert updated.status_changed_by == "operator-1"
        assert updated.status_changed_at is not None
    finally:
        await _cleanup(repo, scan_id, device_id)


async def test_update_vulnerability_missing_returns_none(
    repo: ScannerPostgresRepo,
) -> None:
    """Patching a non-existent vuln id returns None (caller → 404)."""
    assert await repo.update_vulnerability(999_999_999, status=VulnStatus.RESOLVED) is None


async def test_update_vulnerability_no_status_change_keeps_timestamp(
    repo: ScannerPostgresRepo,
) -> None:
    """Patching only ``severity`` does not stamp ``status_changed_at``."""
    device_id = await _make_device(repo)
    scan_id = await repo.start_scan(module_name="_be1_unit_vuln_sev")
    try:
        await repo.upsert_vulnerability_observation(
            scan_id=scan_id,
            device_id=device_id,
            vuln_id="CVE-2024-0002",
            severity="LOW",
        )
        async with repo._Session() as session:

            res = await session.execute(
                select(VulnerabilityObservation).where(VulnerabilityObservation.device_id == device_id)
            )
            vuln_pk = int(res.scalar_one().id)

        updated = await repo.update_vulnerability(vuln_pk, severity="CRITICAL")
        assert updated is not None
        assert updated.severity == "CRITICAL"
        assert updated.status_changed_at is None
    finally:
        await _cleanup(repo, scan_id, device_id)
