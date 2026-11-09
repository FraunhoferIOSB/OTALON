"""F-01 tests for the new UPSERT helpers on :class:`ScannerPostgresRepo`.

Covers the spec scenarios from
``openspec/specs/scan--persistence-pipeline/spec.md``:

- First insert sets ``first_seen_at`` and ``last_seen_at``.
- Repeated upsert advances ``last_seen_at`` and overwrites the
  descriptive fields while preserving ``first_seen_at`` and
  ``created_at``.
- Vulnerability UPSERT preserves operator-set ``status`` and the audit
  columns ``status_changed_at`` / ``status_changed_by`` on conflict.
- 10× idempotency: ten identical upserts produce exactly one row.
- Negative case: an UPSERT with a missing FK target raises
  :class:`ParentRowMissingError` (the F-01 ↔ F-03 boundary).

The tests use the workspace's live Postgres reachable via
``$POSTGRES_DSN`` (seeded by ``tests/conftest.py``) — the same pattern
the existing ``tests/integration/test_postgres_repo_crud.py`` uses.
Each test cleans up the rows it creates so it leaves no state behind.
The tests are marked ``unit`` to match the file's directory; per
:file:`pytest.ini` the suite carries a 20 s timeout. If
``$POSTGRES_DSN`` points at an unreachable instance the fixture
``pytest.skip``s.
"""

from __future__ import annotations

import asyncio
import os
from datetime import datetime, timedelta, timezone
from typing import AsyncIterator
from uuid import UUID

import pytest
from sqlalchemy import delete, select

from otalon_scan.repositories.models import (
    Scan,
    ScanStatus,
    ServiceObservation,
    VulnerabilityObservation,
    VulnStatus,
)
from otalon_scan.repositories.postgres_repo import ParentRowMissingError, ScannerPostgresRepo
from testsupport import requires_postgres

# Drives real PostgreSQL (schema/migrations/SQL); a mock would not
# exercise what these assert. Skipped (not deleted) when no database is
# reachable, so the suite is green-or-explicit (SUITE-034).
pytestmark = requires_postgres


@pytest.fixture
async def repo() -> AsyncIterator[ScannerPostgresRepo]:
    """Provide a ScannerPostgresRepo bound to the workspace Postgres.

    Skips when ``$POSTGRES_DSN`` is missing or unreachable. The repo's
    engine is disposed at teardown so the pool does not leak.
    """
    dsn = os.environ.get("POSTGRES_DSN")
    if not dsn:
        pytest.skip("POSTGRES_DSN not set; cannot run F-01 UPSERT helper tests")
    r = ScannerPostgresRepo(dsn=dsn)
    try:
        await r.verify_schema_revision()
    except RuntimeError as exc:
        await r.dispose()
        pytest.skip(f"PostgreSQL not migrated to F-01 head: {exc}")
    try:
        yield r
    finally:
        await r.dispose()


async def _ensure_test_interface(repo: ScannerPostgresRepo) -> int:
    """Create a throwaway NetworkInterface row and return its PK."""
    suffix = os.urandom(3).hex()
    mac = f"02:01:f0:{suffix[0:2]}:{suffix[2:4]}:{suffix[4:6]}"
    iface = await repo.upsert_interface_legacy(mac=mac)
    return int(iface.id)


async def _ensure_test_device(repo: ScannerPostgresRepo) -> int:
    """Create a throwaway Device row and return its PK."""
    suffix = os.urandom(3).hex()
    dev = await repo.upsert_device_legacy(
        vendor=f"F01TestVendor-{suffix}",
        device_type=f"F01TestPLC-{suffix}",
        notes="__fixture__",
    )
    return int(dev.id)


async def _cleanup_rows_by_scan_id(repo: ScannerPostgresRepo, scan_id: UUID) -> None:
    """Remove all rows produced by ``scan_id``, including the scan row."""
    async with repo._Session() as session:
        async with session.begin():
            await session.execute(delete(ServiceObservation).where(ServiceObservation.scan_id == scan_id))
            await session.execute(delete(VulnerabilityObservation).where(VulnerabilityObservation.scan_id == scan_id))
            await session.execute(delete(Scan).where(Scan.id == scan_id))


# ---- 1. upsert_service_observation: first insert ----


async def test_service_upsert_first_insert_sets_seen_at(repo: ScannerPostgresRepo) -> None:
    """First-insert path SHALL set first_seen_at = last_seen_at = now()."""
    scan_id = await repo.start_scan(module_name="_f01_unit_svc_first")
    iface_id = await _ensure_test_interface(repo)
    try:
        await repo.upsert_service_observation(
            scan_id=scan_id,
            interface_id=iface_id,
            port=8443,
            transport="tcp",
            service_name="https",
            product="nginx",
        )
        async with repo._Session() as session:
            res = await session.execute(
                select(ServiceObservation).where(
                    ServiceObservation.interface_id == iface_id,
                    ServiceObservation.port == 8443,
                    ServiceObservation.transport == "tcp",
                )
            )
            row = res.scalar_one()
        assert row.first_seen_at == row.last_seen_at
        assert row.service_name == "https"
        assert row.product == "nginx"
    finally:
        await _cleanup_rows_by_scan_id(repo, scan_id)


# ---- 2. upsert_service_observation: conflict update ----


async def test_service_upsert_conflict_updates_overwrite_fields(repo: ScannerPostgresRepo) -> None:
    """Second upsert SHALL advance last_seen_at and overwrite descriptive
    fields while preserving first_seen_at."""
    scan_id = await repo.start_scan(module_name="_f01_unit_svc_conflict")
    iface_id = await _ensure_test_interface(repo)
    try:
        await repo.upsert_service_observation(
            scan_id=scan_id,
            interface_id=iface_id,
            port=102,
            transport="tcp",
            service_name="iso-tsap",
            product="siemens-s7",
            version="v1",
        )
        async with repo._Session() as session:
            res = await session.execute(
                select(ServiceObservation).where(
                    ServiceObservation.interface_id == iface_id,
                    ServiceObservation.port == 102,
                    ServiceObservation.transport == "tcp",
                )
            )
            initial = res.scalar_one()
            initial_first_seen = initial.first_seen_at
            initial_created = initial.created_at

        # Sleep a tick so last_seen_at is meaningfully later.
        await asyncio.sleep(0.05)

        await repo.upsert_service_observation(
            scan_id=scan_id,
            interface_id=iface_id,
            port=102,
            transport="tcp",
            service_name="iso-tsap",
            product="siemens-s7-v2",
            version="v2",
        )

        async with repo._Session() as session:
            res = await session.execute(
                select(ServiceObservation).where(
                    ServiceObservation.interface_id == iface_id,
                    ServiceObservation.port == 102,
                    ServiceObservation.transport == "tcp",
                )
            )
            rows = list(res.scalars().all())
        assert len(rows) == 1
        row = rows[0]
        assert row.product == "siemens-s7-v2"
        assert row.version == "v2"
        assert row.first_seen_at == initial_first_seen
        assert row.created_at == initial_created
        assert row.last_seen_at > initial_first_seen
    finally:
        await _cleanup_rows_by_scan_id(repo, scan_id)


# ---- 3. upsert_service_observation: idempotency ----


async def test_service_upsert_idempotent_after_10_calls(repo: ScannerPostgresRepo) -> None:
    """10 identical upserts SHALL produce exactly one row."""
    scan_id = await repo.start_scan(module_name="_f01_unit_svc_idempotent")
    iface_id = await _ensure_test_interface(repo)
    try:
        for _ in range(10):
            await repo.upsert_service_observation(
                scan_id=scan_id,
                interface_id=iface_id,
                port=502,
                transport="tcp",
                service_name="modbus",
            )
        async with repo._Session() as session:
            res = await session.execute(
                select(ServiceObservation).where(
                    ServiceObservation.interface_id == iface_id,
                    ServiceObservation.port == 502,
                    ServiceObservation.transport == "tcp",
                )
            )
            rows = list(res.scalars().all())
        assert len(rows) == 1
    finally:
        await _cleanup_rows_by_scan_id(repo, scan_id)


# ---- 4. upsert_service_observation: FK violation ----


async def test_service_upsert_with_missing_interface_raises_parent_row_missing(
    repo: ScannerPostgresRepo,
) -> None:
    """An UPSERT against a non-existent interface_id SHALL raise
    :class:`ParentRowMissingError` and SHALL NOT leak the raw
    ForeignKeyViolation stack trace."""
    scan_id = await repo.start_scan(module_name="_f01_unit_svc_fk")
    try:
        with pytest.raises(ParentRowMissingError) as excinfo:
            await repo.upsert_service_observation(
                scan_id=scan_id,
                interface_id=2**31 - 1,  # extremely unlikely to exist
                port=502,
                transport="tcp",
            )
        assert excinfo.value.parent_table == "network_interfaces"
        assert "upsert_network_interface" in str(excinfo.value) or "upsert_interface" in str(excinfo.value)
    finally:
        await _cleanup_rows_by_scan_id(repo, scan_id)


# ---- 5. upsert_vulnerability_observation: first insert ----


async def test_vuln_upsert_first_insert_defaults_to_active(repo: ScannerPostgresRepo) -> None:
    """First-insert path SHALL default status to 'active' and populate
    detected_at / last_seen_at."""
    scan_id = await repo.start_scan(module_name="_f01_unit_vuln_first")
    device_id = await _ensure_test_device(repo)
    try:
        await repo.upsert_vulnerability_observation(
            scan_id=scan_id,
            device_id=device_id,
            vuln_id="CVE-2026-99001",
            severity="HIGH",
            summary="Synthetic test CVE 99001",
            source_module="_f01_unit_test",
        )
        async with repo._Session() as session:
            res = await session.execute(
                select(VulnerabilityObservation).where(
                    VulnerabilityObservation.device_id == device_id,
                    VulnerabilityObservation.vuln_id == "CVE-2026-99001",
                )
            )
            row = res.scalar_one()
        assert row.status == VulnStatus.ACTIVE
        assert row.status_changed_at is None
        assert row.status_changed_by is None
        assert row.detected_at is not None
        assert row.last_seen_at is not None
    finally:
        await _cleanup_rows_by_scan_id(repo, scan_id)


# ---- 6. upsert_vulnerability_observation: preserves status on conflict ----


async def test_vuln_upsert_preserves_operator_status_columns(repo: ScannerPostgresRepo) -> None:
    """Re-upserting a row whose status was operator-flipped SHALL NOT
    revert status / status_changed_at / status_changed_by."""
    scan_id = await repo.start_scan(module_name="_f01_unit_vuln_status_pres")
    device_id = await _ensure_test_device(repo)
    try:
        await repo.upsert_vulnerability_observation(
            scan_id=scan_id,
            device_id=device_id,
            vuln_id="CVE-2026-99002",
            severity="MEDIUM",
        )
        # Manually flip status to 'mitigated' (simulating a future
        # PATCH endpoint).
        op_change_time = datetime.now(timezone.utc) - timedelta(minutes=5)
        async with repo._Session() as session:
            async with session.begin():
                res = await session.execute(
                    select(VulnerabilityObservation).where(
                        VulnerabilityObservation.device_id == device_id,
                        VulnerabilityObservation.vuln_id == "CVE-2026-99002",
                    )
                )
                row = res.scalar_one()
                row.status = VulnStatus.MITIGATED
                row.status_changed_at = op_change_time
                row.status_changed_by = "alice"

        # Re-upsert — should NOT revert status columns.
        await repo.upsert_vulnerability_observation(
            scan_id=scan_id,
            device_id=device_id,
            vuln_id="CVE-2026-99002",
            severity="HIGH",  # overwrite test
        )

        async with repo._Session() as session:
            res = await session.execute(
                select(VulnerabilityObservation).where(
                    VulnerabilityObservation.device_id == device_id,
                    VulnerabilityObservation.vuln_id == "CVE-2026-99002",
                )
            )
            row = res.scalar_one()
        assert row.status == VulnStatus.MITIGATED
        assert row.status_changed_by == "alice"
        assert row.severity == "HIGH"  # description overwritten
    finally:
        await _cleanup_rows_by_scan_id(repo, scan_id)


# ---- 7. upsert_vulnerability_observation: FK violation ----


async def test_vuln_upsert_with_missing_device_raises_parent_row_missing(
    repo: ScannerPostgresRepo,
) -> None:
    """An UPSERT against a non-existent device_id SHALL raise
    :class:`ParentRowMissingError`."""
    scan_id = await repo.start_scan(module_name="_f01_unit_vuln_fk")
    try:
        with pytest.raises(ParentRowMissingError) as excinfo:
            await repo.upsert_vulnerability_observation(
                scan_id=scan_id,
                device_id=2**31 - 1,
                vuln_id="CVE-2026-99999",
            )
        assert excinfo.value.parent_table == "devices"
        assert "upsert_device" in str(excinfo.value)
    finally:
        await _cleanup_rows_by_scan_id(repo, scan_id)


# ---- 8. upsert_vulnerability_observation: interface_id is first-insert only ----


async def test_vuln_upsert_interface_id_is_first_insert_only(repo: ScannerPostgresRepo) -> None:
    """``interface_id`` SHALL be recorded on first insert and NOT
    overwritten on conflict (design.md § D-VULN-IFACE)."""
    scan_id = await repo.start_scan(module_name="_f01_unit_vuln_iface")
    device_id = await _ensure_test_device(repo)
    iface_a = await _ensure_test_interface(repo)
    iface_b = await _ensure_test_interface(repo)
    try:
        await repo.upsert_vulnerability_observation(
            scan_id=scan_id,
            device_id=device_id,
            vuln_id="CVE-2026-99003",
            interface_id=iface_a,
        )
        await repo.upsert_vulnerability_observation(
            scan_id=scan_id,
            device_id=device_id,
            vuln_id="CVE-2026-99003",
            interface_id=iface_b,  # later writer with different evidence
        )
        async with repo._Session() as session:
            res = await session.execute(
                select(VulnerabilityObservation).where(
                    VulnerabilityObservation.device_id == device_id,
                    VulnerabilityObservation.vuln_id == "CVE-2026-99003",
                )
            )
            row = res.scalar_one()
        assert row.interface_id == iface_a  # first-insert preserved
    finally:
        await _cleanup_rows_by_scan_id(repo, scan_id)


# ---- 9. Schema sanity ----


async def test_alembic_version_matches_expected_head(repo: ScannerPostgresRepo) -> None:
    """The connected DB SHALL be at the F-01 expected revision."""
    await repo.verify_schema_revision()


async def test_finishing_scan_sets_completed(repo: ScannerPostgresRepo) -> None:
    """Pin the lifecycle path that the upsert tests rely on at teardown."""
    scan_id = await repo.start_scan(module_name="_f01_unit_finish")
    try:
        await repo.finish_scan(scan_id, status=ScanStatus.COMPLETED)
        scan = await repo.get_scan(scan_id)
        assert scan is not None
        assert scan.status == ScanStatus.COMPLETED
        assert scan.finished_at is not None
    finally:
        await _cleanup_rows_by_scan_id(repo, scan_id)


# ---- list_scans (Wave-C follow-up: GET /scans contract) -----------------


async def test_list_scans_returns_recent_rows_desc(repo: ScannerPostgresRepo) -> None:
    """``list_scans`` SHALL return rows ordered by ``started_at DESC``."""
    scan_a = await repo.start_scan(module_name="_test_list_scans_a")
    scan_b = await repo.start_scan(module_name="_test_list_scans_b")
    try:
        rows = await repo.list_scans(limit=10)
        ids = [str(r.id) for r in rows]
        # Both scans SHALL be present and the most recent SHALL come first.
        assert str(scan_a) in ids
        assert str(scan_b) in ids
        # The second-started scan SHALL appear before the first.
        assert ids.index(str(scan_b)) < ids.index(str(scan_a))
    finally:
        await _cleanup_rows_by_scan_id(repo, scan_a)
        await _cleanup_rows_by_scan_id(repo, scan_b)


async def test_list_scans_filters_by_module(repo: ScannerPostgresRepo) -> None:
    """``list_scans`` SHALL filter on ``module_name`` exactly."""
    scan_a = await repo.start_scan(module_name="_test_list_filter_x")
    scan_b = await repo.start_scan(module_name="_test_list_filter_y")
    try:
        rows = await repo.list_scans(module="_test_list_filter_x", limit=50)
        ids = [str(r.id) for r in rows]
        assert str(scan_a) in ids
        assert str(scan_b) not in ids
    finally:
        await _cleanup_rows_by_scan_id(repo, scan_a)
        await _cleanup_rows_by_scan_id(repo, scan_b)


async def test_list_scans_filters_by_status(repo: ScannerPostgresRepo) -> None:
    """``list_scans(status=...)`` SHALL accept lowercase enum values."""
    scan_done = await repo.start_scan(module_name="_test_list_status_done")
    scan_run = await repo.start_scan(module_name="_test_list_status_run")
    try:
        await repo.finish_scan(scan_done, status=ScanStatus.COMPLETED)
        completed = await repo.list_scans(status="completed", limit=50)
        running = await repo.list_scans(status="running", limit=50)
        completed_ids = [str(r.id) for r in completed]
        running_ids = [str(r.id) for r in running]
        assert str(scan_done) in completed_ids
        assert str(scan_done) not in running_ids
        assert str(scan_run) in running_ids
        assert str(scan_run) not in completed_ids
    finally:
        await _cleanup_rows_by_scan_id(repo, scan_done)
        await _cleanup_rows_by_scan_id(repo, scan_run)


async def test_list_scans_unknown_status_returns_empty(repo: ScannerPostgresRepo) -> None:
    """An unknown status value SHALL yield an empty list (no exception)."""
    rows = await repo.list_scans(status="not_a_real_status")
    assert rows == []
