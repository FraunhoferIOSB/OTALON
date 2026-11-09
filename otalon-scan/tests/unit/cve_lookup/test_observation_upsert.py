"""DB-backed tests for the CVE observation upsert repo (Task 2.4, D5).

Pins the three D5 spec scenarios against the live workspace Postgres
(seeded ``$POSTGRES_DSN``; skips when unreachable):

- Re-lookup updates ``last_seen_at`` without duplicating the row.
- A hit that disappears is soft-marked stale (``metadata.lifecycle =
  'stale'``, audit-stamped ``auto``) and is NEVER deleted.
- An operator-set status (``status_changed_by != 'auto'``) survives an
  auto re-lookup.

The tests create only throwaway rows they own and clean them up; they
never drop tables or touch pre-existing observations.
"""

from __future__ import annotations

import asyncio
import os
from datetime import datetime, timezone
from typing import AsyncIterator

import pytest
from sqlalchemy import delete, select

from otalon_scan.cve_lookup.sources.base import CveHit
from otalon_scan.repositories.models import (
    Device,
    Scan,
    VulnerabilityObservation,
    VulnStatus,
)
from otalon_scan.repositories.postgres_repo import ScannerPostgresRepo
from otalon_scan.repositories.vulnerability_observation_repo import (
    LIFECYCLE_KEY,
    LIFECYCLE_STALE,
    VulnerabilityObservationRepo,
)
from testsupport import requires_postgres

# Drives real PostgreSQL (schema/SQL); a mock would not exercise what
# these assert. Skipped (not deleted) when no database is reachable, so
# the suite is green-or-explicit (SUITE-034).
pytestmark = requires_postgres


@pytest.fixture
async def repo() -> AsyncIterator[ScannerPostgresRepo]:
    """A ScannerPostgresRepo bound to the workspace Postgres (or skip)."""
    dsn = os.environ.get("POSTGRES_DSN")
    if not dsn:
        pytest.skip("POSTGRES_DSN not set; cannot run Task 2.4 upsert tests")
    r = ScannerPostgresRepo(dsn=dsn)
    try:
        await r.verify_schema_revision()
    except RuntimeError as exc:
        await r.dispose()
        pytest.skip(f"PostgreSQL not migrated to expected head: {exc}")
    try:
        yield r
    finally:
        await r.dispose()


async def _new_device(repo: ScannerPostgresRepo) -> int:
    suffix = os.urandom(3).hex()
    dev = await repo.upsert_device_legacy(
        vendor=f"WBTestVendor-{suffix}",
        device_type=f"WBTestPLC-{suffix}",
        notes="__cve_wb_fixture__",
    )
    return int(dev.id)


async def _cleanup(repo: ScannerPostgresRepo, scan_id: object, device_id: int) -> None:
    async with repo._Session() as session:
        async with session.begin():
            await session.execute(
                delete(VulnerabilityObservation).where(VulnerabilityObservation.device_id == device_id)
            )
            await session.execute(delete(Scan).where(Scan.id == scan_id))
            await session.execute(delete(Device).where(Device.id == device_id))


def _hit(vuln_id: str, score: float = 9.8) -> CveHit:
    return CveHit(
        vuln_id=vuln_id,
        severity="critical",
        cvss_score=score,
        summary="test cve",
        metadata={"cvss_raw_scores": {"cvssMetricV31": score}},
    )


async def test_relookup_updates_last_seen_no_duplicate(repo: ScannerPostgresRepo) -> None:
    """A second identical lookup advances last_seen_at, no duplicate row (D5)."""
    scan_id = await repo.start_scan(module_name="_wb_relookup")
    device_id = await _new_device(repo)
    facade = VulnerabilityObservationRepo(repo)
    try:
        await facade.persist_asset_hits(scan_id=scan_id, device_id=device_id, hits=[_hit("CVE-WB-1")])
        async with repo._Session() as session:
            row = (
                await session.execute(
                    select(VulnerabilityObservation).where(VulnerabilityObservation.device_id == device_id)
                )
            ).scalar_one()
            first_seen = row.last_seen_at
            detected = row.detected_at

        await asyncio.sleep(0.05)
        await facade.persist_asset_hits(scan_id=scan_id, device_id=device_id, hits=[_hit("CVE-WB-1")])

        async with repo._Session() as session:
            rows = list(
                (
                    await session.execute(
                        select(VulnerabilityObservation).where(VulnerabilityObservation.device_id == device_id)
                    )
                ).scalars()
            )
        assert len(rows) == 1
        assert rows[0].last_seen_at > first_seen
        assert rows[0].detected_at == detected
    finally:
        await _cleanup(repo, scan_id, device_id)


async def test_disappeared_hit_becomes_stale_not_deleted(repo: ScannerPostgresRepo) -> None:
    """A hit absent from a later lookup is stale-marked, not deleted (D5)."""
    scan_id = await repo.start_scan(module_name="_wb_stale")
    device_id = await _new_device(repo)
    facade = VulnerabilityObservationRepo(repo)
    try:
        await facade.persist_asset_hits(scan_id=scan_id, device_id=device_id, hits=[_hit("CVE-WB-A"), _hit("CVE-WB-B")])
        # Second lookup only returns A → B has disappeared.
        await facade.persist_asset_hits(scan_id=scan_id, device_id=device_id, hits=[_hit("CVE-WB-A")])

        async with repo._Session() as session:
            rows = {
                r.vuln_id: r
                for r in (
                    await session.execute(
                        select(VulnerabilityObservation).where(VulnerabilityObservation.device_id == device_id)
                    )
                ).scalars()
            }
        assert set(rows) == {"CVE-WB-A", "CVE-WB-B"}  # not deleted
        b = rows["CVE-WB-B"]
        assert (b.metadata_json or {}).get(LIFECYCLE_KEY) == LIFECYCLE_STALE
        assert b.status_changed_by == "auto"
        a = rows["CVE-WB-A"]
        assert (a.metadata_json or {}).get(LIFECYCLE_KEY) != LIFECYCLE_STALE
        assert await facade.count_active(device_id) == 1
    finally:
        await _cleanup(repo, scan_id, device_id)


async def test_operator_status_survives_auto_relookup(repo: ScannerPostgresRepo) -> None:
    """An operator-set status is never overwritten by the auto lookup (D5)."""
    scan_id = await repo.start_scan(module_name="_wb_operator_lock")
    device_id = await _new_device(repo)
    facade = VulnerabilityObservationRepo(repo)
    try:
        await facade.persist_asset_hits(scan_id=scan_id, device_id=device_id, hits=[_hit("CVE-WB-OP")])
        # Operator triages it as a false positive.
        async with repo._Session() as session:
            async with session.begin():
                row = (
                    await session.execute(
                        select(VulnerabilityObservation).where(VulnerabilityObservation.device_id == device_id)
                    )
                ).scalar_one()
                row.status = VulnStatus.FALSE_POSITIVE
                row.status_changed_by = "operator:alice"
                row.status_changed_at = datetime.now(tz=timezone.utc)

        # Auto re-lookup where the hit has disappeared.
        await facade.persist_asset_hits(scan_id=scan_id, device_id=device_id, hits=[])

        async with repo._Session() as session:
            row = (
                await session.execute(
                    select(VulnerabilityObservation).where(VulnerabilityObservation.device_id == device_id)
                )
            ).scalar_one()
        assert row.status == VulnStatus.FALSE_POSITIVE
        assert row.status_changed_by == "operator:alice"
        assert (row.metadata_json or {}).get(LIFECYCLE_KEY) != LIFECYCLE_STALE
    finally:
        await _cleanup(repo, scan_id, device_id)
