"""Tests for alembic migration 0015 (SC-02, SUITE-031 audit).

SC-02: :class:`~otalon_scan.repositories.models.ScanStatus` defines
``CANCELLED_PARTIAL`` (ORM, ``models.py``) but no migration added the value
to the ``scan_status`` Postgres enum, so every D4 cancel wrote an invalid
enum label and the scan stranded at ``RUNNING``.

Label-case note: the ORM column is ``SQLEnum(ScanStatus, name="scan_status")``
WITHOUT ``values_callable``, so SQLAlchemy persists the enum *member names*
(uppercase) as labels — the live database carries
``{PENDING,RUNNING,COMPLETED,FAILED,ABORTED}``. The migration therefore adds
``'CANCELLED_PARTIAL'`` (uppercase), matching the driver-visible label.

The schema-shape tests run against the workspace Postgres and skip when
``POSTGRES_DSN`` is unset/unreachable, mirroring ``test_alembic_migration.py``.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from typing import Any, AsyncIterator

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

_MIGRATION_PATH = Path(__file__).resolve().parents[2] / "alembic" / "versions" / "0015_scan_status_cancelled_partial.py"

# The ORM-visible member names for the scan_status enum (member-name label
# convention — see module docstring), in declaration order.
_SCAN_STATUS_LABELS: tuple[str, ...] = (
    "PENDING",
    "RUNNING",
    "COMPLETED",
    "FAILED",
    "ABORTED",
    "CANCELLED_PARTIAL",
)


def _load_migration() -> Any:
    """Import the 0015 migration module by path (no package import side effects)."""
    spec = importlib.util.spec_from_file_location("migration_0015", _MIGRATION_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _to_async_dsn(dsn: str) -> str:
    if dsn.startswith("postgresql+asyncpg://"):
        return dsn
    for prefix in ("postgresql+psycopg2://", "postgresql://", "postgres://"):
        if dsn.startswith(prefix):
            return "postgresql+asyncpg://" + dsn[len(prefix) :]
    return dsn


@pytest.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    """Yield an asyncpg engine bound to the workspace Postgres (skips otherwise)."""
    raw = os.environ.get("POSTGRES_DSN")
    if not raw:
        pytest.skip("POSTGRES_DSN not set; cannot run 0015 schema tests")
    eng = create_async_engine(_to_async_dsn(raw), pool_pre_ping=True)
    try:
        async with eng.connect() as conn:
            await conn.exec_driver_sql("SELECT 1")
    except Exception as exc:
        await eng.dispose()
        pytest.skip(f"PostgreSQL unreachable: {exc}")
    try:
        yield eng
    finally:
        await eng.dispose()


def test_migration_revision_chain() -> None:
    """0015 SHALL descend directly from 0014 and be the unique head."""
    module = _load_migration()
    assert module.revision == "0015"
    assert module.down_revision == "0014"

    from alembic.config import Config
    from alembic.script import ScriptDirectory

    cfg = Config(str(Path(__file__).resolve().parents[2] / "alembic.ini"))
    script = ScriptDirectory.from_config(cfg)
    heads = list(script.get_heads())
    assert heads == ["0015"]


def test_upgrade_emits_idempotent_alter_type(monkeypatch: pytest.MonkeyPatch) -> None:
    """``upgrade()`` SHALL issue exactly the idempotent enum extension."""
    module = _load_migration()
    executed: list[str] = []
    monkeypatch.setattr(module.op, "execute", lambda stmt: executed.append(str(stmt)))
    module.upgrade()
    assert executed == ["ALTER TYPE scan_status ADD VALUE IF NOT EXISTS 'CANCELLED_PARTIAL'"]


def test_downgrade_is_documented_noop() -> None:
    """Enum values cannot be dropped in place; downgrade SHALL not raise."""
    module = _load_migration()
    module.downgrade()  # must not raise


def test_expected_alembic_revision_matches_head() -> None:
    """The repo's startup gate SHALL expect the new head (same-commit bump)."""
    from otalon_scan.repositories.postgres_repo import ScannerPostgresRepo

    assert ScannerPostgresRepo.EXPECTED_ALEMBIC_REVISION == "0015"


async def test_scan_status_enum_contains_cancelled_partial(engine: AsyncEngine) -> None:
    """The live ``scan_status`` enum SHALL carry all six member-name labels."""
    async with engine.connect() as conn:
        res = await conn.exec_driver_sql("SELECT enum_range(NULL::scan_status)::text AS values")
        row = res.first()
    assert row is not None
    actual = tuple(str(row[0]).strip("{}").split(","))
    assert actual == _SCAN_STATUS_LABELS


async def test_scan_row_accepts_cancelled_partial(engine: AsyncEngine) -> None:
    """End-to-end: a scan row SHALL accept the D4 terminal status and be
    readable back (pre-migration this raised ``invalid input value``)."""
    from otalon_scan.repositories.models import ScanStatus
    from otalon_scan.repositories.postgres_repo import ScannerPostgresRepo

    dsn = os.environ["POSTGRES_DSN"]
    repo = ScannerPostgresRepo(dsn=dsn)
    try:
        scan_id = await repo.start_scan(module_name="sc02-enum-probe", parameters={})
        try:
            await repo.finish_scan(scan_id, status=ScanStatus.CANCELLED_PARTIAL)
            row = await repo.get_scan(scan_id)
            assert row is not None
            assert row.status is ScanStatus.CANCELLED_PARTIAL
        finally:
            await repo.delete_scan(scan_id)
    finally:
        await repo.dispose()
