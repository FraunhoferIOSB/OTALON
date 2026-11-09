"""Tests for alembic migration 0000 (SC-06, SUITE-031 audit).

SC-06: the 5 core tables (``devices``, ``network_interfaces``, ``scans``,
``service_observations``, ``vulnerability_observations``) existed in NO
migration — the chain started at ``0001`` with ``drop_column``/view DDL
against tables it never created, so ``alembic upgrade head`` on a fresh
database failed. Migration ``0000_core_base_tables`` reconstructs the
pre-0001 baseline (including the two legacy jsonb columns that ``0001``
drops) idempotently.

Layers:

1. **Unit** — revision-chain shape and idempotent statement shape, no DB.
2. **Fresh-DB end-to-end** — creates a scratch database on the workspace
   Postgres, runs the real ``alembic upgrade head`` against it, asserts the
   core schema, and drops the scratch database. Skips when Postgres is
   unreachable, mirroring the neighbouring ``test_alembic_migration*.py``
   fixtures.
"""

from __future__ import annotations

import importlib.util
import os
import re
import uuid
from pathlib import Path
from typing import Any, List

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_MIGRATION_0000_PATH = _PROJECT_ROOT / "alembic" / "versions" / "0000_core_base_tables.py"

CORE_TABLES: tuple[str, ...] = (
    "devices",
    "network_interfaces",
    "scans",
    "service_observations",
    "vulnerability_observations",
)


def _load_migration(path: Path, name: str) -> Any:
    """Import a migration module by path (no package import side effects)."""
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _captured_upgrade(module: Any, monkeypatch: pytest.MonkeyPatch) -> List[str]:
    """Run ``upgrade()`` with ``op.execute`` captured; return the statements."""
    executed: List[str] = []
    monkeypatch.setattr(module.op, "execute", lambda stmt: executed.append(str(stmt)))
    module.upgrade()
    return executed


# ---- 1. Unit layer ----


def test_base_revision_is_chain_root() -> None:
    """0000 SHALL be the new chain root; 0001 SHALL descend from it."""
    m0000 = _load_migration(_MIGRATION_0000_PATH, "migration_0000")
    m0001 = _load_migration(
        _PROJECT_ROOT / "alembic" / "versions" / "0001_initial_view_and_upserts.py", "migration_0001"
    )
    assert m0000.revision == "0000"
    assert m0000.down_revision is None
    assert m0001.down_revision == "0000"


def test_single_linear_head() -> None:
    """The chain SHALL stay linear with the single head at the latest revision."""
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    cfg = Config(str(_PROJECT_ROOT / "alembic.ini"))
    script = ScriptDirectory.from_config(cfg)
    assert list(script.get_heads()) == ["0015"]
    bases = [r.revision for r in script.walk_revisions() if r.is_base]
    assert bases == ["0000"]


def test_upgrade_creates_five_core_tables(monkeypatch: pytest.MonkeyPatch) -> None:
    """``upgrade()`` SHALL create all five core tables and the ``scan_status``
    enum plus the pre-existing interface unique constraints."""
    module = _load_migration(_MIGRATION_0000_PATH, "migration_0000")
    statements = _captured_upgrade(module, monkeypatch)
    sql = "\n".join(statements)
    for table in CORE_TABLES:
        assert re.search(rf"CREATE TABLE IF NOT EXISTS {table}\b", sql), f"missing CREATE TABLE for {table}"
    assert "scan_status" in sql and "CREATE TYPE" in sql
    for constraint in ("uq_iface_mac", "uq_iface_ipv4", "uq_iface_ipv6"):
        assert constraint in sql
    assert "ix_network_interfaces_device_id" in sql


def test_upgrade_is_idempotent_by_construction(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every emitted statement SHALL be re-runnable (IF NOT EXISTS / DO-block)
    so a partially-initialised database cannot wedge the migration."""
    module = _load_migration(_MIGRATION_0000_PATH, "migration_0000")
    statements = _captured_upgrade(module, monkeypatch)
    for stmt in statements:
        head = stmt.lstrip().upper()
        if head.startswith("CREATE TABLE") or head.startswith("CREATE UNIQUE INDEX") or head.startswith("CREATE INDEX"):
            assert "IF NOT EXISTS" in head, f"non-idempotent statement: {stmt[:80]}"
        elif "CREATE TYPE" in head:
            assert head.startswith("DO"), f"CREATE TYPE must be guarded by a DO-block: {stmt[:80]}"
    # Re-running the upgrade emits the same idempotent statement set.
    again = _captured_upgrade(module, monkeypatch)
    assert again == statements


def test_0001_legacy_columns_exist_in_0000(monkeypatch: pytest.MonkeyPatch) -> None:
    """0001 drops ``devices.vulnerabilities`` and
    ``network_interfaces.open_ports_summary`` — 0000 SHALL create both so the
    chain replays faithfully on a fresh database."""
    module = _load_migration(_MIGRATION_0000_PATH, "migration_0000")
    sql = "\n".join(_captured_upgrade(module, monkeypatch))
    assert re.search(r"CREATE TABLE IF NOT EXISTS devices\b[\s\S]*?\bvulnerabilities\b", sql)
    assert re.search(r"CREATE TABLE IF NOT EXISTS network_interfaces\b[\s\S]*?\bopen_ports_summary\b", sql)


# ---- 2. Fresh-DB end-to-end layer ----


def _admin_dsn() -> str:
    raw = os.environ.get("POSTGRES_DSN")
    if not raw:
        pytest.skip("POSTGRES_DSN not set; cannot run fresh-DB migration test")
    return raw


def test_upgrade_head_on_fresh_database() -> None:
    """``alembic upgrade head`` SHALL succeed on an empty database and produce
    the 5 core tables + the full ``scan_status`` enum (incl. the SC-02
    ``CANCELLED_PARTIAL`` label)."""
    psycopg2 = pytest.importorskip("psycopg2")
    from alembic import command
    from alembic.config import Config

    admin_dsn = _admin_dsn()
    scratch = f"scan031_fresh_{uuid.uuid4().hex[:12]}"
    try:
        admin = psycopg2.connect(admin_dsn, dbname="postgres")
    except Exception as exc:
        pytest.skip(f"PostgreSQL unreachable: {exc}")
    admin.autocommit = True
    try:
        with admin.cursor() as cur:
            cur.execute(f'CREATE DATABASE "{scratch}"')
    finally:
        admin.close()

    scratch_dsn = re.sub(r"/[^/]+$", f"/{scratch}", admin_dsn)
    old = os.environ.get("POSTGRES_DSN")
    os.environ["POSTGRES_DSN"] = scratch_dsn
    try:
        cfg = Config(str(_PROJECT_ROOT / "alembic.ini"))
        cfg.set_main_option("script_location", str(_PROJECT_ROOT / "alembic"))
        command.upgrade(cfg, "head")

        conn = psycopg2.connect(scratch_dsn)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT table_name FROM information_schema.tables "
                    "WHERE table_schema='public' AND table_name = ANY(%s)",
                    (list(CORE_TABLES),),
                )
                found = {row[0] for row in cur.fetchall()}
                assert found == set(CORE_TABLES)

                cur.execute("SELECT enum_range(NULL::scan_status)::text")
                labels = str(cur.fetchone()[0])
                for label in ("PENDING", "RUNNING", "COMPLETED", "FAILED", "ABORTED", "CANCELLED_PARTIAL"):
                    assert label in labels

                cur.execute("SELECT version_num FROM alembic_version")
                assert cur.fetchone()[0] == "0015"

                # Smoke: a Scan row round-trips through the migrated schema.
                cur.execute(
                    "INSERT INTO scans (id, module_name, status, started_at, created_at) "
                    "VALUES (gen_random_uuid(), 'arp_scan', 'CANCELLED_PARTIAL', now(), now()) "
                    "RETURNING status"
                )
                assert cur.fetchone()[0] == "CANCELLED_PARTIAL"
                conn.rollback()
        finally:
            conn.close()
    finally:
        if old is None:
            os.environ.pop("POSTGRES_DSN", None)
        else:
            os.environ["POSTGRES_DSN"] = old
        admin = psycopg2.connect(admin_dsn, dbname="postgres")
        admin.autocommit = True
        try:
            with admin.cursor() as cur:
                cur.execute(f'DROP DATABASE IF EXISTS "{scratch}"')
        finally:
            admin.close()
