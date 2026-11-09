"""Persistent cleanup of test-fixture pollution in the otalon-clas Postgres DB.

Intent
------
Test-fixture rows from integration tests, Playwright runs, and smoke checks
accumulate in the ``devices`` and ``network_interfaces`` tables on the
shared Postgres instance. This script removes those rows deterministically
so the live UI is not cluttered with synthetic data.

Replaces the throwaway ``/tmp/cleanup-fixtures.sh``. Run from any host that
has network access to the DB and a working venv with ``asyncpg`` installed.

Deletion criteria (mirror ``/tmp/cleanup-fixtures.sh`` + the new marker)
-----------------------------------------------------------------------
* Devices matching ANY of:
    - ``vendor LIKE '%Test%'``
    - ``device_type LIKE '%Test%'``
    - ``article_number LIKE '%Test%'``
    - ``vendor = 'Smoke'``
    - ``notes LIKE '%__fixture__%'`` (new marker convention; see
      ``otalon-scan/CONTRIBUTING.md`` § "Test Fixtures")
  Network interfaces owned by these devices are deleted FIRST (the FK is
  ``ON DELETE SET NULL`` upstream, so pre-emptive deletion avoids
  orphans).

* Orphan / mock network interfaces:
    - ``mac_address LIKE '02:01:f0:%'`` (locally-administered test MACs)
    - ``mac_address LIKE '02:00:%'``   (additional test MAC range)
    - ``ipv4_address << inet '10.99.99.0/24'``  (mock subnet)
    - ``ipv4_address << inet '172.18.0.0/16'``  (Docker bridge range)
    - ``host(ipv4_address) ~ '^10\\.[0-9]+\\.[0-9]+\\.11$'`` (mock
      ``10.x.x.11/32`` pattern)

The ``scans`` table is intentionally NOT touched: scan history is signal,
not pollution. Counts for ``scans`` are reported BEFORE and AFTER so the
operator can confirm.

When to run
-----------
* After an integration-test run that hit the live DB (CI or local).
* Whenever the topology UI shows synthetic devices that bypassed the
  marker convention.
* Routinely from a cron / nightly task; ``--dry-run`` is safe.

Usage
-----
::

    # Dry run (default): no DELETEs, just report what would happen.
    python scripts/cleanup_db_fixtures.py

    # Apply destructively, single transaction.
    python scripts/cleanup_db_fixtures.py --apply

    # Apply with a pg_dump safety net first.
    python scripts/cleanup_db_fixtures.py --apply \\
        --backup /tmp/cyberclas-$(date -u +%Y%m%dT%H%M%SZ).sql

DSN resolution
--------------
Uses the same configuration plumbing as the otalon-scan service:
``otalon-scan/config/config.json`` → ``$POSTGRES_DSN``. The script
never accepts credentials on the command line.

Exit codes
----------
* 0 — success (dry run report or successful apply)
* 1 — connection error
* 2 — user aborted at confirmation prompt
* 3 — SQL error during the cleanup transaction
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Ensure ``otalon_scan.settings`` resolves when the script is invoked from
# the subproject root (``python scripts/cleanup_db_fixtures.py``): SUITE-032
# moved the package under ``src/``, so ``src`` is the sys.path entry.
_PROJECT_ROOT = Path(__file__).resolve().parents[1] / "src"
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

try:
    import asyncpg
except ImportError as exc:  # pragma: no cover - environment guard
    print(
        "ERROR: asyncpg is required. Activate the workspace venv (.venv313) "
        "or pip install -r otalon-scan/requirements.txt.",
        file=sys.stderr,
    )
    raise SystemExit(1) from exc

from otalon_scan.settings import get_default_settings  # noqa: E402

logger = logging.getLogger("cleanup_db_fixtures")

# --- SQL fragments ----------------------------------------------------------
# Centralised so the dry-run reporter and the apply path stay in lock-step.


def _device_predicate(alias: str = "") -> str:
    """Return the device-deletion predicate, optionally table-qualified.

    ``alias`` is empty for plain ``DELETE FROM devices`` (column names
    resolve unambiguously) and ``"d"`` for ``DELETE ... USING devices d``
    (where ``notes`` exists on both tables and must be qualified).
    """
    p = f"{alias}." if alias else ""
    return (
        f"{p}vendor LIKE '%Test%' "
        f"OR {p}device_type LIKE '%Test%' "
        f"OR {p}article_number LIKE '%Test%' "
        f"OR {p}vendor = 'Smoke' "
        f"OR {p}notes LIKE '%__fixture__%'"
    )


_DEVICE_PREDICATE = _device_predicate()
_DEVICE_PREDICATE_QUALIFIED = _device_predicate("d")

_ORPHAN_INTERFACE_PREDICATE = r"""
    mac_address LIKE '02:01:f0:%'
    OR mac_address LIKE '02:00:%'
    OR ipv4_address << inet '10.99.99.0/24'
    OR ipv4_address << inet '172.18.0.0/16'
    OR host(ipv4_address) ~ '^10\.[0-9]+\.[0-9]+\.11$'
"""

_COUNT_QUERIES: dict[str, str] = {
    "devices": "SELECT COUNT(*) FROM devices",
    "network_interfaces": "SELECT COUNT(*) FROM network_interfaces",
    "scans": "SELECT COUNT(*) FROM scans",
}

_DRY_RUN_QUERIES: dict[str, str] = {
    "devices_to_delete": f"SELECT COUNT(*) FROM devices WHERE {_DEVICE_PREDICATE}",
    "interfaces_of_test_devices": (
        "SELECT COUNT(*) FROM network_interfaces ni "
        "JOIN devices d ON ni.device_id = d.id "
        f"WHERE {_DEVICE_PREDICATE_QUALIFIED}"
    ),
    "orphan_interfaces": f"SELECT COUNT(*) FROM network_interfaces WHERE {_ORPHAN_INTERFACE_PREDICATE}",
}


@dataclass(frozen=True)
class Counts:
    """Snapshot of table counts at a single moment in time."""

    devices: int
    network_interfaces: int
    scans: int

    def render(self) -> str:
        return f"devices={self.devices:<6} " f"network_interfaces={self.network_interfaces:<6} " f"scans={self.scans}"


def _normalise_dsn_for_asyncpg(dsn: str) -> str:
    """Strip SQLAlchemy driver prefixes that asyncpg.connect cannot parse.

    The service uses ``postgresql+asyncpg://`` (SQLAlchemy form). The
    asyncpg driver wants the bare ``postgresql://`` URL.
    """
    if dsn.startswith("postgresql+asyncpg://"):
        return "postgresql://" + dsn[len("postgresql+asyncpg://") :]
    if dsn.startswith("postgresql+psycopg2://"):
        return "postgresql://" + dsn[len("postgresql+psycopg2://") :]
    return dsn


def _resolve_dsn() -> str:
    """Resolve the Postgres DSN via the otalon-scan settings module.

    Falls back to ``$POSTGRES_DSN`` directly if the settings loader cannot
    parse the config (e.g. when this script is run from a CI image without
    a populated config tree).
    """
    try:
        raw = get_default_settings().postgres.dsn
    except Exception as exc:  # noqa: BLE001 - any settings failure
        logger.debug("settings loader failed (%s); falling back to $POSTGRES_DSN", exc)
        raw = os.environ.get("POSTGRES_DSN") or ""
        if not raw:
            raise RuntimeError("Cannot resolve DSN: settings load failed and $POSTGRES_DSN is unset") from exc
    return _normalise_dsn_for_asyncpg(raw)


async def _fetch_counts(conn: asyncpg.Connection) -> Counts:
    results: dict[str, int] = {}
    for name, query in _COUNT_QUERIES.items():
        row = await conn.fetchrow(query)
        results[name] = int(row[0]) if row is not None else 0
    return Counts(
        devices=results["devices"],
        network_interfaces=results["network_interfaces"],
        scans=results["scans"],
    )


async def _fetch_dry_run_estimates(conn: asyncpg.Connection) -> dict[str, int]:
    estimates: dict[str, int] = {}
    for name, query in _DRY_RUN_QUERIES.items():
        row = await conn.fetchrow(query)
        estimates[name] = int(row[0]) if row is not None else 0
    return estimates


async def _execute_cleanup(conn: asyncpg.Connection) -> dict[str, int]:
    """Run the cleanup in a single transaction. Returns deleted-row counts."""
    deleted: dict[str, int] = {}
    async with conn.transaction():
        # 1) Interfaces owned by test devices (so we don't leave them as
        #    NULL-device orphans after the device DELETE below).
        result = await conn.execute(
            "DELETE FROM network_interfaces ni "
            "USING devices d "
            "WHERE ni.device_id = d.id "
            f"  AND ({_DEVICE_PREDICATE_QUALIFIED})"
        )
        deleted["interfaces_of_test_devices"] = _parse_rowcount(result)

        # 2) Orphan / mock interfaces (test MAC prefixes + mock subnets +
        #    10.x.x.11 mock pattern).
        result = await conn.execute(f"DELETE FROM network_interfaces WHERE {_ORPHAN_INTERFACE_PREDICATE}")
        deleted["orphan_interfaces"] = _parse_rowcount(result)

        # 3) The test devices themselves.
        result = await conn.execute(f"DELETE FROM devices WHERE {_DEVICE_PREDICATE}")
        deleted["devices"] = _parse_rowcount(result)

    return deleted


def _parse_rowcount(status: str) -> int:
    """Parse asyncpg ``execute`` status strings like ``DELETE 42``."""
    parts = status.split()
    if len(parts) >= 2 and parts[-1].isdigit():
        return int(parts[-1])
    return 0


def _run_pg_dump(backup_path: Path, dsn: str) -> None:
    """Best-effort pg_dump backup; raises if pg_dump itself fails."""
    backup_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["pg_dump", "--dbname", dsn, "--file", str(backup_path)]
    logger.info("running backup: %s", " ".join(shlex.quote(c) for c in cmd))
    # S603: invoked with a fixed, hard-coded argv list (no shell=True); the
    # only operator-controlled value is ``backup_path`` from --backup, which
    # is converted via str(Path(...)) and passed as a separate argv element.
    completed = subprocess.run(cmd, capture_output=True, text=True, check=False)  # noqa: S603
    if completed.returncode != 0:
        raise RuntimeError(f"pg_dump failed (exit {completed.returncode}): {completed.stderr.strip()}")
    logger.info("backup written to %s", backup_path)


async def _main_async(args: argparse.Namespace) -> int:
    dsn = _resolve_dsn()
    logger.info("DSN resolved (host portion only): %s", _safe_dsn_for_log(dsn))

    try:
        conn = await asyncpg.connect(dsn=dsn)
    except (OSError, asyncpg.PostgresError) as exc:
        logger.error("cannot connect to Postgres: %s", exc)
        return 1

    try:
        before = await _fetch_counts(conn)
        print(f"BEFORE: {before.render()}")

        estimates = await _fetch_dry_run_estimates(conn)
        print("Would delete:")
        for name, count in estimates.items():
            print(f"  {name:<35} {count}")

        total_to_delete = sum(estimates.values())

        if args.dry_run:
            print("[dry-run] no changes applied. Re-run with --apply to execute.")
            return 0

        if total_to_delete == 0:
            print("Nothing to delete. Exiting cleanly.")
            return 0

        if args.backup is not None:
            try:
                _run_pg_dump(Path(args.backup), dsn)
            except RuntimeError as exc:
                logger.error("backup failed; aborting: %s", exc)
                return 1

        try:
            deleted = await _execute_cleanup(conn)
        except asyncpg.PostgresError as exc:
            logger.error("SQL error during cleanup: %s", exc)
            return 3

        print("Deleted:")
        for name, count in deleted.items():
            print(f"  {name:<35} {count}")

        after = await _fetch_counts(conn)
        print(f"AFTER:  {after.render()}")
        return 0
    finally:
        await conn.close()


def _safe_dsn_for_log(dsn: str) -> str:
    """Strip the password segment from a libpq DSN for logging."""
    # Handles ``postgresql://user:pass@host:port/db`` style.
    if "://" in dsn and "@" in dsn:
        scheme, _, rest = dsn.partition("://")
        creds, _, host = rest.rpartition("@")
        user = creds.split(":", 1)[0] if creds else ""
        return f"{scheme}://{user}:***@{host}"
    return "<dsn redacted>"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Remove test-fixture pollution from the otalon-clas Postgres DB.",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--dry-run",
        action="store_true",
        default=True,
        help="Report what would be deleted; do nothing destructive (default).",
    )
    mode.add_argument(
        "--apply",
        dest="dry_run",
        action="store_false",
        help="Execute the deletion in a single transaction.",
    )
    parser.add_argument(
        "--backup",
        type=str,
        default=None,
        help="Path for a pg_dump backup taken before --apply (optional).",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable DEBUG logging on stderr.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    try:
        return asyncio.run(_main_async(args))
    except KeyboardInterrupt:
        print("Aborted by user.", file=sys.stderr)
        return 2
    except RuntimeError as exc:
        logger.error("%s", exc)
        return 1


def _entrypoint() -> Any:  # pragma: no cover - thin wrapper
    sys.exit(main())


if __name__ == "__main__":  # pragma: no cover
    _entrypoint()
