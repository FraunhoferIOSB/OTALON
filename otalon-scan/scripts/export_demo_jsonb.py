"""Export hand-curated jsonb demo data from the legacy schema.

Snapshots the contents of ``devices.vulnerabilities`` and
``network_interfaces.open_ports_summary`` to a JSON file before the
``refactor-otalon-scan-persistence-pipeline-v1`` migration drops both
columns. The companion script ``migrate_demo_jsonb_to_observations.py``
re-imports the JSON into the normalised observation tables after the
migration runs.

Usage:

    python scripts/export_demo_jsonb.py \
        --dsn "postgresql://postgres:test123@localhost:5432/otalon-clas" \
        --output .dev/snapshots/demo_jsonb_export.json

Falls back to ``$POSTGRES_DSN`` when ``--dsn`` is omitted. The output is
a single JSON document with two top-level arrays:

    {
      "exported_at": "<iso-8601>",
      "devices": [
        {"id": <int>, "vulnerabilities": <jsonb-payload-or-null>}, ...
      ],
      "network_interfaces": [
        {"id": <int>, "open_ports_summary": <jsonb-payload-or-null>}, ...
      ]
    }

This script is intentionally a sync ``psycopg2``-free, ``asyncpg``-based
helper: it runs once per migration window from a developer or operator
shell, not from production code paths.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import asyncpg

DEFAULT_OUTPUT = Path(".dev/snapshots/demo_jsonb_export.json")


async def _fetch_jsonb_columns(dsn: str) -> dict[str, Any]:
    """Connect to ``dsn`` and read the two jsonb columns into memory."""
    conn = await asyncpg.connect(dsn)
    try:
        device_rows = await conn.fetch("SELECT id, vulnerabilities FROM devices ORDER BY id")
        interface_rows = await conn.fetch("SELECT id, open_ports_summary FROM network_interfaces ORDER BY id")
    finally:
        await conn.close()

    devices: list[dict[str, Any]] = []
    for row in device_rows:
        payload = row["vulnerabilities"]
        if isinstance(payload, str):
            payload = json.loads(payload)
        devices.append({"id": row["id"], "vulnerabilities": payload})

    interfaces: list[dict[str, Any]] = []
    for row in interface_rows:
        payload = row["open_ports_summary"]
        if isinstance(payload, str):
            payload = json.loads(payload)
        interfaces.append({"id": row["id"], "open_ports_summary": payload})

    return {"devices": devices, "network_interfaces": interfaces}


def _resolve_dsn(cli_dsn: str | None) -> str:
    """Pick the DSN from CLI first, then ``$POSTGRES_DSN``."""
    dsn = cli_dsn or os.environ.get("POSTGRES_DSN")
    if not dsn:
        raise SystemExit("ERROR: no DSN provided (use --dsn or set POSTGRES_DSN)")
    # asyncpg does not understand the SQLAlchemy ``postgresql+asyncpg://``
    # scheme; strip that suffix if present.
    if dsn.startswith("postgresql+asyncpg://"):
        dsn = "postgresql://" + dsn[len("postgresql+asyncpg://") :]
    if dsn.startswith("postgresql+psycopg2://"):
        dsn = "postgresql://" + dsn[len("postgresql+psycopg2://") :]
    return dsn


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Export legacy jsonb demo data before persistence-pipeline migration.")
    parser.add_argument(
        "--dsn",
        default=None,
        help="PostgreSQL DSN (defaults to $POSTGRES_DSN).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"Output JSON path (default: {DEFAULT_OUTPUT}).",
    )
    return parser


async def _run(dsn: str, output: Path) -> int:
    """Execute the export and write the result to ``output``.

    Returns the total row count (devices + interfaces) for the summary.
    """
    payload = await _fetch_jsonb_columns(dsn)
    payload["exported_at"] = datetime.now(timezone.utc).isoformat()

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")

    return len(payload["devices"]) + len(payload["network_interfaces"])


def main(argv: list[str] | None = None) -> int:
    """Entry point — parses CLI, runs the async export, prints a summary."""
    args = _build_arg_parser().parse_args(argv)
    dsn = _resolve_dsn(args.dsn)
    try:
        total = asyncio.run(_run(dsn, args.output))
    except (asyncpg.PostgresError, OSError) as exc:
        print(f"ERROR: export failed: {exc}", file=sys.stderr)
        return 1
    print(f"Exported {total} rows to {args.output} " f"(devices + network_interfaces jsonb columns).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
