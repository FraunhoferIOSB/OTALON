"""Re-import the legacy jsonb demo snapshot into the relational tables.

Companion script to ``export_demo_jsonb.py``. Reads a JSON snapshot
written before the ``refactor-otalon-scan-persistence-pipeline-v1``
migration dropped the ``devices.vulnerabilities`` and
``network_interfaces.open_ports_summary`` jsonb columns, and replays
the content into the normalised ``service_observations`` and
``vulnerability_observations`` tables using the new
:meth:`ScannerPostgresRepo.upsert_service_observation` and
:meth:`ScannerPostgresRepo.upsert_vulnerability_observation` helpers.

The script creates one new ``scans`` row per invocation with
``module_name='demo_import'`` and writes all observations against that
scan, so re-imports are clearly attributable in the database. Reruns
are idempotent thanks to the UNIQUE constraints on the observation
tables (re-running produces the same row set; ``last_seen_at`` advances
to ``now()``).

Usage::

    python scripts/migrate_demo_jsonb_to_observations.py \
        --input .dev/snapshots/demo_jsonb_export.json \
        --dsn "postgresql://postgres:test123@localhost:5432/otalon-clas"

    # Plan-only:
    python scripts/migrate_demo_jsonb_to_observations.py \
        --input .dev/snapshots/demo_jsonb_export.json --dry-run

Tolerated input shapes for ``vulnerabilities``:

- ``null`` / missing — skipped.
- list of dicts ``[{vuln_id, severity, summary, ...}, ...]`` — each
  element produces one ``vulnerability_observations`` row.
- dict ``{vuln_id: ..., ...}`` (single CVE) — promoted to a 1-element
  list.

Tolerated input shapes for ``open_ports_summary``:

- ``null`` / missing — skipped.
- ``{"tcp": [502, 8080], "udp": [161]}`` — per-protocol port lists.
- ``{"open": [{"port": 502, "proto": "tcp"}, ...]}`` — the existing
  netcap / port_scan emitted shape.

Operator runbook (post-F-01 migration window):

1. Take a baseline snapshot: ``docker exec postgres pg_dump -U postgres
   otalon-clas > .dev/snapshots/pre-persistence-pipeline-<ts>.sql``.
2. Export the live jsonb columns:
   ``python scripts/export_demo_jsonb.py --output .dev/snapshots/demo_jsonb_export.json``.
3. Apply the migration: ``alembic upgrade head``.
4. Re-import: ``python scripts/migrate_demo_jsonb_to_observations.py
   --input .dev/snapshots/demo_jsonb_export.json``.
5. Verify row counts: ``SELECT count(*) FROM service_observations;``
   etc.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any
from uuid import UUID

# Make ``src`` importable when run from the otalon-scan root or
# from the workspace root via ``python otalon-scan/scripts/...``.
_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from sqlalchemy import select  # noqa: E402

from otalon_scan.repositories.models import Device, NetworkInterface  # noqa: E402
from otalon_scan.repositories.postgres_repo import (  # noqa: E402
    ParentRowMissingError,
    ScannerPostgresRepo,
)
from otalon_scan.utils.mac import InvalidMacError, canonicalise  # noqa: E402

DEFAULT_INPUT = Path(".dev/snapshots/demo_jsonb_export.json")


def _resolve_dsn(cli_dsn: str | None) -> str:
    """Mirror of :func:`export_demo_jsonb._resolve_dsn`."""
    dsn = cli_dsn or os.environ.get("POSTGRES_DSN")
    if not dsn:
        raise SystemExit("ERROR: no DSN provided (use --dsn or set POSTGRES_DSN)")
    return dsn


def _normalise_vulnerabilities(payload: Any) -> list[dict[str, Any]]:
    """Coerce the legacy ``vulnerabilities`` jsonb into a list of dicts."""
    if payload is None:
        return []
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        # Two shapes seen in the wild:
        #   1. {"items": [...]} — explicit wrapper.
        #   2. {"vuln_id": "...", ...} — single-CVE flat dict.
        if "items" in payload and isinstance(payload["items"], list):
            return [item for item in payload["items"] if isinstance(item, dict)]
        return [payload]
    return []


def _normalise_open_ports(payload: Any) -> list[dict[str, Any]]:
    """Coerce the legacy ``open_ports_summary`` jsonb into a list of dicts.

    Output shape: ``[{port: int, transport: str, service_name: str|None,
    product: str|None, version: str|None, ...}]``.
    """
    if payload is None:
        return []
    out: list[dict[str, Any]] = []
    if isinstance(payload, dict):
        # Shape A: ``{"open": [{"port": ..., "proto": ...}, ...]}``
        if "open" in payload and isinstance(payload["open"], list):
            for item in payload["open"]:
                if not isinstance(item, dict):
                    continue
                port = item.get("port")
                transport = item.get("proto") or item.get("transport") or "tcp"
                if port is None:
                    continue
                out.append(
                    {
                        "port": int(port),
                        "transport": str(transport),
                        "service_name": item.get("service") or item.get("service_name"),
                        "product": item.get("product"),
                        "version": item.get("version"),
                    }
                )
            return out
        # Shape B: per-protocol port lists ``{"tcp": [...], "udp": [...]}``.
        for proto_key, port_list in payload.items():
            if not isinstance(port_list, list):
                continue
            for port in port_list:
                try:
                    port_int = int(port)
                except (TypeError, ValueError):
                    continue
                out.append(
                    {
                        "port": port_int,
                        "transport": str(proto_key),
                        "service_name": None,
                        "product": None,
                        "version": None,
                    }
                )
    return out


async def _resolve_interface_id(repo: ScannerPostgresRepo, ref_id: int) -> int | None:
    """Return the persisted interface PK for ``ref_id`` (export side id)."""
    async with repo._Session() as session:
        res = await session.execute(select(NetworkInterface).where(NetworkInterface.id == ref_id))
        iface = res.scalar_one_or_none()
        return int(iface.id) if iface is not None else None


async def _resolve_device_id(repo: ScannerPostgresRepo, ref_id: int) -> int | None:
    """Return the persisted device PK for ``ref_id`` (export side id)."""
    async with repo._Session() as session:
        res = await session.execute(select(Device).where(Device.id == ref_id))
        dev = res.scalar_one_or_none()
        return int(dev.id) if dev is not None else None


async def _ensure_device_has_primary_mac(repo: ScannerPostgresRepo, device_id: int) -> str | None:
    """Ensure ``devices.primary_mac`` is populated for ``device_id``; return it.

    F-03 (``refactor-otalon-scan-device-network-ownership-v1``): every
    device touched by the demo-import path SHALL carry a non-NULL
    ``primary_mac``. The alembic ``0002_device_identity_and_parents``
    migration runs a best-effort back-fill from each device's first
    MAC-bearing ``network_interfaces`` row; this helper performs the
    equivalent for the rare case where back-fill could not source a
    MAC (e.g. fresh DB seeded without running the migration's UPDATE).

    Returns:
        The canonical primary_mac of the device, or ``None`` if no
        MAC-bearing interface is linked to it. Callers that receive
        ``None`` SHALL skip the device with a clear warning rather
        than fabricate an identity.
    """
    async with repo._Session() as session:
        dev = await session.get(Device, device_id)
        if dev is None:
            return None
        if dev.primary_mac is not None:
            return str(dev.primary_mac)
        # Find the first MAC-bearing interface (smallest id).
        res = await session.execute(
            select(NetworkInterface)
            .where(NetworkInterface.device_id == device_id)
            .where(NetworkInterface.mac_address.is_not(None))
            .order_by(NetworkInterface.id)
            .limit(1)
        )
        iface = res.scalar_one_or_none()
        if iface is None or iface.mac_address is None:
            return None
        try:
            canonical = canonicalise(str(iface.mac_address))
        except InvalidMacError:
            return None

    # Apply via the F-03 helper so the row picks up the canonical
    # natural-key UPSERT semantics (including the CHECK enforcement).
    await repo.upsert_device(primary_mac=canonical)
    return canonical


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Re-import the pre-migration jsonb demo snapshot into observation tables."
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT,
        help=f"Input JSON path (default: {DEFAULT_INPUT}).",
    )
    parser.add_argument(
        "--dsn",
        default=None,
        help="PostgreSQL DSN (defaults to $POSTGRES_DSN).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the planned UPSERTs without committing them.",
    )
    return parser


async def _run(
    *,
    dsn: str,
    input_path: Path,
    dry_run: bool,
) -> tuple[int, int, int, UUID | None]:
    """Execute the re-import.

    Returns:
        Tuple of (services_upserted, vulns_upserted, skipped_rows, scan_id).
    """
    payload = json.loads(input_path.read_text(encoding="utf-8"))
    devices_in = payload.get("devices") or []
    interfaces_in = payload.get("network_interfaces") or []

    repo = ScannerPostgresRepo(dsn=dsn)
    services = 0
    vulns = 0
    skipped = 0
    scan_id: UUID | None = None

    try:
        if not dry_run:
            scan_id = await repo.start_scan(
                module_name="demo_import",
                parameters={
                    "note": "demo re-import after persistence-pipeline migration",
                    "source_file": str(input_path),
                },
            )
        else:
            scan_id = None

        for entry in interfaces_in:
            ref_id = entry.get("id")
            ports = _normalise_open_ports(entry.get("open_ports_summary"))
            if not ports:
                continue
            if dry_run:
                for p in ports:
                    print(
                        f"DRY-RUN upsert_service_observation "
                        f"interface_id={ref_id} port={p['port']}/{p['transport']} "
                        f"service={p.get('service_name')!r}"
                    )
                services += len(ports)
                continue

            iface_id = await _resolve_interface_id(repo, ref_id)
            if iface_id is None:
                skipped += len(ports)
                continue
            assert scan_id is not None
            for p in ports:
                try:
                    await repo.upsert_service_observation(
                        scan_id=scan_id,
                        interface_id=iface_id,
                        port=p["port"],
                        transport=p["transport"],
                        service_name=p.get("service_name"),
                        product=p.get("product"),
                        version=p.get("version"),
                    )
                    services += 1
                except ParentRowMissingError as exc:
                    print(f"WARN: skipped service row: {exc}", file=sys.stderr)
                    skipped += 1

        for entry in devices_in:
            ref_id = entry.get("id")
            vlist = _normalise_vulnerabilities(entry.get("vulnerabilities"))
            if not vlist:
                continue
            if dry_run:
                for v in vlist:
                    print(
                        f"DRY-RUN upsert_vulnerability_observation "
                        f"device_id={ref_id} vuln_id={v.get('vuln_id')!r} "
                        f"severity={v.get('severity')!r}"
                    )
                vulns += len(vlist)
                continue

            device_id = await _resolve_device_id(repo, ref_id)
            if device_id is None:
                skipped += len(vlist)
                continue
            # F-03: ensure the device carries a non-NULL primary_mac
            # (back-fill should already have done this, but verify
            # defensively so a stale DB is caught here rather than
            # silently producing orphan vuln rows on a parent without
            # natural-key identity).
            primary_mac = await _ensure_device_has_primary_mac(repo, device_id)
            if primary_mac is None:
                print(
                    f"WARN: device id={device_id} has no MAC-bearing interface; "
                    f"skipping {len(vlist)} vulnerability rows for it "
                    f"(F-03 requires devices.primary_mac to be non-NULL)",
                    file=sys.stderr,
                )
                skipped += len(vlist)
                continue
            assert scan_id is not None
            for v in vlist:
                vuln_id = v.get("vuln_id")
                if not vuln_id:
                    skipped += 1
                    continue
                try:
                    await repo.upsert_vulnerability_observation(
                        scan_id=scan_id,
                        device_id=device_id,
                        vuln_id=str(vuln_id),
                        severity=v.get("severity"),
                        summary=v.get("summary"),
                        source_module=v.get("source_module") or "demo_import",
                        metadata_json={
                            k: v[k] for k in v if k not in {"vuln_id", "severity", "summary", "source_module"}
                        }
                        or None,
                    )
                    vulns += 1
                except ParentRowMissingError as exc:
                    print(f"WARN: skipped vulnerability row: {exc}", file=sys.stderr)
                    skipped += 1

        if not dry_run:
            from otalon_scan.repositories.models import ScanStatus

            assert scan_id is not None
            await repo.finish_scan(scan_id, status=ScanStatus.COMPLETED)
    finally:
        await repo.dispose()

    return services, vulns, skipped, scan_id


def main(argv: list[str] | None = None) -> int:
    """Entry point — parses CLI, runs the async re-import, prints a summary."""
    args = _build_arg_parser().parse_args(argv)
    dsn = _resolve_dsn(args.dsn)
    if not args.input.exists():
        print(f"ERROR: input file not found: {args.input}", file=sys.stderr)
        return 1
    services, vulns, skipped, scan_id = asyncio.run(_run(dsn=dsn, input_path=args.input, dry_run=args.dry_run))
    mode = "DRY-RUN" if args.dry_run else "COMMITTED"
    print(
        f"[{mode}] services upserted={services} "
        f"vulnerabilities upserted={vulns} skipped={skipped}" + (f" scan_id={scan_id}" if scan_id else "")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
