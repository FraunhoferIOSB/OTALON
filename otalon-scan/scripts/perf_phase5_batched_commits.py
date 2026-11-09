#!/usr/bin/env python
"""Phase 5 (HC16) commit-count + WAL-growth benchmark.

Measures the effect of batched commits in ``ModuleManager._persist_batch``
on a 20-host × 50-port port-scan workload.

Methodology
-----------

The script drives the production persistence sink (``_persist_findings`` in
``otalon_scan.api.server``) twice against a freshly-created benchmark database:

1. **Pre-refactor simulation** — ``batch_size=1``. Each finding flows through
   its own ``_persist_batch`` invocation, which approximates the pre-Phase-2
   shape (one commit per device, the HC6 era pattern: modules used to open a
   :class:`ScannerPostgresRepo` and call ``set_log_data`` per discovered
   device, committing each row individually).

2. **Post-refactor (Phase 5)** — ``batch_size=100`` (D3 default). All 20
   hosts (each carrying their 50-port summary in ``open_ports_summary``)
   fit inside a single chunk; the orchestrator commits in one (or a few)
   bounded chunks.

The benchmark counts:

- ``pg_stat_database.xact_commit`` delta for the target DB
  (committed transactions).
- ``pg_current_wal_lsn()`` delta in bytes (WAL bytes generated).

Because ``pg_stat_statements`` is not loaded in the workspace's PostgreSQL
container (verified at the time of writing — ``SHOW shared_preload_libraries``
returns empty), commit count is taken from ``pg_stat_database`` which is a
fully equivalent metric for the "commits per scan" question.

Run
---

::

    POSTGRES_DSN=postgresql://postgres:test123@localhost:5432/cyberscan_bench \\
      python scripts/perf_phase5_batched_commits.py

Outputs a JSON report on stdout AND writes it to
``.dev/phase5-hc16-commit-bench.json`` for the OpenSpec outcome record.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List

# Capture POSTGRES_DSN BEFORE any ``src.*`` import. Several src modules
# (``otalon_scan.settings`` via ``otalon_scan.core.log_config``) call
# ``load_dotenv(override=True)`` against the workspace ``.env`` at import
# time, which would otherwise clobber whatever caller-provided DSN is in
# the shell environment. Pinning the value here makes the benchmark
# honour the env var the operator set on the CLI.
_ENV_DSN_AT_IMPORT = os.environ.get("POSTGRES_DSN")

# Ensure src/ is importable when invoked directly from the subproject root.
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

import sqlalchemy as sa  # noqa: E402,I001
from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402,I001

from otalon_scan.core.models import DeviceFinding, ScanResult  # noqa: E402,I001
from otalon_scan.core.module_manager import ModuleManager  # noqa: E402,I001
from otalon_scan.repositories.models import ScanStatus  # noqa: E402,I001
from otalon_scan.repositories.postgres_repo import (  # noqa: E402,I001
    ScannerPostgresRepo,
    _to_async_dsn,
)


@dataclass
class ScenarioResult:
    """Outcome for a single benchmark scenario."""

    label: str
    batch_size: int
    findings: int
    commits_delta: int
    wal_bytes_delta: int
    elapsed_seconds: float


def _build_port_scan_payload(num_hosts: int, num_ports: int) -> List[Dict[str, Any]]:
    """Synthesize a realistic 20×50 port-scan ``raw_results`` payload.

    Each host has an IPv4 and ``num_ports`` open TCP ports (1-1000 range).
    Matches the shape produced by ``otalon_scan.modules.port_scan.start``.
    """
    hosts: List[Dict[str, Any]] = []
    for h in range(num_hosts):
        open_ports = [
            {
                "port": 1000 + p,
                "protocol": "tcp",
                "state": "open",
                "service": "test",
                "product": "synthetic",
                "version": "0.0",
                "extrainfo": "bench",
                "cpe": "",
            }
            for p in range(num_ports)
        ]
        hosts.append(
            {
                "ip_address": f"10.99.0.{h + 1}",
                "hostnames": [f"bench-host-{h + 1}"],
                "open_ports": open_ports,
            }
        )
    return hosts


def _build_findings(num_hosts: int, num_ports: int) -> List[DeviceFinding]:
    """Build :class:`DeviceFinding` objects matching the port-scan payload."""
    return [
        DeviceFinding(
            ipv4=f"10.99.0.{h + 1}",
            open_ports_summary={"open": [{"port": 1000 + p, "proto": "tcp"} for p in range(num_ports)]},
        )
        for h in range(num_hosts)
    ]


async def _get_stats(engine: Any, dbname: str) -> Dict[str, int]:
    """Snapshot ``xact_commit`` for ``dbname`` and the current WAL LSN."""
    async with engine.connect() as conn:
        commits = (
            await conn.execute(
                sa.text("SELECT xact_commit FROM pg_stat_database WHERE datname = :n"),
                {"n": dbname},
            )
        ).scalar_one()
        # Cast WAL LSN to numeric bytes by querying its pg_lsn → bytea offset.
        wal = (await conn.execute(sa.text("SELECT pg_current_wal_lsn() - '0/0'::pg_lsn"))).scalar_one()
    return {"commits": int(commits), "wal": int(wal)}


async def _run_scenario(
    dsn: str,
    dbname: str,
    label: str,
    batch_size: int,
    findings: List[DeviceFinding],
    raw_port_payload: List[Dict[str, Any]],
) -> ScenarioResult:
    """Run the persistence path for one scenario and return its measurements."""
    # Production architecture: the persistence sink is dispatched from a
    # synchronous monitor thread onto the FastAPI event loop via
    # ``asyncio.run_coroutine_threadsafe``. We mirror that here with a
    # dedicated background loop owning ALL repo operations — asyncpg
    # connections are loop-bound and cannot be safely shared across loops.
    sink_loop = asyncio.new_event_loop()

    import threading

    loop_thread = threading.Thread(target=sink_loop.run_forever, daemon=True)
    loop_thread.start()

    def _on_sink(coro: Any, timeout: float = 60.0) -> Any:
        fut = asyncio.run_coroutine_threadsafe(coro, sink_loop)
        return fut.result(timeout=timeout)

    repo = ScannerPostgresRepo(dsn=dsn)
    _on_sink(repo.ensure_schema())

    # Stats engine — separate from the repo's pool so its own DB chatter
    # doesn't contaminate the count. Use the postgres maintenance DB.
    maint_dsn = _to_async_dsn(dsn).rsplit("/", 1)[0] + "/postgres"
    stats_engine = create_async_engine(maint_dsn)

    # Reset tables to avoid duplicate-key noise across repeated runs.
    async def _truncate() -> None:
        async with repo.engine.begin() as conn:
            await conn.execute(
                sa.text(
                    "TRUNCATE service_observations, vulnerability_observations, "
                    "network_interfaces, devices, scans RESTART IDENTITY CASCADE"
                )
            )

    _on_sink(_truncate())

    scan_id = _on_sink(repo.start_scan(module_name="bench/port_scan"))

    def _persist_sink(scan_id_str: str, batch: List[DeviceFinding], result: ScanResult) -> None:
        async def _impl() -> None:
            from datetime import datetime

            now = datetime.utcnow()
            # Phase 5 production shape: single batched transaction per
            # ``_persist_batch`` call (one commit per chunk).
            await repo.save_findings_batch(scan_id_str, batch, scanned_at=now)
            # Only on the terminal call (carries raw_results) persist the
            # port-level service observations.
            raw = result.raw_results
            if isinstance(raw, list):
                await repo.save_port_scan_results(scan_id_str, raw)

        fut = asyncio.run_coroutine_threadsafe(_impl(), sink_loop)
        fut.result(timeout=120.0)

    def _finish_sink(scan_id_str: str, status: str, err: Any) -> None:
        async def _impl() -> None:
            mapping = {
                "completed": ScanStatus.COMPLETED,
                "failed": ScanStatus.FAILED,
                "aborted": ScanStatus.ABORTED,
                "cancelled_partial": ScanStatus.CANCELLED_PARTIAL,
            }
            await repo.finish_scan(scan_id_str, status=mapping.get(status, ScanStatus.FAILED))

        fut = asyncio.run_coroutine_threadsafe(_impl(), sink_loop)
        fut.result(timeout=30.0)

    empty_modules = Path("/tmp") / "bench_modules"
    empty_modules.mkdir(exist_ok=True)
    mgr = ModuleManager(modules_path=str(empty_modules), batch_size=batch_size)
    mgr.set_persist_sink(_persist_sink)
    mgr.set_finish_sink(_finish_sink)

    # ---- Measurement window ----

    import time

    pre = await _get_stats(stats_engine, dbname)
    t0 = time.perf_counter()

    # Persist all findings (this is what the orchestrator does at finalize:
    # one _persist_batch call with the full list; chunking happens inside).
    result = ScanResult(
        module_name="bench/port_scan",
        protocol="tcp",
        findings=findings,
        raw_results=raw_port_payload,
    )
    mgr._persist_batch(str(scan_id), findings, result)
    _finish_sink(str(scan_id), "completed", None)

    elapsed = time.perf_counter() - t0
    post = await _get_stats(stats_engine, dbname)

    await stats_engine.dispose()

    # Dispose the production repo on the sink loop (asyncpg connections
    # are loop-bound and must close on their owning loop).
    try:
        _on_sink(repo.dispose(), timeout=10.0)
    except Exception:
        pass

    sink_loop.call_soon_threadsafe(sink_loop.stop)
    loop_thread.join(timeout=5.0)

    return ScenarioResult(
        label=label,
        batch_size=batch_size,
        findings=len(findings),
        commits_delta=post["commits"] - pre["commits"],
        wal_bytes_delta=post["wal"] - pre["wal"],
        elapsed_seconds=elapsed,
    )


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hosts", type=int, default=20)
    parser.add_argument("--ports", type=int, default=50)
    parser.add_argument(
        "--dsn",
        # ``_ENV_DSN_AT_IMPORT`` is captured at module-import time, before
        # ``otalon_scan.settings`` runs ``load_dotenv(override=True)`` against the
        # workspace ``.env`` — so this respects the operator's shell DSN.
        default=_ENV_DSN_AT_IMPORT or "postgresql://postgres:test123@localhost:5432/cyberscan_bench",
    )
    parser.add_argument(
        "--out",
        default=".dev/phase5-hc16-commit-bench.json",
        help="Output JSON report path (relative to subproject root).",
    )
    args = parser.parse_args()

    # The CLI default already captured the env var before any src.* import
    # ran load_dotenv, so args.dsn is authoritative regardless of what the
    # workspace .env file later overrides.
    dsn = args.dsn
    dbname = dsn.rsplit("/", 1)[-1].split("?", 1)[0]

    findings = _build_findings(args.hosts, args.ports)
    raw_payload = _build_port_scan_payload(args.hosts, args.ports)

    pre_refactor = await _run_scenario(
        dsn,
        dbname,
        label="pre-refactor (batch_size=1)",
        batch_size=1,
        findings=findings,
        raw_port_payload=raw_payload,
    )
    post_refactor = await _run_scenario(
        dsn,
        dbname,
        label="post-refactor (batch_size=100, D3 default)",
        batch_size=100,
        findings=findings,
        raw_port_payload=raw_payload,
    )

    reduction_pct = (
        100.0 * (pre_refactor.commits_delta - post_refactor.commits_delta) / pre_refactor.commits_delta
        if pre_refactor.commits_delta
        else 0.0
    )
    wal_reduction_pct = (
        100.0 * (pre_refactor.wal_bytes_delta - post_refactor.wal_bytes_delta) / pre_refactor.wal_bytes_delta
        if pre_refactor.wal_bytes_delta
        else 0.0
    )

    report = {
        "config": {
            "hosts": args.hosts,
            "ports": args.ports,
            "dsn_db": dbname,
            "d3_batch_size": 100,
        },
        "scenarios": [asdict(pre_refactor), asdict(post_refactor)],
        "summary": {
            "commit_count_reduction_pct": round(reduction_pct, 2),
            "wal_bytes_reduction_pct": round(wal_reduction_pct, 2),
            "meets_80pct_target": reduction_pct >= 80.0,
        },
    }

    out_path = ROOT / args.out
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2))
    json.dump(report, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0 if reduction_pct >= 80.0 else 2


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
