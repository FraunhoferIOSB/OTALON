# otalon-scan test layout

This directory hosts the otalon-scan test suite. Conventions documented
here augment the workspace-wide `AGENTS.md` testing standards with the
subproject-specific bits.

## Layout

- `tests/unit/` — fast, isolated tests. No external services. Run via
  plain `pytest` from the subproject root.
- `tests/integration/` — tests that boot the FastAPI lifespan and/or
  exercise a real PostgreSQL instance. Marked module-level with
  `pytestmark = pytest.mark.integration` (HC13/HC14).
- `tests/manual/` — scripts intended for ad-hoc developer runs; not
  collected by default.
- `tests/unit/__snapshots__/` — `syrupy` Amber snapshots written by
  D-T2 snapshot tests (`test_snapshot_*.py`). Syrupy stores the
  `.ambr` files in a `__snapshots__/` directory adjacent to the
  test module by default.

## Markers

- `@pytest.mark.integration` — requires a reachable Postgres at
  `POSTGRES_DSN` (workspace `core-db` docker compose profile up). CI
  splits the tiers via:
  - Fast: `pytest -m "not integration"`
  - Slow: `pytest -m integration`
- `@pytest.mark.timeout(N)` — per-test wall-clock cap (pytest-timeout).

## Snapshot tests (D-T2)

`tests/unit/test_snapshot_api_and_reports.py` pins the JSON shape of:

- API response envelopes (`ModulesResponse`, `RunningScansResponse`,
  `FinishedScansResponse`, `StartScanResponse`).
- Module final-report `ScanResult` shapes for `arp_scan`, `port_scan`,
  `pn_discovery`.

### Updating snapshots

When a snapshot diff appears:

1. **Read the diff before doing anything.** A snapshot change is a
   shape-contract change — does it reflect an intentional schema bump
   (new field added, value type widened), or an accidental reshape
   (field renamed, nesting collapsed, type silently changed)?
2. If the change is intentional, regenerate:
   ```bash
   source .venv313/bin/activate
   cd otalon-scan
   pytest tests/unit/test_snapshot_api_and_reports.py --snapshot-update
   ```
   Commit the regenerated snapshot together with the source change so a
   reviewer can see the schema bump in one diff.
3. If the change is NOT intentional, fix the source so the snapshot
   passes again. Do **not** run `--snapshot-update` to make a regression
   "go away".

The snapshots are deliberately stripped of wall-clock timestamps
(`started_at`, `finished_at`) to avoid spurious diffs across runs.

## Property-based tests (D-T1)

`tests/unit/test_parsers_property.py` uses Hypothesis to drive the
input validators in `src/otalon_scan/core/validators.py` with generated IPs,
CIDRs, port ranges, and timing templates. When a new parser/validator
lands in `src/otalon_scan/core/validators.py`, add a corresponding strategy here.
