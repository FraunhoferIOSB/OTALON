# OTALON-SCAN scan modules

This directory contains the active-network scan modules used by the
`ModuleManager` orchestrator (`src/otalon_scan/core/module_manager.py`). Every module
under `src/otalon_scan/modules/<name>/` is a **pure scanner**: it accepts a validated
`ScanConfig`, yields an asynchronous stream of progress events plus
exactly one terminal result, and **does not touch the database**.

The contract is defined by the `ScanModule` Protocol in
`src/otalon_scan/core/protocols.py` and is enforced at orchestrator load time. The
two relevant capability specs are:

- `openspec/specs/scan--module-contract.md` — what a module is.
- `openspec/specs/scan--persistence-ownership.md` — who writes to PG.

Both invariants exist because the audit reorganization (see
`refactor-otalon-scan-async-and-orchestrator-persistence`) moved all
persistence out of modules and into the orchestrator, eliminated the
`sys.path` mutation pattern, and removed the `asyncio.run()` calls that
were preventing the API surface from going `async def`.

## The `ScanModule` Protocol

```python
# src/otalon_scan/core/protocols.py
@runtime_checkable
class ScanModule(Protocol):
    name: str

    def scan(
        self,
        config: ScanConfig,
    ) -> AsyncIterator[ScanProgress | ScanResult]:
        ...
```

- `name` — MITRE ATT&CK ICS technique ID plus the technique key
  (e.g. `"T0846/pn_discovery"`, `"T0840/port_scan"`,
  `"T1018/arp_scan"`, `"T0888/snmp_scan"`,
  `"T0846/opcua_discover"`). The orchestrator uses this for logging,
  SSE correlation, and tagging the `scans` row.
- `scan(config)` — `async def` returning an `AsyncIterator`. The
  orchestrator iterates with `async for`.

The Protocol is `@runtime_checkable` and the orchestrator's
`ModuleManager._import_module_class()` (`src/otalon_scan/core/module_manager.py:529`)
calls `isinstance(mod_class(), ScanModule)` on every load (decision D2,
"hard runtime check"). A class that fails the check is rejected with
`ScanModuleError`; the orchestrator does **not** fall back to a
lenient duck-typed path.

## The yield contract

A `scan()` invocation MUST yield, in order:

1. Zero or more `ScanProgress` events — one per host, per
   host-and-port, or per scanner-specific checkpoint. These drive the
   SSE endpoint `GET /scans/{scan_id}/events` and feed the
   orchestrator's batched-persistence accumulator.
2. Exactly one terminal `ScanResult` — the final yield, carrying the
   full `findings` collection. The orchestrator treats this yield as
   the "scan completed successfully" signal and then writes the
   `scans` row to `status='completed'`.

Both shapes are Pydantic v2 models defined in `src/otalon_scan/core/models.py`.

Edge cases:

- **Empty result.** A scan over a subnet with no responsive hosts
  yields zero `ScanProgress` events and exactly one `ScanResult` with
  `findings == []`. Modules MUST NOT skip the terminal yield.
- **Cancellation.** If the orchestrator cancels the run, modules
  receive `asyncio.CancelledError` at the next `await` boundary. They
  MUST tear down any spawned subprocess (`nmap`, `pysnmp`), close
  sockets, and re-raise. The orchestrator handles the partial flush
  and `cancelled_partial` status on the persistence side (see D4,
  `scan--persistence-ownership`).
- **Module-internal failure.** Wrap underlying exceptions in
  `ScanModuleError`:

  ```python
  try:
      proc = await asyncio.create_subprocess_exec(...)
  except OSError as exc:
      raise ScanModuleError(f"nmap subprocess failed: {exc}") from exc
  ```

  The orchestrator catches `ScanModuleError`, sets the scan to
  `FAILED`, writes the message to `scans.error_message`, and stops.

## Prohibitions

These prohibitions are enforced by the orchestrator, by CI grep gates,
and by the audit-driven specs above. Violations are bugs, not
preferences.

1. **No DB writes from modules.** Modules MUST NOT import
   `ScannerPostgresRepo` or any other repository, MUST NOT call
   `save_*` / `write_*` / `finish_*`, and MUST NOT open any
   `psycopg`/`asyncpg`/`SQLAlchemy` connection. All persistence is
   owned by the orchestrator and funnels through
   `ModuleManager._persist_batch()`.
   CI gate: `grep -rn "ScannerPostgresRepo" src/otalon_scan/modules/` MUST return
   zero hits.

2. **No `sys.path` mutation.** Modules MUST NOT call
   `sys.path.insert(...)` or `sys.path.append(...)`. Cross-file
   imports inside a module use **relative imports**
   (`from .walker import walk_device`); cross-package imports use
   absolute `src.*` imports.
   CI gate: `grep -rn "sys.path" src/` MUST return zero production hits.

3. **No `asyncio.run()` in library code.** `asyncio.run(...)` MUST
   only appear inside `if __name__ == "__main__":` blocks or under
   dedicated CLI entry-point scripts. Module `scan()` methods
   `await` their async dependencies on the caller's event loop.
   CI gate: `grep -rn "asyncio.run" src/` MUST yield only
   `if __name__ == "__main__":`-guarded hits.

4. **No bare `except Exception: pass`.** Modules MUST NOT silently
   swallow exceptions. Catch the narrowest exception type and re-raise
   as `ScanModuleError` with a descriptive message.

## How to add a new module

The current module set lives at:

```
src/otalon_scan/modules/
├── arp_scan/        T1018/arp_scan          (Nmap ARP sweep)
├── opcua_discover/  T0846/opcua_discover    (OPC UA endpoint discovery)
├── pn_discovery/    T0846/pn_discovery      (PROFINET DCP discovery)
├── port_scan/       T0840/port_scan         (Nmap TCP/UDP port scan)
└── snmp_scan/       T0888/snmp_scan         (SNMP v2c/v3 walk)
```

To add a new scanner, e.g. `modbus_discover`:

1. **Pick a MITRE ATT&CK ICS technique ID** for `name`. Use the
   most-specific technique the scanner actually exercises. For Modbus
   reconnaissance, `T0846/modbus_discover` is appropriate.

2. **Create the directory layout:**

   ```
   src/otalon_scan/modules/modbus_discover/
   ├── __init__.py          # MUST exist (HC9 package hygiene)
   ├── config.json          # default ScanConfig parameters
   └── start.py             # defines the ScanModule-conforming class
   ```

   `__init__.py` is mandatory: the orchestrator loads `start.py` via
   `importlib.util.spec_from_file_location()` with
   `submodule_search_locations=[<module_dir>]`, which requires the
   directory to be a real package so relative imports resolve.

3. **Implement the Protocol in `start.py`:**

   ```python
   from otalon_scan.core.models import ScanConfig, ScanProgress, ScanResult
   from otalon_scan.core.protocols import ScanModuleError

   class ModbusDiscoverModule:
       """Conforms to otalon_scan.core.protocols.ScanModule."""

       name: str = "T0846/modbus_discover"

       async def scan(self, config: ScanConfig):
           try:
               async for host in self._probe(config):
                   yield ScanProgress(
                       module_name=self.name,
                       scan_id=config.scan_id,
                       host=host,
                       ...,
                   )
           except OSError as exc:
               raise ScanModuleError(
                   f"modbus probe failed: {exc}"
               ) from exc

           yield ScanResult(
               module_name=self.name,
               scan_id=config.scan_id,
               findings=collected,
               ...,
           )
   ```

   The class name is discovered automatically by
   `_get_scan_module_class()` (`src/otalon_scan/core/module_manager.py:74`) — it
   walks the module's attributes and picks the first class that looks
   like a `ScanModule` (has `name: str` plus `scan`). No registration
   call is needed; placement under `src/otalon_scan/modules/<name>/start.py` is
   sufficient.

4. **Default config** goes into `config.json` and is merged with the
   API caller's `overrides` by the orchestrator before
   `ScanConfig(...)` validation. Don't re-parse it inside the module.

5. **Tests.** Place unit tests under
   `otalon-scan/tests/unit/modules/test_modbus_discover.py`. Because
   the module never touches the DB, tests are pure I/O assertions
   over the yielded `AsyncIterator`. Use `pytest-asyncio` (already
   wired with `asyncio_mode = "auto"` in `pytest.ini`):

   ```python
   async def test_modbus_yields_progress_and_result():
       module = ModbusDiscoverModule()
       events = [e async for e in module.scan(_make_config())]
       assert isinstance(events[-1], ScanResult)
       assert all(isinstance(e, ScanProgress) for e in events[:-1])
   ```

6. **Wire-up.** The orchestrator discovers modules by listing
   `src/otalon_scan/modules/*/start.py`; no central registry to edit. The
   `_import_module_class()` call enforces the Protocol on first load,
   so a non-conforming class will surface as a `ScanModuleError` at
   API startup time, not at scan-run time.

## Where things live

| Concern | File |
|---|---|
| `ScanModule` Protocol + `ScanModuleError` | `src/otalon_scan/core/protocols.py` |
| `ScanConfig` / `ScanProgress` / `ScanResult` | `src/otalon_scan/core/models.py` |
| Orchestrator + batched persistence seam | `src/otalon_scan/core/module_manager.py` (`_persist_batch`, `_on_forwarder_item`, `set_finish_sink`) |
| Async repository (single PG writer) | `src/otalon_scan/repositories/postgres_repo.py` |
| FastAPI handlers + SSE | `src/otalon_scan/api/server.py` (incl. `GET /scans/{scan_id}/events`) |
| Capability specs | `openspec/specs/scan--module-contract.md`, `openspec/specs/scan--persistence-ownership.md` |
