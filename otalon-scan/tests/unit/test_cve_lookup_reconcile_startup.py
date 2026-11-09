"""WA.5 test: the lifespan startup reconciles interrupted CVE-lookup jobs.

The crash-recovery acceptance (SCAN-026 WA.5): a DB ``running``
``cve_lookups`` record without a live registry task is finalized as
``failed`` ("interrupted") when the service starts.

The substantive DB transition is covered at the repo level by
``tests/unit/repositories/test_cve_lookup_repo.py``
(``test_reconcile_fails_orphaned_running_keeps_active``). This test
verifies the **wiring**: that the FastAPI lifespan startup actually calls
:meth:`ScannerPostgresRepo.reconcile_interrupted_lookups` with the
registry's active job ids — using lightweight stubs so it needs neither a
Postgres instance nor the module discovery path.
"""

from __future__ import annotations

import os
from typing import Any, List

import pytest
from asgi_lifespan import LifespanManager


@pytest.mark.timeout(20)
async def test_lifespan_calls_reconcile_on_startup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The lifespan SHALL invoke ``reconcile_interrupted_lookups`` once."""
    os.environ["OTALON_SCAN_ALLOWED_KEYS"] = "test-operator:operator:operator-test-key"

    import otalon_scan.api.server as srv

    reconcile_calls: List[dict[str, Any]] = []
    scan_reconcile_calls: List[int] = []

    class _StubRepo:
        """Minimal repo recording the reconcile call and schema probe."""

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        async def ensure_schema(self) -> None:
            return None

        async def reconcile_interrupted_lookups(self, *, active_job_ids: Any) -> int:
            reconcile_calls.append({"active_job_ids": list(active_job_ids)})
            return 3

        async def reconcile_interrupted_scans(self) -> int:
            scan_reconcile_calls.append(1)
            return 2

        async def dispose(self) -> None:
            return None

    class _StubManager:
        """Minimal ModuleManager stub satisfying the lifespan wiring."""

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            class _Bus:
                def attach_loop(self, _loop: Any) -> None:
                    return None

            self.progress_bus = _Bus()

        def set_persist_sink(self, _sink: Any) -> None:
            return None

        def set_finish_sink(self, _sink: Any) -> None:
            return None

        def set_findings_sink(self, _sink: Any) -> None:
            return None

        def set_persistence_error_callback(self, _cb: Any) -> None:
            return None

        def shutdown(self) -> None:
            return None

    monkeypatch.setattr(srv, "ScannerPostgresRepo", _StubRepo)
    monkeypatch.setattr(srv, "ModuleManager", _StubManager)
    monkeypatch.setattr(srv, "validate_module_default_configs", lambda _path: None)

    class _StubSettings:
        class _Modules:
            path = "/tmp/does-not-matter"

        class _Postgres:
            dsn = "postgresql://stub"

        modules = _Modules()
        postgres = _Postgres()

    from otalon_scan.settings import Settings

    monkeypatch.setattr(Settings, "from_json", classmethod(lambda _cls, _path: _StubSettings()))
    monkeypatch.setattr(srv, "_resolve_config_path", lambda: "/tmp/config.json")

    async with LifespanManager(srv.app):
        pass

    assert len(reconcile_calls) == 1
    # At cold start the registry holds no live tasks.
    assert reconcile_calls[0]["active_job_ids"] == []
    # E2E-B2: orphaned RUNNING scans are reconciled once on startup too.
    assert len(scan_reconcile_calls) == 1
