"""Regression tests for SCAN-005 (operator-path scans stuck on RUNNING).

Root cause (``.dev/todo/context/SCAN-005.md``): on the operator path the API
layer calls :meth:`ModuleManager.register_scan_id` synchronously at scan START
— before the child module process has produced any output. The previous fix
wrote the persistence ``scan_id`` INTO the ``module_results`` Manager dict
under ``module_results[uid]["scan_id"]``. ~30-120 s later the child process
finishes and writes its terminal payload as a FULL dict replacement
(``shared_results[uid] = {"module_name", "results", "scan_result",
"findings"}``) — without the ``scan_id`` key. That replacement CLOBBERED the
parent-written ``scan_id``.

By the time the monitor thread fires :meth:`_finalize_run`, the scan_id is
gone, so the run is deferred into ``_pending_finalize`` and returns. But
``register_scan_id`` already ran (at scan START) and never runs again, so the
deferred finalisation is never re-driven — the ``finish_scan`` UPDATE never
fires and the scan row is stranded at ``status=RUNNING`` / ``finished_at=NULL``
forever.

The SCAN-005 fix keeps the scan_id in a parent-only ``_scan_id_by_uid``
mapping the child never references, so the terminal payload cannot clobber it.

These mirror the unit-test shape of ``test_be3_finalize_status_race.py`` — no
PostgreSQL, no event loop; the ``ModuleManager`` is pointed at an empty modules
directory and driven through its lifecycle methods.
"""

from __future__ import annotations

from typing import Any, List, Optional, Tuple

import pytest

from otalon_scan.core.module_manager import ModuleManager


@pytest.fixture()
def manager(tmp_path: Any) -> ModuleManager:
    """A ModuleManager over an empty modules dir (no discovery required)."""
    empty_modules = tmp_path / "modules"
    empty_modules.mkdir()
    return ModuleManager(modules_path=str(empty_modules), batch_size=3)


def _write_child_terminal_payload(
    manager: ModuleManager,
    uid: str,
    *,
    module: str = "port_scan",
    error: Optional[str] = None,
    findings: Optional[List[dict[str, Any]]] = None,
) -> None:
    """Emulate the child process writing its terminal payload.

    Reproduces the exact FULL dict replacement done by ``_run_module_proc``
    (module_manager.py): a brand-new dict with NO ``scan_id`` key. In the
    pre-SCAN-005 code this overwrote ``module_results[uid]`` and clobbered any
    parent-written ``scan_id``.
    """
    payload: dict[str, Any] = {
        "module_name": module,
        "results": None,
        "scan_result": None,
        "findings": findings or [],
    }
    if error is not None:
        payload["error"] = error
    manager.module_results[uid] = payload


def test_scan_id_survives_child_terminal_payload_operator_path(
    manager: ModuleManager,
) -> None:
    """SCAN-005 core regression: operator-path ordering.

    register_scan_id runs FIRST (scan START), THEN the child writes its
    terminal full-dict payload, THEN the monitor fires _finalize_run. The
    scan MUST reach a terminal status addressed to the DB scan_id — it must
    NOT defer forever (the stuck-RUNNING symptom).

    Mutation guard: revert the fix (let register_scan_id write scan_id into
    module_results instead of _scan_id_by_uid) and this assertion goes RED,
    because the child payload clobbers the scan_id, _finalize_run defers, and
    no re-drive ever happens → finish_calls stays empty.
    """
    finish_calls: List[Tuple[str, str, Optional[str]]] = []
    manager.set_finish_sink(lambda s, st, e: finish_calls.append((s, st, e)))

    uid = "run-operator"
    db_scan_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"

    # 1. Scan START: API registers the DB scan_id synchronously, before the
    #    child has produced any output.
    manager.register_scan_id(uid, db_scan_id)
    assert uid not in manager._pending_finalize

    # 2. ~30-120 s later: the child finishes and writes its terminal payload
    #    as a full dict replacement (no scan_id key) — the clobber.
    _write_child_terminal_payload(manager, uid, module="port_scan")

    # 3. The monitor thread fires _finalize_run.
    manager._finalize_run(uid, "port_scan")

    # The scan MUST be finalised against the DB scan_id — not deferred,
    # not stuck.
    assert len(finish_calls) == 1, (
        "scan was deferred/stranded instead of finalised — the child terminal "
        "payload clobbered the scan_id (SCAN-005 regressed)"
    )
    addressed_scan_id, status, error_message = finish_calls[0]
    assert addressed_scan_id == db_scan_id
    assert addressed_scan_id != uid
    assert status == "completed"
    assert error_message is None
    assert uid not in manager._pending_finalize


def test_scan_id_lookup_reads_parent_only_mapping(manager: ModuleManager) -> None:
    """SCAN-005 invariant: the resolved scan_id is independent of the child
    payload. After the child overwrites ``module_results[uid]`` with a payload
    that carries no scan_id, ``_lookup_scan_id`` still returns the DB UUID."""
    uid = "run-lookup"
    db_scan_id = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

    manager.register_scan_id(uid, db_scan_id)
    _write_child_terminal_payload(manager, uid)

    assert manager._lookup_scan_id(uid) == db_scan_id


def test_fast_scan_defer_then_redrive_still_works(manager: ModuleManager) -> None:
    """SCAN-005 must NOT break the genuine fast-scan path: a run that finishes
    BEFORE register_scan_id ran is deferred, then re-driven on registration.

    Mutation guard for the opposite direction: if the fix accidentally made
    _finalize_run read scan_id from module_results again (so a child payload
    without scan_id is treated as 'ready'), this would finalise against the
    run UUID prematurely. Here we assert the correct defer→re-drive ordering.
    """
    finish_calls: List[Tuple[str, str, Optional[str]]] = []
    manager.set_finish_sink(lambda s, st, e: finish_calls.append((s, st, e)))

    uid = "run-fast"
    db_scan_id = "cccccccc-cccc-cccc-cccc-cccccccccccc"

    # Child finishes FIRST (fast scan), before register_scan_id.
    _write_child_terminal_payload(manager, uid, module="arp_scan")

    # Monitor fires before the scan_id is known → must defer, not finalise.
    manager._finalize_run(uid, "arp_scan")
    assert finish_calls == []
    assert uid in manager._pending_finalize

    # API registers the scan_id second → re-drives the deferred finalisation.
    manager.register_scan_id(uid, db_scan_id)

    assert len(finish_calls) == 1
    addressed_scan_id, status, _ = finish_calls[0]
    assert addressed_scan_id == db_scan_id
    assert status == "completed"
    assert uid not in manager._pending_finalize
