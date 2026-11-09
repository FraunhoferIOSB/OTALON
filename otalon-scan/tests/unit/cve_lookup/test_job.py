"""WA.3 tests for the CVE-lookup async job wrapper (SCAN-026).

Covers :class:`otalon_scan.cve_lookup.job.LookupJobRegistry`, the Fork-2b
task-registry wrapper around the unchanged
:func:`otalon_scan.cve_lookup.core.run_lookup`:

- a successful run calls ``run_lookup`` exactly once, persists the result,
  finalizes the record as ``completed`` with the CONCEPT §6 summary, and
  emits one ``progress`` event per asset plus a terminal ``done`` event;
- a forced error → the record is finalized ``failed`` with the error text
  and a terminal ``failed`` event, and **no exception leaks** from the
  task.

Fully in-process: no Postgres, no network. The CVE source and repo are
fakes; ``run_lookup`` runs for real against the fake source (it is pure).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from uuid import uuid4

import pytest

from otalon_scan.cve_lookup.core import LookupResult, run_lookup
from otalon_scan.cve_lookup.job import LookupJobRegistry
from otalon_scan.cve_lookup.sources.base import CveHit, LookupAsset
from otalon_scan.repositories.models import CveLookupStatus


class _FakeSource:
    """CVE source returning a fixed hit list per asset and counting calls."""

    def __init__(self, hits_by_device: Dict[int, List[CveHit]]) -> None:
        self._hits = hits_by_device
        self.fetch_calls = 0

    async def fetch(self, asset: LookupAsset) -> List[CveHit]:
        self.fetch_calls += 1
        return list(self._hits.get(asset.device_id, []))


class _ExplodingSource:
    """CVE source that raises on the first fetch (forced-error path)."""

    async def fetch(self, asset: LookupAsset) -> List[CveHit]:
        raise RuntimeError("NVD unreachable")


class _FakeRepo:
    """Records ``finish_lookup`` calls for assertion."""

    def __init__(self) -> None:
        self.finished: List[Dict[str, Any]] = []

    async def finish_lookup(
        self,
        lookup_id: Any,
        status: CveLookupStatus,
        summary: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None,
    ) -> None:
        self.finished.append(
            {
                "lookup_id": str(lookup_id),
                "status": status,
                "summary": summary,
                "error": error,
            }
        )


class _FakeScanFinalizer:
    """Records the synthetic-scan terminal finalizations (E2E-B1).

    The job body invokes the injected ``finalize_scan`` callback on every
    terminal branch (completed / failed / aborted); this fake captures the
    ``(status, error)`` tuples so a test can assert the synthetic ``scans``
    row would be finalized — the previous success-only path left an
    operator-cancelled scan stuck ``RUNNING``.
    """

    def __init__(self) -> None:
        self.calls: List[Dict[str, Any]] = []

    async def __call__(self, status_value: str, error_text: Optional[str]) -> None:
        self.calls.append({"status": status_value, "error": error_text})


def _assets() -> List[LookupAsset]:
    return [
        LookupAsset(device_id=1, vendor="Siemens", product="S7-1500", version="2.8"),
        LookupAsset(device_id=2, vendor="Phoenix", product="ILC", version="1.0"),
    ]


async def test_successful_run_completes_and_calls_run_lookup_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A happy run → completed, run_lookup once, per-asset + done events."""
    source = _FakeSource(
        {
            1: [CveHit(vuln_id="CVE-2024-0001", severity="critical", cvss_score=9.8)],
            2: [],
        }
    )
    repo = _FakeRepo()
    written: List[LookupResult] = []

    async def _persist(job_id: str, result: LookupResult) -> int:
        written.append(result)
        return result.total_hits

    # Wrap run_lookup to count invocations without changing its behaviour.
    import otalon_scan.cve_lookup.job as job_mod

    calls = {"n": 0}
    real_run_lookup = run_lookup

    async def _counting_run_lookup(assets: Any, src: Any, **kwargs: Any) -> LookupResult:
        calls["n"] += 1
        return await real_run_lookup(assets, src, **kwargs)

    monkeypatch.setattr(job_mod, "run_lookup", _counting_run_lookup)

    registry = LookupJobRegistry()
    job_id = uuid4()

    events: List[Dict[str, Any]] = []

    async def _drain() -> None:
        async for evt in registry.progress_bus.subscribe(str(job_id)):
            events.append(evt)

    import asyncio

    finalizer = _FakeScanFinalizer()
    drainer = asyncio.ensure_future(_drain())
    task = registry.start(
        job_id=job_id,
        assets=_assets(),
        source=source,
        repo=repo,
        persist=_persist,
        finalize_scan=finalizer,
        api_key_used=True,
    )
    await task
    await drainer

    # synthetic scan finalized completed exactly once (E2E-B1 parity).
    assert finalizer.calls == [{"status": "completed", "error": None}]
    # run_lookup called exactly once.
    assert calls["n"] == 1
    # source.fetch called once per asset (run_lookup internals, unchanged).
    assert source.fetch_calls == 2
    # persisted once.
    assert len(written) == 1
    # finalized completed with the CONCEPT §6 summary.
    assert len(repo.finished) == 1
    fin = repo.finished[0]
    assert fin["status"] is CveLookupStatus.COMPLETED
    assert fin["error"] is None
    summary = fin["summary"]
    assert summary["assets_scanned"] == 2
    assert summary["cves_found"] == 1
    assert summary["critical"] == 1
    assert summary["rate_limit_hits"] == 0
    assert len(summary["per_asset"]) == 2
    # events: 2 progress + 1 terminal done.
    progress = [e for e in events if e["event"] == "progress"]
    done = [e for e in events if e["event"] == "done"]
    assert len(progress) == 2
    assert len(done) == 1
    assert done[0]["data"]["job_id"] == str(job_id)
    assert done[0]["data"]["status"] == "completed"
    assert done[0]["data"]["cves_found"] == 1
    assert done[0]["data"]["critical"] == 1


async def test_forced_error_finalizes_failed_without_leak() -> None:
    """A forced error → failed status + failed event, no exception leak."""
    repo = _FakeRepo()

    async def _persist(job_id: str, result: LookupResult) -> int:
        return 0

    registry = LookupJobRegistry()
    job_id = uuid4()

    import asyncio

    events: List[Dict[str, Any]] = []

    async def _drain() -> None:
        async for evt in registry.progress_bus.subscribe(str(job_id)):
            events.append(evt)

    finalizer = _FakeScanFinalizer()
    drainer = asyncio.ensure_future(_drain())
    task = registry.start(
        job_id=job_id,
        assets=_assets(),
        source=_ExplodingSource(),
        repo=repo,
        persist=_persist,
        finalize_scan=finalizer,
        api_key_used=False,
    )
    # The task MUST complete without raising.
    await task
    assert task.exception() is None
    await drainer

    # synthetic scan finalized failed with the error text (E2E-B1).
    assert len(finalizer.calls) == 1
    assert finalizer.calls[0]["status"] == "failed"
    assert "NVD unreachable" in (finalizer.calls[0]["error"] or "")
    assert len(repo.finished) == 1
    fin = repo.finished[0]
    assert fin["status"] is CveLookupStatus.FAILED
    assert fin["error"] is not None
    assert "NVD unreachable" in fin["error"]
    failed = [e for e in events if e["event"] == "failed"]
    assert len(failed) == 1
    assert failed[0]["data"]["status"] == "failed"
    assert "NVD unreachable" in failed[0]["data"]["error"]


async def test_stream_events_live_yields_progress_then_terminal() -> None:
    """``stream_events`` on a live job yields progress + one terminal done."""
    source = _FakeSource(
        {
            1: [CveHit(vuln_id="CVE-2024-0001", severity="critical", cvss_score=9.8)],
            2: [],
        }
    )
    repo = _FakeRepo()

    async def _persist(job_id: str, result: LookupResult) -> int:
        return result.total_hits

    registry = LookupJobRegistry()
    job_id = uuid4()

    collected: List[Dict[str, Any]] = []

    async def _consume() -> None:
        async for evt in registry.stream_events(job_id):
            collected.append(evt)

    import asyncio

    consumer = asyncio.ensure_future(_consume())
    task = registry.start(
        job_id=job_id,
        assets=_assets(),
        source=source,
        repo=repo,
        persist=_persist,
        finalize_scan=_FakeScanFinalizer(),
        api_key_used=True,
    )
    await task
    await consumer

    progress = [e for e in collected if e["event"] == "progress"]
    terminal = [e for e in collected if e["event"] in ("done", "failed")]
    assert len(progress) == 2
    assert len(terminal) == 1
    assert terminal[0]["event"] == "done"
    assert terminal[0]["data"]["job_id"] == str(job_id)
    assert terminal[0]["data"]["status"] == "completed"


async def test_stream_events_replays_terminal_for_finished_job() -> None:
    """A late ``stream_events`` subscriber still gets the terminal event."""
    source = _FakeSource({1: [], 2: []})
    repo = _FakeRepo()

    async def _persist(job_id: str, result: LookupResult) -> int:
        return 0

    registry = LookupJobRegistry()
    job_id = uuid4()

    # Run the job to completion FIRST — the live queue is gone afterwards.
    task = registry.start(
        job_id=job_id,
        assets=_assets(),
        source=source,
        repo=repo,
        persist=_persist,
        finalize_scan=_FakeScanFinalizer(),
        api_key_used=False,
    )
    await task

    # Now subscribe — only the retained terminal event must be replayed.
    replayed: List[Dict[str, Any]] = []
    async for evt in registry.stream_events(job_id):
        replayed.append(evt)

    assert len(replayed) == 1
    assert replayed[0]["event"] == "done"
    assert replayed[0]["data"]["job_id"] == str(job_id)
    assert replayed[0]["data"]["status"] == "completed"


async def test_request_cancel_finalizes_aborted_with_terminal_event() -> None:
    """Cooperative cancellation → aborted status + terminal aborted event (R-02).

    A source that blocks on the first asset's ``fetch`` lets the test flag
    the job for cancellation mid-sweep; the next iteration boundary then
    raises :class:`LookupCancelled`, finalizing the job as ``aborted``
    with a terminal ``aborted`` event and no exception leak.
    """
    import asyncio

    registry = LookupJobRegistry()
    job_id = uuid4()
    first_fetch_started = asyncio.Event()
    release_first_fetch = asyncio.Event()

    class _BlockingSource:
        async def fetch(self, asset: LookupAsset) -> List[CveHit]:
            first_fetch_started.set()
            await release_first_fetch.wait()
            return []

    repo = _FakeRepo()

    async def _persist(job_id: str, result: LookupResult) -> int:
        return 0

    events: List[Dict[str, Any]] = []

    async def _drain() -> None:
        async for evt in registry.progress_bus.subscribe(str(job_id)):
            events.append(evt)

    finalizer = _FakeScanFinalizer()
    drainer = asyncio.ensure_future(_drain())
    task = registry.start(
        job_id=job_id,
        assets=_assets(),
        source=_BlockingSource(),
        repo=repo,
        persist=_persist,
        finalize_scan=finalizer,
        api_key_used=False,
    )

    await first_fetch_started.wait()
    assert registry.request_cancel(job_id) is True
    release_first_fetch.set()

    await task
    assert task.exception() is None
    await drainer

    # synthetic scan finalized aborted (E2E-B1: no stuck RUNNING row).
    assert len(finalizer.calls) == 1
    assert finalizer.calls[0]["status"] == "aborted"
    assert len(repo.finished) == 1
    fin = repo.finished[0]
    assert fin["status"] is CveLookupStatus.ABORTED
    aborted = [e for e in events if e["event"] == "aborted"]
    assert len(aborted) == 1
    assert aborted[0]["data"]["status"] == "aborted"
    # The cancel flag is cleared after the job settles.
    assert registry.request_cancel(job_id) is False


async def test_request_cancel_interrupts_single_inflight_fetch() -> None:
    """Hard-cancel interrupts a single long in-flight NVD ``await`` (R-02).

    A single-asset lookup has no further iteration boundary, so the
    between-asset flag check cannot stop a slow query mid-flight. The
    accompanying ``task.cancel()`` must interrupt the awaited ``fetch`` so
    Stop is honoured immediately rather than after the query returns.
    """
    import asyncio

    registry = LookupJobRegistry()
    job_id = uuid4()
    fetch_started = asyncio.Event()

    class _HangingSource:
        async def fetch(self, asset: LookupAsset) -> List[CveHit]:
            fetch_started.set()
            await asyncio.sleep(3600)  # never returns on its own
            return []

    repo = _FakeRepo()

    async def _persist(job_id: str, result: LookupResult) -> int:
        return 0

    finalizer = _FakeScanFinalizer()
    task = registry.start(
        job_id=job_id,
        assets=[_assets()[0]],
        source=_HangingSource(),
        repo=repo,
        persist=_persist,
        finalize_scan=finalizer,
        api_key_used=False,
    )

    await fetch_started.wait()
    assert registry.request_cancel(job_id) is True
    await asyncio.wait_for(task, timeout=5)
    assert task.exception() is None

    assert len(repo.finished) == 1
    assert repo.finished[0]["status"] is CveLookupStatus.ABORTED
    assert finalizer.calls == [{"status": "aborted", "error": "Cancelled by operator"}]


async def test_await_cancelled_blocks_until_terminal_finalization() -> None:
    """``await_cancelled`` returns only after the abort path finalizes (E2E-B1).

    The ``/stop`` endpoint awaits this so the synthetic ``scans`` row is
    durably ``aborted`` and the DB session released before HTTP 200 — the
    fire-and-forget cancel previously returned while the row was still
    ``RUNNING`` (the event-loop-block symptom).
    """
    import asyncio

    registry = LookupJobRegistry()
    job_id = uuid4()
    fetch_started = asyncio.Event()

    class _HangingSource:
        async def fetch(self, asset: LookupAsset) -> List[CveHit]:
            fetch_started.set()
            await asyncio.sleep(3600)
            return []

    repo = _FakeRepo()
    finalizer = _FakeScanFinalizer()

    async def _persist(job_id: str, result: LookupResult) -> int:
        return 0

    registry.start(
        job_id=job_id,
        assets=[_assets()[0]],
        source=_HangingSource(),
        repo=repo,
        persist=_persist,
        finalize_scan=finalizer,
        api_key_used=False,
    )

    await fetch_started.wait()
    assert registry.request_cancel(job_id) is True
    finalized = await registry.await_cancelled(job_id, timeout=5)

    assert finalized is True
    # By the time await_cancelled returns BOTH rows are finalized aborted.
    assert repo.finished and repo.finished[0]["status"] is CveLookupStatus.ABORTED
    assert finalizer.calls == [{"status": "aborted", "error": "Cancelled by operator"}]


def test_active_job_ids_empty_after_completion() -> None:
    """After a job finishes, the registry reports no active job ids."""
    import asyncio

    async def _run() -> List[str]:
        repo = _FakeRepo()

        async def _persist(job_id: str, result: LookupResult) -> int:
            return 0

        registry = LookupJobRegistry()
        job_id = uuid4()
        task = registry.start(
            job_id=job_id,
            assets=[],
            source=_FakeSource({}),
            repo=repo,
            persist=_persist,
            finalize_scan=_FakeScanFinalizer(),
            api_key_used=False,
        )
        await task
        return registry.active_job_ids()

    assert asyncio.run(_run()) == []
