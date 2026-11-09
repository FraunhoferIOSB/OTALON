"""Unit tests for :class:`JobRunner` runtime retrain orchestration.

Covers the tasks 8.2 checkbox claims that previously had no test at all
(audit F4): in-process single-flight, ``retrain_paused`` fast-fail, the
empty-window failure, failure rollback (no publish on error), the
stage-then-publish ordering (no live mutation before all training
succeeds — audit B-02/B-03), worker-ownership guards (B-05), and the
cooperative shutdown boundary (B-06).

The heavy training helpers are replaced with fakes via monkeypatch so
the tests exercise the JobRunner state machine, not polars/sklearn.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import polars as pl
import pytest

import otalon_clas.runtime.job_runner as job_runner_mod
from otalon_clas.common.postgres_connector import (
    PostgresConnector,
    RetrainJob,
    RuntimeConfig,
)
from otalon_clas.runtime.job_runner import JobRunner
from otalon_clas.runtime.retrain_job_repository import RetrainJobRepository


class _FakeInflux:
    """Influx stub returning a marker DataFrame, an empty one, or raising.

    ``unavailable=True`` raises :class:`InfluxUnavailableError` from ``fetch`` so
    tests can prove the JobRunner distinguishes a transient/stale source failure
    from a genuinely empty window (CAPTURE 48).
    """

    def __init__(self, empty: bool = False, unavailable: bool = False) -> None:
        self._empty = empty
        self._unavailable = unavailable

    def fetch(self, start: str, stop: str) -> Any:
        if self._unavailable:
            from otalon_clas.common.influx_connector import InfluxUnavailableError

            raise InfluxUnavailableError("stale gRPC channel to 10.0.0.9:8181")
        return pl.DataFrame() if self._empty else pl.DataFrame({"value": [1]})


class _IntervalInflux:
    """Influx stub returning a distinct frame for each requested interval."""

    def __init__(self, frames: dict[tuple[str, str], pl.DataFrame]) -> None:
        self.frames = frames
        self.calls: list[tuple[str, str]] = []

    def fetch(self, start: str, stop: str) -> pl.DataFrame:
        self.calls.append((start, stop))
        return self.frames[(start, stop)]


class _FakePreprocessor:
    def preprocess_for_training(self, df: Any) -> Any:
        return df


class _FakeModuleConfig:
    def __init__(self, name: str = "conn", classification_enabled: bool = True) -> None:
        self.name = name
        self.bounds_enabled = True
        self.tag_key = "uci"

        class _Freq:
            enabled = True

        class _Cls:
            enabled = classification_enabled
            force_publish_class_set_shrink = False

        self.frequency_monitor = _Freq()
        self.classification = _Cls()


class _FakeBundle:
    """Duck-typed bundle sufficient for JobRunner staging."""

    def __init__(
        self,
        name: str = "conn",
        empty: bool = False,
        classification_enabled: bool = True,
        unavailable: bool = False,
    ) -> None:
        self.config = _FakeModuleConfig(name, classification_enabled=classification_enabled)
        self.influx = _FakeInflux(empty=empty, unavailable=unavailable)
        self.preprocessor = _FakePreprocessor()
        self.published: list[str] = []


class _FakeModelStore:
    """Model store stub whose ``has_model`` answers from a fixed name set."""

    def __init__(self, deployed: set[str] | None = None) -> None:
        self._deployed = deployed or set()

    def has_model(self, module_name: str) -> bool:
        return module_name in self._deployed


def _make_connector(tmp_path: Path) -> PostgresConnector:
    db = tmp_path / "jr.sqlite"
    pg = PostgresConnector(dsn=f"sqlite:///{db}", pool_size=1, max_overflow=0)
    RetrainJob.__table__.create(pg.engine, checkfirst=True)
    RuntimeConfig.__table__.create(pg.engine, checkfirst=True)
    return pg


def _seed_queued(pg: PostgresConnector, job_ref: str, scope: str = "bounds_frequency") -> None:
    RetrainJobRepository(pg).insert_queued(
        job_ref=job_ref,
        scope=scope,
        window_start="2026-05-08 12:00:00",
        window_stop="2026-05-08 12:30:00",
    )


@pytest.fixture()
def patched_helpers(monkeypatch: pytest.MonkeyPatch) -> dict[str, list]:
    """Replace compute/publish helpers with recording fakes."""
    published: list[str] = []
    computed: list[str] = []

    class _BoundsCand:
        def __init__(self, module: str) -> None:
            self.module = module

    class _FreqCand:
        def __init__(self, module: str) -> None:
            self.module = module
            # A staged frequency candidate always carries its computed profiles;
            # the runner only stages a candidate whose profiles dict is truthy.
            self.profiles = {f"{module}-s1": object()}

    def _compute_bounds(config: Any, bundle: Any, df: Any) -> Any:
        computed.append(f"bounds:{bundle.config.name}")
        return _BoundsCand(bundle.config.name)

    def _compute_freq(bundle: Any, df: Any) -> Any:
        computed.append(f"freq:{bundle.config.name}")
        return _FreqCand(bundle.config.name)

    def _publish_bounds(bundle: Any, cand: Any, *, invalidate_cache: bool = True) -> None:
        published.append(f"bounds:{cand.module}")

    def _publish_freq(bundle: Any, cand: Any, *, notify_channel: Any = None) -> None:
        published.append(f"freq:{cand.module}")

    monkeypatch.setattr(job_runner_mod, "compute_bounds_candidate", _compute_bounds)
    monkeypatch.setattr(job_runner_mod, "compute_frequency_candidate", _compute_freq)
    monkeypatch.setattr(job_runner_mod, "publish_bounds_candidate", _publish_bounds)
    monkeypatch.setattr(job_runner_mod, "publish_frequency_candidate", _publish_freq)
    return {"published": published, "computed": computed}


@pytest.fixture()
def patched_classifier_helpers(monkeypatch: pytest.MonkeyPatch) -> dict[str, list]:
    """Replace classifier train/publish helpers with recording fakes.

    ``_swap_model_into_bundle`` is stubbed too so publication does not try
    to reload a real model file through the fake store.
    """
    trained: list[str] = []
    published: list[str] = []

    class _ClfCand:
        def __init__(self, module: str) -> None:
            self.module = module
            self.metrics = {"accuracy": 1.0}

    def _train_clf(bundle: Any, df: Any, *, mitre_file: Any = None) -> Any:
        trained.append(bundle.config.name)
        return _ClfCand(bundle.config.name)

    def _publish_clf(
        store: Any,
        bundle: Any,
        cand: Any,
        *,
        swap_into_bundle: bool = False,
        force_publish_class_set_shrink: bool = False,
    ) -> bool:
        published.append(cand.module)
        return True

    monkeypatch.setattr(job_runner_mod, "train_classifier_candidate", _train_clf)
    monkeypatch.setattr(job_runner_mod, "publish_classifier_candidate", _publish_clf)
    monkeypatch.setattr(JobRunner, "_swap_model_into_bundle", lambda self, bundle: None)
    return {"trained": trained, "published": published}


def _seed_classifier_job(pg: PostgresConnector, job_ref: str) -> None:
    """Insert a queued classifier-scope job with a readable mitre_file."""
    RetrainJobRepository(pg).insert_queued(
        job_ref=job_ref,
        scope="classifier",
        window_start="2026-05-08 12:00:00",
        window_stop="2026-05-08 12:30:00",
        mitre_file=__file__,
    )


def _seed_classifier_job_with_intervals(pg: PostgresConnector, job_ref: str) -> None:
    """Insert classifier job whose intervals overlap at one sample boundary."""
    RetrainJobRepository(pg).insert_queued(
        job_ref=job_ref,
        scope="classifier",
        window_start="2026-05-08 12:00:00",
        window_stop="2026-05-08 12:30:00",
        mitre_file=__file__,
        intervals=[
            ("2026-05-08 12:00:00", "2026-05-08 12:15:00"),
            ("2026-05-08 12:15:00", "2026-05-08 12:30:00"),
        ],
    )


def _make_runner(
    pg: PostgresConnector,
    bundles: list[_FakeBundle],
    model_store: Any = None,
) -> JobRunner:
    return JobRunner(
        config=object(),
        pg=pg,
        model_store=model_store if model_store is not None else object(),
        bundles=bundles,  # type: ignore[arg-type]
    )


def _wait_terminal(repo: RetrainJobRepository, job_ref: str, timeout: float = 5.0) -> Any:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        dto = repo.get(job_ref)
        if dto is not None and dto.state in {"succeeded", "failed"}:
            return dto
        time.sleep(0.02)
    return repo.get(job_ref)


def _join_job(runner: JobRunner, timeout: float = 5.0) -> None:
    """Wait for the in-flight job thread to finish naturally (no stop signal)."""
    thread = runner._thread
    if thread is not None:
        thread.join(timeout=timeout)


def test_happy_path_stages_then_publishes(tmp_path: Path, patched_helpers: dict[str, list]) -> None:
    """All modules stage before any publish; job ends succeeded."""
    pg = _make_connector(tmp_path)
    repo = RetrainJobRepository(pg)
    _seed_queued(pg, "job-ok")
    runner = _make_runner(pg, [_FakeBundle("conn"), _FakeBundle("mac_traffic")])

    assert runner.try_run("job-ok") is True
    _join_job(runner)

    dto = _wait_terminal(repo, "job-ok")
    assert dto is not None and dto.state == "succeeded"
    # Both modules were computed and published.
    assert set(patched_helpers["published"]) == {
        "bounds:conn",
        "freq:conn",
        "bounds:mac_traffic",
        "freq:mac_traffic",
    }


def test_second_job_refused_while_running(tmp_path: Path) -> None:
    """In-process single-flight: a second try_run is refused while locked."""
    pg = _make_connector(tmp_path)
    _seed_queued(pg, "job-1")
    runner = _make_runner(pg, [_FakeBundle("conn")])

    # Hold the lock to simulate a running job.
    assert runner._lock.acquire(blocking=False) is True
    try:
        assert runner.try_run("job-2") is False
    finally:
        runner._lock.release()


def test_paused_job_fast_fails_without_claim(tmp_path: Path) -> None:
    """retrain_paused=true fails the job without training (task 8.2)."""
    pg = _make_connector(tmp_path)
    repo = RetrainJobRepository(pg)
    _seed_queued(pg, "job-paused")
    runner = _make_runner(pg, [_FakeBundle("conn")])
    # Force the pause check to report paused.
    runner._is_paused = lambda: True  # type: ignore[method-assign]

    assert runner.try_run("job-paused") is True
    _join_job(runner)

    dto = _wait_terminal(repo, "job-paused")
    assert dto is not None and dto.state == "failed"
    assert "paused" in (dto.error or "").lower() or "paused" in dto.detail.lower()


def test_empty_window_fails_and_publishes_nothing(tmp_path: Path, patched_helpers: dict[str, list]) -> None:
    """An all-empty training window fails the job and publishes nothing (F3)."""
    pg = _make_connector(tmp_path)
    repo = RetrainJobRepository(pg)
    _seed_queued(pg, "job-empty")
    runner = _make_runner(pg, [_FakeBundle("conn", empty=True)])

    assert runner.try_run("job-empty") is True
    _join_job(runner)

    dto = _wait_terminal(repo, "job-empty")
    assert dto is not None and dto.state == "failed"
    assert patched_helpers["published"] == []


def test_source_unavailable_fails_distinctly_from_empty(tmp_path: Path, patched_helpers: dict[str, list]) -> None:
    """A stale/unreachable Influx source fails with a source-error, not 'empty'.

    CAPTURE 48: transient Influx restarts / stale gRPC clients may not be
    collapsed into the misleading ``empty/insufficient data`` result. The
    terminal evidence must name the data-source failure and publish nothing.
    """
    pg = _make_connector(tmp_path)
    repo = RetrainJobRepository(pg)
    _seed_queued(pg, "job-unavailable")
    runner = _make_runner(pg, [_FakeBundle("conn", unavailable=True)])

    assert runner.try_run("job-unavailable") is True
    _join_job(runner)

    dto = _wait_terminal(repo, "job-unavailable")
    assert dto is not None and dto.state == "failed"
    evidence = f"{dto.error or ''} {dto.detail or ''}".lower()
    # Source failure is named explicitly and is NOT reported as empty data.
    assert "training data unavailable" in evidence
    assert "empty/insufficient data" not in evidence
    assert patched_helpers["published"] == []


def test_empty_and_unavailable_yield_different_terminal_evidence(
    tmp_path: Path, patched_helpers: dict[str, list]
) -> None:
    """The empty-window and source-unavailable paths produce distinct errors."""
    pg = _make_connector(tmp_path)
    repo = RetrainJobRepository(pg)
    _seed_queued(pg, "job-empty-2")
    _seed_queued(pg, "job-unavail-2")

    runner_empty = _make_runner(pg, [_FakeBundle("conn", empty=True)])
    assert runner_empty.try_run("job-empty-2") is True
    _join_job(runner_empty)
    empty_dto = _wait_terminal(repo, "job-empty-2")

    runner_unavail = _make_runner(pg, [_FakeBundle("conn", unavailable=True)])
    assert runner_unavail.try_run("job-unavail-2") is True
    _join_job(runner_unavail)
    unavail_dto = _wait_terminal(repo, "job-unavail-2")

    assert empty_dto is not None and unavail_dto is not None
    empty_evidence = f"{empty_dto.error or ''} {empty_dto.detail or ''}".lower()
    unavail_evidence = f"{unavail_dto.error or ''} {unavail_dto.detail or ''}".lower()
    assert "empty/insufficient data" in empty_evidence
    assert "training data unavailable" in unavail_evidence
    assert empty_evidence != unavail_evidence


def test_bounds_frequency_scope_stages_and_publishes_both_artifacts(
    tmp_path: Path, patched_helpers: dict[str, list]
) -> None:
    """A data-bearing bounds_frequency window stages then publishes bounds+freq.

    CAPTURE 48: a data-bearing window must atomically publish real bounds AND
    frequency artifacts. This proves the ``bounds_frequency`` scope computes
    both candidate kinds during staging and publishes both on success, with no
    publication happening before staging completes.
    """
    pg = _make_connector(tmp_path)
    repo = RetrainJobRepository(pg)
    _seed_queued(pg, "job-bf", scope="bounds_frequency")
    runner = _make_runner(pg, [_FakeBundle("conn")])

    assert runner.try_run("job-bf") is True
    _join_job(runner)

    dto = _wait_terminal(repo, "job-bf")
    assert dto is not None and dto.state == "succeeded"
    # Both artifact kinds were computed (staged) and published for the module.
    assert set(patched_helpers["computed"]) == {"bounds:conn", "freq:conn"}
    assert set(patched_helpers["published"]) == {"bounds:conn", "freq:conn"}
    # The job records the trained module in its metrics evidence.
    assert dto.metrics is not None
    assert "conn" in (dto.metrics.get("trained_modules") or [])


def test_failure_in_second_module_publishes_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A training failure in any module leaves prior artifacts unpublished (B-02)."""
    pg = _make_connector(tmp_path)
    repo = RetrainJobRepository(pg)
    _seed_queued(pg, "job-fail")
    published: list[str] = []

    def _compute_bounds(config: Any, bundle: Any, df: Any) -> Any:
        if bundle.config.name == "mac_traffic":
            raise RuntimeError("boom during staging")

        class _C:
            module = bundle.config.name

        return _C()

    def _compute_freq(bundle: Any, df: Any) -> Any:
        class _C:
            module = bundle.config.name
            profiles = {f"{bundle.config.name}-s1": object()}

        return _C()

    monkeypatch.setattr(job_runner_mod, "compute_bounds_candidate", _compute_bounds)
    monkeypatch.setattr(job_runner_mod, "compute_frequency_candidate", _compute_freq)
    monkeypatch.setattr(
        job_runner_mod,
        "publish_bounds_candidate",
        lambda *a, **k: published.append("bounds"),
    )
    monkeypatch.setattr(
        job_runner_mod,
        "publish_frequency_candidate",
        lambda *a, **k: published.append("freq"),
    )

    runner = _make_runner(pg, [_FakeBundle("conn"), _FakeBundle("mac_traffic")])
    assert runner.try_run("job-fail") is True
    _join_job(runner)

    dto = _wait_terminal(repo, "job-fail")
    assert dto is not None and dto.state == "failed"
    # Nothing published even though the first module staged fine.
    assert published == []


def test_worker_aborts_when_ownership_lost(
    tmp_path: Path, patched_helpers: dict[str, list], monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the row is reaped mid-run, the worker aborts and cannot flap it (B-05)."""
    pg = _make_connector(tmp_path)
    repo = RetrainJobRepository(pg)
    _seed_queued(pg, "job-reap")

    # After staging, simulate the reaper stealing the row before publish.
    original_publish_bounds = job_runner_mod.publish_bounds_candidate

    def _steal_then_publish(bundle: Any, cand: Any, **k: Any) -> None:
        with pg.session() as session:
            row = session.query(RetrainJob).filter_by(job_ref="job-reap").one()
            if row.state != "failed":
                row.state = "failed"
                row.worker_id = None
                row.error = "heartbeat timeout"
        original_publish_bounds(bundle, cand, **k)

    monkeypatch.setattr(job_runner_mod, "publish_bounds_candidate", _steal_then_publish)

    runner = _make_runner(pg, [_FakeBundle("conn")])
    # set_state('publishing') must fail because worker lost ownership.
    assert runner.try_run("job-reap") is True
    _join_job(runner)

    dto = repo.get("job-reap")
    assert dto is not None
    # The reaped 'failed' terminal state must NOT have flapped to succeeded.
    assert dto.state == "failed"
    assert dto.error == "heartbeat timeout"


def test_stop_before_start_refuses_new_jobs(tmp_path: Path) -> None:
    """After a stop request, try_run refuses to start a job (B-06)."""
    pg = _make_connector(tmp_path)
    _seed_queued(pg, "job-late")
    runner = _make_runner(pg, [_FakeBundle("conn")])
    runner.request_stop()
    assert runner.try_run("job-late") is False


def test_stop_uses_non_daemon_thread(tmp_path: Path, patched_helpers: dict[str, list]) -> None:
    """The job thread is non-daemon so shutdown can join it (B-06)."""
    pg = _make_connector(tmp_path)
    _seed_queued(pg, "job-nd")
    runner = _make_runner(pg, [_FakeBundle("conn")])
    assert runner.try_run("job-nd") is True
    assert runner._thread is not None
    assert runner._thread.daemon is False
    runner.stop(timeout=5.0)


# ---------------------------------------------------------------------------
# Classifier runtime scope = EXISTING persisted classifiers only.
#
# The runtime "retrain existing classifiers" path MUST retrain only modules
# that already have a deployed classifier artifact (in the current
# deployment: ``conn``). Modules enabled for live prediction but WITHOUT a
# persisted model (``mac_traffic``/``proto_traffic``) MUST be skipped with
# an explicit reason and MUST NOT get a first-time model — CLAS-004 stays
# out of scope. A classifier job with zero existing candidates MUST fail
# safely and publish nothing.
# ---------------------------------------------------------------------------


def test_classifier_scope_stages_only_existing_model(
    tmp_path: Path, patched_classifier_helpers: dict[str, list]
) -> None:
    """Only the module with a deployed classifier (conn) is staged/published."""
    pg = _make_connector(tmp_path)
    repo = RetrainJobRepository(pg)
    _seed_classifier_job(pg, "job-clf")
    store = _FakeModelStore(deployed={"conn"})
    runner = _make_runner(
        pg,
        [_FakeBundle("conn"), _FakeBundle("mac_traffic"), _FakeBundle("proto_traffic")],
        model_store=store,
    )

    assert runner.try_run("job-clf") is True
    _join_job(runner)

    dto = _wait_terminal(repo, "job-clf")
    assert dto is not None and dto.state == "succeeded"
    # Only conn was trained/published; mac/proto were never trained.
    assert patched_classifier_helpers["trained"] == ["conn"]
    assert patched_classifier_helpers["published"] == ["conn"]


def test_classifier_scope_fetches_interval_union_and_deduplicates_samples(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Outer classifier flow trains on one deduplicated multi-interval frame."""
    pg = _make_connector(tmp_path)
    repo = RetrainJobRepository(pg)
    _seed_classifier_job_with_intervals(pg, "job-clf-intervals")
    frame_a = pl.DataFrame(
        {
            "time": ["2026-05-08T12:10:00", "2026-05-08T12:15:00"],
            "uci": ["series-a", "series-a"],
            "feature": [1.0, 2.0],
        }
    )
    frame_b = pl.DataFrame(
        {
            "time": ["2026-05-08T12:15:00", "2026-05-08T12:20:00"],
            "uci": ["series-a", "series-a"],
            "feature": [2.0, 3.0],
        }
    )
    influx = _IntervalInflux(
        {
            ("2026-05-08 12:00:00", "2026-05-08 12:15:00"): frame_a,
            ("2026-05-08 12:15:00", "2026-05-08 12:30:00"): frame_b,
        }
    )
    bundle = _FakeBundle("conn")
    bundle.influx = influx
    captured: list[pl.DataFrame] = []

    class _ClfCandidate:
        module = "conn"
        metrics = {"accuracy": 1.0}

    def _train(bundle: Any, df: pl.DataFrame, *, mitre_file: Any = None) -> Any:
        captured.append(df)
        return _ClfCandidate()

    monkeypatch.setattr(job_runner_mod, "train_classifier_candidate", _train)
    monkeypatch.setattr(
        job_runner_mod,
        "publish_classifier_candidate",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(JobRunner, "_swap_model_into_bundle", lambda self, bundle: None)

    runner = _make_runner(pg, [bundle], model_store=_FakeModelStore(deployed={"conn"}))
    assert runner.try_run("job-clf-intervals") is True
    _join_job(runner)

    dto = _wait_terminal(repo, "job-clf-intervals")
    assert dto is not None and dto.state == "succeeded"
    assert influx.calls == [
        ("2026-05-08 12:00:00", "2026-05-08 12:15:00"),
        ("2026-05-08 12:15:00", "2026-05-08 12:30:00"),
    ]
    assert len(captured) == 1
    assert captured[0].height == 3
    assert captured[0]["feature"].to_list() == [1.0, 2.0, 3.0]


def test_classifier_scope_skips_missing_models_with_reason(
    tmp_path: Path, patched_classifier_helpers: dict[str, list]
) -> None:
    """mac/proto without a deployed model are skipped and recorded as skipped."""
    pg = _make_connector(tmp_path)
    repo = RetrainJobRepository(pg)
    _seed_classifier_job(pg, "job-clf-skip")
    store = _FakeModelStore(deployed={"conn"})
    runner = _make_runner(
        pg,
        [_FakeBundle("conn"), _FakeBundle("mac_traffic"), _FakeBundle("proto_traffic")],
        model_store=store,
    )

    assert runner.try_run("job-clf-skip") is True
    _join_job(runner)

    dto = _wait_terminal(repo, "job-clf-skip")
    assert dto is not None and dto.state == "succeeded"
    skipped = (dto.metrics or {}).get("classifier_skipped", {})
    assert set(skipped) == {"mac_traffic", "proto_traffic"}
    assert "no deployed classifier artifact" in skipped["mac_traffic"]
    # No first-time model was trained for the skipped modules.
    assert "mac_traffic" not in patched_classifier_helpers["trained"]
    assert "proto_traffic" not in patched_classifier_helpers["trained"]


def test_classifier_scope_fails_safely_when_no_existing_candidate(
    tmp_path: Path, patched_classifier_helpers: dict[str, list]
) -> None:
    """A classifier job with zero deployed classifiers fails and publishes nothing."""
    pg = _make_connector(tmp_path)
    repo = RetrainJobRepository(pg)
    _seed_classifier_job(pg, "job-clf-none")
    store = _FakeModelStore(deployed=set())
    runner = _make_runner(
        pg,
        [_FakeBundle("mac_traffic"), _FakeBundle("proto_traffic")],
        model_store=store,
    )

    assert runner.try_run("job-clf-none") is True
    _join_job(runner)

    dto = _wait_terminal(repo, "job-clf-none")
    assert dto is not None and dto.state == "failed"
    assert "no module with an already" in (dto.error or "").lower() or "deployed classifier" in (dto.error or "")
    # Nothing trained, nothing published — no first-time model created.
    assert patched_classifier_helpers["trained"] == []
    assert patched_classifier_helpers["published"] == []


def test_classifier_scope_skips_disabled_classification(
    tmp_path: Path, patched_classifier_helpers: dict[str, list]
) -> None:
    """A module with classification.enabled=false is skipped before has_model."""
    pg = _make_connector(tmp_path)
    repo = RetrainJobRepository(pg)
    _seed_classifier_job(pg, "job-clf-disabled")
    # conn has a deployed model but classification is disabled -> skipped.
    store = _FakeModelStore(deployed={"conn"})
    runner = _make_runner(
        pg,
        [_FakeBundle("conn", classification_enabled=False)],
        model_store=store,
    )

    assert runner.try_run("job-clf-disabled") is True
    _join_job(runner)

    dto = _wait_terminal(repo, "job-clf-disabled")
    assert dto is not None and dto.state == "failed"
    assert patched_classifier_helpers["trained"] == []


def _seed_classifier_job_with_mitre(pg: PostgresConnector, job_ref: str, mitre_file: str) -> None:
    """Insert a queued classifier job with an explicit mitre_file path."""
    RetrainJobRepository(pg).insert_queued(
        job_ref=job_ref,
        scope="classifier",
        window_start="2026-05-08 12:00:00",
        window_stop="2026-05-08 12:30:00",
        mitre_file=mitre_file,
    )


def _make_runner_with_allowed_dirs(
    pg: PostgresConnector,
    bundles: list[_FakeBundle],
    allowed_mitre_dirs: tuple[str, ...],
    model_store: Any = None,
) -> JobRunner:
    return JobRunner(
        config=object(),
        pg=pg,
        model_store=model_store if model_store is not None else object(),
        bundles=bundles,  # type: ignore[arg-type]
        allowed_mitre_dirs=allowed_mitre_dirs,
    )


def test_runtime_mitre_file_outside_allowed_dir_is_rejected_before_training(
    tmp_path: Path, patched_classifier_helpers: dict[str, list]
) -> None:
    """A runtime mitre_file outside the allow-listed parent fails pre-read.

    Reproduces the production allow-list (a non-empty ``allowed_mitre_dirs``
    derived from the configured ``mitre_technique_file`` parent). A job whose
    ``mitre_file`` resolves outside that directory must fail the job before
    any Influx fetch or ``train_classifier_candidate`` call.
    """
    pg = _make_connector(tmp_path)
    repo = RetrainJobRepository(pg)

    allowed_dir = tmp_path / "labels"
    allowed_dir.mkdir()
    (allowed_dir / "mitre.json").write_text("{}", encoding="utf-8")

    outside_dir = tmp_path / "elsewhere"
    outside_dir.mkdir()
    outside_file = outside_dir / "evil.json"
    outside_file.write_text("{}", encoding="utf-8")

    _seed_classifier_job_with_mitre(pg, "job-clf-traversal", str(outside_file))
    store = _FakeModelStore(deployed={"conn"})
    runner = _make_runner_with_allowed_dirs(
        pg,
        [_FakeBundle("conn")],
        allowed_mitre_dirs=(str(allowed_dir),),
        model_store=store,
    )

    assert runner.try_run("job-clf-traversal") is True
    _join_job(runner)

    dto = _wait_terminal(repo, "job-clf-traversal")
    assert dto is not None and dto.state == "failed"
    assert "outside the allowed label directories" in (dto.error or "")
    # Rejected before any training happened.
    assert patched_classifier_helpers["trained"] == []
    assert patched_classifier_helpers["published"] == []


def test_runtime_mitre_file_inside_allowed_dir_passes_validation(
    tmp_path: Path, patched_classifier_helpers: dict[str, list]
) -> None:
    """A mitre_file under the allow-listed parent is accepted and trains."""
    pg = _make_connector(tmp_path)
    repo = RetrainJobRepository(pg)

    allowed_dir = tmp_path / "labels"
    allowed_dir.mkdir()
    allowed_file = allowed_dir / "mitre.json"
    allowed_file.write_text("{}", encoding="utf-8")

    _seed_classifier_job_with_mitre(pg, "job-clf-allowed", str(allowed_file))
    store = _FakeModelStore(deployed={"conn"})
    runner = _make_runner_with_allowed_dirs(
        pg,
        [_FakeBundle("conn")],
        allowed_mitre_dirs=(str(allowed_dir),),
        model_store=store,
    )

    assert runner.try_run("job-clf-allowed") is True
    _join_job(runner)

    dto = _wait_terminal(repo, "job-clf-allowed")
    assert dto is not None and dto.state == "succeeded"
    assert "conn" in patched_classifier_helpers["trained"]
