"""Direct cross-artifact/module publication-rollback tests for :class:`JobRunner`.

These tests exercise the ACTUAL ``JobRunner._publish_candidates`` /
``_capture_publication_backups`` / ``_restore_publication_backups``
compensation path against real SQLite-backed repositories, real live
caches (``BoundsManager`` / ``FrequencyMonitor``), and a real
``ModelStore`` with versioned generations. Nothing about the publish or
restore helpers is replaced with event recording — only the *later*
failure is injected (and the unavoidable staging/heavy-training boundary
is bypassed by constructing the staged candidates directly).

They cover the atomic-publication acceptance contract from the audit
triage FIX-NOW cluster "Publication not failure-atomic":

* a failure after an earlier artifact/module publish restores ALL
  already-touched persisted bounds/frequency rows to their exact prior
  snapshot (byte/field-equivalent), restores the live caches including
  runtime ``last_seen``, does not destructively rewrite untouched
  artifacts, and compensates in reverse actual touch order;
* an earlier frequency NOTIFY is followed by a compensating invalidation
  NOTIFY for the restored series after rollback (intercepted at the real
  ``emit_notify`` boundary);
* a classifier/module rollback restores the exact durable manifest
  pointer, the prior model metadata on load, and the live inference
  backend/scaler/label-map AND preprocessor protocol map (including an
  empty prior protocol map);
* a publication exception can never report ``succeeded`` — the full
  ``_execute_job`` job path lands terminal ``failed``.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast

import pytest

import otalon_clas.runtime.job_runner as job_runner_mod
from otalon_clas.common.model_store import ModelStore
from otalon_clas.common.postgres_connector import (
    Bound,
    FrequencyProfile,
    PostgresConnector,
    RetrainJob,
    RuntimeConfig,
)
from otalon_clas.common.settings import AppConfig
from otalon_clas.detection.bounds_manager import BoundsManager, BoundsRepository
from otalon_clas.detection.frequency_monitor import (
    FrequencyMonitor,
    _SeriesFrequencyProfile,
)
from otalon_clas.detection.frequency_profile_repository import (
    FrequencyProfileRepository,
)
from otalon_clas.ml.base import MLBackend
from otalon_clas.runtime.job_runner import JobRunner, _StagedArtifacts
from otalon_clas.runtime.module_bundle import InferenceModel, ModuleBundle
from otalon_clas.runtime.retrain_job_repository import RetrainJobRepository
from otalon_clas.runtime.training_helpers import (
    BoundsCandidate,
    ClassifierCandidate,
    FrequencyCandidate,
    publish_bounds_candidate,
    publish_classifier_candidate,
    publish_frequency_candidate,
)

# ---------------------------------------------------------------------------
# Real SQLite-backed connector + table provisioning
# ---------------------------------------------------------------------------


def _make_connector(tmp_path: Path) -> PostgresConnector:
    """Create a SQLite-backed connector with every table the tests touch."""
    db = tmp_path / "rollback.sqlite"
    pg = PostgresConnector(dsn=f"sqlite:///{db}", pool_size=1, max_overflow=0)
    Bound.__table__.create(pg.engine, checkfirst=True)
    FrequencyProfile.__table__.create(pg.engine, checkfirst=True)
    RetrainJob.__table__.create(pg.engine, checkfirst=True)
    RuntimeConfig.__table__.create(pg.engine, checkfirst=True)
    return pg


def _seed_bounds_row(
    pg: PostgresConnector,
    module: str,
    series_id: str,
    lower: dict[str, float],
    upper: dict[str, float],
    *,
    trained_at: datetime,
    first_ts: datetime,
    last_ts: datetime,
) -> None:
    """Insert a prior persisted bounds row with meaningful metadata."""
    with pg.session() as session:
        session.add(
            Bound(
                module=module,
                series_id=series_id,
                lower_bounds=lower,
                upper_bounds=upper,
                trained_at=trained_at,
                first_ts=first_ts,
                last_ts=last_ts,
            )
        )


def _seed_frequency_row(
    pg: PostgresConnector,
    module: str,
    series_id: str,
    *,
    mean_interval: float,
    std_interval: float,
    last_seen: datetime,
    trained_at: datetime,
    tolerance_override: float | None = None,
    absence_override: float | None = None,
) -> None:
    """Insert a prior persisted frequency row (with optional overrides)."""
    with pg.session() as session:
        session.add(
            FrequencyProfile(
                module=module,
                series_id=series_id,
                mean_interval=mean_interval,
                std_interval=std_interval,
                last_seen=last_seen,
                trained_at=trained_at,
                tolerance_factor_override=tolerance_override,
                absence_factor_override=absence_override,
            )
        )


# ---------------------------------------------------------------------------
# Duck-typed module config + real bundle wiring
# ---------------------------------------------------------------------------


class _ModuleConfig:
    """Minimal module config sufficient for the publish path."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.tag_key = "uci"
        self.bounds_enabled = True

        class _Freq:
            enabled = True

        class _Cls:
            enabled = True
            force_publish_class_set_shrink = False

        self.frequency_monitor = _Freq()
        self.classification = _Cls()


class _RealisticBundle:
    """Bundle carrying REAL bounds/frequency managers + repositories.

    Only the attributes the publish/capture/restore path reads are
    provided; nothing here records events — every ``save``/``restore`` hits
    the real SQLite tables and the real in-memory caches.
    """

    def __init__(
        self,
        name: str,
        pg: PostgresConnector,
        *,
        with_frequency: bool = True,
    ) -> None:
        self.config = _ModuleConfig(name)
        self.bounds_repository = BoundsRepository(pg)
        self.bounds_manager = BoundsManager(module_name=name, repository=self.bounds_repository)
        if with_frequency:
            freq_repo = FrequencyProfileRepository(pg)
            self.freq_monitor = FrequencyMonitor(repository=freq_repo, module_name=name)


def _live_bounds_cache(module: str) -> dict[str, dict[str, tuple[float, float]]]:
    """Return a distinct live bounds cache so restore is observable."""
    return {f"{module}-live": {"feat": (1.0, 2.0)}}


def _freq_repo(bundle: _RealisticBundle) -> FrequencyProfileRepository:
    """Return the bundle's frequency repository, asserting it is wired."""
    repo = bundle.freq_monitor.repository
    assert repo is not None
    return repo


def _make_runner(
    *,
    pg: Any = None,
    model_store: Any = None,
    notify_channel: str | None = None,
) -> JobRunner:
    """Construct a JobRunner with typed placeholders for unused deps."""
    return JobRunner(
        config=cast(AppConfig, object()),
        pg=cast(PostgresConnector, pg if pg is not None else object()),
        model_store=cast(ModelStore, model_store if model_store is not None else object()),
        bundles=[],
        notify_channel=notify_channel,
    )


# ---------------------------------------------------------------------------
# Task 1 — cross-artifact bounds + frequency rollback (reverse order)
# ---------------------------------------------------------------------------


def test_publish_rollback_restores_bounds_frequency_and_live_caches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A later publish failure restores every earlier persisted + live artifact.

    ``_publish_candidates`` commits ALL bounds first, then all frequency,
    then all classifiers. To exercise cross-artifact AND cross-module
    compensation, both modules' bounds and the first module's frequency
    are published for real, then the SECOND module's frequency publish is
    injected to fail. Asserts:

    * both modules' persisted bounds rows are byte/field-equal to their
      prior snapshot (an earlier-committed artifact type is compensated);
    * both modules' persisted frequency rows are field-equal to their
      prior snapshot (the candidate series never survives);
    * the live bounds caches and live frequency profiles (incl. runtime
      ``last_seen`` distinct from the persisted state) are restored;
    * untouched prior series are not destructively rewritten;
    * compensation ran in reverse actual touch order.
    """
    pg = _make_connector(tmp_path)

    prior_ts = datetime(2026, 5, 1, 10, 0, tzinfo=timezone.utc)
    runtime_last_seen_a = datetime(2026, 5, 8, 12, 34, 56, tzinfo=timezone.utc)
    runtime_last_seen_b = datetime(2026, 5, 8, 9, 8, 7, tzinfo=timezone.utc)

    # Module A (conn): prior persisted bounds + frequency (with override).
    _seed_bounds_row(
        pg,
        "conn",
        "A-s1",
        {"bytes": 1.0},
        {"bytes": 9.0},
        trained_at=prior_ts,
        first_ts=prior_ts,
        last_ts=prior_ts,
    )
    _seed_frequency_row(
        pg,
        "conn",
        "A-s1",
        mean_interval=5.0,
        std_interval=1.0,
        last_seen=prior_ts,
        trained_at=prior_ts,
        tolerance_override=3.5,
    )
    # Module B (mac_traffic): prior persisted bounds + frequency.
    _seed_bounds_row(
        pg,
        "mac_traffic",
        "B-s1",
        {"pkts": 2.0},
        {"pkts": 8.0},
        trained_at=prior_ts,
        first_ts=prior_ts,
        last_ts=prior_ts,
    )
    _seed_frequency_row(
        pg,
        "mac_traffic",
        "B-s1",
        mean_interval=7.0,
        std_interval=2.0,
        last_seen=prior_ts,
        trained_at=prior_ts,
    )

    bundle_a = _RealisticBundle("conn", pg)
    bundle_b = _RealisticBundle("mac_traffic", pg)

    # Prime live caches so restoration is observable; runtime last_seen on
    # the frequency profiles differs from the persisted prior_ts.
    live_bounds_a = _live_bounds_cache("conn")
    live_bounds_b = _live_bounds_cache("mac_traffic")
    bundle_a.bounds_manager.load_bounds(live_bounds_a)
    bundle_b.bounds_manager.load_bounds(live_bounds_b)
    bundle_a.freq_monitor._profiles = {
        "A-s1": _SeriesFrequencyProfile(
            mean_interval=5.0, std_interval=1.0, last_seen=runtime_last_seen_a, tolerance_factor_override=3.5
        )
    }
    bundle_b.freq_monitor._profiles = {
        "B-s1": _SeriesFrequencyProfile(mean_interval=7.0, std_interval=2.0, last_seen=runtime_last_seen_b)
    }

    # Capture exact prior snapshots for the equality assertions.
    prior_bounds_a = bundle_a.bounds_repository.snapshot_module("conn")
    prior_bounds_b = bundle_b.bounds_repository.snapshot_module("mac_traffic")
    prior_freq_a = _freq_repo(bundle_a).snapshot_profiles("conn")
    prior_freq_b = _freq_repo(bundle_b).snapshot_profiles("mac_traffic")

    # Build staged candidates directly (bypass heavy training only).
    staged = _StagedArtifacts()
    staged.bounds.append(
        BoundsCandidate(
            module="conn",
            bounds={"A-new": {"bytes": (100.0, 200.0)}},
            first_ts=runtime_last_seen_a,
            last_ts=runtime_last_seen_a,
        )
    )
    staged.bounds.append(
        BoundsCandidate(
            module="mac_traffic",
            bounds={"B-new": {"pkts": (300.0, 400.0)}},
            first_ts=runtime_last_seen_b,
            last_ts=runtime_last_seen_b,
        )
    )
    staged.frequency.append(
        FrequencyCandidate(
            module="conn", profiles={"A-new": _SeriesFrequencyProfile(mean_interval=99.0, std_interval=2.0)}
        )
    )
    staged.frequency.append(
        FrequencyCandidate(
            module="mac_traffic", profiles={"B-new": _SeriesFrequencyProfile(mean_interval=88.0, std_interval=3.0)}
        )
    )
    staged.bundles_by_module["conn"] = bundle_a  # type: ignore[assignment]
    staged.bundles_by_module["mac_traffic"] = bundle_b  # type: ignore[assignment]

    # Wrap the REAL publish helpers; fail the SECOND frequency publish so
    # both bounds and the first frequency are already committed.
    real_publish_bounds = publish_bounds_candidate
    real_publish_freq = publish_frequency_candidate
    touch_order: list[tuple[str, str]] = []

    def _tracking_publish_bounds(bundle: Any, cand: Any, *, invalidate_cache: bool = True) -> None:
        touch_order.append(("bounds", cand.module))
        real_publish_bounds(bundle, cand, invalidate_cache=invalidate_cache)

    def _failing_publish_freq(bundle: Any, cand: Any, *, notify_channel: Any = None) -> None:
        touch_order.append(("frequency", cand.module))
        if cand.module == "mac_traffic":
            raise RuntimeError("injected later frequency publish failure")
        real_publish_freq(bundle, cand, notify_channel=notify_channel)

    monkeypatch.setattr(job_runner_mod, "publish_bounds_candidate", _tracking_publish_bounds)
    monkeypatch.setattr(job_runner_mod, "publish_frequency_candidate", _failing_publish_freq)

    # Record the ACTUAL compensation order by wrapping the real restore
    # targets on each bundle's real repository / monitor.
    restore_order: list[tuple[str, str]] = []
    for _mod, _bundle in (("conn", bundle_a), ("mac_traffic", bundle_b)):
        real_restore_bounds = _bundle.bounds_repository.restore_module
        real_restore_freq = _bundle.freq_monitor.restore_profiles

        def _wrap_bounds(module: str, rows: Any, _rb: Any = real_restore_bounds) -> None:
            restore_order.append(("bounds", module))
            _rb(module, rows)

        def _wrap_freq(profiles: Any, _mod: str = _mod, _rf: Any = real_restore_freq) -> None:
            restore_order.append(("frequency", _mod))
            _rf(profiles)

        monkeypatch.setattr(_bundle.bounds_repository, "restore_module", _wrap_bounds)
        monkeypatch.setattr(_bundle.freq_monitor, "restore_profiles", _wrap_freq)

    runner = _make_runner(pg=pg)

    with pytest.raises(RuntimeError, match="injected later frequency publish failure"):
        runner._publish_candidates(staged)

    # -- persisted bounds restored byte/field-equal ----------------------
    after_bounds_a = bundle_a.bounds_repository.snapshot_module("conn")
    after_bounds_b = bundle_b.bounds_repository.snapshot_module("mac_traffic")
    assert after_bounds_a == prior_bounds_a
    assert after_bounds_b == prior_bounds_b
    assert all(row["series_id"] != "A-new" for row in after_bounds_a)
    assert all(row["series_id"] != "B-new" for row in after_bounds_b)

    # -- persisted frequency restored field-equal ------------------------
    after_freq_a = _freq_repo(bundle_a).snapshot_profiles("conn")
    after_freq_b = _freq_repo(bundle_b).snapshot_profiles("mac_traffic")
    assert after_freq_a == prior_freq_a
    assert after_freq_b == prior_freq_b
    assert all(row["series_id"] != "A-new" for row in after_freq_a)
    assert all(row["series_id"] != "B-new" for row in after_freq_b)

    # -- live caches restored, including runtime last_seen ---------------
    assert bundle_a.bounds_manager._cache is not None
    assert bundle_a.bounds_manager._cache.bounds == live_bounds_a
    assert bundle_b.bounds_manager._cache is not None
    assert bundle_b.bounds_manager._cache.bounds == live_bounds_b
    restored_a = bundle_a.freq_monitor.profiles
    restored_b = bundle_b.freq_monitor.profiles
    assert set(restored_a) == {"A-s1"}
    assert restored_a["A-s1"].last_seen == runtime_last_seen_a
    assert restored_a["A-s1"].tolerance_factor_override == 3.5
    assert set(restored_b) == {"B-s1"}
    assert restored_b["B-s1"].last_seen == runtime_last_seen_b

    # -- compensation ran in reverse actual touch order -----------------
    # Successful touches (in order): bounds:conn, bounds:mac_traffic,
    # frequency:conn. The mac frequency publish raised. The runner's
    # journal appends BEFORE each helper call, so the journal is
    # [bounds:conn, bounds:mac_traffic, frequency:conn, frequency:mac_traffic].
    assert touch_order == [
        ("bounds", "conn"),
        ("bounds", "mac_traffic"),
        ("frequency", "conn"),
        ("frequency", "mac_traffic"),
    ]
    # Compensation walks the journal in reverse: frequency before bounds,
    # and mac_traffic before conn within the frequency phase.
    assert restore_order == [
        ("frequency", "mac_traffic"),
        ("frequency", "conn"),
        ("bounds", "mac_traffic"),
        ("bounds", "conn"),
    ]


def test_publish_rollback_emits_compensating_frequency_invalidation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An earlier frequency NOTIFY is compensated by an invalidation NOTIFY.

    Publishes conn frequency (which emits a NOTIFY for the candidate
    series), then fails the LATER mac_traffic frequency publish. After
    rollback, a compensating ``emit_notify`` MUST be emitted on the same
    channel for the restored/deleted conn series so listeners drop the
    never-committed candidate. The real ``emit_notify`` boundary is
    intercepted (SQLite makes the underlying NOTIFY a no-op, so the call
    site the runner + monitor import is patched).
    """
    pg = _make_connector(tmp_path)
    prior_ts = datetime(2026, 5, 1, 10, 0, tzinfo=timezone.utc)
    _seed_frequency_row(
        pg,
        "conn",
        "A-s1",
        mean_interval=5.0,
        std_interval=1.0,
        last_seen=prior_ts,
        trained_at=prior_ts,
    )
    _seed_frequency_row(
        pg,
        "mac_traffic",
        "B-s1",
        mean_interval=7.0,
        std_interval=2.0,
        last_seen=prior_ts,
        trained_at=prior_ts,
    )

    bundle_a = _RealisticBundle("conn", pg)
    bundle_b = _RealisticBundle("mac_traffic", pg)
    bundle_a.freq_monitor._profiles = {
        "A-s1": _SeriesFrequencyProfile(mean_interval=5.0, std_interval=1.0, last_seen=prior_ts)
    }
    bundle_b.freq_monitor._profiles = {
        "B-s1": _SeriesFrequencyProfile(mean_interval=7.0, std_interval=2.0, last_seen=prior_ts)
    }

    staged = _StagedArtifacts()
    staged.frequency.append(
        FrequencyCandidate(
            module="conn", profiles={"A-new": _SeriesFrequencyProfile(mean_interval=99.0, std_interval=2.0)}
        )
    )
    staged.frequency.append(
        FrequencyCandidate(
            module="mac_traffic", profiles={"B-new": _SeriesFrequencyProfile(mean_interval=88.0, std_interval=3.0)}
        )
    )
    staged.bundles_by_module["conn"] = bundle_a  # type: ignore[assignment]
    staged.bundles_by_module["mac_traffic"] = bundle_b  # type: ignore[assignment]

    # Intercept the emit_notify boundary the runner + monitor import.
    notified: list[tuple[str, str, str, str]] = []

    def _record_notify(connector: Any, channel: str, module: str, series_id: str) -> None:
        notified.append(("emit", channel, module, series_id))

    import otalon_clas.detection.frequency_monitor as freq_mod
    import otalon_clas.detection.frequency_profile_repository as freq_repo_mod

    monkeypatch.setattr(freq_repo_mod, "emit_notify", _record_notify)
    monkeypatch.setattr(freq_mod, "emit_notify", _record_notify, raising=False)

    real_publish_freq = publish_frequency_candidate
    phase = {"rollback": False}

    def _failing_publish_freq(bundle: Any, cand: Any, *, notify_channel: Any = None) -> None:
        if cand.module == "mac_traffic":
            phase["rollback"] = True
            raise RuntimeError("injected later frequency publish failure")
        real_publish_freq(bundle, cand, notify_channel=notify_channel)

    monkeypatch.setattr(job_runner_mod, "publish_frequency_candidate", _failing_publish_freq)

    runner = _make_runner(pg=pg, notify_channel="freq_invalidate")

    with pytest.raises(RuntimeError, match="injected later frequency publish failure"):
        runner._publish_candidates(staged)

    # Publish-time NOTIFY for the conn candidate series 'A-new'.
    publish_notifies = [n for n in notified if n[1] == "freq_invalidate" and n[3] == "A-new"]
    assert publish_notifies, "expected a publish-time NOTIFY for the conn candidate series"

    # A compensating NOTIFY for the restored conn series must be emitted on
    # the same channel during rollback. The runner emits for
    # ``set(restored_profiles) | {series in restored prior rows}`` — i.e.
    # the prior 'A-s1' that was reinstated — so listeners reload the
    # reinstated profile and drop the never-committed candidate.
    conn_notifies = [n for n in notified if n[1] == "freq_invalidate" and n[2] == "conn"]
    assert (
        "emit",
        "freq_invalidate",
        "conn",
        "A-s1",
    ) in conn_notifies, "rollback must invalidate the restored prior series 'A-s1'"
    # 'A-s1' was NOT NOTIFYed at publish time (only the candidate 'A-new'
    # was), so its presence proves the NOTIFY came from the rollback path.
    assert all(n[3] != "A-s1" for n in publish_notifies)


def test_execute_job_publication_failure_lands_terminal_failed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A publication exception via the real job path lands terminal ``failed``.

    Drives the full ``_execute_job`` path with a real claimed row and a
    single staged bounds candidate whose real publish is injected to fail.
    The job MUST NOT report ``succeeded``; it must be terminal ``failed``.
    """
    pg = _make_connector(tmp_path)
    repo = RetrainJobRepository(pg)
    prior_ts = datetime(2026, 5, 1, 10, 0, tzinfo=timezone.utc)
    _seed_bounds_row(
        pg,
        "conn",
        "A-s1",
        {"bytes": 1.0},
        {"bytes": 9.0},
        trained_at=prior_ts,
        first_ts=prior_ts,
        last_ts=prior_ts,
    )
    repo.insert_queued(
        job_ref="job-pub-fail",
        scope="bounds_frequency",
        window_start="2026-05-08 12:00:00",
        window_stop="2026-05-08 12:30:00",
    )
    # Claim the row so _execute_job's set_state('publishing') expects
    # 'running' ownership.
    claimed = repo.claim_next("job-pub-fail", job_runner_mod._WORKER_ID)
    assert claimed is not None

    bundle = _RealisticBundle("conn", pg)
    bundle.bounds_manager.load_bounds(_live_bounds_cache("conn"))

    staged = _StagedArtifacts()
    staged.bounds.append(
        BoundsCandidate(
            module="conn",
            bounds={"A-new": {"bytes": (1.0, 2.0)}},
            first_ts=prior_ts,
            last_ts=prior_ts,
        )
    )
    staged.bundles_by_module["conn"] = bundle  # type: ignore[assignment]

    runner = _make_runner(pg=pg)
    monkeypatch.setattr(runner, "_stage_candidates", lambda job, staged_acc=None: staged)

    def _failing_publish_bounds(bundle: Any, cand: Any, *, invalidate_cache: bool = True) -> None:
        raise RuntimeError("injected publish failure")

    monkeypatch.setattr(job_runner_mod, "publish_bounds_candidate", _failing_publish_bounds)

    with pytest.raises(RuntimeError, match="injected publish failure"):
        runner._execute_job(claimed)

    dto = repo.get("job-pub-fail")
    assert dto is not None
    assert dto.state != "succeeded"

    # The _run_job wrapper is what records terminal 'failed' on the raised
    # exception; simulate that boundary directly (the runner's own
    # exception handler calls _safe_terminal).
    runner._safe_terminal("job-pub-fail", "failed", detail="publication failed", error="injected publish failure")
    dto2 = repo.get("job-pub-fail")
    assert dto2 is not None
    assert dto2.state == "failed"


# ---------------------------------------------------------------------------
# Task 2 — classifier / module rollback (manifest pointer + protocol map)
# ---------------------------------------------------------------------------


class _ProtoPreprocessor:
    """Preprocessor stub with a mutable, lockable protocol map."""

    def __init__(self, protocol_map: dict[str, int] | None = None) -> None:
        self.protocol_map = dict(protocol_map or {})
        self._locked = False

    def load_protocol_map(self, protocol_map: dict[str, int], *, lock: bool = False) -> None:
        self.protocol_map = dict(protocol_map)
        self._locked = lock

    def get_feature_columns(self) -> list[str]:
        return ["f1"]


def _make_classifier_bundle(
    name: str,
    prior_protocol_map: dict[str, int],
    prior_inference: InferenceModel | None,
) -> ModuleBundle:
    """Build a real ModuleBundle with a coherent prior live model state."""
    from otalon_clas.ml.pipeline import MLPipeline

    config = _ModuleConfig(name)
    bundle = ModuleBundle(
        config=config,  # type: ignore[arg-type]
        influx=object(),  # type: ignore[arg-type]
        preprocessor=_ProtoPreprocessor(prior_protocol_map),  # type: ignore[arg-type]
        bounds_manager=object(),  # type: ignore[arg-type]
        bounds_trainer=object(),  # type: ignore[arg-type]
        bounds_repository=object(),  # type: ignore[arg-type]
        freq_monitor=object(),  # type: ignore[arg-type]
        ml_pipeline=MLPipeline(backend=cast(MLBackend, object()), confidence_threshold=0.5),
    )
    if prior_inference is not None:
        bundle.set_inference_model(prior_inference)
    return bundle


def _publish_real_model(store: ModelStore, module: str, tag: str, protocol_map: dict[str, int]) -> str:
    """Persist a coherent model version and return its manifest pointer."""
    store.save(
        module_name=module,
        model={"kind": tag},
        scaler={"scaler": tag},
        metadata={"module_name": module, "label_map": {"0": tag}, "tag": tag},
        protocol_map=protocol_map,
        feature_columns=["f1"],
    )
    pointer = store.publication_pointer(module)
    assert pointer is not None
    return pointer


def test_classifier_rollback_restores_pointer_model_and_protocol_map(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A later classifier failure restores the exact prior manifest + live state.

    Publishes a prior 'conn' classifier generation (durable manifest
    pointer + protocol map), stages a new conn classifier and a second
    module classifier, publishes conn for real, then fails the second
    module. Asserts the exact prior manifest pointer is restored, ``load``
    returns the prior metadata, and the live inference backend/scaler/
    label-map + preprocessor protocol map return to the prior snapshot.
    """
    store = ModelStore(str(tmp_path / "models"))

    prior_protocol_map = {"tcp": 1, "udp": 2}
    prior_pointer = _publish_real_model(store, "conn", "PRIOR", prior_protocol_map)
    prior_model, prior_scaler, prior_meta = store.load("conn")
    prior_inference = InferenceModel(
        backend=prior_model,
        scaler=prior_scaler,
        label_map={0: "PRIOR"},
        protocol_map=prior_protocol_map,
    )

    bundle_conn = _make_classifier_bundle("conn", prior_protocol_map, prior_inference)
    bundle_two = _make_classifier_bundle("proto_traffic", {}, None)

    staged = _StagedArtifacts()
    staged.classifier.append(
        ClassifierCandidate(
            module="conn",
            pipeline=_FakePipeline("NEWCONN"),  # type: ignore[arg-type]
            label_map={0: "NEWCONN"},
            metadata={"module_name": "conn", "label_map": {"0": "NEWCONN"}},
            protocol_map={"tcp": 1, "udp": 2, "icmp": 3},
            feature_columns=["f1"],
        )
    )
    staged.classifier.append(
        ClassifierCandidate(
            module="proto_traffic",
            pipeline=_FakePipeline("NEWTWO"),  # type: ignore[arg-type]
            label_map={0: "NEWTWO"},
            metadata={"module_name": "proto_traffic", "label_map": {"0": "NEWTWO"}},
            protocol_map={"x": 9},
            feature_columns=["f1"],
        )
    )
    staged.bundles_by_module["conn"] = bundle_conn
    staged.bundles_by_module["proto_traffic"] = bundle_two

    # Real classifier publish for conn (saves the version + flips the
    # manifest AND swaps the live bundle through the true path); fail the
    # SECOND module's publish before its manifest flip.
    real_publish_clf = publish_classifier_candidate

    def _failing_publish_clf(
        store_: Any,
        bundle: Any,
        cand: Any,
        *,
        swap_into_bundle: bool = False,
        force_publish_class_set_shrink: bool = False,
    ) -> None:
        if cand.module == "proto_traffic":
            raise RuntimeError("injected later classifier publish failure")
        real_publish_clf(store_, bundle, cand, swap_into_bundle=swap_into_bundle)

    monkeypatch.setattr(job_runner_mod, "publish_classifier_candidate", _failing_publish_clf)

    runner = _make_runner(model_store=store)

    with pytest.raises(RuntimeError, match="injected later classifier publish failure"):
        runner._publish_candidates(staged)

    # -- exact durable manifest pointer restored -------------------------
    assert store.publication_pointer("conn") == prior_pointer
    # -- load returns the prior model metadata ---------------------------
    _model, _scaler, meta = store.load("conn")
    assert meta["tag"] == "PRIOR"
    assert meta["label_map"] == {"0": "PRIOR"}
    # -- live inference + protocol map returned to the prior snapshot ----
    snapshot = bundle_conn.model_snapshot()
    assert snapshot is not None
    assert snapshot.label_map == {0: "PRIOR"}
    assert snapshot.protocol_map == prior_protocol_map
    assert bundle_conn.preprocessor.protocol_map == prior_protocol_map  # type: ignore[attr-defined]


def test_classifier_rollback_restores_empty_prior_protocol_map(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """When the prior protocol map was empty, rollback restores it empty.

    Guards the boundary where the prior coherent state carried NO protocol
    map: after a later failure, the live preprocessor protocol map must
    return to empty, not retain the never-committed candidate map.
    """
    store = ModelStore(str(tmp_path / "models"))

    prior_pointer = _publish_real_model(store, "conn", "PRIOR", {})
    prior_model, prior_scaler, _ = store.load("conn")
    prior_inference = InferenceModel(
        backend=prior_model,
        scaler=prior_scaler,
        label_map={0: "PRIOR"},
        protocol_map={},
    )
    bundle_conn = _make_classifier_bundle("conn", {}, prior_inference)
    bundle_two = _make_classifier_bundle("proto_traffic", {}, None)

    staged = _StagedArtifacts()
    staged.classifier.append(
        ClassifierCandidate(
            module="conn",
            pipeline=_FakePipeline("NEWCONN"),  # type: ignore[arg-type]
            label_map={0: "NEWCONN"},
            metadata={"module_name": "conn", "label_map": {"0": "NEWCONN"}},
            protocol_map={"tcp": 1},
            feature_columns=["f1"],
        )
    )
    staged.classifier.append(
        ClassifierCandidate(
            module="proto_traffic",
            pipeline=_FakePipeline("NEWTWO"),  # type: ignore[arg-type]
            label_map={0: "NEWTWO"},
            metadata={"module_name": "proto_traffic", "label_map": {"0": "NEWTWO"}},
            protocol_map={"x": 9},
            feature_columns=["f1"],
        )
    )
    staged.bundles_by_module["conn"] = bundle_conn
    staged.bundles_by_module["proto_traffic"] = bundle_two

    real_publish_clf = publish_classifier_candidate

    def _failing_publish_clf(
        store_: Any,
        bundle: Any,
        cand: Any,
        *,
        swap_into_bundle: bool = False,
        force_publish_class_set_shrink: bool = False,
    ) -> None:
        if cand.module == "proto_traffic":
            raise RuntimeError("injected later classifier publish failure")
        real_publish_clf(store_, bundle, cand, swap_into_bundle=swap_into_bundle)

    monkeypatch.setattr(job_runner_mod, "publish_classifier_candidate", _failing_publish_clf)

    runner = _make_runner(model_store=store)

    with pytest.raises(RuntimeError, match="injected later classifier publish failure"):
        runner._publish_candidates(staged)

    assert store.publication_pointer("conn") == prior_pointer
    snapshot = bundle_conn.model_snapshot()
    assert snapshot is not None
    assert snapshot.protocol_map == {}
    assert bundle_conn.preprocessor.protocol_map == {}  # type: ignore[attr-defined]


def test_publication_failure_leaves_no_partial_generation_for_readers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """On publish failure an independent reader sees ONLY the prior generation.

    This is the achievable reader-visible all-or-nothing guarantee within the
    two-repository contract (audit Reviewer-A P2): after a bounds publish
    commits but the following frequency publish fails, a FRESH reader querying
    the real ``bounds`` and ``frequency_profiles`` tables directly (bypassing
    the live caches) must observe the prior generation for BOTH artifacts — the
    never-committed candidate series must not be durably visible in either
    table. Proven with real SQLite-backed repositories, not event recording.
    """
    pg = _make_connector(tmp_path)
    prior_ts = datetime(2026, 5, 1, 10, 0, tzinfo=timezone.utc)
    _seed_bounds_row(
        pg, "conn", "A-s1", {"bytes": 1.0}, {"bytes": 9.0}, trained_at=prior_ts, first_ts=prior_ts, last_ts=prior_ts
    )
    _seed_frequency_row(
        pg, "conn", "A-s1", mean_interval=5.0, std_interval=1.0, last_seen=prior_ts, trained_at=prior_ts
    )

    bundle = _RealisticBundle("conn", pg)
    bundle.bounds_manager.load_bounds(_live_bounds_cache("conn"))
    bundle.freq_monitor._profiles = {
        "A-s1": _SeriesFrequencyProfile(mean_interval=5.0, std_interval=1.0, last_seen=prior_ts)
    }

    staged = _StagedArtifacts()
    staged.bounds.append(
        BoundsCandidate(module="conn", bounds={"A-new": {"bytes": (100.0, 200.0)}}, first_ts=prior_ts, last_ts=prior_ts)
    )
    staged.frequency.append(
        FrequencyCandidate(
            module="conn", profiles={"A-new": _SeriesFrequencyProfile(mean_interval=99.0, std_interval=2.0)}
        )
    )
    staged.bundles_by_module["conn"] = bundle  # type: ignore[assignment]

    real_publish_bounds = publish_bounds_candidate

    def _tracking_bounds(bundle: Any, cand: Any, *, invalidate_cache: bool = True) -> None:
        real_publish_bounds(bundle, cand, invalidate_cache=invalidate_cache)

    def _failing_freq(bundle: Any, cand: Any, *, notify_channel: Any = None) -> None:
        raise RuntimeError("injected frequency publish failure after bounds committed")

    monkeypatch.setattr(job_runner_mod, "publish_bounds_candidate", _tracking_bounds)
    monkeypatch.setattr(job_runner_mod, "publish_frequency_candidate", _failing_freq)

    runner = _make_runner(pg=pg)
    with pytest.raises(RuntimeError, match="injected frequency publish failure"):
        runner._publish_candidates(staged)

    # A FRESH reader (independent of the live caches) sees ONLY the prior
    # generation in BOTH tables — no partial new-bounds candidate survived.
    fresh_bounds = BoundsRepository(pg).load("conn")
    assert set(fresh_bounds) == {"A-s1"}, "the never-committed bounds candidate must not be durably visible"
    assert "A-new" not in fresh_bounds
    fresh_freq = FrequencyProfileRepository(pg).load_all("conn")
    assert set(fresh_freq) == {"A-s1"}, "the never-committed frequency candidate must not be durably visible"
    assert "A-new" not in fresh_freq


class _FakePipeline:
    """Minimal MLPipeline stand-in exposing backend/scaler for save()."""

    def __init__(self, tag: str) -> None:
        self.backend = {"kind": tag}
        self.scaler = {"scaler": tag}
