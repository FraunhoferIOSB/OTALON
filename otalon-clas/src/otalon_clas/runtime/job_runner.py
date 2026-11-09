"""In-process runtime retrain job runner for otalon-clas.

Claims queued :class:`RetrainJob` rows from PostgreSQL and executes the
requested training inside the running process as a **stage-then-publish**
pipeline:

1. **Stage** — every enabled module is trained into an in-memory / isolated
   candidate (bounds dict, frequency profiles, a freshly-built classifier
   pipeline). Nothing touches the live DB, files, or bundle yet.
2. **Publish** — only after *all* candidates succeed does the runner mutate
   the live artifacts: bounds ``save(replace=True)`` + cache invalidation,
   frequency upsert + NOTIFY, ML atomic manifest write + an in-process
   model swap under the bundle's shared read/write lock.

If any stage fails the job is marked ``failed`` and NO artifact is
published, so the live loop keeps serving the previous model coherently
(audit B-02 / B-03 / F3). At most one job runs at a time (single-flight via
a ``threading.Lock`` and the atomic DB claim). State transitions are guarded
by worker ownership so a reaped job cannot be resurrected (audit B-05), and
shutdown is cooperative at phase boundaries (audit B-06).
"""

from __future__ import annotations

import os
import socket
import threading
import time
from copy import deepcopy
from pathlib import Path
from typing import Any, cast

import polars as pl
from loguru import logger

from otalon_clas.common.influx_connector import InfluxUnavailableError
from otalon_clas.common.model_store import ModelStore
from otalon_clas.common.postgres_connector import PostgresConnector
from otalon_clas.common.settings import AppConfig
from otalon_clas.runtime.job_dto import RetrainJobDTO
from otalon_clas.runtime.module_bundle import InferenceModel, ModuleBundle
from otalon_clas.runtime.retrain_job_repository import (
    RetrainJobClaimError,
    RetrainJobRepository,
)
from otalon_clas.runtime.runtime_config_repository import RuntimeConfigRepository
from otalon_clas.runtime.series_blacklist_source import SeriesBlacklistSource
from otalon_clas.runtime.training_helpers import (
    BoundsCandidate,
    ClassifierCandidate,
    FrequencyCandidate,
    compute_bounds_candidate,
    compute_frequency_candidate,
    publish_bounds_candidate,
    publish_classifier_candidate,
    publish_frequency_candidate,
    train_classifier_candidate,
)

_HEARTBEAT_INTERVAL_S: float = 15.0
_WORKER_ID: str = f"{socket.gethostname()}-{os.getpid()}"
_CLASSIFIER_MODULES: frozenset[str] = frozenset({"conn", "mac_traffic", "proto_traffic"})


class JobRunner:
    """Executes runtime retrain jobs inside the live otalon-clas process.

    Args:
        config: Application configuration. Runtime-config overrides have
            already been applied.
        pg: PostgreSQL connector.
        model_store: ML model persistence store.
        bundles: Per-module runtime bundles.
        notify_channel: Frequency-profile NOTIFY channel used to refresh
            caches after runtime frequency training.
        allowed_mitre_dirs: Directories a ``job.mitre_file`` must live
            under to be accepted at the worker boundary. When empty, any
            readable path is accepted (audit B-07).
        blacklist_source: Shared series-blacklist runtime source. When
            given, each job start refreshes every trainer's blacklist
            from ``current()`` (CLAS-071); ``None`` keeps boot defaults.
    """

    def __init__(
        self,
        config: AppConfig,
        pg: PostgresConnector,
        model_store: ModelStore,
        bundles: list[ModuleBundle],
        notify_channel: str | None = None,
        allowed_mitre_dirs: tuple[str, ...] = (),
        blacklist_source: SeriesBlacklistSource | None = None,
    ) -> None:
        """Initialize the runner without starting any threads."""
        self._config = config
        self._pg = pg
        self._model_store = model_store
        self._bundles = bundles
        self._notify_channel = notify_channel
        self._allowed_mitre_dirs = allowed_mitre_dirs
        self._blacklist_source = blacklist_source
        self._repository = RetrainJobRepository(pg)
        self._runtime_config = RuntimeConfigRepository(pg)
        self._lock = threading.Lock()
        self._current_job_ref: str | None = None
        self._stop_event = threading.Event()
        self._job_done = threading.Event()
        self._job_done.set()
        self._thread: threading.Thread | None = None

    @property
    def is_running(self) -> bool:
        """Return True when a job thread is currently active."""
        return self._lock.locked()

    def try_run(self, job_ref: str) -> bool:
        """Claim and start a job if no other job is running.

        Returns True when the job thread was started, False when
        single-flight prevented it or a stop has been requested.
        """
        if self._stop_event.is_set():
            logger.info("JobRunner: refusing {} because stop was requested", job_ref)
            return False
        if not self._lock.acquire(blocking=False):
            logger.info(
                "JobRunner: ignoring {} because another job is already running",
                job_ref,
            )
            return False
        self._job_done.clear()
        thread = threading.Thread(
            target=self._run_job,
            args=(job_ref,),
            name=f"retrain-job-{job_ref}",
            daemon=False,
        )
        self._thread = thread
        thread.start()
        return True

    def request_stop(self) -> None:
        """Signal any in-flight job to stop at the next phase boundary."""
        self._stop_event.set()

    def stop(self, timeout: float = 30.0) -> None:
        """Signal the current job to stop and join its (non-daemon) thread."""
        self._stop_event.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=timeout)
            if thread.is_alive():
                logger.warning(
                    "JobRunner: job thread still alive after {}s stop timeout",
                    timeout,
                )

    def _check_not_stopped(self, phase: str) -> None:
        """Raise if a shutdown was requested at a safe phase boundary."""
        if self._stop_event.is_set():
            raise _JobCancelled(f"stop requested before {phase}")

    def _run_job(self, job_ref: str) -> None:
        """Claim, stage-train, publish and transition a single job."""
        self._current_job_ref = job_ref
        heartbeat_thread: threading.Thread | None = None
        try:
            if self._is_paused():
                self._repository.set_terminal(
                    job_ref,
                    "failed",
                    detail="runtime retraining is paused via runtime_config",
                    error="training.retrain_paused=true",
                    worker_id=None,
                    expected_states=("queued",),
                )
                return

            job = self._repository.claim_next(job_ref, _WORKER_ID)
            if job is None:
                logger.info("JobRunner: {} was already claimed", job_ref)
                return

            logger.info("JobRunner: claimed {} (scope={})", job_ref, job.scope)
            self._refresh_trainers_blacklist()

            heartbeat_thread = threading.Thread(
                target=self._heartbeat_loop,
                args=(job_ref,),
                name=f"retrain-heartbeat-{job_ref}",
                daemon=True,
            )
            heartbeat_thread.start()

            self._execute_job(job)

        except _JobCancelled as exc:
            logger.warning("JobRunner: {} cancelled: {}", job_ref, exc)
            self._safe_terminal(job_ref, "failed", detail="cancelled on shutdown", error=str(exc))
        except RetrainJobClaimError as exc:
            # Lost ownership (reaper/other worker won). Do NOT publish or
            # overwrite the terminal state that the winner set (audit B-05).
            logger.warning("JobRunner: {} aborting, ownership lost: {}", job_ref, exc)
        except Exception as exc:
            logger.exception("JobRunner: {} failed", job_ref)
            self._safe_terminal(
                job_ref,
                "failed",
                detail="training or publication failed",
                error=str(exc) or type(exc).__name__,
            )
        finally:
            # Signal the heartbeat loop to exit BEFORE joining it, otherwise
            # the join blocks for a full heartbeat interval.
            self._job_done.set()
            if heartbeat_thread is not None:
                heartbeat_thread.join(timeout=5.0)
            self._current_job_ref = None
            self._lock.release()

    def _refresh_trainers_blacklist(self) -> None:
        """Refresh each trainer's blacklist from the runtime source.

        Called once at job start (CLAS-071 task 4.3), so a retrain uses
        the blacklist instance current when the job began. ``None`` (no
        runtime row) restores each trainer's per-module boot default. A
        source failure logs and keeps the trainers' active instances.
        """
        if self._blacklist_source is None:
            return
        try:
            current = self._blacklist_source.current()
        except Exception:
            logger.exception("JobRunner: series-blacklist resolve failed; trainers keep " "their active instances")
            return
        for bundle in self._bundles:
            bundle.bounds_trainer.update_blacklist(current)
            logger.info(
                "JobRunner: trainer blacklist refreshed for '{}' ({} pattern(s), source={})",
                bundle.config.name,
                len(bundle.bounds_trainer.blacklist.patterns),
                "runtime row" if current is not None else "boot default",
            )

    def _execute_job(self, job: RetrainJobDTO) -> None:
        """Stage all candidates, then publish under ownership guards."""
        # -- Stage phase --------------------------------------------------
        # Training-mode preprocessing persists port-collapse rules, so this
        # phase is NOT free of live mutation. Anything it overwrites is
        # snapshotted first and rolled back if the job does not complete
        # (audit CLAS-02).
        self._check_not_stopped("staging")
        staged = _StagedArtifacts()
        try:
            staged = self._stage_candidates(job, staged)
            if not staged.has_any():
                raise ValueError(
                    "runtime retrain produced no trainable artifact for the "
                    "requested window (empty/insufficient data)"
                )

            # -- Publish phase: guarded, atomic per artifact --------------
            self._check_not_stopped("publishing")
            self._repository.set_state(
                job.job_ref,
                "publishing",
                worker_id=_WORKER_ID,
                expected_states=("running",),
                detail="publishing artifacts atomically",
            )
            self._publish_candidates(staged)
        except BaseException:
            self._restore_rule_backups(staged)
            raise

        landed = self._repository.set_terminal(
            job.job_ref,
            "succeeded",
            detail="training and publication complete",
            worker_id=_WORKER_ID,
            expected_states=("publishing",),
            metrics=staged.metrics(),
        )
        if not landed:
            raise RetrainJobClaimError(f"{job.job_ref}: could not finalize succeeded (ownership lost)")
        logger.info("JobRunner: {} succeeded", job.job_ref)

    def _stage_candidates(self, job: RetrainJobDTO, staged: _StagedArtifacts | None = None) -> _StagedArtifacts:
        """Train every module into isolated candidates without publishing.

        Args:
            job: The retrain job being executed.
            staged: Optional accumulator supplied by the caller so the
                rule snapshots survive an exception raised mid-staging
                (audit CLAS-02). A fresh one is created when omitted.

        Returns:
            The populated accumulator.
        """
        staged = staged if staged is not None else _StagedArtifacts()
        mitre_file = self._validated_mitre_file(job) if job.scope == "classifier" else None

        for bundle in self._bundles:
            self._check_not_stopped("module staging")
            mod = bundle.config
            if job.scope == "classifier" and not self._classifier_module_in_scope(mod, staged):
                continue
            logger.info("JobRunner: staging module '{}' for {}", mod.name, job.job_ref)
            df = self._fetch_training_data(bundle, job)
            if df.is_empty():
                logger.warning(
                    "Module '{}': no training data in [{}, {}]",
                    mod.name,
                    job.window_start,
                    job.window_stop,
                )
                continue
            self._capture_rule_backup(staged, bundle)
            df_processed = bundle.preprocessor.preprocess_for_training(df)

            if job.scope == "bounds_frequency":
                if mod.bounds_enabled:
                    staged.bounds.append(compute_bounds_candidate(self._config, bundle, df_processed))
                    staged.bundles_by_module[mod.name] = bundle
                frequency_enabled = self._runtime_config.get_bool(
                    "otalon-clas",
                    f"detection.{mod.name}.frequency_enabled",
                    default=mod.frequency_monitor.enabled,
                )
                if frequency_enabled:
                    frequency = compute_frequency_candidate(bundle, df_processed)
                    # ``compute_frequency_candidate`` always returns a
                    # FrequencyCandidate; stage it only when it actually
                    # produced profiles (an empty profiles dict means nothing to
                    # publish). The prior ``getattr(frequency, "profiles", True)``
                    # was a vacuous guard — the attribute always exists, so the
                    # default was dead and an empty candidate was still staged.
                    if frequency.profiles:
                        staged.frequency.append(frequency)
                        staged.bundles_by_module[mod.name] = bundle
            elif job.scope == "classifier":
                candidate = train_classifier_candidate(bundle, df, mitre_file=mitre_file)
                if candidate is not None:
                    staged.classifier.append(candidate)
                    staged.bundles_by_module[mod.name] = bundle

        if job.scope == "classifier" and not staged.classifier:
            raise ValueError(
                "runtime classifier retrain found no module with an already "
                "deployed classifier to retrain "
                f"(skipped: {sorted(staged.classifier_skipped)}); "
                "first-time classifier training is out of scope for the "
                "runtime path (CLAS-004)"
            )
        return staged

    def _fetch_training_data(self, bundle: ModuleBundle, job: RetrainJobDTO) -> pl.DataFrame:
        """Fetch interval union and remove duplicate samples at boundaries."""
        ranges = job.intervals or [[job.window_start, job.window_stop]]
        try:
            frames = [cast(pl.DataFrame, bundle.influx.fetch(start=start, stop=stop)) for start, stop in ranges]
        except InfluxUnavailableError as exc:
            raise ValueError(f"training data unavailable: {exc}") from exc
        non_empty = [frame for frame in frames if not frame.is_empty()]
        if not non_empty:
            return pl.DataFrame()
        combined = pl.concat(non_empty, how="vertical_relaxed")
        return combined.unique(maintain_order=True)

    def _classifier_module_in_scope(self, mod: Any, staged: _StagedArtifacts) -> bool:
        """Return True only for a module with a deployed classifier artifact.

        The runtime classifier scope retrains EXISTING persisted
        classifiers only; a module that is enabled for live prediction but
        has no deployed model (in the current deployment: ``mac_traffic``
        and ``proto_traffic``) is skipped with an explicit log and a
        recorded metrics reason, so a runtime retrain never silently
        creates a first-time model (CLAS-004 stays out of scope).
        """
        if not mod.classification.enabled:
            staged.classifier_skipped[mod.name] = "classification.enabled=false"
            return False
        if not self._model_store.has_model(mod.name):
            staged.classifier_skipped[mod.name] = "no deployed classifier artifact"
            logger.info(
                "JobRunner: skipping classifier module '{}' — no deployed "
                "classifier to retrain (runtime scope = existing classifiers "
                "only; first-time training is CLAS-004, out of scope)",
                mod.name,
            )
            return False
        return True

    def _publish_candidates(self, staged: _StagedArtifacts) -> None:
        """Publish staged artifacts failure-atomically with deterministic order.

        Atomicity contract (audit Reviewer-A P2, honest scope):

        * **Per artifact**: each ``bounds`` publish is one ``save(replace=True)``
          transaction and each ``frequency`` publish is one stats-UPSERT
          transaction, so a single reader of *that one* table never sees a torn
          row set.
        * **On failure**: if ANY publish raises, every already-committed
          artifact/module is compensated back to its exact captured snapshot
          (persisted rows AND live caches) in reverse touch order, so a failed
          job leaves NO durable new generation. This is the reader-visible
          all-or-nothing guarantee that is achievable within the existing
          two-repository contract, and it is proven against real repositories in
          ``test_job_runner_publication_rollback.py``.
        * **On success, cross-artifact**: bounds and frequency are consumed by
          two INDEPENDENT readers (``BoundsManager`` cache ← ``bounds`` table;
          ``FrequencyMonitor`` cache ← ``frequency_profiles`` table) with no
          shared reader, so a single durable generation *pointer* cannot be made
          reader-visible without rewriting the live detection hot path. A
          concurrent reader may therefore observe new-bounds+old-frequency (or
          vice-versa) for a bounded window (one detection tick / cache TTL)
          during a *successful* publish. That transient mixed visibility is the
          documented, non-overclaimed contract — it is NOT collapsed into a
          false "single atomic transaction" claim. Ordering is deterministic
          (bounds sorted by module, then frequency sorted by module, then
          classifiers) so the window is stable and reproducible.
        """
        backups = self._capture_publication_backups(staged)
        journal: list[tuple[str, str]] = []
        try:
            for bounds in sorted(staged.bounds, key=lambda c: c.module):
                bundle = staged.bundles_by_module[bounds.module]
                journal.append(("bounds", bounds.module))
                publish_bounds_candidate(bundle, bounds, invalidate_cache=True)
            for freq in sorted(staged.frequency, key=lambda c: c.module):
                bundle = staged.bundles_by_module[freq.module]
                journal.append(("frequency", freq.module))
                publish_frequency_candidate(bundle, freq, notify_channel=self._notify_channel)
            for clf in sorted(staged.classifier, key=lambda c: c.module):
                bundle = staged.bundles_by_module[clf.module]
                journal.append(("classifier", clf.module))
                published = publish_classifier_candidate(
                    self._model_store,
                    bundle,
                    clf,
                    swap_into_bundle=False,
                    force_publish_class_set_shrink=bundle.config.classification.force_publish_class_set_shrink,
                )
                if published:
                    self._swap_model_into_bundle(bundle)
        except Exception as exc:
            try:
                self._restore_publication_backups(backups, journal)
            except Exception as compensation_exc:
                raise RuntimeError(
                    f"publication failed ({exc}); compensation failed ({compensation_exc})"
                ) from compensation_exc
            raise

    def _capture_rule_backup(self, staged: _StagedArtifacts, bundle: ModuleBundle) -> None:
        """Snapshot a module's port-collapse rules before staging rewrites them.

        Training-mode preprocessing persists freshly computed rules, so
        the pre-staging state must be captured first to make the job
        undoable (audit CLAS-02). Recorded once per module and per job.

        Args:
            staged: Accumulator holding the per-job snapshots.
            bundle: Bundle whose preprocessor is about to run in training mode.
        """
        module = bundle.config.name
        if module in staged.rule_backups:
            return
        repository = getattr(bundle.preprocessor, "_rules_repository", None)
        if repository is None or not hasattr(repository, "snapshot_module"):
            return
        try:
            staged.rule_backups[module] = list(repository.snapshot_module(module))
        except Exception:
            logger.exception(
                "JobRunner: could not snapshot port-collapse rules for '{}'; "
                "refusing to stage a change that cannot be rolled back",
                module,
            )
            raise

    def _restore_rule_backups(self, staged: _StagedArtifacts) -> None:
        """Put pre-staging port-collapse rules back after a failed job.

        Restores both the persisted rows and the live preprocessor cache,
        so the next detection tick normalizes series exactly as it did
        before the failed job (audit CLAS-02).
        """
        for module, rules in staged.rule_backups.items():
            bundle = staged.bundles_by_module.get(module)
            if bundle is None:
                bundle = next((b for b in self._bundles if b.config.name == module), None)
            if bundle is None:
                continue
            repository = getattr(bundle.preprocessor, "_rules_repository", None)
            if repository is None or not hasattr(repository, "restore_module"):
                continue
            try:
                repository.restore_module(module, rules)
                if hasattr(bundle.preprocessor, "reload_rules_cache"):
                    bundle.preprocessor.reload_rules_cache()
                logger.info(
                    "JobRunner: restored {} port-collapse rules for '{}'",
                    len(rules),
                    module,
                )
            except Exception:
                logger.exception("JobRunner: failed to restore port-collapse rules for '{}'", module)

    def _capture_publication_backups(self, staged: _StagedArtifacts) -> dict[str, dict[str, Any]]:
        """Capture persisted and live state before the first publication."""
        backups: dict[str, dict[str, Any]] = {}
        bounds_modules = {c.module for c in staged.bounds}
        frequency_modules = {c.module for c in staged.frequency}
        classifier_modules = {c.module for c in staged.classifier}
        modules = bounds_modules | frequency_modules | classifier_modules
        for module in modules:
            bundle = staged.bundles_by_module[module]
            backup: dict[str, Any] = {"bundle": bundle}
            if module in bounds_modules and hasattr(bundle, "bounds_repository"):
                backup["bounds_rows"] = bundle.bounds_repository.snapshot_module(module)
                backup["bounds_cache"] = deepcopy(getattr(bundle.bounds_manager, "_cache", None))
            if module in frequency_modules and hasattr(bundle, "freq_monitor"):
                repository = bundle.freq_monitor.repository
                backup["profile_rows"] = repository.snapshot_profiles(module) if repository is not None else None
                backup["profiles"] = deepcopy(bundle.freq_monitor.profiles)
            if module in classifier_modules and hasattr(self._model_store, "load"):
                backup["model_pointer"] = self._model_store.publication_pointer(module)
                backup["inference"] = bundle.model_snapshot() if hasattr(bundle, "model_snapshot") else None
            backups[module] = backup
        return backups

    def _restore_publication_backups(self, backups: dict[str, dict[str, Any]], journal: list[tuple[str, str]]) -> None:
        """Restore previously touched database, file, and live state."""
        restored: set[tuple[str, str]] = set()
        for kind, module in reversed(journal):
            if (kind, module) in restored:
                continue
            restored.add((kind, module))
            backup = backups[module]
            bundle = backup["bundle"]
            if kind == "bounds":
                bundle.bounds_repository.restore_module(module, backup["bounds_rows"])
                cached = backup["bounds_cache"]
                bundle.bounds_manager._cache = cached
            elif kind == "frequency":
                repository = bundle.freq_monitor.repository
                if repository is not None:
                    repository.restore_snapshot(module, backup["profile_rows"] or [])
                profiles = backup["profiles"]
                bundle.freq_monitor.restore_profiles(profiles)
                if self._notify_channel and repository is not None:
                    for series_id in set(profiles) | {
                        series_id for row in backup["profile_rows"] or [] if (series_id := str(row["series_id"]))
                    }:
                        from otalon_clas.detection.frequency_profile_repository import (
                            emit_notify,
                        )

                        emit_notify(
                            repository._connector,
                            self._notify_channel,
                            module,
                            series_id,
                        )
            elif kind == "classifier":
                self._model_store.restore_publication_pointer(module, backup["model_pointer"])
                bundle.restore_inference_model(backup["inference"])

    def _swap_model_into_bundle(self, bundle: ModuleBundle) -> None:
        """Reload the freshly published model and swap it under the lock.

        Only a missing artifact is tolerated here. An
        ``ArtifactIntegrityError`` propagates to the publication
        try/except in :meth:`_publish_staged`, triggering the normal
        compensation: a model that fails its write-time integrity check
        between the publish and this reload must not go live (CLAS-048).
        """
        try:
            model, scaler, metadata = self._model_store.load(bundle.config.name)
        except FileNotFoundError:
            logger.warning(
                "JobRunner: no persisted model for '{}' after classifier publish",
                bundle.config.name,
            )
            return
        raw_map = metadata.get("label_map", {})
        label_map = {int(k): v for k, v in raw_map.items()}
        protocol_map = metadata.get("protocol_map")
        raw_features = metadata.get("feature_columns")
        if protocol_map and hasattr(bundle.preprocessor, "load_protocol_map"):
            bundle.preprocessor.load_protocol_map(protocol_map, lock=True)
        bundle.set_inference_model(
            InferenceModel(
                backend=model,
                scaler=scaler,
                label_map=label_map,
                protocol_map=protocol_map,
                # Carry the trained feature order into the live snapshot so
                # a retrained model is scored on its own columns, exactly
                # like a boot-loaded one (audit CLAS-03).
                feature_columns=tuple(raw_features) if raw_features else None,
            )
        )
        logger.info("JobRunner: swapped classifier for '{}' in-process", bundle.config.name)

    def _validated_mitre_file(self, job: RetrainJobDTO) -> str | None:
        """Validate ``job.mitre_file`` at the worker boundary (audit B-07).

        Raises:
            ValueError: When the file is missing, unreadable, or outside
                the allow-listed directories.
        """
        mitre_file = job.mitre_file
        if not mitre_file:
            raise ValueError("classifier job is missing mitre_file")
        path = Path(mitre_file)
        if not path.is_file() or not os.access(path, os.R_OK):
            raise ValueError(f"mitre_file is not a readable file: {mitre_file}")
        if self._allowed_mitre_dirs:
            resolved = path.resolve()
            allowed = any(self._is_within(resolved, Path(base).resolve()) for base in self._allowed_mitre_dirs)
            if not allowed:
                raise ValueError(f"mitre_file {mitre_file} is outside the allowed label directories")
        return mitre_file

    @staticmethod
    def _is_within(candidate: Path, base: Path) -> bool:
        """Return True when *candidate* is inside *base* (no traversal)."""
        try:
            candidate.relative_to(base)
            return True
        except ValueError:
            return False

    def _is_paused(self) -> bool:
        """Return True when runtime retraining is paused via runtime_config."""
        return bool(self._runtime_config.get_bool("otalon-clas", "training.retrain_paused", default=False))

    def _safe_terminal(self, job_ref: str, state: str, *, detail: str, error: str | None) -> None:
        """Record a terminal state without letting a failure mask the cause."""
        try:
            self._repository.set_terminal(
                job_ref,
                state,
                detail=detail,
                worker_id=_WORKER_ID,
                error=error,
            )
        except Exception:
            logger.exception("JobRunner: failed to record terminal state for {}", job_ref)

    def _heartbeat_loop(self, job_ref: str) -> None:
        """Emit periodic heartbeats while the job is active.

        If a heartbeat reports lost ownership (the reaper won), request a
        cooperative stop so the worker aborts before publishing (B-05/B-06).
        """
        while not self._job_done.is_set():
            if self._job_done.wait(_HEARTBEAT_INTERVAL_S):
                break
            try:
                owned = self._repository.heartbeat(job_ref, _WORKER_ID)
                if not owned:
                    logger.warning(
                        "JobRunner: {} lost ownership per heartbeat; requesting stop",
                        job_ref,
                    )
                    self._stop_event.set()
                    break
            except Exception:
                logger.exception("JobRunner: heartbeat failed for {}", job_ref)


class _JobCancelled(RuntimeError):
    """Raised internally when a job is cancelled at a phase boundary."""


class _StagedArtifacts:
    """Holds staged, not-yet-published candidates for a single job."""

    def __init__(self) -> None:
        """Initialize empty candidate lists."""
        self.bounds: list[BoundsCandidate] = []
        self.frequency: list[FrequencyCandidate] = []
        self.classifier: list[ClassifierCandidate] = []
        self.bundles_by_module: dict[str, ModuleBundle] = {}
        self.classifier_skipped: dict[str, str] = {}
        self.rule_backups: dict[str, list[Any]] = {}
        """Port-collapse rules per module as they were BEFORE staging.

        ``preprocess_for_training`` resolves rules in training mode, which
        persists them (``PortCollapseRulesRepository.save`` — a DELETE +
        INSERT of every rule for the module) and overwrites the live
        preprocessor cache. That happens during staging, before any
        publish decision, yet the publication backups captured only
        bounds/frequency/model state. A job that failed after staging
        therefore left the live UCI normalization and per-series
        ``bucket_seconds`` permanently replaced while ``bounds`` still
        held the old series ids — every subsequent row flagged NoBounds
        (audit CLAS-02). Captured here so the compensation path can put
        the previous rules back.
        """

    def has_any(self) -> bool:
        """Return True when at least one artifact was staged."""
        return bool(self.bounds or self.frequency or self.classifier)

    def metrics(self) -> dict[str, Any]:
        """Summarize the staged work for the job's metrics column."""
        trained = sorted(
            {c.module for c in self.bounds} | {c.module for c in self.frequency} | {c.module for c in self.classifier}
        )
        clf_metrics = {c.module: c.metrics for c in self.classifier}
        return {
            "trained_modules": trained,
            "classifier_metrics": clf_metrics,
            "classifier_skipped": dict(self.classifier_skipped),
        }

    def time(self) -> float:
        """Return a monotonic marker (placeholder for future timing)."""
        return time.monotonic()
