"""Long-lived supervisor that owns the live loop and runtime retrain jobs.

The supervisor applies ``runtime_config`` boot precedence, starts the
retrain-job LISTEN/NOTIFY listener, and runs the existing live loop
(callback). On shutdown it stops the listener and any in-flight job.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from loguru import logger

from otalon_clas.common.model_store import ModelStore
from otalon_clas.common.postgres_connector import PostgresConnector
from otalon_clas.common.settings import AppConfig
from otalon_clas.pipeline.builder import PipelineBuilder
from otalon_clas.runtime.job_runner import JobRunner
from otalon_clas.runtime.module_bundle import ModuleBundle
from otalon_clas.runtime.retrain_job_listener import RetrainJobListener
from otalon_clas.runtime.runtime_config_repository import RuntimeConfigRepository
from otalon_clas.runtime.series_blacklist_listener import SeriesBlacklistListener
from otalon_clas.runtime.series_blacklist_source import SeriesBlacklistSource


class RuntimeSupervisor:
    """Owns live-mode execution and runtime retrain jobs.

    The supervisor applies ``runtime_config`` boot precedence, starts
    the retrain-job LISTEN/NOTIFY listener and the series-blacklist
    listener (CLAS-071), and runs the existing live loop (callback).
    On shutdown it stops both listeners and any in-flight job. It owns
    the shared :class:`SeriesBlacklistSource`, which the live loop and
    the retrain JobRunner both resolve from.

    Args:
        config: Application configuration (env/config.json defaults).
        pg: PostgreSQL connector.
        model_store: ML model persistence store.
        bundles: Per-module runtime bundles.
        pipeline_builder: Post-processing pipeline.
    """

    def __init__(
        self,
        config: AppConfig,
        pg: PostgresConnector,
        model_store: ModelStore,
        bundles: list[ModuleBundle],
        pipeline_builder: PipelineBuilder,
    ) -> None:
        """Wire the supervisor without starting threads."""
        self._config = config
        self._pg = pg
        self._model_store = model_store
        self._bundles = bundles
        self._pipeline_builder = pipeline_builder
        self._runtime_config = RuntimeConfigRepository(pg)
        self.blacklist_source = SeriesBlacklistSource(repository=RuntimeConfigRepository(pg))
        self._blacklist_listener = SeriesBlacklistListener(
            connector=pg,
            on_invalidation=self.blacklist_source.mark_dirty,
        )
        self._job_runner: JobRunner | None = None
        self._listener: RetrainJobListener | None = None

    def _on_job_ref(self, job_ref: str) -> None:
        """Callback invoked by the listener for each queued job."""
        if self._job_runner is None:
            return
        started = self._job_runner.try_run(job_ref)
        if not started:
            logger.info(
                "RuntimeSupervisor: job {} not started (single-flight)",
                job_ref,
            )

    def _apply_runtime_overrides(self) -> None:
        """Apply ``runtime_config`` precedence to hot-reconfigurable keys.

        Secrets are never read from ``runtime_config``. The env/config.json
        values are the bootstrap defaults; persisted rows win at runtime.
        """
        # Informational only: the effective pause decision is re-read per
        # job by the JobRunner (a boot-time pause must not wedge the live
        # loop), so this log just surfaces the boot-time value (audit A-12).
        paused = self._runtime_config.get_bool("otalon-clas", "training.retrain_paused", default=False)
        if paused:
            logger.info(
                "RuntimeSupervisor: training.retrain_paused=true at boot "
                "(re-evaluated per job; live loop unaffected)"
            )

        quantile = self._runtime_config.get_float("otalon-clas", "training.default_quantile", default=None)
        if quantile is not None:
            self._config.training.boundary.quantile = quantile
            logger.info(
                "RuntimeSupervisor: overridden boundary quantile to {}",
                quantile,
            )

        cls_global = self._runtime_config.get_bool("otalon-clas", "classification.training_enabled", default=None)
        if cls_global is not None:
            for mod in self._config.modules:
                if mod.enabled:
                    mod.classification.training_enabled = cls_global
            logger.info(
                "RuntimeSupervisor: overridden classification.training_enabled to {}",
                cls_global,
            )

        for mod in self._config.modules:
            frequency = self._runtime_config.get_bool(
                "otalon-clas", f"detection.{mod.name}.frequency_enabled", default=None
            )
            if frequency is not None:
                mod.frequency_monitor.enabled = frequency

    def run(
        self,
        live_loop: Callable[[], None],
    ) -> None:
        """Start the supervisor and run the live loop until interruption.

        Args:
            live_loop: Blocking callable that executes the live detection
                loop. The supervisor stops its own threads after it returns.
        """
        self._apply_runtime_overrides()

        notify_channel = None
        if self._config.frequency_monitor.persistence_enabled:
            notify_channel = self._config.frequency_monitor.notify_channel

        self._job_runner = JobRunner(
            config=self._config,
            pg=self._pg,
            model_store=self._model_store,
            bundles=self._bundles,
            notify_channel=notify_channel,
            allowed_mitre_dirs=self._allowed_mitre_dirs(),
            blacklist_source=self.blacklist_source,
        )

        self._listener = RetrainJobListener(
            connector=self._pg,
            poll_interval_seconds=max(10, self._config.prediction.live.poll_interval_seconds * 2),
            on_job_ref=self._on_job_ref,
        )
        self._listener.start()
        self._blacklist_listener.start()
        logger.info("RuntimeSupervisor: starting live loop")

        try:
            live_loop()
        except KeyboardInterrupt:
            logger.info("RuntimeSupervisor: KeyboardInterrupt received")
        finally:
            logger.info("RuntimeSupervisor: shutting down")
            # Signal a cooperative stop first so an in-flight job aborts at
            # its next phase boundary and does NOT publish after shutdown was
            # requested (audit B-06), then stop the listener and join the
            # non-daemon job thread.
            if self._job_runner is not None:
                self._job_runner.request_stop()
            if self._listener is not None:
                self._listener.stop(timeout=5.0)
            self._blacklist_listener.stop()
            if self._job_runner is not None:
                self._job_runner.stop(timeout=30.0)

    def _allowed_mitre_dirs(self) -> tuple[str, ...]:
        """Collect label directories a runtime classifier job may read.

        Derived from each module's configured ``mitre_technique_file`` so a
        runtime ``job.mitre_file`` must resolve under a directory the
        deployment already trusts (audit B-07). Empty when no module has a
        configured label file, in which case the worker accepts any
        readable path.
        """
        dirs: set[str] = set()
        for mod in self._config.modules:
            configured = getattr(mod.classification, "mitre_technique_file", "")
            if configured:
                parent = str(Path(configured).resolve().parent)
                dirs.add(parent)
        return tuple(sorted(dirs))
