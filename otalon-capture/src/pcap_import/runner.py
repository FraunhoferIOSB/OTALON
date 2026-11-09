"""Execution of a single PCAP import through the shared capture pipeline.

The runner is the only place that knows how a capture file becomes InfluxDB
points, and it does so by reusing the adapter's own pipeline: Netcap++ in
``PCAP`` mode feeds the same aggregation and the same
:class:`~otalon_capture.influxdb_writer.InfluxDBWriter` that live capture uses.
No second aggregation implementation exists.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Protocol

from loguru import logger

from ._adapter import CapturePipeline, CaptureType, PipelineResult, Settings
from .models import ImportPhase, ImportRequest
from .settings import DEFAULT_IMPORT_DIR

ProgressCallback = Callable[[ImportPhase, str], None]

__all__ = [
    "DEFAULT_IMPORT_DIR",
    "ImportCancelled",
    "ImportPathError",
    "ImportRunner",
    "PipelineImportRunner",
    "ProgressCallback",
    "resolve_capture_path",
]


class ImportPathError(ValueError):
    """Raised when a requested capture path lies outside the import volume."""


def resolve_capture_path(file_path: str, import_dir: str | None = None) -> Path:
    """Resolve ``file_path`` and require it to live inside the import volume.

    The worker accepted any absolute path and merely checked
    ``Path(...).is_file()``, so an authenticated-in-name-only caller could
    read **any** file the process could open — ``/etc/shadow``,
    ``/proc/self/environ``, a mounted host tree — and have its bytes fed
    through the capture pipeline (audit CAP-02).

    Both sides are fully resolved before comparison, so symlinks inside
    the import volume that point outside it are rejected too; a
    ``..`` sequence cannot survive :meth:`Path.resolve`.

    Args:
        file_path: Path supplied by the job owner.
        import_dir: Directory the file must live under. Defaults to
            :data:`DEFAULT_IMPORT_DIR`. Callers on the service path pass
            ``PcapImportSettings.import_dir``, which carries the resolved
            ``$PCAP_IMPORT_DIR`` placeholder (PCAP-007).

    Returns:
        The resolved, contained path.

    Raises:
        ImportPathError: When the path escapes the import directory.
        FileNotFoundError: When no regular file exists at the path.
    """
    root = Path(import_dir or DEFAULT_IMPORT_DIR).resolve()
    candidate = Path(file_path).resolve()

    if candidate == root or root not in candidate.parents:
        raise ImportPathError(f"Capture file must be located inside {root}, got: {file_path}")
    if not candidate.is_file():
        raise FileNotFoundError(f"Capture file not found: {file_path}")
    if candidate.is_symlink():  # pragma: no cover - resolve() already followed it
        raise ImportPathError(f"Capture file must not be a symlink: {file_path}")
    return candidate


class ImportCancelled(RuntimeError):
    """Raised when a running import was cancelled by an operator request."""


class ImportRunner(Protocol):
    """Structural type of an import execution, so tests can substitute a double."""

    def run(
        self,
        job: ImportRequest,
        progress: ProgressCallback,
        cancel_event: threading.Event,
    ) -> Dict[str, Any]:
        """Execute ``job`` and return a result summary."""
        ...


def _load_import_settings(adapter_config_file: str, file_path: str) -> Settings:
    """Build adapter settings pointed at ``file_path`` in PCAP mode.

    The InfluxDB target, aggregation options and write options are taken
    verbatim from the adapter configuration, so imported data lands in exactly
    the same measurements as live data.

    Args:
        adapter_config_file: Path to the adapter's ``config.json``.
        file_path: Capture file the import should read.

    Returns:
        Settings whose capture source is the capture file in ``PCAP`` mode.
    """

    settings = Settings.from_json(Path(adapter_config_file))
    capture = settings.capture.model_copy(update={"source": file_path, "type": CaptureType.PCAP})
    return settings.model_copy(update={"capture": capture})


class PipelineImportRunner:
    """Run an import by replaying a capture file through :class:`CapturePipeline`."""

    def __init__(
        self,
        adapter_config_file: str,
        progress_interval_records: int = 5000,
        import_dir: str = DEFAULT_IMPORT_DIR,
    ) -> None:
        """Store what is needed to construct a pipeline per job.

        Args:
            adapter_config_file: Path to the adapter's ``config.json``.
            progress_interval_records: Records between progress callbacks.
            import_dir: Containment boundary for every capture file, taken
                from ``PcapImportSettings.import_dir`` on the service path.
        """

        self._adapter_config_file = adapter_config_file
        self._progress_interval_records = progress_interval_records
        self._import_dir = import_dir

    def run(
        self,
        job: ImportRequest,
        progress: ProgressCallback,
        cancel_event: threading.Event,
    ) -> Dict[str, Any]:
        """Import ``job``'s capture file into InfluxDB.

        Args:
            job: The import job to execute.
            progress: Callback invoked with phase and human-readable event text.
            cancel_event: Set by the service when the import should abort.

        Returns:
            A result summary with counters and the covered time range.

        Raises:
            ImportCancelled: When ``cancel_event`` was set before completion.
            ImportPathError: When the capture file lies outside the import volume.
            FileNotFoundError: When the capture file does not exist.
            Exception: Any error from the capture or write path, so the service
                can record it as the job's failure diagnosis.
        """

        progress(ImportPhase.VALIDATING, f"Prüfe Datei {job.file_path}")
        # Containment is enforced here, immediately before the file is
        # handed to the pipeline, so no caller can reach the read path
        # with an unchecked location (audit CAP-02).
        capture_path = resolve_capture_path(job.file_path, self._import_dir)

        settings = _load_import_settings(self._adapter_config_file, str(capture_path))
        pipeline = self._build_pipeline(settings, progress, cancel_event)

        progress(ImportPhase.READING, f"Netcap++ liest {capture_path.name}")
        result = self._drive(pipeline, cancel_event)
        if cancel_event.is_set():
            raise ImportCancelled(f"Import of {capture_path.name} was cancelled.")
        progress(ImportPhase.WRITING, f"{result.points_written} Punkt(e) geschrieben")
        return _summarise(result, job)

    def _build_pipeline(
        self,
        settings: Settings,
        progress: ProgressCallback,
        cancel_event: threading.Event,
    ) -> CapturePipeline:
        """Create the pipeline, wiring progress reporting and cancellation."""

        pipeline: Optional[CapturePipeline] = None

        def on_progress(running: PipelineResult) -> None:
            if cancel_event.is_set() and pipeline is not None:
                pipeline.stop()
                return
            progress(
                ImportPhase.READING,
                f"{running.records_processed} Datensatz/Datensätze gelesen",
            )

        pipeline = CapturePipeline(
            settings,
            progress=on_progress,
            progress_interval=self._progress_interval_records,
        )
        return pipeline

    @staticmethod
    def _drive(pipeline: CapturePipeline, cancel_event: threading.Event) -> PipelineResult:
        """Run the pipeline, stopping it promptly when cancellation is requested."""

        watchdog_done = threading.Event()

        def watch() -> None:
            while not watchdog_done.wait(0.2):
                if cancel_event.is_set():
                    logger.info("Cancellation requested — stopping capture pipeline.")
                    pipeline.stop()
                    return

        watchdog = threading.Thread(target=watch, name="import-cancel-watch", daemon=True)
        watchdog.start()
        try:
            return pipeline.run()
        finally:
            watchdog_done.set()
            watchdog.join(timeout=2.0)


def _summarise(result: PipelineResult, job: ImportRequest) -> Dict[str, Any]:
    """Build the result payload reported to the job owner on completion."""

    summary: Dict[str, Any] = {
        "records_processed": result.records_processed,
        "points_written": result.points_written,
        "file_path": job.file_path,
    }
    if job.original_filename:
        summary["original_filename"] = job.original_filename
    summary["time_start"] = _isoformat(result.first_record_ms, job.time_start)
    summary["time_end"] = _isoformat(result.last_record_ms, job.time_end)
    return summary


def _isoformat(epoch_ms: Optional[int], fallback: Any) -> Optional[str]:
    """Render epoch milliseconds as an ISO-8601 string, falling back to ``fallback``.

    The capture's own timestamps take precedence;     the owner-supplied window is
    used only when the pipeline observed no usable record time.
    """

    if epoch_ms is not None:
        return datetime.fromtimestamp(epoch_ms / 1000.0, tz=timezone.utc).isoformat()
    if fallback is None:
        return None
    return fallback.isoformat() if hasattr(fallback, "isoformat") else str(fallback)
