"""Configuration models for the PCAP import worker.

Mirrors the ``$ENV_VAR`` placeholder convention used by the adapter and the
recorder in this subproject, so the worker is configured the same way as its
siblings — since SUITE-038 by literally sharing their loader base.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Union

from pydantic import BaseModel, ConfigDict, PositiveInt

from capture_settings_base import CaptureBaseSettings

JsonPath = Union[str, Path]


class ApiConfig(BaseModel):
    """Bind address of the worker's own HTTP surface."""

    host: str = "0.0.0.0"
    port: PositiveInt = 9092


class ReporterConfig(BaseModel):
    """Outbound reporting channel to the job's owner.

    Attributes:
        base_url: Root URL of the job owner's API. Empty disables reporting,
            which keeps the worker usable before the owner endpoint exists.
        job_path_template: Path template for a single job record; ``{display_id}``
            is substituted with the job's display identifier.
        token: Optional bearer token for the internal endpoint.
        timeout_s: Per-request timeout in seconds.
        max_attempts: Bounded number of attempts per report before giving up.
        retry_backoff_s: Delay between attempts in seconds.
    """

    base_url: str = ""
    job_path_template: str = "/internal/jobs/{display_id}"
    token: Optional[str] = None
    timeout_s: float = 5.0
    max_attempts: PositiveInt = 3
    retry_backoff_s: float = 1.0


class LogConfig(BaseModel):
    """Logging configuration for the import worker."""

    level: str = "INFO"
    file: str = "logs/pcap_import.log"


DEFAULT_IMPORT_DIR = "/import"
"""Container path of the shared ``pcap-import-data`` volume.

Matches ``PCAP_IMPORT_DIR`` in ``.env.compose`` and the literal mount in
``docker-compose.yml``. Applies when the worker runs without a config file
supplying the placeholder — the value ``runner.py`` used as its last
fallback before PCAP-007 moved it onto this model.
"""


class PcapImportSettings(CaptureBaseSettings):
    """Aggregate configuration of the import worker.

    Attributes:
        api: Bind address of the worker's HTTP surface.
        reporter: Outbound progress-reporting configuration.
        log: Logging configuration.
        adapter_config_file: Path to the adapter config supplying the InfluxDB
            connection, aggregation options and write options reused verbatim.
        progress_interval_records: Records between progress reports.
        import_dir: Directory every capture file must live under. The
            containment boundary of ``runner.resolve_capture_path``.
    """

    # Declared explicitly: the shared base forbids extra keys, while this
    # model has always ignored them (SUITE-038).
    model_config = ConfigDict(extra="ignore")

    api: ApiConfig = ApiConfig()
    reporter: ReporterConfig = ReporterConfig()
    log: LogConfig = LogConfig()
    adapter_config_file: str = "config/config.json"
    progress_interval_records: PositiveInt = 5000
    import_dir: str = DEFAULT_IMPORT_DIR
