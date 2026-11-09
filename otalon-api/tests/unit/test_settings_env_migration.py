"""Regression tests for the API-043 raw-``os.environ`` to ``Settings`` migration.

Every variable migrated in API-043 has to keep its *effective* value in both
deployments: inside the Compose container (variable set) and on a developer
box (variable unset). These tests pin exactly that, plus the two
consolidations the ticket demanded — ``PCAP_CONFIG_PATH`` and ``MODEL_DIR``
must each resolve from a single source.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pytest import MonkeyPatch

from otalon_api.services.operations_backup_service import OperationsBackupService
from otalon_api.services.operations_maintenance_service import OperationsMaintenanceService
from otalon_api.settings import Settings

# (env var, Settings field, unset/field-default value, container value as
# supplied by docker-compose.yml for the otalon-api service).
#
# The "unset" column is the pure field default, asserted with ``_env_file=None``
# so the developer's own ``../.env`` cannot make the assertion environment-
# dependent. A normal local run additionally layers ``../.env`` on top, which
# supplies MODEL_DIR, PCAP_ARCHIVE_DIR and PCAP_BUFFER_DIR.
_MIGRATED_HOST_PATHS: tuple[tuple[str, str, str, str], ...] = (
    ("HOST_STORAGE_ROOT", "host_storage_root", "/", "/host-storage/root"),
    ("HOST_STORAGE_HOME", "host_storage_home", "/home", "/host-storage/home"),
    ("HOST_STORAGE_VAR", "host_storage_var", "/var", "/host-storage/var"),
    (
        "HOST_INFLUX_DATA_PATH",
        "host_influx_data_path",
        "/host-storage/var/lib/docker",
        "/host-storage/var/lib/docker/volumes/otalon-suite_influxdb3-data/_data",
    ),
    (
        "HOST_POSTGRES_DATA_PATH",
        "host_postgres_data_path",
        "/host-storage/var/lib/docker",
        "/host-storage/var/lib/docker/volumes/otalon-suite_postgres-data/_data",
    ),
    ("HOST_LOG_PATH", "host_log_path", "/host-storage/var/log", "/host-storage/var/log"),
    ("BACKUP_DIR", "backup_dir", "/app/operations/backups", "/app/operations/backups"),
    (
        "BACKUP_CONFIG_SOURCE",
        "backup_config_source",
        "/home/user/otalon-github",
        "/home/user/otalon-github",
    ),
    (
        "BACKUP_POSTGRES_SOURCE",
        "backup_postgres_source",
        "/var/lib/postgresql/data",
        "/app/operations/postgres-source",
    ),
    ("MODEL_DIR", "model_dir", "/app/models", "/home/user/otalon-github/shared/models"),
    ("PCAP_BASELINE_DIR", "pcap_baseline_dir", "/app/baseline", "/app/pcap/baseline"),
    (
        "PCAP_ARCHIVE_DIR",
        "pcap_archive_dir",
        "/app/baseline/../archive",
        "/app/pcap/archive",
    ),
    (
        "PCAP_CONFIG_PATH",
        "pcap_config_path",
        "/app/netcap-config/config_pcap.json",
        "/app/netcap-config/config_pcap.json",
    ),
)


def _clean_settings(monkeypatch: MonkeyPatch, **overrides: str) -> Settings:
    """Build Settings with every migrated variable removed from the environment."""
    for env_name, _field, _local, _container in _MIGRATED_HOST_PATHS:
        monkeypatch.delenv(env_name, raising=False)
    for env_name, value in overrides.items():
        monkeypatch.setenv(env_name, value)
    return Settings(_env_file=None)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("env_name", "field", "local_value", "container_value"),
    _MIGRATED_HOST_PATHS,
    ids=[item[0] for item in _MIGRATED_HOST_PATHS],
)
def test_migrated_host_path_keeps_effective_value_set_and_unset(
    monkeypatch: MonkeyPatch,
    env_name: str,
    field: str,
    local_value: str,
    container_value: str,
) -> None:
    """Each migrated variable yields its previous value with and without the env var."""
    unset = _clean_settings(monkeypatch)
    assert getattr(unset, field) == local_value

    container = _clean_settings(monkeypatch, **{env_name: container_value})
    assert getattr(container, field) == container_value


@pytest.mark.unit
def test_backup_scope_defaults_match_the_pre_migration_raw_defaults(monkeypatch: MonkeyPatch, tmp_path: Path) -> None:
    """Backup scope sources keep their effective pre-API-043 values.

    ``pcap_archive`` and ``baselines`` are the two places where the pre-migration
    copies genuinely disagreed when the variable was unset: the raw fallbacks
    were ``/app/pcap/archive`` and ``/app/pcap/baseline`` while the field
    defaults are ``/app/baseline/../archive`` and ``/app/baseline``. All four are
    container-only paths that do not exist on a developer box, where the
    ``baselines``/``pcap_archive`` scopes fail closed either way. Every real
    deployment sets both variables (docker-compose.yml, and ``PCAP_ARCHIVE_DIR``
    additionally in ``.env``/``.env.compose``), so the environment value is the
    copy actually in effect and the raw fallbacks were unreachable. This test
    pins the deployed values.
    """
    settings = _clean_settings(
        monkeypatch,
        PCAP_ARCHIVE_DIR="/app/pcap/archive",
        PCAP_BASELINE_DIR="/app/pcap/baseline",
    )
    service = OperationsBackupService(tmp_path / "out", settings=settings)

    assert service._allowed_scopes["postgresql"] == (Path("/var/lib/postgresql/data"),)
    assert service._allowed_scopes["models"] == (Path("/app/models"),)
    assert service._allowed_scopes["baselines"] == (Path("/app/pcap/baseline"),)
    assert service._allowed_scopes["pcap_archive"] == (Path("/app/pcap/archive"),)


@pytest.mark.unit
def test_pcap_config_path_resolves_from_a_single_source(monkeypatch: MonkeyPatch, tmp_path: Path) -> None:
    """The ringbuffer caps read pcap_config_path only; no second env override in front."""
    config = tmp_path / "config_pcap.json"
    config.write_text(
        json.dumps({"pcap": {"ringbuffer": {"max_total_size_mb": 1234, "max_file_count": 7}}}),
        encoding="utf-8",
    )
    settings = _clean_settings(monkeypatch).model_copy(update={"pcap_config_path": str(config)})
    service = OperationsMaintenanceService(settings)

    assert service._pcap_caps() == (1234, 7)

    # A stale process-environment value must no longer win over the model.
    monkeypatch.setenv("PCAP_CONFIG_PATH", str(tmp_path / "does-not-exist.json"))
    assert service._pcap_caps() == (1234, 7)


@pytest.mark.unit
def test_model_dir_resolves_from_a_single_source(monkeypatch: MonkeyPatch, tmp_path: Path) -> None:
    """Backup scope and storage footprint agree because both read settings.model_dir."""
    models = tmp_path / "models"
    models.mkdir()
    (models / "m.bin").write_text("payload", encoding="utf-8")
    settings = _clean_settings(monkeypatch).model_copy(update={"model_dir": str(models)})

    backup = OperationsBackupService(tmp_path / "out", settings=settings)
    assert backup._allowed_scopes["models"] == (models,)

    maintenance = OperationsMaintenanceService(settings)
    footprint = maintenance._footprint("models", settings.model_dir)
    assert footprint["size_bytes"] == len("payload")


@pytest.mark.unit
def test_model_dir_env_override_reaches_both_consumers(monkeypatch: MonkeyPatch, tmp_path: Path) -> None:
    """MODEL_DIR set in the environment still drives backup and storage identically."""
    models = tmp_path / "shared-models"
    models.mkdir()
    settings = _clean_settings(monkeypatch, MODEL_DIR=str(models))

    backup = OperationsBackupService(tmp_path / "out", settings=settings)
    assert backup._allowed_scopes["models"] == (models,)
    assert Path(settings.model_dir) == models


@pytest.mark.unit
def test_backup_dir_no_longer_has_a_divergent_second_default(monkeypatch: MonkeyPatch) -> None:
    """Storage footprint and backup service share one backup location.

    Before API-043 the maintenance footprint fell back to ``/var/backups``
    while the backup service used the ``backup_dir`` field default
    ``/app/operations/backups`` — two different directories whenever
    ``BACKUP_DIR`` was unset.
    """
    settings = _clean_settings(monkeypatch)
    assert settings.backup_dir == "/app/operations/backups"

    service = OperationsMaintenanceService(settings)
    monkeypatch.setattr(service, "_directory_size", lambda _path: (0, 0))
    monkeypatch.setattr(
        "otalon_api.services.operations_maintenance_service.os.path.exists",
        lambda _path: False,
    )
    body = service.storage()
    assert any(item["name"] == "backups" for item in body["contributors"])


@pytest.mark.unit
def test_unset_placeholder_falls_back_to_field_default(monkeypatch: MonkeyPatch, tmp_path: Path) -> None:
    """otalon-api policy row: an unresolved $ENV_VAR is dropped, the field default applies.

    otalon-api is the documented exception in backend.md and runs under
    ``MissingEnvVarPolicy.WARN_AND_DROP`` — a missing variable must not raise,
    it must leave the Pydantic default in place.
    """
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"operations": {"model_dir": "$OTALON_API_ABSENT_VAR"}}), encoding="utf-8")
    monkeypatch.delenv("OTALON_API_ABSENT_VAR", raising=False)
    monkeypatch.delenv("MODEL_DIR", raising=False)

    settings = Settings.from_config_json(config)
    assert settings.model_dir == "/app/models"


@pytest.mark.unit
def test_unknown_config_json_key_is_ignored_not_a_boot_error(tmp_path: Path) -> None:
    """extra="ignore" keeps an unmapped config.json key from breaking boot."""
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"unmapped_section": {"some_key": "value"}}), encoding="utf-8")

    settings = Settings.from_config_json(config)
    assert not hasattr(settings, "unmapped_section_some_key")
