"""Focused Wave-F system maintenance contract tests.

Covers the corrected Wave-F surfaces directly: truthful storage caps from the
runtime-visible shipped config, storage reconciliation, fail-closed backup
sources, archive verification + staleness, redacted host-persisted support
bundle, truthful manual-only update gate, no-mutation health check, suite-only
service listing incl. ``otalon-ai`` with core rejection, and the reset/
restore executors behind fail-closed safety gates (exercised with fakes/temp
data only — a correctly confirmed fake path invokes ONLY the mapped narrow
operation and no live destructive action ever runs).
"""

from __future__ import annotations

import json
import zipfile
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from _pytest.monkeypatch import MonkeyPatch
from fastapi.testclient import TestClient
from otalon_common.auth import UserRole

from otalon_api.dependencies import (
    get_compose_runner,
    get_docker_service,
    get_influx_repo,
    get_operations_backup_service,
    get_operations_jobs_service,
    get_operations_maintenance_service,
    get_operations_reset_service,
    get_postgres_repo,
    get_session_repo,
)
from otalon_api.domain.operations import OperationsJob
from otalon_api.main import app
from otalon_api.middleware.session_auth import SESSION_COOKIE_NAME
from otalon_api.repositories.identity_repo import UserEntry
from otalon_api.services.operations_backup_service import OperationsBackupService
from otalon_api.services.operations_maintenance_service import OperationsMaintenanceService
from otalon_api.services.operations_reset_service import OperationsResetService
from otalon_api.settings import Settings

_REAL_PCAP_CONFIG = "/home/user/otalon-suite/otalon-capture/config/config_pcap.json"

# (TestClient, jobs mock, backup service, fake reset repo)
ClientFixture = tuple[TestClient, Any, "OperationsBackupService", "_FakeResetRepo"]


def _settings() -> Settings:
    """Build settings without external services, pointing at the real shipped config."""
    return Settings(
        admin_api_key="test-secret",
        pcap_buffer_dir="/tmp/buffer",
        pcap_archive_dir="/tmp/archive",
        operations_artifact_dir="/tmp/otalon-operations-test",
        pcap_config_path=_REAL_PCAP_CONFIG,
    )


def _user(role: UserRole = UserRole.ADMIN, username: str = "alice") -> UserEntry:
    """Build an active product user for protected operation requests."""
    return UserEntry(
        id=1,
        username=username,
        password_hash="hash",
        role=role,
        must_change_password=False,
        disabled=False,
        last_login_at=None,
    )


class _FakeResetRepo:
    """Records narrow delete calls; proves only mapped tables are touched."""

    def __init__(self) -> None:
        self.deleted: list[str] = []

    def delete_all_rows(self, table_name: str) -> int:
        self.deleted.append(table_name)
        return 7

    def delete_all_rows_batch(self, table_names: tuple[str, ...]) -> dict[str, int]:
        for table_name in table_names:
            self.delete_all_rows(table_name)
        return {table_name: 7 for table_name in table_names}


@pytest.fixture()
def client(tmp_path: Path) -> Iterator[ClientFixture]:
    """Install safe dependency doubles for contract tests."""
    settings = _settings()
    backup = OperationsBackupService(tmp_path)
    reset_repo = _FakeResetRepo()
    app.dependency_overrides[get_operations_maintenance_service] = lambda: OperationsMaintenanceService(settings)
    app.dependency_overrides[get_operations_backup_service] = lambda: backup
    app.dependency_overrides[get_operations_reset_service] = lambda: OperationsResetService(reset_repo)
    app.dependency_overrides[get_postgres_repo] = lambda: MagicMock(health_check=lambda: True)
    influx = MagicMock()
    influx.health_check.return_value = True
    app.dependency_overrides[get_influx_repo] = lambda: influx
    docker = MagicMock()
    docker.list_containers.return_value = [
        {"name": "otalon-api", "status": "running", "core_db": False},
        {"name": "otalon-ai", "status": "running", "core_db": False},
        {"name": "postgres", "status": "running", "core_db": True},
    ]
    docker.get_container_logs.return_value = "log-line"
    app.dependency_overrides[get_docker_service] = lambda: docker
    compose = MagicMock()
    compose.run_action.return_value = {"exit_code": 0}
    app.dependency_overrides[get_compose_runner] = lambda: compose
    jobs = MagicMock()
    jobs.record_job = AsyncMock(
        return_value=OperationsJob(
            id=1,
            display_id="J-1",
            type="maintenance",
            title="Maintenance",
            state="queued",
            trigger="operator",
            actor="alice",
            started_at=datetime.now(timezone.utc),
        )
    )
    jobs.start_job = AsyncMock(return_value=None)
    jobs.complete_job = AsyncMock(return_value=None)
    jobs.fail_job = AsyncMock(return_value=None)
    jobs.append_audit = AsyncMock()
    app.dependency_overrides[get_operations_jobs_service] = lambda: jobs
    session_repo = MagicMock()
    session_repo.validate_and_touch.return_value = _user()
    app.dependency_overrides[get_session_repo] = lambda: session_repo
    with patch("otalon_api.middleware.auth.get_settings", return_value=settings):
        with patch("otalon_api.middleware.session_auth.get_session_repo", return_value=session_repo):
            test_client = TestClient(app, raise_server_exceptions=False)
            test_client.cookies.set(SESSION_COOKIE_NAME, "test-session")
            yield test_client, jobs, backup, reset_repo
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Storage — real caps + reconciliation
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_storage_reconciles_and_only_ringbuffer_has_cap(client: ClientFixture) -> None:
    """Storage response exposes ringbuffer caps and no contributor quotas."""
    response, *_ = client
    body = response.get("/api/v1/operations/storage", headers={"X-API-Key": "test-secret"}).json()
    assert "cap_gb" in body["ringbuffer"]
    assert all("max" not in item for item in body["contributors"])


@pytest.mark.unit
def test_storage_reads_real_pcap_caps_from_shipped_config(monkeypatch: MonkeyPatch, tmp_path: Path) -> None:
    """Ringbuffer caps come from the runtime-visible shipped Netcap config."""
    service = OperationsMaintenanceService(_settings())
    usage = type("Usage", (), {"total": 1000, "used": 500, "free": 500})()
    monkeypatch.setattr("otalon_api.services.operations_maintenance_service.shutil.disk_usage", lambda _: usage)
    monkeypatch.setattr(service, "_directory_size", lambda _: (100, 2))
    body = service.storage()
    assert body["ringbuffer"]["cap_gb"] == 50.0
    assert body["ringbuffer"]["file_cap"] == 2000
    assert body["unattributed_gb"] == 0.0
    assert any(item["name"] == "PCAP ringbuffer" for item in body["contributors"])


@pytest.mark.unit
def test_storage_reports_host_mounts_independently_in_decimal_gb(monkeypatch: MonkeyPatch) -> None:
    """/, /home and /var are read from the host-visible contract, each distinctly."""
    settings = _settings().model_copy(
        update={
            "host_storage_root": "/host-storage/root",
            "host_storage_home": "/host-storage/home",
            "host_storage_var": "/host-storage/var",
        }
    )
    service = OperationsMaintenanceService(settings)
    sizes = {
        "/host-storage/root": (31_000_000_000, 13_000_000_000, 18_000_000_000),
        "/host-storage/home": (274_000_000_000, 166_000_000_000, 108_000_000_000),
        "/host-storage/var": (129_000_000_000, 108_000_000_000, 21_000_000_000),
    }

    def _usage(path: str) -> Any:
        total, used, free = sizes[path]
        return type("Usage", (), {"total": total, "used": used, "free": free})()

    monkeypatch.setattr("otalon_api.services.operations_maintenance_service.os.path.exists", lambda _p: True)
    monkeypatch.setattr("otalon_api.services.operations_maintenance_service.shutil.disk_usage", _usage)
    monkeypatch.setattr(service, "_directory_size", lambda _p: (0, 0))
    body = service.storage()
    mounts = body["host"]["mounts"]
    assert set(mounts) == {"/", "/home", "/var"}
    assert mounts["/home"]["total_gb"] == 274.0
    assert mounts["/var"]["used_gb"] == 108.0
    assert mounts["/"]["purpose"] == "System / OS"
    assert "Docker" in mounts["/var"]["purpose"]
    assert body["host"]["unit"] == "GB"
    # decimal GB with two decimals, no GiB fields leak.
    assert "free_gib" not in body["host"]
    assert "used_gib" not in mounts["/"]


@pytest.mark.unit
def test_storage_unknown_when_root_mount_absent(monkeypatch: MonkeyPatch) -> None:
    """When no host root mount is visible the host facts stay unknown/null."""
    service = OperationsMaintenanceService(_settings())
    monkeypatch.setattr("otalon_api.services.operations_maintenance_service.os.path.exists", lambda _p: False)
    monkeypatch.setattr(service, "_directory_size", lambda _p: (0, 0))
    body = service.storage()
    assert body["host"]["mounts"] == {}
    assert body["unattributed_gb"] is None
    assert body["ringbuffer"]["state"] == "unknown"


@pytest.mark.unit
def test_storage_caps_fail_closed_when_config_missing(monkeypatch: MonkeyPatch) -> None:
    """Missing config yields 0/0 caps rather than invented limits."""
    settings = Settings(admin_api_key="x", pcap_config_path="/nonexistent/config_pcap.json")
    service = OperationsMaintenanceService(settings)
    monkeypatch.setattr(
        "otalon_api.services.operations_maintenance_service.Path.read_text",
        lambda *a, **k: (_ for _ in ()).throw(OSError("missing")),
    )
    cap_mb, file_cap = service._pcap_caps()
    assert (cap_mb, file_cap) == (0, 0)


# ---------------------------------------------------------------------------
# Support bundle — path safety + redaction + local
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_support_bundle_rejects_escape(tmp_path: Path) -> None:
    """Support artifacts cannot escape suite-owned root."""
    service = OperationsMaintenanceService(_settings())
    with pytest.raises(ValueError):
        service.create_support_bundle(tmp_path / "outside")


@pytest.mark.unit
def test_support_bundle_is_redacted_and_local(client: ClientFixture, tmp_path: Path) -> None:
    """Support bundle preview and artifact enforce local privacy boundary."""
    response, *_ = client
    headers = {"X-API-Key": "test-secret"}
    preview = response.get("/api/v1/operations/support-bundle/preview", headers=headers).json()
    result = response.post(
        "/api/v1/operations/support-bundle",
        json={"output_dir": "bundles"},
        headers=headers,
    ).json()
    assert "PCAPs" in preview["excluded"]
    assert result["uploaded"] is False
    assert "password" not in json.loads(Path(result["path"]).read_text(encoding="utf-8"))


@pytest.mark.unit
def test_support_bundle_redacts_hostnames_and_ips(client: ClientFixture, tmp_path: Path) -> None:
    """The bundle honours its advertised hostname/IP redaction (F-AUDIT-03).

    The preview advertises hostnames/IPs as redacted (design Decision 5); the
    written artifact must not leak an IPv4/IPv6 address or a DNS hostname even
    when a monkeypatched maintenance surface injects one.
    """
    response, *_ = client
    headers = {"X-API-Key": "test-secret"}
    leaky = {
        "version": {"suite": {"version": "10.0.0.1"}},
        "storage": {"note": "reached db.internal.example.com"},
    }
    with (
        patch.object(OperationsMaintenanceService, "version", return_value=leaky["version"]),
        patch.object(OperationsMaintenanceService, "storage", return_value=leaky["storage"]),
    ):
        result = response.post(
            "/api/v1/operations/support-bundle",
            json={"output_dir": "bundles"},
            headers=headers,
        ).json()
    written = Path(result["path"]).read_text(encoding="utf-8")
    assert "10.0.0.1" not in written
    assert "db.internal.example.com" not in written
    assert "REDACTED-HOST" in written


# ---------------------------------------------------------------------------
# Backup — config allowlist, fail-closed sources, verification, staleness
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_backup_config_scope_archives_allowlisted_config_only(tmp_path: Path) -> None:
    """A config backup archives allowlisted config files and redacts secrets."""
    source = tmp_path / "src-root"
    (source / "otalon-api/config").mkdir(parents=True)
    (source / "otalon-api/config/config.json").write_text(
        json.dumps({"api_key": "SECRET", "port": 8090}), encoding="utf-8"
    )
    (source / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    with patch.dict("os.environ", {"BACKUP_CONFIG_SOURCE": str(source)}):
        service = OperationsBackupService(tmp_path / "out")
        manifest = service.create_manifest(["config"])
    assert manifest["verified"] is True
    with zipfile.ZipFile(manifest["archive"]) as bundle:
        names = bundle.namelist()
        # Each config file keeps its allowlist-relative path (no basename collision).
        assert "config/otalon-api/config/config.json" in names
        assert "config/docker-compose.yml" in names
        payload = json.loads(bundle.read("config/otalon-api/config/config.json"))
    assert payload["api_key"] == "***REDACTED***"
    assert payload["port"] == 8090


@pytest.mark.unit
def test_backup_unknown_scope_rejected(tmp_path: Path) -> None:
    """Traversal-like or unknown scopes are rejected before any archive."""
    service = OperationsBackupService(tmp_path / "out")
    with pytest.raises(ValueError):
        service.create_manifest(["../secrets"])


@pytest.mark.unit
def test_influx_scope_is_catalogued_but_backup_fails_closed(tmp_path: Path) -> None:
    """InfluxDB scope is visible without pretending a raw copy is consistent."""
    service = OperationsBackupService(tmp_path / "out")
    scope = {item["scope"]: item for item in service.scope_catalog()}["influx"]
    assert scope["available"] is False
    with pytest.raises(RuntimeError, match="no built-in backup command"):
        service.create_manifest(["influx"])


@pytest.mark.unit
def test_full_backup_expands_only_local_capable_scopes(tmp_path: Path) -> None:
    """FULL remains usable and never claims unavailable Influx evidence."""
    source = tmp_path / "src-root"
    (source / "otalon-api/config").mkdir(parents=True)
    (source / "otalon-api/config/config.json").write_text("{}", encoding="utf-8")
    models = tmp_path / "models"
    models.mkdir()
    (models / "model.bin").write_text("model", encoding="utf-8")
    with patch.dict(
        "os.environ",
        {
            "BACKUP_CONFIG_SOURCE": str(source),
            "MODEL_DIR": str(models),
            "BACKUP_POSTGRES_SOURCE": str(tmp_path / "postgres"),
            "PCAP_BASELINE_DIR": str(tmp_path / "baselines"),
            "PCAP_ARCHIVE_DIR": str(tmp_path / "pcap-archive"),
        },
    ):
        for name in ("BACKUP_POSTGRES_SOURCE", "PCAP_BASELINE_DIR", "PCAP_ARCHIVE_DIR"):
            directory = Path(__import__("os").environ[name])
            directory.mkdir()
            (directory / "payload").write_text("data", encoding="utf-8")
        manifest = OperationsBackupService(tmp_path / "out").create_manifest(["FULL"])
    assert "influx" not in manifest["scope"]
    assert set(manifest["scope"]) == {"config", "postgresql", "models", "baselines", "pcap_archive"}


@pytest.mark.unit
def test_local_full_backup_precheck_reports_full_backup(tmp_path: Path) -> None:
    """A verified local FULL manifest satisfies the full-backup precheck."""
    source = tmp_path / "src-root"
    (source / "otalon-api/config").mkdir(parents=True)
    (source / "otalon-api/config/config.json").write_text("{}", encoding="utf-8")
    sources = {
        "BACKUP_POSTGRES_SOURCE": tmp_path / "postgres",
        "MODEL_DIR": tmp_path / "models",
        "PCAP_BASELINE_DIR": tmp_path / "baselines",
        "PCAP_ARCHIVE_DIR": tmp_path / "pcap-archive",
    }
    for directory in sources.values():
        directory.mkdir()
        (directory / "payload").write_text("data", encoding="utf-8")
    env = {"BACKUP_CONFIG_SOURCE": str(source)} | {key: str(value) for key, value in sources.items()}
    with patch.dict("os.environ", env):
        service = OperationsBackupService(tmp_path / "out")
        service.create_manifest(["FULL"])
        result = service.restore_precheck([], "RESTORE")
    assert result["full_backup"] is True


@pytest.mark.unit
def test_local_partial_backup_precheck_reports_not_full(tmp_path: Path) -> None:
    """A verified local partial manifest cannot satisfy the full-backup gate."""
    source = tmp_path / "src-root"
    (source / "otalon-api/config").mkdir(parents=True)
    (source / "otalon-api/config/config.json").write_text("{}", encoding="utf-8")
    with patch.dict("os.environ", {"BACKUP_CONFIG_SOURCE": str(source)}):
        service = OperationsBackupService(tmp_path / "out")
        service.create_manifest(["config"])
        latest = service.latest()
        result = service.restore_precheck([], "RESTORE")
    assert latest is not None
    assert latest["verified"] is True
    assert result["full_backup"] is False


@pytest.mark.unit
def test_mixed_influx_backup_fails_before_archive_or_latest(tmp_path: Path) -> None:
    """An unavailable scope rejects a mixed request atomically."""
    out = tmp_path / "out"
    service = OperationsBackupService(out)
    with pytest.raises(RuntimeError, match="no built-in backup command"):
        service.create_manifest(["config", "influx"])
    assert not out.exists()


@pytest.mark.unit
def test_influx_backup_endpoint_returns_422_and_fails_job(client: ClientFixture) -> None:
    """Explicit Influx backup is controlled, job-visible failure without manifest."""
    response, jobs, backup, _repo = client
    jobs.start_job = AsyncMock(return_value=MagicMock(id=1, display_id="J-1", model_dump=lambda **_: {}))
    jobs.fail_job = AsyncMock()
    result = response.post(
        "/api/v1/operations/backup",
        json={"scope": ["influx"]},
        headers={"X-API-Key": "test-secret"},
    )
    assert result.status_code == 422
    jobs.fail_job.assert_awaited_once()
    assert not list(backup._directory.glob("*.json"))


@pytest.mark.unit
def test_mixed_backup_endpoint_has_no_archive_or_latest(client: ClientFixture) -> None:
    """Mixed local plus Influx request leaves backup storage untouched."""
    response, jobs, backup, _repo = client
    jobs.start_job = AsyncMock(return_value=MagicMock(id=1, display_id="J-1", model_dump=lambda **_: {}))
    jobs.fail_job = AsyncMock()
    result = response.post(
        "/api/v1/operations/backup",
        json={"scope": ["config", "influx"]},
        headers={"X-API-Key": "test-secret"},
    )
    assert result.status_code == 422
    jobs.fail_job.assert_awaited_once()
    assert backup.latest() is None
    assert list(backup._directory.glob("*.zip")) == []


@pytest.mark.unit
def test_influx_backup_endpoint_leaves_no_backup_artifacts(client: ClientFixture) -> None:
    """Explicit Influx failure leaves manifests, archives, and temp archives absent."""
    response, jobs, backup, _repo = client
    jobs.start_job = AsyncMock(return_value=MagicMock(id=1, display_id="J-1", model_dump=lambda **_: {}))
    jobs.fail_job = AsyncMock()
    result = response.post(
        "/api/v1/operations/backup",
        json={"scope": ["influx"]},
        headers={"X-API-Key": "test-secret"},
    )
    assert result.status_code == 422
    jobs.fail_job.assert_awaited_once()
    assert not (backup._directory / "latest.json").exists()
    assert list(backup._directory.glob("*.zip")) == []
    assert list(backup._directory.glob("backup-*.zip")) == []


@pytest.mark.unit
def test_influx_restore_precheck_reports_operator_requirement(tmp_path: Path) -> None:
    """Influx restore precheck cannot claim compatibility without evidence."""
    result = OperationsBackupService(tmp_path).restore_precheck(["influx"], "RESTORE INFLUX")
    assert result["compatible"] is False
    assert result["capability"] == "unavailable"
    assert result["confirmed"] is True
    assert "object-storage snapshot" in result["detail"]


@pytest.mark.unit
def test_influx_restore_non_dry_run_stays_unavailable(tmp_path: Path) -> None:
    """Influx restore cannot execute even with typed confirmation."""
    service = OperationsBackupService(tmp_path, restore_executor=lambda _scope: {"called": True})
    result = service.restore(["influx"], "RESTORE INFLUX", dry_run=True)
    assert result["executed"] is False
    with pytest.raises(ValueError, match="verified, compatible backup"):
        service.restore(["influx"], "RESTORE INFLUX", dry_run=False)


@pytest.mark.unit
def test_backup_missing_source_fails_closed(tmp_path: Path) -> None:
    """A requested scope with a missing source fails closed, no false archive."""
    with patch.dict("os.environ", {"MODEL_DIR": str(tmp_path / "does-not-exist")}):
        service = OperationsBackupService(tmp_path / "out")
        with pytest.raises(ValueError, match="unavailable"):
            service.create_manifest(["models"])


@pytest.mark.unit
def test_backup_empty_source_fails_closed(tmp_path: Path) -> None:
    """An empty source directory fails closed rather than a 0-content archive."""
    empty = tmp_path / "models"
    empty.mkdir()
    with patch.dict("os.environ", {"MODEL_DIR": str(empty)}):
        service = OperationsBackupService(tmp_path / "out")
        with pytest.raises(ValueError, match="empty"):
            service.create_manifest(["models"])


@pytest.mark.unit
def test_backup_symlink_source_fails_closed(tmp_path: Path) -> None:
    """A symlinked source is rejected (no symlink escape)."""
    real = tmp_path / "real"
    real.mkdir()
    (real / "m.bin").write_text("x", encoding="utf-8")
    link = tmp_path / "link"
    link.symlink_to(real)
    with patch.dict("os.environ", {"MODEL_DIR": str(link)}):
        service = OperationsBackupService(tmp_path / "out")
        with pytest.raises(ValueError, match="unavailable"):
            service.create_manifest(["models"])


@pytest.mark.unit
def test_backup_directory_symlink_rejected(tmp_path: Path) -> None:
    """A symlinked backup directory is refused at construction."""
    target = tmp_path / "real-out"
    target.mkdir()
    link = tmp_path / "link-out"
    link.symlink_to(target)
    with pytest.raises(ValueError, match="symlink"):
        OperationsBackupService(link)


@pytest.mark.unit
def test_backup_verification_and_staleness(tmp_path: Path) -> None:
    """latest() re-verifies archive checksum and computes age/staleness."""
    source = tmp_path / "models"
    source.mkdir()
    (source / "m.bin").write_text("payload", encoding="utf-8")
    with patch.dict("os.environ", {"MODEL_DIR": str(source)}):
        service = OperationsBackupService(tmp_path / "out")
        service.create_manifest(["models"])
    latest = service.latest()
    assert latest is not None
    assert latest["verified"] is True
    assert latest["stale"] is False
    assert latest["age_seconds"] >= 0
    # Corrupt the archive; verification must flip to False.
    Path(latest["archive"]).write_bytes(b"corrupted")
    reverified = service.latest()
    assert reverified is not None
    assert reverified["verified"] is False


@pytest.mark.unit
def test_backups_endpoint_reverifies(client: ClientFixture) -> None:
    """GET /backups reports verification derived from re-checking the archive."""
    response, _jobs, _backup, _repo = client
    # No backup yet → not verified.
    body = response.get("/api/v1/operations/backups", headers={"X-API-Key": "test-secret"}).json()
    assert body["verified"] is False
    influx = {item["scope"]: item for item in body["scopes"]}["influx"]
    assert influx["backup_supported"] is False
    assert influx["restore_supported"] is False


# ---------------------------------------------------------------------------
# Update gate — truthful, manual-only, no call-home
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_update_check_is_manual_only_with_truthful_gate(client: ClientFixture) -> None:
    """Update gate reports evidence-bearing states and contacts no registry."""
    response, *_ = client
    body = response.post("/api/v1/operations/update/check", headers={"X-API-Key": "test-secret"}).json()
    assert body["manual_only"] is True
    assert body["registry_contacted"] is False
    statuses = {name: gate["status"] for name, gate in body["gate"].items()}
    assert statuses["compatibility"] == "unknown"
    assert statuses["migrations"] == "unknown"
    assert statuses["rollback"] == "unknown"
    assert statuses["storage"] in {"pass", "warn"}
    assert statuses["backup_age"] in {"pass", "warn"}


# ---------------------------------------------------------------------------
# Health — no mutation, real dimensions
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_health_check_returns_findings_without_mutation(client: ClientFixture) -> None:
    """Health check returns pass/warn/fail/unknown findings and never mutates."""
    response, *_ = client
    body = response.post("/api/v1/operations/health-check", headers={"X-API-Key": "test-secret"}).json()
    assert body["mutations"] == []
    names = {f["name"] for f in body["findings"]}
    assert {"postgresql", "influxdb", "permissions"} <= names
    assert all(f["status"] in {"pass", "warn", "fail", "unknown"} for f in body["findings"])


# ---------------------------------------------------------------------------
# Services — suite-only allowlist incl. otalon-ai, core rejection
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_services_lists_only_suite_and_flags_core(client: ClientFixture) -> None:
    """Service listing returns only allowlisted suite services with core flags."""
    response, *_ = client
    body = response.get("/api/v1/operations/services", headers={"X-API-Key": "test-secret"}).json()
    names = {s["name"] for s in body["services"]}
    assert "otalon-ai" in names
    assert any(s["name"] == "postgres" and s["core_db"] for s in body["services"])


@pytest.mark.unit
def test_service_logs_reject_unlisted(client: ClientFixture) -> None:
    """Logs for an unlisted service are rejected with 404."""
    response, *_ = client
    result = response.get(
        "/api/v1/operations/services/hindsight-memory-pilot/logs",
        headers={"X-API-Key": "test-secret"},
    )
    assert result.status_code == 404


@pytest.mark.unit
def test_service_action_rejects_core_and_wrong_phrase(client: ClientFixture) -> None:
    """Core DB lifecycle is disabled and a wrong typed phrase is rejected."""
    response, *_ = client
    headers = {"X-API-Key": "test-secret"}
    core = response.post(
        "/api/v1/operations/services/action",
        json={
            "service": "postgres",
            "action": "restart",
            "confirmation": "CONFIRM RESTART postgres",
        },
        headers=headers,
    )
    wrong = response.post(
        "/api/v1/operations/services/action",
        json={"service": "otalon-ai", "action": "restart", "confirmation": "nope"},
        headers=headers,
    )
    assert core.status_code == 409
    assert wrong.status_code == 422


@pytest.mark.unit
def test_service_action_uses_session_username_for_job_and_audit(client: ClientFixture) -> None:
    """Service job and audit actor fields use verified session username."""
    response, jobs, _backup, _repo = client
    jobs.record_job.return_value = MagicMock(id=1, display_id="J-1", model_dump=lambda **_: {})
    jobs.maybe_finish_service_job = AsyncMock(return_value=None)
    with patch("otalon_api.api.v1.operations._job_to_detail", return_value={"display_id": "J-1"}):
        result = response.post(
            "/api/v1/operations/services/action",
            json={
                "service": "otalon-ai",
                "action": "restart",
                "confirmation": "CONFIRM RESTART otalon-ai",
            },
            headers={"X-API-Key": "test-secret"},
        )
    assert result.status_code == 200
    assert jobs.record_job.await_args.args[4] == "alice"
    assert jobs.append_audit.await_args.args[0].actor == "alice"


@pytest.mark.unit
@pytest.mark.parametrize(
    "path,payload",
    [
        (
            "/api/v1/operations/reset",
            {"scope": "anomaly-history", "reason": "x", "confirmation": "RESET ANOMALY-HISTORY", "dry_run": False},
        ),
        ("/api/v1/operations/restore", {"scope": ["postgresql"], "dry_run": False}),
        (
            "/api/v1/operations/services/action",
            {"service": "otalon-ai", "action": "restart", "confirmation": "CONFIRM RESTART otalon-ai"},
        ),
    ],
)
def test_named_mutations_require_session_before_side_effects(
    client: ClientFixture, path: str, payload: dict[str, Any]
) -> None:
    """A valid operator key without product session is rejected at middleware."""
    response, jobs, _backup, repo = client
    response.cookies.clear()
    result = response.post(path, json=payload, headers={"X-API-Key": "test-secret"})
    assert result.status_code == 401
    assert repo.deleted == []
    assert jobs.record_job.await_count == 0
    assert jobs.append_audit.await_count == 0


@pytest.mark.unit
def test_named_mutations_reject_non_admin_session_without_side_effects(client: ClientFixture) -> None:
    """Viewer sessions cannot reach reset, restore, or service execution."""
    response, jobs, _backup, repo = client
    session_repo = MagicMock()
    session_repo.validate_and_touch.return_value = _user(UserRole.OPERATOR, "operator-user")
    with patch("otalon_api.middleware.session_auth.get_session_repo", return_value=session_repo):
        result = response.post(
            "/api/v1/operations/reset",
            json={
                "scope": "anomaly-history",
                "reason": "x",
                "confirmation": "RESET ANOMALY-HISTORY",
                "dry_run": False,
            },
            headers={"X-API-Key": "test-secret"},
        )
    assert result.status_code == 403
    assert repo.deleted == []
    assert jobs.append_audit.await_count == 0


# ---------------------------------------------------------------------------
# Restore — precheck-first, fail-closed, never live
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_restore_precheck_is_non_executing(client: ClientFixture) -> None:
    """A dry-run restore returns a precheck and never executes."""
    response, *_ = client
    result = response.post(
        "/api/v1/operations/restore",
        json={"scope": ["postgresql"]},
        headers={"X-API-Key": "test-secret"},
    )
    assert result.status_code == 200
    body = result.json()
    assert body["executed"] is False
    assert body["confirmation_required"] == "RESTORE DATABASE"


@pytest.mark.unit
def test_restore_live_without_executor_fails_closed(client: ClientFixture) -> None:
    """A confirmed non-dry-run restore with no executor fails closed (503)."""
    response, _jobs, backup, _repo = client
    # Seed a verified fresh backup so only the missing executor gates the path.
    with patch.object(
        backup,
        "latest",
        return_value={"verified": True, "stale": False, "scope": ["config"]},
    ):
        result = response.post(
            "/api/v1/operations/restore",
            json={"scope": ["config"], "confirmation": "RESTORE", "dry_run": False},
            headers={"X-API-Key": "test-secret"},
        )
    assert result.status_code == 503
    assert "disabled" in result.json()["detail"].lower()
    client[1].record_job.assert_awaited_once_with(
        "maintenance",
        "Restore backup",
        "operator",
        {"scope": ["config"], "artifact_id": None, "dry_run": False},
        "alice",
        can_cancel=False,
    )
    client[1].start_job.assert_awaited_once_with(1)
    client[1].fail_job.assert_awaited_once()
    audit = client[1].append_audit.await_args.args[0]
    assert audit.actor == "alice"


@pytest.mark.unit
def test_restore_executor_invoked_only_when_fully_confirmed(tmp_path: Path) -> None:
    """A wired executor runs only for confirmed + compatible + fresh + non-dry-run."""
    calls: list[list[str]] = []

    def _executor(scope: list[str]) -> dict[str, Any]:
        calls.append(scope)
        return {"ok": True}

    service = OperationsBackupService(tmp_path, restore_executor=_executor)
    with patch.object(
        service,
        "latest",
        return_value={"verified": True, "stale": False, "scope": ["config"]},
    ):
        # Wrong phrase → ValueError, executor untouched.
        with pytest.raises(ValueError):
            service.restore(["config"], "WRONG", dry_run=False)
        assert calls == []
        out = service.restore(["config"], "RESTORE", dry_run=False)
    assert out["executed"] is True
    assert calls == [["config"]]


@pytest.mark.unit
def test_restore_success_completes_maintenance_job(client: ClientFixture) -> None:
    """A successful non-dry-run restore completes its tracked job."""
    response, jobs, backup, _repo = client
    with (
        patch.object(backup, "latest", return_value={"verified": True, "stale": False, "scope": ["config"]}),
        patch.object(backup, "restore", return_value={"executed": True, "scope": ["config"]}),
    ):
        result = response.post(
            "/api/v1/operations/restore",
            json={"scope": ["config"], "confirmation": "RESTORE", "dry_run": False},
            headers={"X-API-Key": "test-secret"},
        )
    assert result.status_code == 200
    assert result.json()["executed"] is True
    jobs.complete_job.assert_awaited_once()
    assert jobs.append_audit.await_count == 1


@pytest.mark.unit
def test_restore_bad_confirmation_fails_maintenance_job(client: ClientFixture) -> None:
    """A restore ValueError marks its job failed before returning 422."""
    response, jobs, _backup, _repo = client
    result = response.post(
        "/api/v1/operations/restore",
        json={"scope": ["config"], "confirmation": "WRONG", "dry_run": False},
        headers={"X-API-Key": "test-secret"},
    )
    assert result.status_code == 422
    jobs.fail_job.assert_awaited_once_with(1, error="Typed confirmation must be 'RESTORE'")


@pytest.mark.unit
def test_restore_blocks_when_backup_stale(tmp_path: Path) -> None:
    """A confirmed restore is blocked when the latest verified backup is stale."""
    service = OperationsBackupService(tmp_path, restore_executor=lambda scope: {"ok": True})
    with patch.object(
        service,
        "latest",
        return_value={"verified": True, "stale": True, "scope": ["config"]},
    ):
        with pytest.raises(ValueError, match="stale"):
            service.restore(["config"], "RESTORE", dry_run=False)


# ---------------------------------------------------------------------------
# Reset — typed phrase, factory precondition, narrow mapped op, never live
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_reset_rejects_wrong_phrase(client: ClientFixture) -> None:
    """Reset requires the exact typed confirmation phrase."""
    response, *_ = client
    wrong = response.post(
        "/api/v1/operations/reset",
        json={
            "scope": "detection-results",
            "reason": "cleanup test",
            "confirmation": "no",
        },
        headers={"X-API-Key": "test-secret"},
    )
    assert wrong.status_code == 422
    client[1].record_job.assert_awaited_once()
    client[1].start_job.assert_awaited_once_with(1)
    client[1].fail_job.assert_awaited_once_with(1, error="Typed confirmation must be 'RESET DETECTION-RESULTS'")


@pytest.mark.unit
def test_reset_dry_run_audits_without_deleting(client: ClientFixture) -> None:
    """A correctly confirmed dry-run reset audits but deletes nothing."""
    response, jobs, _backup, repo = client
    result = response.post(
        "/api/v1/operations/reset",
        json={
            "scope": "anomaly-history",
            "reason": "cleanup test",
            "confirmation": "RESET ANOMALY-HISTORY",
        },
        headers={"X-API-Key": "test-secret"},
    )
    assert result.status_code == 200
    assert result.json()["executed"] is False
    assert repo.deleted == []
    jobs.complete_job.assert_awaited_once()
    assert jobs.complete_job.await_args.args[0] == 1
    assert jobs.append_audit.await_count == 1
    assert jobs.append_audit.await_args.args[0].actor == "alice"


@pytest.mark.unit
def test_admin_reset_dry_run_false_executes_narrow_scope(client: ClientFixture) -> None:
    """Verified admin live reset reaches only mapped tables and records username."""
    response, jobs, _backup, repo = client
    result = response.post(
        "/api/v1/operations/reset",
        json={
            "scope": "detection-results",
            "reason": "cleanup test",
            "confirmation": "RESET DETECTION-RESULTS",
            "dry_run": False,
        },
        headers={"X-API-Key": "test-secret"},
    )
    assert result.status_code == 200
    assert result.json()["executed"] is True
    assert repo.deleted == ["anomalies"]
    jobs.complete_job.assert_awaited_once()
    assert jobs.append_audit.await_args.args[0].actor == "alice"


@pytest.mark.unit
def test_reset_factory_blocked_by_stale_backup(client: ClientFixture) -> None:
    """A factory reset is blocked when no fresh verified backup exists."""
    response, _jobs, backup, _repo = client
    with patch.object(backup, "latest", return_value=None):
        result = response.post(
            "/api/v1/operations/reset",
            json={
                "scope": "factory",
                "reason": "cleanup test",
                "confirmation": "RESET FACTORY",
            },
            headers={"X-API-Key": "test-secret"},
        )
    assert result.status_code == 409


@pytest.mark.unit
def test_reset_executor_invokes_only_mapped_narrow_tables() -> None:
    """A confirmed non-dry-run reset touches only the mapped allowlisted tables."""
    repo = _FakeResetRepo()
    service = OperationsResetService(repo)
    # Wrong phrase never deletes.
    with pytest.raises(ValueError):
        service.execute("trained-bounds", "WRONG", dry_run=False)
    assert repo.deleted == []
    out = service.execute("trained-bounds", "RESET TRAINED-BOUNDS", dry_run=False)
    assert out["executed"] is True
    assert repo.deleted == ["bounds"]
    assert out["deleted"] == {"bounds": 7}


@pytest.mark.unit
def test_reset_batch_failure_does_not_commit_partial_work() -> None:
    """A repository batch contract owns rollback when a later delete fails."""

    class _AtomicFake:
        def __init__(self) -> None:
            self.committed = False
            self.rolled_back = False

        def delete_all_rows(self, table_name: str) -> int:
            return 1

        def delete_all_rows_batch(self, table_names: tuple[str, ...]) -> dict[str, int]:
            self.rolled_back = True
            raise RuntimeError("second table failed; transaction rolled back")

    repo = _AtomicFake()
    with pytest.raises(RuntimeError, match="rolled back"):
        OperationsResetService(repo).execute("factory", "RESET FACTORY", dry_run=False)
    assert repo.committed is False
    assert repo.rolled_back is True


@pytest.mark.unit
def test_restore_scope_must_be_present_in_verified_manifest(tmp_path: Path) -> None:
    """A config-only backup cannot satisfy a PostgreSQL restore request."""
    service = OperationsBackupService(tmp_path)
    with patch.object(
        service,
        "latest",
        return_value={"verified": True, "stale": False, "scope": ["config"]},
    ):
        result = service.restore_precheck(["postgresql"], "RESTORE DATABASE")
    assert result["compatible"] is False


@pytest.mark.unit
def test_reset_scope_table_mapping_is_allowlisted() -> None:
    """Every mapped reset table is a member of the PG delete allowlist."""
    from otalon_api.repositories.postgres_repo import DB_TABLE_ALLOWLIST

    service = OperationsResetService(_FakeResetRepo())
    for scope in service.scopes():
        for table in service.tables_for(scope):
            assert table in DB_TABLE_ALLOWLIST


@pytest.mark.unit
def test_reset_scope_names_are_truthful_no_misleading_timeseries() -> None:
    """Reset scope names describe the real PG target (F-AUDIT-01 regression).

    The PG-table-only reset surface never touches InfluxDB time-series, so no
    scope may be named ``timeseries``. The scope that clears the ``anomalies``
    detected-anomaly records is named ``detection-results`` and maps ONLY to the
    ``anomalies`` table (not the raw time-series it must never claim to purge).
    """
    service = OperationsResetService(_FakeResetRepo())
    scopes = service.scopes()
    assert "timeseries" not in scopes
    assert "detection-results" in scopes
    assert service.tables_for("detection-results") == ("anomalies",)
    assert service.required_phrase("detection-results") == "RESET DETECTION-RESULTS"


@pytest.mark.unit
def test_reset_detection_results_dry_run_targets_only_anomalies(
    client: ClientFixture,
) -> None:
    """A confirmed dry-run detection-results reset audits and targets only anomalies."""
    response, jobs, _backup, repo = client
    result = response.post(
        "/api/v1/operations/reset",
        json={
            "scope": "detection-results",
            "reason": "audit regression",
            "confirmation": "RESET DETECTION-RESULTS",
        },
        headers={"X-API-Key": "test-secret"},
    )
    assert result.status_code == 200
    body = result.json()
    assert body["executed"] is False
    assert body["tables"] == ["anomalies"]
    assert repo.deleted == []
    assert jobs.append_audit.await_count == 1


@pytest.mark.unit
def test_backup_catalog_assigns_stable_identity_and_scope_metadata(
    tmp_path: Path,
) -> None:
    """Created artifacts remain independently selectable from catalog metadata."""
    source = tmp_path / "source"
    source.mkdir()
    (source / "data.txt").write_text("payload", encoding="utf-8")
    service = OperationsBackupService(tmp_path / "backups")
    service._allowed_scopes["models"] = (source,)
    manifest = service.create_manifest(["models"])
    item = service.catalog()[0]
    assert item["artifact_id"] == manifest["artifact_id"]
    assert item["artifact_name"] == manifest["artifact_name"]
    assert item["scope"] == ["models"]
    selected = service.select(manifest["artifact_id"])
    assert selected is not None
    assert selected["artifact_id"] == manifest["artifact_id"]


@pytest.mark.unit
def test_restore_precheck_uses_selected_catalog_artifact(tmp_path: Path) -> None:
    """Restore compatibility is evaluated against selected artifact metadata."""
    service = OperationsBackupService(tmp_path)
    with patch.object(
        service,
        "select",
        return_value={"verified": True, "stale": False, "scope": ["config"]},
    ) as selected:
        result = service.restore_precheck(["postgresql"], "RESTORE DATABASE", "artifact-1")
    assert result["compatible"] is False
    selected.assert_called_once_with("artifact-1")


@pytest.mark.unit
def test_factory_reset_preview_requires_fresh_full_backup(
    client: ClientFixture,
) -> None:
    """Factory preview rejects verified partial backups without mutation."""
    response, _jobs, backup, repo = client
    with patch.object(
        backup,
        "latest",
        return_value={"verified": True, "stale": False, "scope": ["config"]},
    ):
        result = response.post(
            "/api/v1/operations/reset/postgresql/preview",
            json={"scope": "factory"},
            headers={"X-API-Key": "test-secret"},
        )
    assert result.status_code == 409
    assert repo.deleted == []


@pytest.mark.unit
def test_influx_reset_preview_is_separate_and_non_destructive(
    client: ClientFixture,
) -> None:
    """Influx preview names time-series targets and never executes reset."""
    response, *_ = client
    result = response.post(
        "/api/v1/operations/reset/influx/preview",
        json={"scope": "timeseries"},
        headers={"X-API-Key": "test-secret"},
    )
    assert result.status_code == 200
    assert result.json()["target"] == "influxdb"
    assert result.json()["execution_supported"] is False
    assert result.json()["executed"] is False


@pytest.mark.unit
def test_version_reports_complete_unknown_component_inventory(
    monkeypatch: MonkeyPatch,
) -> None:
    """Version response retains unknown build facts instead of inventing them."""
    monkeypatch.delenv("OTALON_BUILD_REF", raising=False)
    body = OperationsMaintenanceService(_settings()).version()
    names = {item["name"] for item in body["components"]}
    assert {"otalon-api", "otalon-ai", "pcap_recorder"} <= names
    assert body["suite"]["build_ref"] == "unknown"
    assert all(item["build_ref"] == "unknown" for item in body["components"])
