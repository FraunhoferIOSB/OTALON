"""Regression tests for CAP-02 — import-worker auth and path containment.

The worker exposed ``POST /import`` and ``GET /status`` with no
authentication at all, and validated the requested capture file with
nothing but ``Path(...).is_file()``. Together that let any party able to
reach the worker feed **any readable file** — ``/etc/shadow``,
``/proc/self/environ``, a mounted host tree — through the capture pipeline
and into InfluxDB.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterator

import pytest
from fastapi.testclient import TestClient

from pcap_import.api import create_app
from pcap_import.runner import (
    DEFAULT_IMPORT_DIR,
    ImportPathError,
    resolve_capture_path,
)
from pcap_import.service import ImportService
from pcap_import.settings import PcapImportSettings

API_KEY = "test-operator-key"


class _Runner:
    """Runner double that records the jobs it was asked to execute."""

    def __init__(self) -> None:
        self.calls: list[Any] = []

    def run(self, job: Any, progress: Any, cancel_event: Any) -> Dict[str, Any]:
        self.calls.append(job)
        return {"records_processed": 0, "points_written": 0}


@pytest.fixture()
def runner() -> _Runner:
    return _Runner()


@pytest.fixture()
def client(runner: _Runner, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    monkeypatch.setenv("ADMIN_API_KEY", API_KEY)
    service = ImportService(runner=runner)
    with TestClient(create_app(service)) as test_client:
        yield test_client


def _job(file_path: str = "/import/capture.pcap") -> Dict[str, Any]:
    return {"display_id": "job-1", "file_path": file_path}


class TestImportRoutesRequireOperatorKey:
    def test_import_without_a_key_returns_401(self, client: TestClient) -> None:
        assert client.post("/import", json=_job()).status_code == 401

    def test_import_without_a_key_never_reaches_the_runner(self, client: TestClient, runner: _Runner) -> None:
        client.post("/import", json=_job())
        assert runner.calls == []

    def test_status_without_a_key_returns_401(self, client: TestClient) -> None:
        assert client.get("/status").status_code == 401

    def test_cancel_without_a_key_returns_401(self, client: TestClient) -> None:
        """PCAP-005 — cancelling aborts a running import, so it is operator-only."""
        assert client.post("/import/cancel").status_code == 401

    def test_cancel_with_a_wrong_key_returns_401(self, client: TestClient) -> None:
        response = client.post("/import/cancel", headers={"X-API-Key": "nope"})
        assert response.status_code == 401

    def test_unauthenticated_cancel_does_not_touch_a_running_import(self, client: TestClient) -> None:
        """The gate must sit in front of the service, not merely beside it."""
        client.post("/import", json=_job(), headers={"X-API-Key": API_KEY})

        assert client.post("/import/cancel").status_code == 401
        status = client.get("/status", headers={"X-API-Key": API_KEY}).json()
        assert status["state"] != "cancelled"

    def test_cancel_with_the_operator_key_reaches_the_handler(self, client: TestClient) -> None:
        """Authenticated cancel passes the gate; idle then answers 409, not 401."""
        response = client.post("/import/cancel", headers={"X-API-Key": API_KEY})
        assert response.status_code == 409
        assert response.json()["detail"]["message"] == "No import is currently running."

    def test_missing_key_configuration_makes_cancel_503_not_open(
        self, runner: _Runner, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("ADMIN_API_KEY", raising=False)
        monkeypatch.delenv("OTALON_API_ALLOWED_KEYS", raising=False)
        with TestClient(create_app(ImportService(runner=runner))) as unconfigured:
            assert unconfigured.post("/import/cancel").status_code == 503

    def test_wrong_key_returns_401(self, client: TestClient) -> None:
        response = client.post("/import", json=_job(), headers={"X-API-Key": "nope"})
        assert response.status_code == 401

    def test_operator_key_is_accepted(self, client: TestClient) -> None:
        response = client.post("/import", json=_job(), headers={"X-API-Key": API_KEY})
        assert response.status_code == 202

    def test_status_with_the_operator_key_is_accepted(self, client: TestClient) -> None:
        assert client.get("/status", headers={"X-API-Key": API_KEY}).status_code == 200

    def test_health_stays_open_for_container_probes(self, client: TestClient) -> None:
        """``/health`` is the Compose health check and must not require a key."""
        assert client.get("/health").status_code == 200

    def test_missing_key_configuration_is_503_not_open(self, runner: _Runner, monkeypatch: pytest.MonkeyPatch) -> None:
        """With no key configured the worker must fail closed."""
        monkeypatch.delenv("ADMIN_API_KEY", raising=False)
        monkeypatch.delenv("OTALON_API_ALLOWED_KEYS", raising=False)
        with TestClient(create_app(ImportService(runner=runner))) as unconfigured:
            assert unconfigured.post("/import", json=_job()).status_code == 503
        assert runner.calls == []


class TestCapturePathContainment:
    @pytest.fixture()
    def import_dir(self, tmp_path: Path) -> Path:
        directory = tmp_path / "import"
        directory.mkdir()
        return directory

    def test_a_file_inside_the_volume_resolves(self, import_dir: Path) -> None:
        capture = import_dir / "capture.pcap"
        capture.write_bytes(b"\xd4\xc3\xb2\xa1")

        assert resolve_capture_path(str(capture), str(import_dir)) == capture.resolve()

    def test_a_nested_file_resolves(self, import_dir: Path) -> None:
        nested = import_dir / "sub" / "capture.pcap"
        nested.parent.mkdir()
        nested.write_bytes(b"\xd4\xc3\xb2\xa1")

        assert resolve_capture_path(str(nested), str(import_dir)) == nested.resolve()

    def test_an_absolute_outside_path_is_refused(self, import_dir: Path, tmp_path: Path) -> None:
        outsider = tmp_path / "secret.pcap"
        outsider.write_bytes(b"x")

        with pytest.raises(ImportPathError):
            resolve_capture_path(str(outsider), str(import_dir))

    def test_a_dotdot_traversal_is_refused(self, import_dir: Path, tmp_path: Path) -> None:
        outsider = tmp_path / "secret.pcap"
        outsider.write_bytes(b"x")
        traversal = str(import_dir / ".." / "secret.pcap")

        with pytest.raises(ImportPathError):
            resolve_capture_path(traversal, str(import_dir))

    @pytest.mark.parametrize("target", ["/etc/passwd", "/etc/shadow", "/proc/self/environ"])
    def test_sensitive_system_files_are_refused(self, import_dir: Path, target: str) -> None:
        with pytest.raises(ImportPathError):
            resolve_capture_path(target, str(import_dir))

    def test_a_symlink_escaping_the_volume_is_refused(self, import_dir: Path, tmp_path: Path) -> None:
        """resolve() follows the link, so the real target is what is checked."""
        outsider = tmp_path / "secret.pcap"
        outsider.write_bytes(b"x")
        link = import_dir / "innocent.pcap"
        link.symlink_to(outsider)

        with pytest.raises(ImportPathError):
            resolve_capture_path(str(link), str(import_dir))

    def test_the_import_dir_itself_is_refused(self, import_dir: Path) -> None:
        with pytest.raises(ImportPathError):
            resolve_capture_path(str(import_dir), str(import_dir))

    def test_a_missing_file_inside_the_volume_is_file_not_found(self, import_dir: Path) -> None:
        """Containment passes, existence does not — distinct failure modes."""
        with pytest.raises(FileNotFoundError):
            resolve_capture_path(str(import_dir / "absent.pcap"), str(import_dir))

    def test_the_import_dir_comes_from_the_settings_model(
        self, import_dir: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """PCAP-007: ``$PCAP_IMPORT_DIR`` now arrives via the typed settings."""
        capture = import_dir / "capture.pcap"
        capture.write_bytes(b"x")
        monkeypatch.setenv("PCAP_IMPORT_DIR", str(import_dir))
        config = tmp_path / "config_import.json"
        config.write_text(json.dumps({"import_dir": "$PCAP_IMPORT_DIR"}), encoding="utf-8")

        settings = PcapImportSettings.from_json(config)

        assert resolve_capture_path(str(capture), settings.import_dir) == capture.resolve()

    def test_an_unset_import_dir_keeps_the_compose_default(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """No placeholder in the config file leaves the field default in force."""
        monkeypatch.delenv("PCAP_IMPORT_DIR", raising=False)
        config = tmp_path / "config_import.json"
        config.write_text("{}", encoding="utf-8")

        assert PcapImportSettings.from_json(config).import_dir == DEFAULT_IMPORT_DIR

    def test_a_missing_import_dir_variable_raises(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """otalon-capture's declared policy is RAISE, not a silent fallback."""
        monkeypatch.delenv("PCAP_IMPORT_DIR", raising=False)
        config = tmp_path / "config_import.json"
        config.write_text(json.dumps({"import_dir": "$PCAP_IMPORT_DIR"}), encoding="utf-8")

        with pytest.raises(RuntimeError, match="PCAP_IMPORT_DIR"):
            PcapImportSettings.from_json(config)

    def test_the_default_matches_the_compose_mount(self) -> None:
        assert DEFAULT_IMPORT_DIR == "/import"

    def test_the_shipped_config_carries_the_placeholder(self) -> None:
        """The migrated variable must actually be wired in the tracked config."""
        config = Path(__file__).resolve().parents[2] / "config" / "config_import.json"
        assert json.loads(config.read_text(encoding="utf-8"))["import_dir"] == "$PCAP_IMPORT_DIR"


class TestRunnerEnforcesContainment:
    """The check must sit on the real execution path, not just in a helper.

    Asserting only on ``resolve_capture_path`` would still pass if the
    runner stopped calling it, so these drive ``PipelineImportRunner.run``.
    """

    def _runner(self, import_dir: Path) -> Any:
        from pcap_import.runner import PipelineImportRunner

        config = Path(__file__).resolve().parents[2] / "config" / "config_pcap.json"
        return PipelineImportRunner(adapter_config_file=str(config), import_dir=str(import_dir))

    def test_run_refuses_a_file_outside_the_volume(self, tmp_path: Path) -> None:
        import threading

        from pcap_import.models import ImportRequest

        import_dir = tmp_path / "import"
        import_dir.mkdir()
        outsider = tmp_path / "secret.pcap"
        outsider.write_bytes(b"\xd4\xc3\xb2\xa1")

        job = ImportRequest(display_id="job-1", file_path=str(outsider))

        with pytest.raises(ImportPathError):
            self._runner(import_dir).run(job, lambda _p, _e: None, threading.Event())

    def test_run_refuses_a_traversal_path(self, tmp_path: Path) -> None:
        import threading

        from pcap_import.models import ImportRequest

        import_dir = tmp_path / "import"
        import_dir.mkdir()
        outsider = tmp_path / "secret.pcap"
        outsider.write_bytes(b"\xd4\xc3\xb2\xa1")

        # SUITE-044/V3 added a declarative ``..`` rejection to the model, so a
        # traversal request no longer survives construction. The runner-side
        # containment is the real boundary and must keep working on its own,
        # which is what this test covers — hence ``model_construct``, which
        # deliberately skips field validation to reach the runner unfiltered.
        job = ImportRequest.model_construct(
            display_id="job-1",
            file_path=str(import_dir / ".." / "secret.pcap"),
        )

        with pytest.raises(ImportPathError):
            self._runner(import_dir).run(job, lambda _p, _e: None, threading.Event())
