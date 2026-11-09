"""PCAP-007 — raw ``os.environ`` access migrated onto the Settings model.

Two things are pinned here.

**The auth pair is modelled once.** ``OTALON_API_ALLOWED_KEYS`` and
``ADMIN_API_KEY`` used to be read *and re-parsed* inline in both
``pcap_recorder/api.py`` and ``pcap_import/api.py``. The two copies had
already drifted in two security-relevant ways:

* the recorder compared the credential as **bytes** via ``_encode_api_key``
  (audit V4), the worker compared raw ``str`` — so a header byte above
  0x7F crashed the worker's dependency with a ``TypeError`` and turned a
  failed authentication into an unhandled 500 instead of a 401;
* both accepted an ``<name>:operator:`` entry with an **empty** key, which
  made the empty string a valid credential — a request with no
  ``X-API-Key`` header at all then authenticated successfully.

Both are resolved in the safer direction by
``capture_settings_base.OperatorAuthSettings``, which both services call.

**``PCAP_IMPORT_DIR`` is a typed field.** The path-containment boundary is
no longer re-read from the process environment deep inside
``runner.resolve_capture_path``; it travels from ``config_import.json``
through ``PcapImportSettings.import_dir``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterator, List

import pytest
from fastapi.testclient import TestClient

from capture_settings_base import OperatorAuthSettings
from pcap_import.api import create_app as create_import_app
from pcap_import.service import ImportService
from pcap_import.settings import DEFAULT_IMPORT_DIR, PcapImportSettings
from pcap_recorder.api import PcapService
from pcap_recorder.api import create_app as create_recorder_app

API_KEY = "test-operator-key"

AUTH_ENV_VARS = ("ADMIN_API_KEY", "OTALON_API_ALLOWED_KEYS")


@pytest.fixture(autouse=True)
def clean_auth_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Start every test from an unconfigured auth environment.

    The host may legitimately export ``ADMIN_API_KEY``; without this the
    fail-closed assertions below would silently pass for the wrong reason.
    """

    for name in AUTH_ENV_VARS:
        monkeypatch.delenv(name, raising=False)


class _Index:
    """Recorder index double; only the read paths are exercised here."""

    def find_by_timerange(self, start: Any, end: Any, include_non_archive: bool = True) -> List[Any]:
        return []

    def mark_anomaly(self, chunk_ids: Any, labels: Any = None) -> List[Any]:
        return []

    def list_all(self) -> List[Any]:
        return []


class _Ringbuffer:
    def archive_chunks(self, chunk_ids: Any) -> Dict[str, Any]:
        return {}


class _Runner:
    """Import runner double recording whether a job reached execution."""

    def __init__(self) -> None:
        self.calls: List[Any] = []

    def run(self, job: Any, progress: Any, cancel_event: Any) -> Dict[str, Any]:
        self.calls.append(job)
        return {"records_processed": 0, "points_written": 0}


@pytest.fixture()
def import_runner() -> _Runner:
    return _Runner()


@pytest.fixture()
def import_client(import_runner: _Runner) -> Iterator[TestClient]:
    with TestClient(create_import_app(ImportService(runner=import_runner))) as client:
        yield client


@pytest.fixture()
def recorder_client() -> Iterator[TestClient]:
    service = PcapService(index=_Index(), ringbuffer=_Ringbuffer())
    with TestClient(create_recorder_app(service)) as client:
        yield client


def _flag_payload() -> Dict[str, str]:
    return {"start_ts": "2026-03-06T21:08:00", "end_ts": "2026-03-06T21:09:00"}


def _job() -> Dict[str, Any]:
    return {"display_id": "job-1", "file_path": "/import/capture.pcap"}


class TestTheAuthPairResolvesFromOneSource:
    """Both API modules must see the identical credential set."""

    def test_the_admin_key_is_accepted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ADMIN_API_KEY", API_KEY)

        assert OperatorAuthSettings.from_env().matches(API_KEY)

    def test_an_operator_entry_of_the_allowed_list_is_accepted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OTALON_API_ALLOWED_KEYS", f"alice:operator:{API_KEY}")

        assert OperatorAuthSettings.from_env().matches(API_KEY)

    def test_a_non_operator_role_is_not_accepted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Migration must not widen who is authorized."""
        monkeypatch.setenv("OTALON_API_ALLOWED_KEYS", f"bob:viewer:{API_KEY}")

        assert not OperatorAuthSettings.from_env().matches(API_KEY)

    def test_both_sources_are_merged(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ADMIN_API_KEY", "admin-key")
        monkeypatch.setenv("OTALON_API_ALLOWED_KEYS", "alice:operator:alice-key")
        auth = OperatorAuthSettings.from_env()

        assert auth.matches("admin-key")
        assert auth.matches("alice-key")

    def test_both_api_modules_accept_the_same_key(
        self, monkeypatch: pytest.MonkeyPatch, recorder_client: TestClient, import_client: TestClient
    ) -> None:
        monkeypatch.setenv("OTALON_API_ALLOWED_KEYS", f"alice:operator:{API_KEY}")
        headers = {"X-API-Key": API_KEY}

        assert recorder_client.post("/anomalies/flag", json=_flag_payload(), headers=headers).status_code == 200
        assert import_client.post("/import", json=_job(), headers=headers).status_code == 202

    def test_both_api_modules_reject_the_same_wrong_key(
        self, monkeypatch: pytest.MonkeyPatch, recorder_client: TestClient, import_client: TestClient
    ) -> None:
        monkeypatch.setenv("ADMIN_API_KEY", API_KEY)
        headers = {"X-API-Key": "not-the-key"}

        assert recorder_client.post("/anomalies/flag", json=_flag_payload(), headers=headers).status_code == 401
        assert import_client.post("/import", json=_job(), headers=headers).status_code == 401

    def test_a_key_configured_only_for_the_suite_reaches_the_worker(
        self, monkeypatch: pytest.MonkeyPatch, import_client: TestClient
    ) -> None:
        """The worker previously parsed the list itself; it now shares one parser."""
        monkeypatch.setenv("OTALON_API_ALLOWED_KEYS", f"ops:operator:{API_KEY}")

        assert import_client.get("/status", headers={"X-API-Key": API_KEY}).status_code == 200


class TestNoCredentialDefaultAndNoLeak:
    """A credential must never have a default and never be rendered."""

    def test_an_unconfigured_environment_yields_no_keys(self) -> None:
        assert OperatorAuthSettings.from_env().operator_keys == ()

    def test_an_unconfigured_environment_is_not_configured(self) -> None:
        assert not OperatorAuthSettings.from_env().is_configured

    def test_the_key_value_is_not_rendered_in_the_repr(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ADMIN_API_KEY", API_KEY)

        assert API_KEY not in repr(OperatorAuthSettings.from_env())

    def test_the_key_value_is_not_rendered_in_a_model_dump(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ADMIN_API_KEY", API_KEY)

        assert API_KEY not in str(OperatorAuthSettings.from_env().model_dump())


class TestAnUnsetOrEmptyKeyNeverOpensTheEndpoint:
    """Fail closed — an absent credential is a 503, never an admission."""

    def test_the_recorder_answers_503_when_nothing_is_configured(self, recorder_client: TestClient) -> None:
        assert recorder_client.post("/anomalies/flag", json=_flag_payload()).status_code == 503

    def test_the_worker_answers_503_when_nothing_is_configured(
        self, import_client: TestClient, import_runner: _Runner
    ) -> None:
        assert import_client.post("/import", json=_job()).status_code == 503
        assert import_runner.calls == []

    def test_an_empty_admin_key_configures_nothing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ADMIN_API_KEY", "")

        assert not OperatorAuthSettings.from_env().is_configured

    def test_an_empty_admin_key_does_not_admit_an_empty_header(
        self, monkeypatch: pytest.MonkeyPatch, import_client: TestClient, recorder_client: TestClient
    ) -> None:
        monkeypatch.setenv("ADMIN_API_KEY", "")

        assert import_client.post("/import", json=_job()).status_code == 503
        assert recorder_client.post("/anomalies/flag", json=_flag_payload()).status_code == 503

    def test_an_allowed_entry_with_an_empty_key_is_discarded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The pre-PCAP-007 parsers made the empty string a valid credential.

        ``ops:operator:`` produced a three-element split whose key was ``""``.
        The set was then non-empty, so the 503 guard passed, and a request
        carrying no ``X-API-Key`` header compared ``"" == ""`` and
        authenticated. Both copies had this; the shared parser drops it.
        """
        monkeypatch.setenv("OTALON_API_ALLOWED_KEYS", "ops:operator:")

        assert not OperatorAuthSettings.from_env().is_configured

    def test_an_empty_operator_entry_does_not_open_either_endpoint(
        self, monkeypatch: pytest.MonkeyPatch, import_client: TestClient, recorder_client: TestClient
    ) -> None:
        monkeypatch.setenv("OTALON_API_ALLOWED_KEYS", "ops:operator:")

        assert import_client.post("/import", json=_job()).status_code == 503
        assert recorder_client.post("/anomalies/flag", json=_flag_payload()).status_code == 503

    def test_a_valid_entry_survives_alongside_an_empty_one(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Dropping the empty entry must not drop the real credential."""
        monkeypatch.setenv("OTALON_API_ALLOWED_KEYS", f"ops:operator:,alice:operator:{API_KEY}")
        auth = OperatorAuthSettings.from_env()

        assert auth.matches(API_KEY)
        assert not auth.matches("")


class TestTheWorkerNoLongerCrashesOnANonAsciiHeader:
    """The worker inherited the recorder's byte comparison (audit V4)."""

    def test_a_non_ascii_key_is_rejected_not_crashed(
        self, monkeypatch: pytest.MonkeyPatch, import_client: TestClient
    ) -> None:
        monkeypatch.setenv("ADMIN_API_KEY", API_KEY)

        response = import_client.post("/import", json=_job(), headers={"X-API-Key": b"\xe4"})

        assert response.status_code == 401

    def test_a_non_ascii_key_never_reaches_the_runner(
        self, monkeypatch: pytest.MonkeyPatch, import_client: TestClient, import_runner: _Runner
    ) -> None:
        monkeypatch.setenv("ADMIN_API_KEY", API_KEY)
        import_client.post("/import", json=_job(), headers={"X-API-Key": b"\xe4"})

        assert import_runner.calls == []

    def test_a_matching_non_ascii_key_authenticates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ADMIN_API_KEY", "schlüssel-ä")

        assert OperatorAuthSettings.from_env().matches("schlüssel-ä")


class TestImportDirComesFromSettings:
    """``PCAP_IMPORT_DIR`` travels through the typed model, not ``os.environ``."""

    def _config(self, tmp_path: Path, payload: Dict[str, Any]) -> Path:
        config = tmp_path / "config_import.json"
        config.write_text(json.dumps(payload), encoding="utf-8")
        return config

    def test_the_placeholder_resolves_onto_the_field(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PCAP_IMPORT_DIR", "/mnt/imports")
        config = self._config(tmp_path, {"import_dir": "$PCAP_IMPORT_DIR"})

        assert PcapImportSettings.from_json(config).import_dir == "/mnt/imports"

    def test_the_field_default_is_the_compose_mount(self, tmp_path: Path) -> None:
        assert PcapImportSettings.from_json(self._config(tmp_path, {})).import_dir == DEFAULT_IMPORT_DIR

    def test_a_missing_variable_raises_per_the_declared_policy(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """otalon-capture's policy row is RAISE (backend.md, SUITE-038)."""
        monkeypatch.delenv("PCAP_IMPORT_DIR", raising=False)
        config = self._config(tmp_path, {"import_dir": "$PCAP_IMPORT_DIR"})

        with pytest.raises(RuntimeError, match="PCAP_IMPORT_DIR"):
            PcapImportSettings.from_json(config)

    def test_an_unknown_config_key_is_ignored_not_rejected(self, tmp_path: Path) -> None:
        """The policy row is ``extra="ignore"``; the shared base forbids."""
        config = self._config(tmp_path, {"unknown_key": "x"})

        assert PcapImportSettings.from_json(config).import_dir == DEFAULT_IMPORT_DIR

    def test_the_service_wires_the_setting_into_the_runner(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A field nobody reads would be a silent regression of containment."""
        from pcap_import.main import build_service

        monkeypatch.setenv("PCAP_IMPORT_DIR", "/mnt/imports")
        settings = PcapImportSettings.from_json(self._config(tmp_path, {"import_dir": "$PCAP_IMPORT_DIR"}))

        service = build_service(settings)

        assert service._runner._import_dir == "/mnt/imports"

    def test_the_environment_no_longer_overrides_the_configured_directory(self, tmp_path: Path) -> None:
        """The old code re-read the variable; an explicit setting now wins."""
        from pcap_import.runner import resolve_capture_path

        import_dir = tmp_path / "import"
        import_dir.mkdir()
        capture = import_dir / "capture.pcap"
        capture.write_bytes(b"\xd4\xc3\xb2\xa1")

        assert resolve_capture_path(str(capture), str(import_dir)) == capture.resolve()


class TestNoRawEnvironmentAccessRemainsUnjustified:
    """Every surviving raw read must carry a justification at the call site."""

    def test_the_auth_pair_is_read_in_exactly_one_module(self) -> None:
        source_root = Path(__file__).resolve().parents[1] / "src"
        offenders = [
            path.relative_to(source_root).as_posix()
            for path in source_root.rglob("*.py")
            if "ADMIN_API_KEY" in path.read_text(encoding="utf-8")
        ]

        assert offenders == ["capture_settings_base.py"]

    def test_no_module_reads_the_import_dir_variable(self) -> None:
        source_root = Path(__file__).resolve().parents[1] / "src"
        offenders = [
            path.relative_to(source_root).as_posix()
            for path in source_root.rglob("*.py")
            if 'environ.get("PCAP_IMPORT_DIR"' in path.read_text(encoding="utf-8")
        ]

        assert offenders == []
