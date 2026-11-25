"""Conditional WSL key mounts and API-owned file selection without Docker access."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
import yaml

from otalon_api.services.compose_runner import ComposeRunner
from otalon_api.services.env_compose_service import (
    AFFECTED_SERVICES_BY_KEY,
    AI_ENV_KEYS,
    ALLOWED_ENV_KEYS,
    BOOT_ENV_KEYS,
    DISPLAY_BOOT_ENV_KEYS,
    READONLY_BOOT_ENV_KEYS,
    TRAINING_ENV_KEYS,
    _validate_updates,
)
from otalon_api.settings import Settings

_ROOT = Path(__file__).resolve().parents[3]
_WSL = "docker-compose.wsl.yml"
_LIVE = "docker-compose.wsl-live.yml"


class _TaggedSequence(list[Any]):
    """Retain Compose sequence tags without implementing Compose interpolation."""

    def __init__(self, values: list[Any], tag: str) -> None:
        super().__init__(values)
        self.tag = tag


def _load_compose(filename: str) -> dict[str, Any]:
    """Inspect only a named tracked template using isolated safe tag constructors."""

    class ComposeLoader(yaml.SafeLoader):
        """Local loader whose constructors cannot affect other tests."""

    def construct_sequence(loader: ComposeLoader, node: yaml.SequenceNode) -> _TaggedSequence:
        return _TaggedSequence(loader.construct_sequence(node, deep=True), node.tag)

    def construct_reset(loader: ComposeLoader, node: yaml.Node) -> Any:
        if isinstance(node, yaml.SequenceNode):
            return construct_sequence(loader, node)
        if isinstance(node, yaml.ScalarNode) and node.value == "null":
            return loader.construct_yaml_null(node)
        raise ValueError("Unsupported reset fixture node")

    ComposeLoader.add_constructor("!override", construct_sequence)
    ComposeLoader.add_constructor("!reset", construct_reset)
    with (_ROOT / filename).open(encoding="utf-8") as template:
        return yaml.load(template, Loader=ComposeLoader)


@pytest.fixture(autouse=True)
def forbid_docker(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """Fail if a new test tries to initialize a real Docker client."""
    forbidden = MagicMock(side_effect=AssertionError("Docker access is forbidden in unit tests"))
    monkeypatch.setattr("otalon_api.services.compose_runner.docker.from_env", forbidden)
    return forbidden


def _settings(tmp_path: Path, overlay: str = "", capture: str = "", profile: str = "") -> SimpleNamespace:
    """Supply harmless paths only; no environment or Compose file is loaded."""
    return SimpleNamespace(
        compose_image="docker:24.0.9-cli",
        compose_file=str(tmp_path / "docker-compose.yml"),
        env_compose_path=str(tmp_path / "sample.env"),
        compose_overlay=overlay,
        compose_capture_overlay=capture,
        compose_profiles=profile,
    )


def test_wsl_none_retains_logs_and_custody_without_key_bind() -> None:
    """WSL replaces native mounts with only existing custody and persistent logs."""
    wsl = _load_compose(_WSL)
    capture = wsl["services"]["otalon-capture"]
    assert capture["volumes"].tag == "!override"
    assert capture["volumes"] == ["continuous-capture-data:/app/continuous", "./shared/logs:/app/logs"]
    assert capture["environment"] == {
        "INFLUX_URL": "http://influxdb3:8181",
        "CONTINUOUS_ROOT": "/app/continuous",
        "CONTINUOUS_SOURCE_KEY_FILE": "/run/secrets/continuous-source-key",
    }
    assert capture["network_mode"] is None
    assert capture["cap_add"].tag == "!reset"
    assert capture["cap_add"] == []
    assert capture["cap_drop"] == ["ALL"]
    assert capture["security_opt"] == ["no-new-privileges:true"]
    assert wsl["volumes"] == {"continuous-capture-data": None, "continuous-recovery-data": None}


def test_wsl_live_overlay_is_exactly_one_noncreating_readonly_key_bind() -> None:
    """LIVE adds one existing key, with no credential directory or other fields."""
    assert _load_compose(_LIVE) == {
        "services": {
            "otalon-capture": {
                "volumes": [
                    {
                        "type": "bind",
                        "source": "./shared/continuous-source.key",
                        "target": "/run/secrets/continuous-source-key",
                        "read_only": True,
                        "bind": {"create_host_path": False},
                    }
                ]
            }
        }
    }


def test_base_capture_volumes_and_explicit_wsl_api_selection() -> None:
    """Native mounts stay unchanged and WSL passes the installer-selected value."""
    base = _load_compose("docker-compose.yml")
    assert base["services"]["otalon-capture"]["volumes"] == [
        "/etc/localtime:/etc/localtime:ro",
        "/etc/timezone:/etc/timezone:ro",
        "./shared/logs:/app/logs",
        "./shared/pcap/buffer:/app/pcap/buffer",
        "./shared/pcap/archive:/app/pcap/archive",
    ]
    assert "COMPOSE_CAPTURE_OVERLAY" not in base["services"]["otalon-api"]["environment"]
    api = _load_compose(_WSL)["services"]["otalon-api"]
    assert api["environment"]["COMPOSE_OVERLAY"] == _WSL
    assert api["environment"]["COMPOSE_CAPTURE_OVERLAY"] == "${COMPOSE_CAPTURE_OVERLAY:-}"
    assert api["environment"]["COMPOSE_PROFILES"] == "all"
    assert api["volumes"].tag == "!override"
    assert "continuous-capture-data:/app/continuous:ro" in api["volumes"]


def test_settings_capture_overlay_defaults_empty_without_env_file(monkeypatch: pytest.MonkeyPatch) -> None:
    """The additive internal field defaults empty without reading repository env."""
    monkeypatch.delenv("COMPOSE_CAPTURE_OVERLAY", raising=False)
    field = Settings.model_fields.get("compose_capture_overlay")
    assert field is not None
    assert field.annotation is str
    assert field.default == ""
    assert Settings(_env_file=None).compose_capture_overlay == ""


@pytest.mark.parametrize("selected", ["", _LIVE], ids=["none", "live"])
def test_settings_maps_ephemeral_capture_overlay_env(selected: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Existing BaseSettings mapping consumes the explicit harmless variable."""
    monkeypatch.setenv("COMPOSE_CAPTURE_OVERLAY", selected)
    assert Settings(_env_file=None).compose_capture_overlay == selected


def test_capture_overlay_is_not_a_public_config_key() -> None:
    """Overlay selection grants no new editable, training or displayed authority."""
    for registry in (
        ALLOWED_ENV_KEYS,
        BOOT_ENV_KEYS,
        READONLY_BOOT_ENV_KEYS,
        DISPLAY_BOOT_ENV_KEYS,
        AI_ENV_KEYS,
        TRAINING_ENV_KEYS,
        AFFECTED_SERVICES_BY_KEY,
    ):
        assert "COMPOSE_CAPTURE_OVERLAY" not in registry
    assert _validate_updates({"COMPOSE_CAPTURE_OVERLAY": _LIVE}) == ["Key 'COMPOSE_CAPTURE_OVERLAY' is not allowed."]


@pytest.mark.parametrize(
    "overlay,capture", [("", ""), (_WSL, ""), (_WSL, _LIVE)], ids=["native", "wsl-none", "wsl-live"]
)
@pytest.mark.parametrize("profile", ["", "app", "all"], ids=["no-profile", "app", "all"])
@pytest.mark.parametrize("with_env", [False, True], ids=["no-env-file", "sample-env-file"])
def test_selected_prefix_exact_order_and_count(
    tmp_path: Path, overlay: str, capture: str, profile: str, with_env: bool, forbid_docker: MagicMock
) -> None:
    """Selected files precede unchanged profile/env flags with no extra file."""
    settings = _settings(tmp_path, overlay, capture, profile)
    runner = ComposeRunner(settings)
    env_file = settings.env_compose_path if with_env else ""
    expected = ["docker", "compose", "--project-directory", str(tmp_path), "-f", settings.compose_file]
    if overlay:
        expected += ["-f", str(tmp_path / _WSL)]
    if capture:
        expected += ["-f", str(tmp_path / _LIVE)]
    if profile:
        expected += ["--profile", profile]
    if with_env:
        expected += ["--env-file", env_file]
    prefix = runner._compose_prefix(str(tmp_path), env_file)
    assert prefix == expected
    assert prefix.count("-f") == 1 + bool(overlay) + bool(capture)
    assert runner._client is None
    forbid_docker.assert_not_called()


@pytest.mark.parametrize("overlay", ["", _WSL], ids=["native", "wsl"])
@pytest.mark.parametrize(
    "capture",
    [
        "other.yml",
        "/docker-compose.wsl-live.yml",
        "../docker-compose.wsl-live.yml",
        "./docker-compose.wsl-live.yml",
        "docker-compose.WSL-live.yml",
        " docker-compose.wsl-live.yml",
        "docker-compose.wsl-live.yml ",
        "\t",
        "docker-compose.wsl-live.yml\n",
        "docker-compose.wsl-live.yml:other.yml",
    ],
    ids=[
        "arbitrary",
        "absolute",
        "traversal",
        "dot-relative",
        "wrong-case",
        "leading-space",
        "trailing-space",
        "blank",
        "newline",
        "multi-file",
    ],
)
def test_capture_overlay_rejected_before_docker(
    tmp_path: Path, overlay: str, capture: str, forbid_docker: MagicMock
) -> None:
    """Noncanonical paths never receive normalization or Docker access."""
    with pytest.raises(ValueError, match="Compose capture overlay is not allowed"):
        ComposeRunner(_settings(tmp_path, overlay, capture))
    forbid_docker.assert_not_called()


def test_live_capture_overlay_requires_exact_wsl_backend(tmp_path: Path, forbid_docker: MagicMock) -> None:
    """The exact key mount overlay cannot select native capture or another backend."""
    with pytest.raises(ValueError, match="Compose capture overlay requires docker-compose.wsl.yml"):
        ComposeRunner(_settings(tmp_path, capture=_LIVE))
    forbid_docker.assert_not_called()


@pytest.mark.parametrize(
    "overlay",
    ["other.yml", "./docker-compose.wsl.yml", "docker-compose.WSL.yml", "docker-compose.wsl.yml "],
    ids=["arbitrary", "dot-relative", "wrong-case", "trailing-space"],
)
def test_live_capture_overlay_cannot_bypass_backend_allowlist(
    tmp_path: Path, overlay: str, forbid_docker: MagicMock
) -> None:
    """The exact LIVE mount does not relax the existing backend allowlist."""
    with pytest.raises(ValueError, match="Compose overlay is not allowed"):
        ComposeRunner(_settings(tmp_path, overlay, _LIVE))
    forbid_docker.assert_not_called()


def test_older_settings_namespace_without_capture_selection(tmp_path: Path, forbid_docker: MagicMock) -> None:
    """Existing namespaces without the additive field retain their selected files."""
    settings = _settings(tmp_path, overlay=_WSL)
    del settings.compose_capture_overlay
    runner = ComposeRunner(settings)
    assert runner._compose_prefix(str(tmp_path), "") == [
        "docker",
        "compose",
        "--project-directory",
        str(tmp_path),
        "-f",
        settings.compose_file,
        "-f",
        str(tmp_path / _WSL),
    ]
    forbid_docker.assert_not_called()


@pytest.mark.parametrize("capture", ["", _LIVE], ids=["none", "live"])
@pytest.mark.parametrize(
    "action,args",
    [
        ("up", ["up", "-d", "otalon-capture"]),
        ("stop", ["stop", "otalon-capture"]),
        ("restart", ["restart", "otalon-capture"]),
        ("recreate", ["up", "-d", "--force-recreate", "--no-deps", "otalon-capture"]),
    ],
    ids=["up", "stop", "restart", "recreate"],
)
def test_mocked_container_create_uses_same_selected_prefix(
    tmp_path: Path,
    capture: str,
    action: str,
    args: list[str],
    monkeypatch: pytest.MonkeyPatch,
    forbid_docker: MagicMock,
) -> None:
    """All actions, including recreate, pass the chosen set through the real builder."""
    settings = _settings(tmp_path, _WSL, capture, "all")
    runner = ComposeRunner(settings)
    client = MagicMock()
    container = client.containers.create.return_value
    container.wait.return_value = {"StatusCode": 0}
    container.logs.return_value = b"mocked compose output"
    runner._client = client
    monkeypatch.setattr(runner, "is_available", lambda: (True, "mocked availability"))
    result = runner.run_action(action, "otalon-capture")
    expected = [
        "docker",
        "compose",
        "--project-directory",
        str(tmp_path),
        "-f",
        settings.compose_file,
        "-f",
        str(tmp_path / _WSL),
    ]
    if capture:
        expected += ["-f", str(tmp_path / _LIVE)]
    expected += ["--profile", "all", "--env-file", settings.env_compose_path] + args
    client.containers.create.assert_called_once()
    assert client.containers.create.call_args.kwargs["command"] == expected
    assert client.containers.create.call_args.kwargs["working_dir"] == str(tmp_path)
    container.start.assert_called_once_with()
    container.wait.assert_called_once_with(timeout=180)
    container.remove.assert_called_once_with(force=True)
    assert result == {
        "service": "otalon-capture",
        "action": action,
        "exit_code": 0,
        "output": "mocked compose output",
        "success": True,
    }
    forbid_docker.assert_not_called()
