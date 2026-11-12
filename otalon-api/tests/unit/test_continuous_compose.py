"""API recreation keeps the selected Desktop file set, not just the base file."""

from types import SimpleNamespace

import pytest

from otalon_api.services.compose_runner import ComposeRunner


def test_overlay_is_fixed_owned_file_and_recreate_passes_both_files(tmp_path):
    settings = SimpleNamespace(
        compose_image="docker:27-cli",
        compose_file=str(tmp_path / "docker-compose.yml"),
        env_compose_path=str(tmp_path / ".env.compose"),
        compose_overlay="docker-compose.wsl.yml",
        compose_profiles="all",
    )
    runner = ComposeRunner(settings)
    assert hasattr(runner, "_compose_prefix"), "selected-mode compose prefix missing"
    args = runner._compose_prefix(str(tmp_path), settings.env_compose_path)
    assert args.count("-f") == 2 and str(tmp_path / "docker-compose.wsl.yml") in args
    assert "--profile" in args and "all" in args
    assert runner._build_compose_args("recreate", "otalon-clas")[-1] == "otalon-clas"
    settings.compose_overlay = "../../escape.yml"
    with pytest.raises(ValueError):
        ComposeRunner(settings)


def test_env_registry_mask_and_metadata_preserved(tmp_path):
    from otalon_api.services.env_compose_service import EnvComposeService, _is_sensitive

    env = tmp_path / ".env.compose"
    env.write_text("TZ=Europe/Berlin\n")
    env.chmod(0o660)
    before = env.stat()
    settings = SimpleNamespace(env_compose_path=str(env))
    service = EnvComposeService(settings)
    service._write_atomic(["TZ=UTC"])
    after = env.stat()
    assert (after.st_uid, after.st_gid, after.st_mode & 0o777) == (before.st_uid, before.st_gid, 0o660)
    assert _is_sensitive("OTALON_SCAN_ALLOWED_KEYS")
