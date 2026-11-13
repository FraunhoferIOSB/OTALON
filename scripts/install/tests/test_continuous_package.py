"""Windows handoff contains only stdlib collector files and the source credential."""

from __future__ import annotations

import importlib.util
import json
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]


def tool():
    path = ROOT / "scripts/install/prepare_wsl.py"
    assert path.exists(), "continuous Windows setup package missing"
    spec = importlib.util.spec_from_file_location("prepare_wsl", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_export_keeps_credentials_and_supplies_runnable_collector(tmp_path):
    module = tool()
    workspace = tmp_path / "workspace"
    (workspace / "shared/tls").mkdir(parents=True)
    import shutil

    shutil.copytree(ROOT / "otalon-capture/src/windows_collector", workspace / "otalon-capture/src/windows_collector")
    shutil.copytree(ROOT / "otalon-capture/src/desktop_ingest", workspace / "otalon-capture/src/desktop_ingest")
    (workspace / "shared/tls/tls.crt").write_text("fixture-certificate")
    destination = tmp_path / "windows"
    destination.mkdir()
    assert module.prepare(workspace, destination, None) == 0
    key = workspace / "shared/continuous-source.key"
    before = key.read_bytes()
    assert len(before.strip()) == 64
    assert module.prepare(workspace, destination, None) == 0
    assert key.read_bytes() == before
    assert (destination / "source.key").read_bytes() == before
    cfg = json.loads((destination / "collector.sample.json").read_text())
    assert cfg["url"] == "https://127.0.0.1:9493"
    assert not any("ADMIN" in name or "POSTGRES" in name for name in cfg)
    with zipfile.ZipFile(destination / "collector.zip") as package:
        assert "__main__.py" in package.namelist()
        assert "windows_collector/collector.py" in package.namelist()
        assert package.read("windows_collector/collector.py") == (
            ROOT / "otalon-capture/src/windows_collector/collector.py"
        ).read_bytes()
        assert "desktop_ingest/pcap.py" in package.namelist()
        assert not any(".env" in name or name.endswith(".key") for name in package.namelist())

    cfg["interface"] = r"\Device\NPF_{01234567-0123-0123-0123-012345678901}"
    cfg["url"] = "https://collector.example.test:9493"
    configured = json.dumps(cfg, indent=2) + "\n"
    (destination / "collector.sample.json").write_text(configured)
    assert module.prepare(workspace, destination, None) == 0
    assert (destination / "collector.sample.json").read_text() == configured
    assert (destination / "source.key").read_bytes() == before


def test_export_refuses_symlink_key_without_modification(tmp_path):
    module = tool()
    workspace = tmp_path / "workspace"
    (workspace / "shared").mkdir(parents=True)
    victim = tmp_path / "victim"
    victim.write_text("preserve")
    (workspace / "shared/continuous-source.key").symlink_to(victim)
    with pytest.raises(ValueError):
        module.prepare(workspace, tmp_path / "windows", None)
    assert victim.read_text() == "preserve"
