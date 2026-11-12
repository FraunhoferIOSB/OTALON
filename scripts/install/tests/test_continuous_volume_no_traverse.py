"""A matching owner need not grant the init container read access to evidence."""

import importlib.util
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def test_matching_volume_metadata_does_not_traverse_children(tmp_path, monkeypatch):
    p = ROOT / "scripts/install/init_continuous_volume.py"
    spec = importlib.util.spec_from_file_location("init_no_traverse", p)
    assert spec is not None and spec.loader is not None
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    os.chmod(tmp_path, 0o700)

    def forbidden(_):
        raise AssertionError("matching evidence root must not be traversed")

    monkeypatch.setattr(Path, "iterdir", forbidden)
    m.prepare(tmp_path, os.geteuid())
