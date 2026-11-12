"""Volume preparation is empty-only, nonrecursive and preserves existing data."""

import importlib.util
import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]


def tool():
    p = ROOT / "scripts/install/init_continuous_volume.py"
    assert p.is_file(), "continuous volume initializer missing"
    spec = importlib.util.spec_from_file_location("volume_init", p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_populated_volume_with_wrong_owner_is_not_repaired(tmp_path):
    m = tool()
    (tmp_path / "preserve").write_bytes(b"unchanged")
    before = tmp_path.stat()
    with pytest.raises(ValueError, match="metadata"):
        m.prepare(tmp_path, before.st_uid + 1)
    after = tmp_path.stat()
    assert (before.st_uid, before.st_gid, before.st_mode) == (after.st_uid, after.st_gid, after.st_mode)
    assert (tmp_path / "preserve").read_bytes() == b"unchanged"


def test_empty_volume_is_initialized_and_matching_populated_volume_preserved(tmp_path):
    m = tool()
    m.prepare(tmp_path, os.geteuid())
    assert tmp_path.stat().st_mode & 0o777 == 0o700
    child = tmp_path / "owned"
    child.write_bytes(b"preserve")
    before = tmp_path.stat()
    m.prepare(tmp_path, os.geteuid())
    assert tmp_path.stat().st_ino == before.st_ino
    assert child.read_bytes() == b"preserve"


def test_symlink_volume_is_rejected(tmp_path):
    m = tool()
    link = tmp_path / "alias"
    link.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        m.prepare(link, os.geteuid())
