"""Tests fuer den RingbufferManager und Integration mit tcpdump."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

from pcap_recorder.index import PcapIndex
from pcap_recorder.ringbuffer import RingbufferManager
from pcap_recorder.settings import ArchiveConfig, RingbufferConfig

TESTS_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = TESTS_ROOT / ".."
CAPTURE_SAMPLE = TESTS_ROOT / "golden_data" / "PN-S7.pcap"
CONFIG_TEMPLATE = PROJECT_ROOT / "config" / "config_pcap.json"

print(CAPTURE_SAMPLE)
print(CONFIG_TEMPLATE)

# base_dir = Path(__file__).resolve().parent.parent / "golden_data"
# pcap_path = base_dir / "capture_sample.pcapng"
# CAPTURE_SAMPLE = pcap_path
# print(CAPTURE_SAMPLE)


def _build_manager(tmp_path: Path, max_size_mb: int = 1, max_files: int = 2) -> RingbufferManager:
    ring_dir = tmp_path / "buffer"
    archive_dir = tmp_path / "archive"
    index_file = tmp_path / "pcap_index.json"

    ring_cfg = RingbufferConfig(directory=str(ring_dir), max_total_size_mb=max_size_mb, max_file_count=max_files)
    archive_cfg = ArchiveConfig(directory=str(archive_dir))

    index = PcapIndex(index_file)
    manager = RingbufferManager(ring_cfg, archive_cfg, index)
    return manager


def _tcpdump_available() -> bool:
    return shutil.which("tcpdump") is not None


def _tcpreplay_available() -> bool:
    return shutil.which("tcpreplay") is not None


def _copy_config(tmp_path: Path) -> Path:
    payload = json.loads(CONFIG_TEMPLATE.read_text(encoding="utf-8"))
    payload["pcap"]["interface"] = "lo"
    payload["pcap"]["ringbuffer"]["directory"] = str(tmp_path / "buffer")
    payload["pcap"]["archive"]["directory"] = str(tmp_path / "archive")
    payload["pcap"]["chunk_duration_sec"] = 2
    payload["log"]["file"] = str(tmp_path / "pcap.log")
    custom_path = tmp_path / "config_pcap.json"
    custom_path.write_text(json.dumps(payload), encoding="utf-8")
    return custom_path


def _start_recorder(config_path: Path) -> subprocess.Popen[str]:
    env = os.environ.copy()
    env["PCAP_CONFIG_FILE"] = str(config_path)
    env.setdefault("CAPTURE_SOURCE", "lo")
    env.setdefault("PCAP_LOG_FILE", str(config_path.parent / "pcap.log"))
    command = ["python", "-m", "pcap_recorder.main"]
    return subprocess.Popen(
        command,
        cwd=PROJECT_ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


def test_scan_for_new_chunks_indexes_once(tmp_path: Path) -> None:
    manager = _build_manager(tmp_path)
    ring_dir = Path(manager._ringbuffer_config.directory)  # type: ignore[attr-defined]

    chunk_path = ring_dir / "pcap_20260213_120000.pcap"
    chunk_path.parent.mkdir(parents=True, exist_ok=True)
    chunk_path.write_bytes(b"1234")

    discovered_first = manager.scan_for_new_chunks()
    discovered_second = manager.scan_for_new_chunks()

    assert len(discovered_first) == 1
    assert discovered_first[0].filename == chunk_path.name
    assert discovered_second == []


def test_enforce_limits_drops_oldest_file(tmp_path: Path) -> None:
    manager = _build_manager(tmp_path, max_size_mb=1, max_files=1)
    ring_dir = Path(manager._ringbuffer_config.directory)  # type: ignore[attr-defined]
    ring_dir.mkdir(parents=True, exist_ok=True)

    first = ring_dir / "pcap_20260213_120000.pcap"
    second = ring_dir / "pcap_20260213_120100.pcap"
    first.write_bytes(b"0" * 1024 * 1024)
    second.write_bytes(b"0" * 1024 * 1024)

    manager.scan_for_new_chunks()
    manager.scan_for_new_chunks()

    manager.enforce_limits()

    files = list(ring_dir.glob("*.pcap"))
    assert len(files) == 1
    assert files[0].name == second.name


def test_archive_chunks_moves_files(tmp_path: Path) -> None:
    manager = _build_manager(tmp_path)
    ring_dir = Path(manager._ringbuffer_config.directory)  # type: ignore[attr-defined]
    archive_dir = Path(manager._archive_config.directory)  # type: ignore[attr-defined]
    ring_dir.mkdir(parents=True, exist_ok=True)

    file_path = ring_dir / "pcap_20260213_120000.pcap"
    file_path.write_bytes(b"abc")

    manager.scan_for_new_chunks()

    moved = manager.archive_chunks([file_path.name])

    assert file_path.name in moved
    assert (archive_dir / file_path.name).exists()
    assert not file_path.exists()


def _chunk_name(offset_min: int = 0) -> str:
    """Filename with a timestamp near now, so age checks are time-stable."""
    from datetime import datetime, timedelta, timezone

    ts = datetime.now(timezone.utc) - timedelta(minutes=offset_min)
    return f"pcap_{ts.strftime('%Y%m%d_%H%M%S')}.pcap"


def _place_in_archive(manager: RingbufferManager, path: Path, pinned: bool) -> None:
    """Put an already-written chunk into the archive and index it unpinned/pinned."""
    manager._index.add_chunk(path)  # type: ignore[attr-defined]  # noqa: SLF001
    meta = manager._index._entries[path.name]  # type: ignore[attr-defined]  # noqa: SLF001
    meta.path = path
    meta.pinned = pinned
    manager._index._persist()  # type: ignore[attr-defined]  # noqa: SLF001


def test_enforce_archive_limits_exempts_pinned(tmp_path: Path) -> None:
    """Pinned (anomaly-flagged) archive chunks are never evicted (PCAP-017)."""
    manager = _build_manager(tmp_path, max_size_mb=100, max_files=100)
    archive_dir = Path(manager._archive_config.directory)  # type: ignore[attr-defined]
    archive_dir.mkdir(parents=True, exist_ok=True)

    pinned = archive_dir / _chunk_name(offset_min=10)
    plain = archive_dir / _chunk_name(offset_min=0)
    pinned.write_bytes(b"0" * (1024 * 1024))
    plain.write_bytes(b"0" * (1024 * 1024))
    _place_in_archive(manager, pinned, pinned=True)
    _place_in_archive(manager, plain, pinned=False)

    manager.enforce_archive_limits()

    assert (archive_dir / pinned.name).exists()


def test_archive_chunks_pins_what_it_moves(tmp_path: Path) -> None:
    """PCAP-017: chunks moved by archive_chunks are pinned, so the sweep keeps them."""
    manager = _build_manager(tmp_path, max_size_mb=100, max_files=100)
    ring_dir = Path(manager._ringbuffer_config.directory)  # type: ignore[attr-defined]
    archive_dir = Path(manager._archive_config.directory)  # type: ignore[attr-defined]
    ring_dir.mkdir(parents=True, exist_ok=True)

    chunk = ring_dir / _chunk_name(offset_min=0)
    chunk.write_bytes(b"x")
    manager.scan_for_new_chunks()
    manager.archive_chunks([chunk.name])

    meta = manager._index._entries[chunk.name]  # type: ignore[attr-defined]  # noqa: SLF001
    assert meta.pinned is True
    assert meta.is_anomaly is True


def test_enforce_archive_limits_respects_age_limit(tmp_path: Path) -> None:
    """Unpinned chunks older than max_age_days are evicted; recent ones stay."""
    from datetime import datetime, timedelta, timezone

    manager = _build_manager(tmp_path, max_size_mb=100, max_files=100)
    archive_dir = Path(manager._archive_config.directory)  # type: ignore[attr-defined]
    archive_dir.mkdir(parents=True, exist_ok=True)

    old = archive_dir / _chunk_name(offset_min=0)
    recent = archive_dir / _chunk_name(offset_min=1)
    old.write_bytes(b"a")
    recent.write_bytes(b"b")
    _place_in_archive(manager, old, pinned=False)
    _place_in_archive(manager, recent, pinned=False)

    # Force the old chunk's start to 100 days ago; default max_age_days is 90.
    meta = manager._index._entries[old.name]  # type: ignore[attr-defined]  # noqa: SLF001
    meta.start_ts = datetime.now(timezone.utc) - timedelta(days=100)
    manager._index._persist()  # type: ignore[attr-defined]  # noqa: SLF001

    manager.enforce_archive_limits()

    assert not old.exists()
    assert recent.exists()


def test_enforce_limits_uses_real_file_size_not_discovery_size(tmp_path: Path) -> None:
    """PCAP-017: tcpdump keeps growing a chunk after it was indexed.

    The index must not keep the size seen at discovery (1 byte here);
    the ringbuffer limit has to count what is on disk now.
    """
    manager = _build_manager(tmp_path, max_size_mb=1, max_files=100)
    ring_dir = Path(manager._ringbuffer_config.directory)  # type: ignore[attr-defined]
    ring_dir.mkdir(parents=True, exist_ok=True)

    first = ring_dir / "pcap_20260101_000000.pcap"
    second = ring_dir / "pcap_20260101_000030.pcap"
    first.write_bytes(b"x")
    second.write_bytes(b"y")
    manager.scan_for_new_chunks()

    # Simulate tcpdump appending to the first chunk after indexing.
    with first.open("ab") as handle:
        handle.write(b"z" * (2 * 1024 * 1024))

    manager.enforce_limits()

    assert not first.exists(), "oldest chunk must be evicted once real size exceeds 1 MB"
    assert second.exists()


# Not working as Unit test, due to sudo/root permissions (better for integration test)
# @pytest.mark.integration
# def test_recorder_replay_produces_real_chunks(tmp_path: Path) -> None:
#     if not _tcpdump_available():
#         pytest.skip("tcpdump binary is not available on PATH")
#     if not _tcpreplay_available():
#         pytest.skip("tcpreplay binary is not available on PATH")
#     if not CAPTURE_SAMPLE.exists():
#         pytest.skip("Golden capture sample missing")

#     print(tmp_path)

#     config_path = _copy_config(tmp_path)
#     recorder = _start_recorder(config_path)
#     try:
#         time.sleep(2)
#         replay_command = [
#             "tcpreplay",
#             "--intf1=lo",
#             str(CAPTURE_SAMPLE),
#         ]
#         subprocess.run(replay_command, check=True)
#         time.sleep(5)

#         buffer_dir = tmp_path / "buffer"
#         chunk_files = list(buffer_dir.glob("*.pcap"))
#         assert chunk_files, "Recorder did not write any chunks"

#         index_file = buffer_dir / "pcap_index.json"
#         assert index_file.exists(), "pcap_index.json missing"
#         index_data: list[Dict[str, str]] = json.loads(index_file.read_text(encoding="utf-8"))
#         assert index_data, "pcap_index.json is empty"
#     finally:
#         recorder.terminate()
#         try:
#             recorder.wait(timeout=5)
#         except subprocess.TimeoutExpired:
#             recorder.kill()
#             recorder.wait()


def _failing_unlink_for(monkeypatch, doomed_name: str) -> None:
    """Make ``Path.unlink`` fail for one chunk filename (PCAP-014 tests)."""
    original_unlink = Path.unlink

    def selective_unlink(self: Path, missing_ok: bool = False) -> None:
        if self.name == doomed_name:
            raise PermissionError(f"simulated undeletable chunk: {doomed_name}")
        original_unlink(self, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", selective_unlink)


def test_enforce_limits_continues_after_failed_removal(tmp_path: Path, monkeypatch) -> None:
    """PCAP-014: an undeletable chunk must not abort the eviction sweep."""
    manager = _build_manager(tmp_path, max_size_mb=100, max_files=1)
    ring_dir = Path(manager._ringbuffer_config.directory)  # type: ignore[attr-defined]
    ring_dir.mkdir(parents=True, exist_ok=True)

    oldest = ring_dir / "pcap_20260213_120000.pcap"
    middle = ring_dir / "pcap_20260213_120100.pcap"
    newest = ring_dir / "pcap_20260213_120200.pcap"
    for chunk in (oldest, middle, newest):
        chunk.write_bytes(b"0")

    manager.scan_for_new_chunks()
    _failing_unlink_for(monkeypatch, oldest.name)

    manager.enforce_limits()

    # The doomed oldest chunk survives on disk and in the index, but the
    # sweep still evicted the other two instead of stopping at the error.
    assert oldest.exists()
    assert not middle.exists()
    assert not newest.exists()
    assert oldest.name in manager._index._entries  # type: ignore[attr-defined]  # noqa: SLF001
    assert middle.name not in manager._index._entries  # type: ignore[attr-defined]  # noqa: SLF001


def test_enforce_archive_limits_continues_after_failed_removal(tmp_path: Path, monkeypatch) -> None:
    """PCAP-014: an undeletable archive chunk must not block the sweep."""
    from datetime import datetime, timedelta, timezone

    manager = _build_manager(tmp_path, max_size_mb=100, max_files=100)
    archive_dir = Path(manager._archive_config.directory)  # type: ignore[attr-defined]
    archive_dir.mkdir(parents=True, exist_ok=True)

    oldest = archive_dir / _chunk_name(offset_min=0)
    newer = archive_dir / _chunk_name(offset_min=1)
    oldest.write_bytes(b"a")
    newer.write_bytes(b"b")
    _place_in_archive(manager, oldest, pinned=False)
    _place_in_archive(manager, newer, pinned=False)

    manager._index._entries[oldest.name].start_ts = (  # type: ignore[attr-defined]  # noqa: SLF001
        datetime.now(timezone.utc) - timedelta(days=100)
    )
    manager._index._entries[newer.name].start_ts = (  # type: ignore[attr-defined]  # noqa: SLF001
        datetime.now(timezone.utc) - timedelta(days=99)
    )
    manager._index._persist()  # type: ignore[attr-defined]  # noqa: SLF001

    _failing_unlink_for(monkeypatch, oldest.name)

    manager.enforce_archive_limits()

    assert oldest.exists()
    assert not newer.exists()
