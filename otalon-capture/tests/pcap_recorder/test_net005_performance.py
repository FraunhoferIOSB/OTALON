"""Regression tests for the NET-005 recorder-side performance fixes.

* CAP-03 — every index mutation serialized, ``fsync``ed and replaced the
  FULL JSON index, so a scan discovering *n* chunks performed *n*
  whole-file writes of an ever-growing document.
* CAP-04 — the set of already-indexed filenames was rebuilt from
  ``list_all()`` on every iteration of the discovery glob loop.

Both are asserted by counting the underlying work rather than by timing,
so the tests are deterministic.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any, List

import pytest

from pcap_recorder.index import PcapIndex
from pcap_recorder.ringbuffer import RingbufferManager
from pcap_recorder.settings import ArchiveConfig, RingbufferConfig


def _make_chunks(directory: Path, count: int) -> List[Path]:
    paths = []
    for i in range(count):
        path = directory / f"pcap_20260306_2108{i:02d}.pcap"
        path.write_bytes(b"\xd4\xc3\xb2\xa1")
        paths.append(path)
    return paths


@pytest.fixture()
def index(tmp_path: Path) -> PcapIndex:
    return PcapIndex(tmp_path / "index.json", chunk_duration=timedelta(seconds=60))


class TestIndexBatching:
    """CAP-03 — deferred writes, without weakening durability."""

    def test_a_single_add_still_persists_immediately(self, index: PcapIndex, tmp_path: Path) -> None:
        chunk = _make_chunks(tmp_path, 1)[0]
        index.add_chunk(chunk)

        reloaded = PcapIndex(index._index_file, chunk_duration=timedelta(seconds=60))
        assert [meta.filename for meta in reloaded.list_all()] == [chunk.name]

    def test_a_batch_writes_once(self, index: PcapIndex, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        chunks = _make_chunks(tmp_path, 25)
        writes = {"count": 0}
        original = index._write

        def counting_write() -> None:
            writes["count"] += 1
            original()

        monkeypatch.setattr(index, "_write", counting_write)

        with index.batch():
            for chunk in chunks:
                index.add_chunk(chunk)

        assert writes["count"] == 1, "a batch must collapse to a single index write"

    def test_without_a_batch_each_mutation_writes(
        self, index: PcapIndex, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Pins the contract the batch is an optimisation OF."""
        chunks = _make_chunks(tmp_path, 5)
        writes = {"count": 0}
        original = index._write
        monkeypatch.setattr(index, "_write", lambda: (writes.__setitem__("count", writes["count"] + 1), original())[1])

        for chunk in chunks:
            index.add_chunk(chunk)

        assert writes["count"] == 5

    def test_batch_contents_survive_a_reload(self, index: PcapIndex, tmp_path: Path) -> None:
        chunks = _make_chunks(tmp_path, 10)
        with index.batch():
            for chunk in chunks:
                index.add_chunk(chunk)

        reloaded = PcapIndex(index._index_file, chunk_duration=timedelta(seconds=60))
        assert len(reloaded.list_all()) == 10

    def test_a_batch_persists_even_when_the_block_raises(
        self, index: PcapIndex, tmp_path: Path
    ) -> None:
        """A partially-completed batch must not be silently lost."""
        chunks = _make_chunks(tmp_path, 3)
        with pytest.raises(RuntimeError):
            with index.batch():
                for chunk in chunks:
                    index.add_chunk(chunk)
                raise RuntimeError("boom")

        reloaded = PcapIndex(index._index_file, chunk_duration=timedelta(seconds=60))
        assert len(reloaded.list_all()) == 3

    def test_nested_batches_write_once_at_the_outermost_exit(
        self, index: PcapIndex, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        chunks = _make_chunks(tmp_path, 4)
        writes = {"count": 0}
        original = index._write
        monkeypatch.setattr(index, "_write", lambda: (writes.__setitem__("count", writes["count"] + 1), original())[1])

        with index.batch():
            index.add_chunk(chunks[0])
            with index.batch():
                index.add_chunk(chunks[1])
            assert writes["count"] == 0, "inner exit must not flush"
        assert writes["count"] == 1

    def test_flush_writes_pending_changes(
        self, index: PcapIndex, tmp_path: Path
    ) -> None:
        chunk = _make_chunks(tmp_path, 1)[0]
        index._defer_depth = 1  # simulate being inside a batch
        index.add_chunk(chunk)
        index._defer_depth = 0
        index.flush()

        reloaded = PcapIndex(index._index_file, chunk_duration=timedelta(seconds=60))
        assert len(reloaded.list_all()) == 1


class TestRingbufferScan:
    """CAP-04 — the known-filename set is built once per scan."""

    def _manager(self, tmp_path: Path, index: PcapIndex) -> RingbufferManager:
        ring_dir = tmp_path / "ring"
        ring_dir.mkdir(exist_ok=True)
        archive_dir = tmp_path / "archive"
        archive_dir.mkdir(exist_ok=True)
        return RingbufferManager(
            RingbufferConfig(
                directory=str(ring_dir),
                max_total_size_mb=1000,
                max_file_count=1000,
            ),
            ArchiveConfig(directory=str(archive_dir), max_archive_gb=10, max_age_days=30),
            index,
        )

    def test_scan_calls_list_all_once(
        self, tmp_path: Path, index: PcapIndex, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        manager = self._manager(tmp_path, index)
        _make_chunks(Path(manager._ringbuffer_path), 20)

        calls = {"count": 0}
        original = index.list_all

        def counting_list_all() -> Any:
            calls["count"] += 1
            return original()

        monkeypatch.setattr(index, "list_all", counting_list_all)

        manager.scan_for_new_chunks()

        assert calls["count"] == 1, "list_all must not be re-run per directory entry"

    def test_scan_indexes_every_new_chunk(self, tmp_path: Path, index: PcapIndex) -> None:
        manager = self._manager(tmp_path, index)
        _make_chunks(Path(manager._ringbuffer_path), 12)

        discovered = manager.scan_for_new_chunks()

        assert len(discovered) == 12
        assert len(index.list_all()) == 12

    def test_a_second_scan_discovers_nothing_new(
        self, tmp_path: Path, index: PcapIndex
    ) -> None:
        manager = self._manager(tmp_path, index)
        _make_chunks(Path(manager._ringbuffer_path), 5)
        manager.scan_for_new_chunks()

        assert manager.scan_for_new_chunks() == []

    def test_scan_writes_the_index_once(
        self, tmp_path: Path, index: PcapIndex, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """CAP-03 at the call site that made it quadratic."""
        manager = self._manager(tmp_path, index)
        _make_chunks(Path(manager._ringbuffer_path), 15)

        writes = {"count": 0}
        original = index._write
        monkeypatch.setattr(index, "_write", lambda: (writes.__setitem__("count", writes["count"] + 1), original())[1])

        manager.scan_for_new_chunks()

        assert writes["count"] == 1
