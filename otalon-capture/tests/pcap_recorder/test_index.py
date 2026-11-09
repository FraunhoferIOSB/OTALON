"""Tests fuer das Index-Management."""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

from pcap_recorder.index import PcapIndex


def _create_chunk(tmp_path: Path, name: str, size: int = 100) -> Path:
    path = tmp_path / name
    path.write_bytes(b"0" * size)
    return path


def test_add_chunk_and_persist(tmp_path: Path) -> None:
    index_file = tmp_path / "pcap_index.json"
    chunk_file = _create_chunk(tmp_path, "pcap_20260213_120000.pcap")

    index = PcapIndex(index_file)
    meta = index.add_chunk(chunk_file)

    assert meta.filename == "pcap_20260213_120000.pcap"
    assert meta.size_bytes == chunk_file.stat().st_size
    assert meta.start_ts == datetime.strptime("20260213_120000", "%Y%m%d_%H%M%S")
    assert meta.end_ts == meta.start_ts + timedelta(seconds=60)

    index_reloaded = PcapIndex(index_file)
    assert len(index_reloaded.list_all()) == 1


def test_find_by_timerange_filters(tmp_path: Path) -> None:
    index_file = tmp_path / "pcap_index.json"
    index = PcapIndex(index_file)

    chunk_a = _create_chunk(tmp_path, "pcap_20260213_120000.pcap")
    chunk_b = _create_chunk(tmp_path, "pcap_20260213_120100.pcap")
    index.add_chunk(chunk_a)
    index.add_chunk(chunk_b)

    start = datetime.strptime("20260213_120030", "%Y%m%d_%H%M%S")
    end = datetime.strptime("20260213_120130", "%Y%m%d_%H%M%S")

    matches = index.find_by_timerange(start, end)

    assert len(matches) == 2
    assert matches[0].filename == chunk_a.name
    assert matches[1].filename == chunk_b.name


def test_mark_anomaly_updates_entries(tmp_path: Path) -> None:
    index_file = tmp_path / "pcap_index.json"
    index = PcapIndex(index_file)

    chunk = _create_chunk(tmp_path, "pcap_20260213_120000.pcap")
    index.add_chunk(chunk)

    updated = index.mark_anomaly([chunk.name], labels={"uci": "demo"})

    assert updated[0].is_anomaly is True
    assert updated[0].labels["uci"] == "demo"
