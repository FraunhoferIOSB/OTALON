"""PCAP-018 regression: the index must survive concurrent writers.

The ringbuffer tick runs on the asyncio loop while the anomaly flag route runs
on the FastAPI threadpool. Both mutate the same ``PcapIndex``. Before the fix
``_write`` used one fixed temp name (``pcap_index.json.tmp``) with no lock, so
two writers collided on ``os.replace`` and the index could stop being written.
"""

from __future__ import annotations

import threading
from datetime import datetime, timedelta
from pathlib import Path

from pcap_recorder.index import PcapIndex


def _seed(index_file: Path, count: int) -> PcapIndex:
    index = PcapIndex(index_file)
    base = datetime(2026, 11, 2, 10, 0, 0)
    for i in range(count):
        ts = base + timedelta(seconds=30 * i)
        name = f"{ts:%Y%m%d_%H%M%S}.pcap"
        path = index_file.parent / name
        path.write_bytes(b"x" * 16)
        index.add_chunk(path)
    return index


def test_concurrent_persist_never_raises_and_leaves_valid_index(tmp_path: Path) -> None:
    index_file = tmp_path / "pcap_index.json"
    index = _seed(index_file, 40)

    errors: list[BaseException] = []
    stop = threading.Event()

    def writer(kind: str) -> None:
        try:
            names = [m.filename for m in index.list_all()][:5]
            while not stop.is_set():
                if kind == "mark":
                    index.mark_anomaly(names, None)
                else:
                    with index.batch():
                        index._dirty = True  # noqa: SLF001 - mirrors a scan batch
        except BaseException as exc:  # noqa: BLE001 - collect, do not hide
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(k,)) for k in ("mark", "batch") for _ in range(2)]
    for t in threads:
        t.start()
    threading.Event().wait(1.5)
    stop.set()
    for t in threads:
        t.join(timeout=10)

    assert not errors, errors[:2]
    reloaded = PcapIndex(index_file)
    assert len(reloaded.list_all()) == 40
    assert not list(tmp_path.glob("*.tmp")), "no leftover temp file"
