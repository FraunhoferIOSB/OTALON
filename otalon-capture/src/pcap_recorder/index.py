"""Index management for tracked PCAP chunks."""

from __future__ import annotations

import json
import os
import tempfile
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional

from loguru import logger

DEFAULT_CHUNK_DURATION = timedelta(seconds=60)


@dataclass
class PcapChunkMeta:
    """Metadata tracked for each generated PCAP chunk."""

    filename: str
    path: Path
    start_ts: datetime
    end_ts: datetime
    size_bytes: int
    is_anomaly: bool = False
    pinned: bool = False
    labels: Dict[str, str] = field(default_factory=dict)


class PcapIndex:
    """Maintain a persisted registry of ringbuffer chunks."""

    def __init__(
        self, index_file: Path, chunk_duration: timedelta = DEFAULT_CHUNK_DURATION
    ) -> None:
        self._index_file = index_file
        self._index_file.parent.mkdir(parents=True, exist_ok=True)
        self._chunk_duration = chunk_duration
        self._entries: Dict[str, PcapChunkMeta] = {}
        self._defer_depth = 0
        self._dirty = False
        # PCAP-018: the ringbuffer tick (asyncio loop) and the anomaly flag
        # route (FastAPI threadpool) both mutate this index. One re-entrant
        # lock serializes mutations, batch bookkeeping and the on-disk write.
        self._lock = threading.RLock()
        self._load()

    @contextmanager
    def batch(self) -> Iterator["PcapIndex"]:
        """Defer index writes until the outermost block exits.

        Every mutation used to serialize, ``fsync`` and atomically replace
        the FULL index file. A ringbuffer scan that discovers *n* chunks
        therefore performed *n* whole-file writes of an ever-growing
        document — quadratic I/O, with an fsync each, on the recorder's
        hot path (audit CAP-03).

        Inside this block mutations only mark the index dirty; one write
        happens on exit. Nesting is supported, and the write still happens
        when the block leaves via an exception, so a partially-completed
        batch is never silently lost.

        Yields:
            This index, for convenient ``with index.batch():`` use.
        """
        with self._lock:
            self._defer_depth += 1
            try:
                yield self
            finally:
                self._defer_depth -= 1
                if self._defer_depth == 0 and self._dirty:
                    self._write()

    def flush(self) -> None:
        """Write pending index changes to disk immediately, if any.

        Call on shutdown so a deferred batch cannot outlive the process.
        """
        with self._lock:
            if self._dirty:
                self._write()

    def add_chunk(self, path: Path) -> PcapChunkMeta:
        """Insert or update metadata for a chunk located at ``path``."""

        filename = path.name
        stat_result = path.stat()
        start_ts = self._parse_timestamp(filename)
        end_ts = start_ts + self._chunk_duration
        meta = PcapChunkMeta(
            filename=filename,
            path=path,
            start_ts=start_ts,
            end_ts=end_ts,
            size_bytes=stat_result.st_size,
        )
        with self._lock:
            self._entries[filename] = meta
            logger.debug(
                "Indexed chunk {file} ({size} bytes)",
                file=filename,
                size=stat_result.st_size,
            )
            self._persist()
        return meta

    def mark_anomaly(
        self, chunk_ids: Iterable[str], labels: Optional[Dict[str, str]] = None
    ) -> List[PcapChunkMeta]:
        """Flag selected chunks as anomaly and attach labels."""

        labels = labels or {}
        updated: List[PcapChunkMeta] = []
        with self._lock:
            for chunk_id in chunk_ids:
                meta = self._entries.get(chunk_id)
                if meta is None:
                    continue
                meta.is_anomaly = True
                meta.pinned = True
                meta.labels.update(labels)
                updated.append(meta)
            if updated:
                self._persist()
        logger.info("Marked {count} chunk(s) as anomaly.", count=len(updated))
        return updated

    def find_by_timerange(
        self, start: datetime, end: datetime, include_non_archive: bool = True
    ) -> List[PcapChunkMeta]:
        """Return all chunks intersecting the requested time range."""

        matches: List[PcapChunkMeta] = []
        start = self._ensure_timezone(start)
        end = self._ensure_timezone(end)
        for meta in self._entries.values():
            if not include_non_archive and not meta.is_anomaly:
                continue
            meta_start = self._ensure_timezone(meta.start_ts)
            meta_end = self._ensure_timezone(meta.end_ts)
            if meta_end >= start and meta_start <= end:
                matches.append(meta)
        matches.sort(key=lambda item: self._ensure_timezone(item.start_ts))
        return matches

    def list_all(self) -> List[PcapChunkMeta]:
        return sorted(
            self._entries.values(),
            key=lambda meta: self._ensure_timezone(meta.start_ts),
        )

    def list_anomalies(self) -> List[PcapChunkMeta]:
        return [meta for meta in self._entries.values() if meta.is_anomaly]

    def remove(self, chunk_id: str) -> None:
        with self._lock:
            if chunk_id in self._entries:
                del self._entries[chunk_id]
                self._persist()

    def _load(self) -> None:
        if not self._index_file.exists():
            return
        try:
            with self._index_file.open("r", encoding="utf-8") as handle:
                raw_entries = json.load(handle)
        except json.JSONDecodeError as error:
            self._quarantine_corrupt_index(error)
            return
        for entry in raw_entries:
            meta = PcapChunkMeta(
                filename=entry["filename"],
                path=Path(entry["path"]),
                start_ts=datetime.fromisoformat(entry["start_ts"]),
                end_ts=datetime.fromisoformat(entry["end_ts"]),
                size_bytes=entry["size_bytes"],
                is_anomaly=entry.get("is_anomaly", False),
                pinned=entry.get("pinned", False),
                labels=entry.get("labels", {}),
            )
            self._entries[meta.filename] = meta
        logger.info("Loaded {count} indexed chunk(s).", count=len(self._entries))

    def _quarantine_corrupt_index(self, error: json.JSONDecodeError) -> None:
        timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%S%fZ")
        quarantine_path = self._index_file.with_name(
            f"{self._index_file.stem}.corrupt-{timestamp}{self._index_file.suffix}"
        )
        self._index_file.rename(quarantine_path)
        logger.error(
            "Corrupt index file {file} quarantined to {target}: {error}. "
            "Starting with an empty index; ringbuffer chunks on disk are unaffected.",
            file=self._index_file,
            target=quarantine_path,
            error=error,
        )

    def _persist(self) -> None:
        """Persist the index, honouring an active :meth:`batch` block.

        Inside a batch the write is deferred to the block's exit; outside
        one the behaviour is unchanged (immediate, atomic, fsynced).
        Callers hold ``self._lock`` (re-entrant, so nested calls are fine).
        """
        if self._defer_depth > 0:
            self._dirty = True
            return
        self._write()

    def _write(self) -> None:
        """Serialize the index and atomically replace the file on disk.

        PCAP-018: each write gets a unique temp file in the index directory.
        A fixed ``pcap_index.json.tmp`` let two concurrent writers rename the
        same temp file, so the second ``replace`` found nothing and the index
        stopped being written. The lock keeps the serialized snapshot
        consistent with the entries it describes.
        """
        with self._lock:
            self._dirty = False
            serializable = [
                {
                    "filename": meta.filename,
                    "path": str(meta.path),
                    "start_ts": meta.start_ts.isoformat(),
                    "end_ts": meta.end_ts.isoformat(),
                    "size_bytes": meta.size_bytes,
                    "is_anomaly": meta.is_anomaly,
                    "pinned": meta.pinned,
                    "labels": meta.labels,
                }
                for meta in self._entries.values()
            ]
            fd, tmp_name = tempfile.mkstemp(
                dir=str(self._index_file.parent),
                prefix=self._index_file.name + ".",
                suffix=".tmp",
            )
            tmp_path = Path(tmp_name)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    json.dump(serializable, handle, indent=2)
                    handle.flush()
                    os.fsync(handle.fileno())
                tmp_path.replace(self._index_file)
            except BaseException:
                tmp_path.unlink(missing_ok=True)
                raise

    def _parse_timestamp(self, filename: str) -> datetime:
        base, *_ = filename.split(".", 1)
        try:
            timestamp_str = base.replace("pcap_", "")
            parsed = datetime.strptime(timestamp_str, "%Y%m%d_%H%M%S")
            return parsed.replace(tzinfo=None)
        except ValueError:
            logger.warning(
                "Falling back to current time for filename {filename}",
                filename=filename,
            )
            return datetime.utcnow()

    @staticmethod
    def _ensure_timezone(value: datetime) -> datetime:
        if value.tzinfo is None:
            return value
        return value.replace(tzinfo=None)
