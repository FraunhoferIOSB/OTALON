"""Ringbuffer management for PCAP chunk directories."""

from __future__ import annotations

import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Iterable, List

from loguru import logger

from .index import PcapChunkMeta, PcapIndex
from .settings import ArchiveConfig, RingbufferConfig


class RingbufferManager:
    """Monitor ringbuffer directories and enforce storage limits."""

    def __init__(
        self,
        ringbuffer_config: RingbufferConfig,
        archive_config: ArchiveConfig,
        index: PcapIndex,
    ) -> None:
        self._ringbuffer_config = ringbuffer_config
        self._archive_config = archive_config
        self._index = index
        self._ringbuffer_path = Path(ringbuffer_config.directory)
        self._archive_path = Path(archive_config.directory)
        self._ringbuffer_path.mkdir(parents=True, exist_ok=True)
        self._archive_path.mkdir(parents=True, exist_ok=True)

    def scan_for_new_chunks(self) -> List[PcapChunkMeta]:
        """Discover files in the ringbuffer directory and index new ones."""

        # The known-filename set is built ONCE. Rebuilding it inside the
        # loop walked the whole index per directory entry, making a scan
        # O(n*m) — with a full ringbuffer (thousands of chunks) that is
        # millions of comparisons per scan cycle (audit CAP-04).
        known = {meta.filename for meta in self._index.list_all()}

        discovered: List[PcapChunkMeta] = []
        # One index write for the whole scan instead of one per discovered
        # chunk; each of those rewrote and fsynced the entire JSON document
        # (audit CAP-03).
        with self._index.batch():
            for path in self._ringbuffer_path.glob("*.pcap"):
                if path.name in known:
                    continue
                try:
                    discovered.append(self._index.add_chunk(path))
                    # Keep the set authoritative for the rest of this scan
                    # so a duplicate directory entry cannot be indexed twice.
                    known.add(path.name)
                except Exception as error:  # noqa: BLE001 - logging visibility
                    logger.warning("Failed to index chunk {path}: {error}", path=path, error=error)
        return discovered

    def _refresh_buffer_sizes(self) -> None:
        """Re-read on-disk sizes of buffer chunks into the index (PCAP-017).

        Only buffer entries are touched; archive entries are immutable.
        Missing files keep their last known size so a transient stat error
        does not silently drop accounting.
        """

        changed = False
        for meta in self._index.list_all():
            if meta.path.parent != self._ringbuffer_path:
                continue
            try:
                real = meta.path.stat().st_size
            except OSError:
                continue
            if real != meta.size_bytes:
                meta.size_bytes = real
                changed = True
        if changed:
            self._index._persist()  # noqa: SLF001 - one write for all updates

    def enforce_limits(self) -> None:
        """Ensure ringbuffer limits configured by size and file count.

        PCAP-017: ``size_bytes`` is recorded once at discovery, while
        tcpdump keeps appending to the same chunk for ``-G`` seconds.
        Summing the stale index values let the buffer grow far past
        ``max_total_size_mb``. Refresh sizes from disk first.
        """

        self._refresh_buffer_sizes()
        entries = self._index.list_all()
        total_size = sum(meta.size_bytes for meta in entries if not meta.is_anomaly)
        file_count = sum(1 for meta in entries if not meta.is_anomaly)

        max_size = self._ringbuffer_config.max_total_size_mb * 1024 * 1024
        max_files = self._ringbuffer_config.max_file_count

        candidates = sorted(
            (meta for meta in entries if not meta.is_anomaly),
            key=lambda meta: self._index._ensure_timezone(meta.start_ts),
        )

        removed = False
        # Evicting k chunks wrote the whole index k times; one write for the
        # eviction pass is enough (audit CAP-03). A failed removal is logged
        # and the sweep continues with the next candidate (PCAP-014): one
        # undeletable chunk must not block eviction of all the others.
        with self._index.batch():
            while (total_size > max_size and candidates) or (file_count > max_files and candidates):
                victim = candidates.pop(0)
                try:
                    victim.path.unlink(missing_ok=True)
                    self._index.remove(victim.filename)
                    total_size -= victim.size_bytes
                    file_count -= 1
                    removed = True
                    logger.info(
                        "Removed chunk {filename} to honor ringbuffer limits.",
                        filename=victim.filename,
                    )
                except Exception as error:  # noqa: BLE001 - continue attempts
                    logger.warning(
                        "Failed to remove chunk {filename}: {error}",
                        filename=victim.filename,
                        error=error,
                    )
                    continue

        if not removed:
            logger.debug(
                "Ringbuffer limits satisfied (size={size}, files={count}).",
                size=total_size,
                count=file_count,
            )

    def archive_chunks(self, chunk_ids: Iterable[str]) -> Dict[str, Path]:
        """Move selected chunks to the archive directory and flag them as anomalies."""

        # Indexed once instead of re-scanning the whole index per requested
        # chunk id — same quadratic pattern as the discovery loop
        # (audit CAP-04).
        by_filename = {entry.filename: entry for entry in self._index.list_all()}

        moved: Dict[str, Path] = {}
        for chunk_id in chunk_ids:
            meta = by_filename.get(chunk_id)
            if meta is None:
                continue
            target_path = self._archive_path / meta.filename
            try:
                shutil.move(str(meta.path), target_path)
                meta.path = target_path
                meta.is_anomaly = True
                # Archived chunks are operator-relevant evidence: pin them so
                # the archive sweep (size and age) never evicts them (PCAP-017).
                meta.pinned = True
                moved[chunk_id] = target_path
            except Exception as error:  # noqa: BLE001 - keep partial progress logged
                logger.warning(
                    "Failed to archive chunk {chunk}: {error}",
                    chunk=chunk_id,
                    error=error,
                )
        if moved:
            self._index._persist()
        return moved

    def enforce_archive_limits(self) -> None:
        """Ensure archive size and age limits, evicting oldest non-pinned first.

        Pinned (anomaly-flagged) chunks are exempt from both the size
        and the age sweep so operator-marked evidence is never lost.
        """
        entries = self._index.list_all()
        archive_entries = [meta for meta in entries if meta.path.parent == self._archive_path]
        if not archive_entries:
            return

        max_bytes = self._archive_config.max_archive_gb * 1024 * 1024 * 1024
        max_age = timedelta(days=self._archive_config.max_age_days)
        now = datetime.now(timezone.utc)

        pinned = [meta for meta in archive_entries if meta.pinned]
        evictable = sorted(
            (meta for meta in archive_entries if not meta.pinned),
            key=lambda meta: self._index._ensure_timezone(meta.start_ts),
        )

        total_size = sum(meta.size_bytes for meta in evictable)
        removed = False
        now_naive = self._index._ensure_timezone(now)

        # One index write for the whole archive sweep (audit CAP-03).
        with self._index.batch():
            while evictable:
                oldest = evictable[0]
                age = now_naive - self._index._ensure_timezone(oldest.start_ts)
                if total_size <= max_bytes and age <= max_age:
                    break
                victim = evictable.pop(0)
                try:
                    victim.path.unlink(missing_ok=True)
                    self._index.remove(victim.filename)
                    total_size -= victim.size_bytes
                    removed = True
                    logger.info(
                        "Removed archive chunk {filename} (age={age}, size={size}) " "to honor archive limits.",
                        filename=victim.filename,
                        age=age,
                        size=victim.size_bytes,
                    )
                except Exception as error:  # noqa: BLE001 - continue attempts
                    logger.warning(
                        "Failed to remove archive chunk {filename}: {error}",
                        filename=victim.filename,
                        error=error,
                    )
                    continue

        if not removed:
            logger.debug(
                "Archive limits satisfied (size={size}, files={count}, pinned={pinned}).",
                size=total_size,
                count=len(evictable),
                pinned=len(pinned),
            )

    def tick(self) -> None:
        """Convenience helper to scan and then enforce limits."""

        self.scan_for_new_chunks()
        self.enforce_limits()
        self.enforce_archive_limits()
