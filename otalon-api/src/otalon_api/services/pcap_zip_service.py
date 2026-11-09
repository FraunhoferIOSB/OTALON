"""Streaming ZIP archive builder for alarm PCAP bundles.

Produces a ``application/zip`` stream containing all PCAP chunks the
recorder holds for an alarm window plus a ``metadata.json`` manifest.
The archive is generated incrementally so neither the API process nor
the upstream PCAP recorder ever hold the full bundle in memory.

Pattern
-------

The stdlib :mod:`zipfile` module needs a writable file-like object. We
plug a tiny in-memory buffer (:class:`_StreamingBuffer`) underneath
:class:`zipfile.ZipFile` and drain the buffer after every write call,
yielding bytes to the FastAPI :class:`StreamingResponse`. Each chunk
file is fetched from the recorder via
:meth:`PcapProxyService.stream_chunk` and copied into a per-file
:class:`zipfile.ZipFile.open` writer in 64 KiB slices, so even very
large PCAPs stream end-to-end without buffering.

The manifest is written last so the consumer can confirm the chunk
list matches what arrived on disk.
"""

from __future__ import annotations

import json
import zipfile
from datetime import datetime, timezone
from typing import Any, AsyncIterator

from loguru import logger

from otalon_api.services.pcap_proxy_service import PcapProxyService, UpstreamUnreachable

_DEFAULT_FLUSH_THRESHOLD = 64 * 1024


class _StreamingBuffer:
    """In-memory write target whose content can be drained between writes.

    Implements the minimal subset of the file-protocol that
    :class:`zipfile.ZipFile` uses when constructed with
    ``allowZip64=True`` and a non-seekable stream: ``write``, ``tell``,
    ``flush`` and ``close``. ``zipfile`` only calls ``seek`` when it
    decides the underlying stream is seekable, which is detected via
    the absence of a ``seekable`` attribute or via a ``seekable()`` that
    returns ``False``. We deliberately omit ``seekable`` to keep zipfile
    in streaming mode (it then writes data descriptors and never seeks
    back to patch local headers).
    """

    def __init__(self) -> None:
        self._buf = bytearray()
        self._pos = 0

    def write(self, data: bytes) -> int:
        """Append ``data`` to the buffer and return the byte count."""
        self._buf.extend(data)
        self._pos += len(data)
        return len(data)

    def tell(self) -> int:
        """Return the running byte offset (required by zipfile)."""
        return self._pos

    def flush(self) -> None:
        """No-op: ``StreamingResponse`` controls draining cadence."""

    def close(self) -> None:
        """No-op: the response generator owns the buffer lifetime."""

    def drain(self) -> bytes:
        """Pop and return all buffered bytes.

        Returns:
            Every byte written since the previous drain, in order. The
            internal buffer is reset to empty but ``tell()`` continues
            to report the cumulative offset so zip metadata stays
            consistent.
        """
        if not self._buf:
            return b""
        out = bytes(self._buf)
        self._buf.clear()
        return out


def _build_manifest(
    alarm_id: str,
    start_iso: str,
    end_iso: str,
    files: list[dict[str, Any]],
) -> bytes:
    """Render the ``metadata.json`` payload.

    Args:
        alarm_id: Alarm group UUID.
        start_iso: Alarm window start (ISO 8601, UTC).
        end_iso: Alarm window end (ISO 8601, UTC).
        files: Per-chunk manifest rows produced during streaming.

    Returns:
        UTF-8 encoded, pretty-printed JSON.
    """
    duration_s: float | None = None
    try:
        start_dt = datetime.fromisoformat(start_iso.replace("Z", "+00:00"))
        end_dt = datetime.fromisoformat(end_iso.replace("Z", "+00:00"))
        duration_s = (end_dt - start_dt).total_seconds()
    except ValueError:
        duration_s = None

    manifest: dict[str, Any] = {
        "alarm_id": alarm_id,
        "alarm_window": {
            "start": start_iso,
            "end": end_iso,
            "duration_s": duration_s,
        },
        "chunk_count": len(files),
        "chunks": files,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    return json.dumps(manifest, indent=2, sort_keys=False).encode("utf-8")


def _zip_archive_name(chunk_id: str, index: int) -> str:
    """Compose the in-archive filename for a chunk.

    Preserves the upstream file extension (``.pcap``/``.pcapng``) when
    one is present, otherwise defaults to ``.pcap``.
    """
    if "." in chunk_id:
        suffix = "." + chunk_id.rsplit(".", 1)[-1]
    else:
        suffix = ".pcap"
    return f"chunk-{index:03d}{suffix}"


async def stream_alarm_zip(
    *,
    alarm_id: str,
    start_iso: str,
    end_iso: str,
    chunks: list[dict[str, Any]],
    proxy: PcapProxyService,
    byte_chunk_size: int = _DEFAULT_FLUSH_THRESHOLD,
) -> AsyncIterator[bytes]:
    """Yield a ZIP archive of all alarm chunks plus ``metadata.json``.

    The generator is fully streaming: each PCAP chunk is fetched from
    the recorder via ``GET /chunks/{chunk_id}?format=pcap`` and
    incrementally copied into the zip writer; nothing buffers the
    whole file. Upstream transport errors are propagated as
    :class:`UpstreamUnreachable` so the router can render them as 502 /
    504. Per-chunk 404s are skipped with a warning but do not abort the
    archive — the manifest reflects the chunks that actually made it
    in.

    Args:
        alarm_id: Alarm group UUID, used in the manifest only.
        start_iso: Alarm window start (ISO 8601, UTC).
        end_iso: Alarm window end (ISO 8601, UTC).
        chunks: Ordered chunk metadata rows from the by-alarm endpoint.
            Each row must carry ``chunk_id``; ``start_ts``, ``end_ts``
            and ``size_bytes`` are forwarded into the manifest verbatim.
        proxy: Configured :class:`PcapProxyService` used to fetch
            individual chunks.
        byte_chunk_size: Slice size for the upstream byte iterator.

    Yields:
        Raw ZIP bytes, in order. Suitable for
        :class:`fastapi.responses.StreamingResponse`.
    """
    buf = _StreamingBuffer()
    zf = zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_STORED, allowZip64=True)

    manifest_files: list[dict[str, Any]] = []
    try:
        for index, chunk in enumerate(chunks, start=1):
            chunk_id = str(chunk.get("chunk_id") or chunk.get("filename") or "")
            if not chunk_id:
                continue
            archive_name = _zip_archive_name(chunk_id, index)

            # Probe the upstream BEFORE opening the zip writer: a 404
            # (chunk rotated out between listing and download) is then
            # silently skipped, leaving no orphan zero-byte entry in
            # the archive. Transport failures still propagate.
            byte_iter = proxy.stream_chunk(chunk_id, byte_chunk_size=byte_chunk_size)
            try:
                first_piece = await byte_iter.__anext__()
            except StopAsyncIteration:
                first_piece = b""
            except UpstreamUnreachable:
                raise
            except Exception as exc:
                logger.warning(
                    "pcap-zip: skipping chunk {} ({}: {})",
                    chunk_id,
                    type(exc).__name__,
                    exc,
                )
                continue

            written_bytes = 0
            try:
                with zf.open(archive_name, mode="w", force_zip64=True) as writer:
                    if first_piece:
                        writer.write(first_piece)
                        written_bytes += len(first_piece)
                        drained = buf.drain()
                        if drained:
                            yield drained
                    async for piece in byte_iter:
                        writer.write(piece)
                        written_bytes += len(piece)
                        drained = buf.drain()
                        if drained:
                            yield drained
            except UpstreamUnreachable:
                raise

            manifest_files.append(
                {
                    "archive_name": archive_name,
                    "chunk_id": chunk_id,
                    "size_bytes": written_bytes,
                    "start_ts": chunk.get("start_ts"),
                    "end_ts": chunk.get("end_ts"),
                }
            )
            drained = buf.drain()
            if drained:
                yield drained

        manifest = _build_manifest(alarm_id, start_iso, end_iso, manifest_files)
        zf.writestr("metadata.json", manifest)
        drained = buf.drain()
        if drained:
            yield drained
    finally:
        zf.close()
        tail = buf.drain()
        if tail:
            yield tail
