"""Bounded, streaming intake of an uploaded capture file (UI-078, B2–B5).

The upload is consumed **while it streams**: bytes are hashed and written
to their final storage location as they arrive, and the configured size
budget is enforced against the bytes actually received rather than against
the caller-declared ``Content-Length`` (which a caller may understate).

Three refusals are possible and all of them leave the import directory
clean — the partially written file is removed before the error surfaces:

* the leading bytes are not a recognised capture magic (→ ``422``);
* the budget is exceeded mid-stream (→ ``413``);
* the multipart envelope is unusable (→ ``400``).

The storage name is generated server-side (UUID4 + ``.pcap``). No part of
the caller-supplied filename ever reaches the path; it is kept purely as
metadata.
"""

from __future__ import annotations

import asyncio
import hashlib
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, AsyncIterator, BinaryIO

from loguru import logger
from python_multipart.multipart import MultipartParser, parse_options_header

if TYPE_CHECKING:
    from python_multipart.multipart import MultipartCallbacks

from otalon_api.domain.pcap_import import MAGIC_PREFIX_LENGTH, is_supported_magic

_STORAGE_SUFFIX = ".pcap"
_FIELD_VALUE_LIMIT = 4096


class UploadRejected(Exception):
    """Base class for a refused capture upload."""


class MalformedUpload(UploadRejected):
    """The request is not a usable ``multipart/form-data`` capture upload."""


class UnsupportedCapture(UploadRejected):
    """The uploaded content is not a recognised capture container."""


class UploadTooLarge(UploadRejected):
    """The upload exceeded the configured server-side size budget."""


@dataclass
class StoredUpload:
    """A capture file that has been fully received and stored."""

    path: Path
    filename: str
    size_bytes: int
    sha256: str
    original_filename: str | None = None
    fields: dict[str, str] = field(default_factory=dict)

    @property
    def force(self) -> bool:
        """Return whether the caller asked to bypass the overlap check."""
        return self.fields.get("force", "").strip().lower() in ("1", "true", "yes", "on")


class _CaptureSink:
    """Bounded, digesting file sink for the capture part of the upload."""

    def __init__(self, path: Path, max_bytes: int) -> None:
        """Open *path* for writing and arm the byte budget.

        Args:
            path: Final storage path inside the import directory.
            max_bytes: Hard upper bound on accepted payload bytes.
        """
        self.path = path
        self._max_bytes = max_bytes
        self._digest = hashlib.sha256()
        self._handle: BinaryIO | None = path.open("wb")
        self.size_bytes = 0
        self.head = b""

    def write(self, payload: bytes) -> None:
        """Append *payload*, enforcing the budget and magic-byte check.

        Raises:
            UploadTooLarge: When the budget is exceeded.
            UnsupportedCapture: When the leading bytes are not a capture.
        """
        if self._handle is None:
            return
        self.size_bytes += len(payload)
        if self.size_bytes > self._max_bytes:
            raise UploadTooLarge(f"Upload exceeds the configured limit of {self._max_bytes} bytes")
        if len(self.head) < MAGIC_PREFIX_LENGTH:
            self.head += payload[: MAGIC_PREFIX_LENGTH - len(self.head)]
            if len(self.head) >= MAGIC_PREFIX_LENGTH and not is_supported_magic(self.head):
                raise UnsupportedCapture("File is not a pcap or pcapng capture")
        self._digest.update(payload)
        self._handle.write(payload)

    def finish(self) -> str:
        """Close the file and return the hex digest of everything written."""
        if self._handle is not None:
            self._handle.close()
            self._handle = None
        return self._digest.hexdigest()

    def discard(self) -> None:
        """Close and remove the partial file so nothing is left behind."""
        if self._handle is not None:
            self._handle.close()
            self._handle = None
        self.path.unlink(missing_ok=True)


class _UploadCollector:
    """Multipart callback target that routes the file part into a sink."""

    def __init__(self, sink: _CaptureSink) -> None:
        """Bind the collector to *sink* and reset the parser state."""
        self._sink = sink
        self.fields: dict[str, str] = {}
        self.original_filename: str | None = None
        self.saw_file_part = False
        self._pending: list[bytes] = []
        self._header_field = b""
        self._header_value = b""
        self._disposition = b""
        self._part_name = ""
        self._part_is_file = False
        self._part_value = b""

    def callbacks(self) -> "MultipartCallbacks":
        """Return the ``on_*`` callback mapping for :class:`MultipartParser`."""
        return {
            "on_part_begin": self._on_part_begin,
            "on_part_data": self._on_part_data,
            "on_part_end": self._on_part_end,
            "on_header_field": self._on_header_field,
            "on_header_value": self._on_header_value,
            "on_header_end": self._on_header_end,
            "on_headers_finished": self._on_headers_finished,
        }

    def take_pending(self) -> bytes:
        """Return and clear the file bytes buffered since the last call."""
        if not self._pending:
            return b""
        payload = b"".join(self._pending)
        self._pending.clear()
        return payload

    def _on_part_begin(self) -> None:
        self._disposition = b""
        self._part_name = ""
        self._part_is_file = False
        self._part_value = b""

    def _on_header_field(self, data: bytes, start: int, end: int) -> None:
        self._header_field += data[start:end]

    def _on_header_value(self, data: bytes, start: int, end: int) -> None:
        self._header_value += data[start:end]

    def _on_header_end(self) -> None:
        if self._header_field.lower() == b"content-disposition":
            self._disposition = self._header_value
        self._header_field = b""
        self._header_value = b""

    def _on_headers_finished(self) -> None:
        _disposition, options = parse_options_header(self._disposition)
        self._part_name = options.get(b"name", b"").decode("utf-8", "replace")
        raw_filename = options.get(b"filename")
        self._part_is_file = raw_filename is not None
        if self._part_is_file and raw_filename:
            self.original_filename = raw_filename.decode("utf-8", "replace")
            self.saw_file_part = True

    def _on_part_data(self, data: bytes, start: int, end: int) -> None:
        chunk = data[start:end]
        if self._part_is_file:
            self._pending.append(chunk)
        elif len(self._part_value) < _FIELD_VALUE_LIMIT:
            self._part_value += chunk[: _FIELD_VALUE_LIMIT - len(self._part_value)]

    def _on_part_end(self) -> None:
        if not self._part_is_file and self._part_name:
            self.fields[self._part_name] = self._part_value.decode("utf-8", "replace")


class PcapUploadService:
    """Stream a multipart capture upload into the shared import directory."""

    def __init__(self, import_dir: Path, max_upload_bytes: int) -> None:
        """Configure storage location and size budget.

        Args:
            import_dir: Directory shared with the import worker.
            max_upload_bytes: Hard server-side upload limit in bytes.
        """
        self._import_dir = import_dir
        self._max_upload_bytes = max_upload_bytes

    @property
    def import_dir(self) -> Path:
        """Return the configured import directory."""
        return self._import_dir

    @property
    def max_upload_bytes(self) -> int:
        """Return the configured maximum accepted upload size."""
        return self._max_upload_bytes

    def _new_storage_path(self) -> Path:
        """Return a fresh, purely server-generated storage path."""
        return self._import_dir / f"{uuid.uuid4().hex}{_STORAGE_SUFFIX}"

    @staticmethod
    def _boundary(content_type: str) -> bytes:
        """Extract the multipart boundary or reject the request.

        Raises:
            MalformedUpload: When the header is not multipart/form-data
                or carries no boundary.
        """
        media_type, options = parse_options_header(content_type)
        if media_type.lower() != b"multipart/form-data":
            raise MalformedUpload("Expected a multipart/form-data upload")
        boundary = options.get(b"boundary")
        if not boundary:
            raise MalformedUpload("Multipart upload is missing its boundary")
        return boundary

    async def store(self, content_type: str, stream: AsyncIterator[bytes]) -> StoredUpload:
        """Consume *stream* into a stored capture file.

        Args:
            content_type: The inbound ``Content-Type`` header.
            stream: The raw request body chunks.

        Returns:
            The :class:`StoredUpload` describing the persisted file.

        Raises:
            MalformedUpload: The envelope is unusable or no file was sent.
            UnsupportedCapture: The content is not a capture container.
            UploadTooLarge: The size budget was exceeded.
        """
        boundary = self._boundary(content_type)
        await asyncio.to_thread(self._import_dir.mkdir, parents=True, exist_ok=True)
        sink = await asyncio.to_thread(_CaptureSink, self._new_storage_path(), self._max_upload_bytes)
        collector = _UploadCollector(sink)
        parser = MultipartParser(boundary, collector.callbacks())
        try:
            await self._pump(parser, collector, sink, stream)
            digest = await asyncio.to_thread(sink.finish)
        except UploadRejected:
            await asyncio.to_thread(sink.discard)
            raise
        except Exception as exc:
            await asyncio.to_thread(sink.discard)
            raise MalformedUpload(f"{type(exc).__name__}: {exc}") from exc
        if not collector.saw_file_part or sink.size_bytes == 0:
            await asyncio.to_thread(sink.discard)
            raise MalformedUpload("Upload contained no capture file part")
        if not is_supported_magic(sink.head):
            await asyncio.to_thread(sink.discard)
            raise UnsupportedCapture("File is not a pcap or pcapng capture")
        logger.info("pcap-import: stored upload {} ({} bytes)", sink.path.name, sink.size_bytes)
        return StoredUpload(
            path=sink.path,
            filename=sink.path.name,
            size_bytes=sink.size_bytes,
            sha256=digest,
            original_filename=collector.original_filename,
            fields=collector.fields,
        )

    @staticmethod
    async def _pump(
        parser: MultipartParser,
        collector: _UploadCollector,
        sink: _CaptureSink,
        stream: AsyncIterator[bytes],
    ) -> None:
        """Feed the request body through the parser into the sink."""
        async for chunk in stream:
            if chunk:
                parser.write(chunk)
            payload = collector.take_pending()
            if payload:
                await asyncio.to_thread(sink.write, payload)
        parser.finalize()
        payload = collector.take_pending()
        if payload:
            await asyncio.to_thread(sink.write, payload)
