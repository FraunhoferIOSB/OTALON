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
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, AsyncIterator, BinaryIO, TypeVar

from loguru import logger
from python_multipart.multipart import MultipartParser, parse_options_header

if TYPE_CHECKING:
    from python_multipart.multipart import MultipartCallbacks

from otalon_api.domain.pcap_import import MAGIC_PREFIX_LENGTH, is_supported_magic

_STORAGE_SUFFIX = ".pcap"
_FIELD_VALUE_LIMIT = 4096
_ENVELOPE_LIMIT = 65_536
_FEED_LIMIT = 65_536
_HEADER_LIMIT = 8192
_FIELD_NAME_LIMIT = 128
_FILENAME_LIMIT = 1024
_TEXT_PART_LIMIT = 8
_BOUNDARY_CHARS = frozenset(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'()+_,-./:=? ")
_T = TypeVar("_T")


async def _settle_thread(operation: Callable[..., _T], *args: object, **kwargs: object) -> _T:
    """Join a file operation before propagating even repeated cancellation."""
    task = asyncio.create_task(asyncio.to_thread(operation, *args, **kwargs))
    cancellation: asyncio.CancelledError | None = None
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError as exc:
            cancellation = cancellation or exc
        except BaseException:
            break
    if cancellation is not None:
        # Retrieve any thread exception without replacing the caller's cancellation.
        try:
            task.result()
        except BaseException:
            pass
        raise cancellation
    return task.result()


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
        self.completed = False
        self.payload_bytes = 0
        self.total_bytes = 0
        self._text_names: set[str] = set()
        self._in_headers = False
        self._header_start: int | None = None
        self._feed_offset = 0
        self._feed = b""
        self._feed_tail = b""
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
            "on_end": self._on_end,
        }

    def begin_feed(self, data: bytes) -> None:
        """Count every actual request byte, including parser-ignored framing."""
        self._feed_tail = (self._feed_tail + self._feed)[-3:]
        self._feed_offset = self.total_bytes
        self._feed = data
        self.total_bytes += len(data)

    def check_budgets(self, lookbehind: int = 0) -> None:
        """Check observed payload before writes and reconcile the raw envelope."""
        if self.payload_bytes > self._sink._max_bytes:
            raise UploadTooLarge(f"Upload exceeds the configured limit of {self._sink._max_bytes} bytes")
        if self.total_bytes > self._sink._max_bytes + _ENVELOPE_LIMIT:
            raise UploadTooLarge(
                f"Upload exceeds the total request limit of {self._sink._max_bytes + _ENVELOPE_LIMIT} bytes"
            )
        pending_delimiter = lookbehind if self._part_is_file and not self._in_headers and not self.completed else 0
        if self.total_bytes - self.payload_bytes - pending_delimiter > _ENVELOPE_LIMIT:
            raise UploadTooLarge(f"Multipart envelope exceeds the limit of {_ENVELOPE_LIMIT} bytes")
        if self._in_headers and self._header_start is not None:
            self._check_header_end(self.total_bytes)

    def _check_header_end(self, end: int) -> None:
        if self._header_start is not None and end - self._header_start > _HEADER_LIMIT:
            raise UploadTooLarge(f"Multipart part headers exceed the limit of {_HEADER_LIMIT} bytes")

    def take_pending(self) -> bytes:
        """Return and clear the file bytes buffered since the last call."""
        if not self._pending:
            return b""
        payload = b"".join(self._pending)
        self._pending.clear()
        return payload

    def _on_part_begin(self) -> None:
        self._in_headers = True
        self._header_start = None
        self._header_field = b""
        self._header_value = b""
        self._disposition = b""
        self._part_name = ""
        self._part_is_file = False
        self._part_value = b""

    def _on_header_field(self, data: bytes, start: int, end: int) -> None:
        if self._header_start is None:
            self._header_start = self._feed_offset + start
        self._check_header_end(self._feed_offset + end)
        self._header_field += data[start:end]

    def _on_header_value(self, data: bytes, start: int, end: int) -> None:
        self._check_header_end(self._feed_offset + end)
        self._header_value += data[start:end]

    def _on_header_end(self) -> None:
        if self._header_field.lower() == b"content-disposition":
            self._disposition = self._header_value
        self._header_field = b""
        self._header_value = b""

    def _on_headers_finished(self) -> None:
        # Callback indices preserve raw header whitespace and CRLF accounting.
        raw = self._feed_tail + self._feed
        raw_offset = self._feed_offset - len(self._feed_tail)
        start = max(0, (self._header_start or 0) - raw_offset)
        terminator = raw.find(b"\r\n\r\n", start)
        if terminator < 0:
            raise MalformedUpload("Multipart part headers are incomplete")
        self._check_header_end(raw_offset + terminator + 4)
        self._in_headers = False
        disposition, options = parse_options_header(self._disposition)
        raw_name = options.get(b"name", b"")
        if len(raw_name) > _FIELD_NAME_LIMIT:
            raise UploadTooLarge(f"Multipart field name exceeds the limit of {_FIELD_NAME_LIMIT} UTF-8 bytes")
        self._part_name = raw_name.decode("utf-8")
        if disposition.lower() != b"form-data" or not self._part_name:
            raise MalformedUpload("Multipart part is missing its form-data name")
        raw_filename = options.get(b"filename")
        self._part_is_file = raw_filename is not None
        if raw_filename is not None:
            if self.saw_file_part:
                raise MalformedUpload("Upload must contain exactly one capture file part")
            if len(raw_filename) > _FILENAME_LIMIT:
                raise UploadTooLarge(f"Original filename exceeds the limit of {_FILENAME_LIMIT} UTF-8 bytes")
            self.original_filename = raw_filename.decode("utf-8")
            self.saw_file_part = True
        else:
            if self._part_name in self._text_names:
                raise MalformedUpload("Multipart text field names must be unique")
            if len(self._text_names) >= _TEXT_PART_LIMIT:
                raise MalformedUpload(f"Multipart upload permits at most {_TEXT_PART_LIMIT} text parts")
            self._text_names.add(self._part_name)

    def _on_part_data(self, data: bytes, start: int, end: int) -> None:
        chunk = data[start:end]
        if self._part_is_file:
            self.payload_bytes += len(chunk)
            self._pending.append(chunk)
        else:
            if len(self._part_value) + len(chunk) > _FIELD_VALUE_LIMIT:
                raise UploadTooLarge(f"Multipart field value exceeds the limit of {_FIELD_VALUE_LIMIT} bytes")
            self._part_value += chunk

    def _on_part_end(self) -> None:
        if not self._part_is_file and self._part_name:
            self.fields[self._part_name] = self._part_value.decode("utf-8")
        self._part_is_file = False

    def _on_end(self) -> None:
        self.completed = True


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
        try:
            media_type, options = parse_options_header(content_type)
        except (UnicodeError, ValueError) as exc:
            raise MalformedUpload("Multipart Content-Type is malformed") from exc
        if media_type.lower() != b"multipart/form-data":
            raise MalformedUpload("Expected a multipart/form-data upload")
        boundary = options.get(b"boundary")
        if not boundary:
            raise MalformedUpload("Multipart upload is missing its boundary")
        if len(boundary) > 70 or any(char not in _BOUNDARY_CHARS for char in boundary) or boundary.endswith(b" "):
            raise MalformedUpload("Multipart boundary must contain 1..70 ASCII MIME boundary characters")
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
        sink: _CaptureSink | None = None

        def allocate() -> None:
            nonlocal sink
            sink = _CaptureSink(self._new_storage_path(), self._max_upload_bytes)

        try:
            await _settle_thread(self._import_dir.mkdir, parents=True, exist_ok=True)
            await _settle_thread(allocate)
            assert sink is not None
            collector = _UploadCollector(sink)
            parser = MultipartParser(boundary, collector.callbacks())
            await self._pump(parser, collector, sink, stream, len(boundary) + 8)
            if not collector.saw_file_part or sink.size_bytes == 0:
                raise MalformedUpload("Upload contained no capture file part")
            if not is_supported_magic(sink.head):
                raise UnsupportedCapture("File is not a pcap or pcapng capture")
            digest = await _settle_thread(sink.finish)
        except BaseException as exc:
            if sink is not None:
                try:
                    await _settle_thread(sink.discard)
                except asyncio.CancelledError:
                    if isinstance(exc, asyncio.CancelledError):
                        raise exc
                    raise
            if isinstance(exc, UploadRejected) or not isinstance(exc, Exception):
                raise
            raise MalformedUpload(f"{type(exc).__name__}: {exc}") from exc
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
        lookbehind: int,
    ) -> None:
        """Feed the request body through the parser into the sink."""
        async for chunk in stream:
            for offset in range(0, len(chunk), _FEED_LIMIT):
                data = chunk[offset : offset + _FEED_LIMIT]
                collector.begin_feed(data)
                parser.write(data)
                collector.check_budgets(lookbehind)
                payload = collector.take_pending()
                if payload:
                    await _settle_thread(sink.write, payload)
        parser.finalize()
        collector.check_budgets()
        if not collector.completed:
            raise MalformedUpload("Multipart upload is missing its complete closing boundary")
        payload = collector.take_pending()
        if payload:
            await _settle_thread(sink.write, payload)
