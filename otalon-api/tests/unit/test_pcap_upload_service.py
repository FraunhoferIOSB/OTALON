"""Tests for the streaming capture-upload sink (UI-078 Wave B, B2–B4).

Exercised directly (without FastAPI) so the streaming guarantees can be
asserted precisely: the size bound must bite **while** the body streams,
and every refusal must leave the import directory clean.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import AsyncIterator, Iterator

import pytest

from otalon_api.services.pcap_upload_service import (
    MalformedUpload,
    PcapUploadService,
    UnsupportedCapture,
    UploadTooLarge,
)
from tests.helpers.pcap_fixtures import padded_pcap_bytes, pcap_bytes

pytestmark = pytest.mark.unit

_BOUNDARY = "testboundary"
_CONTENT_TYPE = f"multipart/form-data; boundary={_BOUNDARY}"


@pytest.fixture()
def import_dir() -> Iterator[Path]:
    """Provide an isolated import directory removed after the test."""
    path = Path(tempfile.mkdtemp(prefix="pcap-upload-"))
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def _multipart(content: bytes, filename: str = "kunde.pcap", fields: dict[str, str] | None = None) -> bytes:
    """Assemble a multipart body with one file part and optional fields."""
    parts: list[bytes] = []
    for name, value in (fields or {}).items():
        parts.append(f'--{_BOUNDARY}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'.encode())
    parts.append(
        f'--{_BOUNDARY}\r\nContent-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n".encode()
    )
    parts.append(content)
    parts.append(f"\r\n--{_BOUNDARY}--\r\n".encode())
    return b"".join(parts)


async def _stream(body: bytes, chunk_size: int = 8192) -> AsyncIterator[bytes]:
    """Yield *body* in chunks, mirroring a real request stream."""
    for offset in range(0, len(body), chunk_size):
        yield body[offset : offset + chunk_size]


def _files(import_dir: Path) -> list[Path]:
    """Return the files currently held in the import directory."""
    return [p for p in import_dir.iterdir() if p.is_file()]


class TestAcceptedUpload:
    """B4 — the stored name is generated, the original is metadata."""

    async def test_valid_capture_is_stored_under_a_generated_name(self, import_dir: Path) -> None:
        """The stored file carries a UUID name, not the caller's."""
        service = PcapUploadService(import_dir, 10_000_000)
        content = pcap_bytes([1_700_000_000.0])
        stored = await service.store(_CONTENT_TYPE, _stream(_multipart(content)))
        assert stored.original_filename == "kunde.pcap"
        assert stored.filename != "kunde.pcap"
        assert stored.filename.endswith(".pcap")
        assert stored.path.parent == import_dir
        assert stored.path.read_bytes() == content
        assert stored.size_bytes == len(content)
        assert len(stored.sha256) == 64

    async def test_traversal_name_never_reaches_the_path(self, import_dir: Path) -> None:
        """A ``../`` filename cannot escape the import directory."""
        service = PcapUploadService(import_dir, 10_000_000)
        stored = await service.store(
            _CONTENT_TYPE,
            _stream(_multipart(pcap_bytes([1.0]), filename="../../etc/passwd")),
        )
        assert stored.original_filename == "../../etc/passwd"
        assert ".." not in stored.filename
        assert stored.path.resolve().parent == import_dir.resolve()

    async def test_force_field_is_parsed(self, import_dir: Path) -> None:
        """A ``force`` form field is carried alongside the file."""
        service = PcapUploadService(import_dir, 10_000_000)
        stored = await service.store(
            _CONTENT_TYPE,
            _stream(_multipart(pcap_bytes([1.0]), fields={"force": "true"})),
        )
        assert stored.force is True

    async def test_force_defaults_to_false(self, import_dir: Path) -> None:
        """Without the field the import is not forced."""
        service = PcapUploadService(import_dir, 10_000_000)
        stored = await service.store(_CONTENT_TYPE, _stream(_multipart(pcap_bytes([1.0]))))
        assert stored.force is False


class TestRefusedUpload:
    """B2/B3 — every refusal leaves the import location clean."""

    async def test_non_capture_is_refused(self, import_dir: Path) -> None:
        """Content that is not a capture is rejected regardless of name."""
        service = PcapUploadService(import_dir, 10_000_000)
        with pytest.raises(UnsupportedCapture):
            await service.store(_CONTENT_TYPE, _stream(_multipart(b"PK\x03\x04definitely a zip")))
        assert _files(import_dir) == []

    async def test_oversized_upload_is_refused_mid_stream(self, import_dir: Path) -> None:
        """The bound bites during streaming and removes the partial file."""
        service = PcapUploadService(import_dir, 4096)
        with pytest.raises(UploadTooLarge):
            await service.store(_CONTENT_TYPE, _stream(_multipart(padded_pcap_bytes(100_000))))
        assert _files(import_dir) == []

    async def test_understated_content_length_does_not_help(self, import_dir: Path) -> None:
        """The bound is enforced on received bytes, not on a declared size.

        The sink never sees ``Content-Length`` at all — it only counts what
        it actually writes — so a caller lying about the size gains nothing.
        """
        service = PcapUploadService(import_dir, 4096)
        with pytest.raises(UploadTooLarge):
            await service.store(_CONTENT_TYPE, _stream(_multipart(padded_pcap_bytes(50_000)), chunk_size=512))
        assert _files(import_dir) == []

    async def test_empty_file_part_is_refused(self, import_dir: Path) -> None:
        """A zero-byte upload carries no capture."""
        service = PcapUploadService(import_dir, 10_000_000)
        with pytest.raises(MalformedUpload):
            await service.store(_CONTENT_TYPE, _stream(_multipart(b"")))
        assert _files(import_dir) == []

    async def test_request_without_a_file_part_is_refused(self, import_dir: Path) -> None:
        """A form without a file part is not an upload."""
        service = PcapUploadService(import_dir, 10_000_000)
        body = f'--{_BOUNDARY}\r\nContent-Disposition: form-data; name="force"\r\n\r\ntrue\r\n--{_BOUNDARY}--\r\n'
        with pytest.raises(MalformedUpload):
            await service.store(_CONTENT_TYPE, _stream(body.encode()))
        assert _files(import_dir) == []

    async def test_non_multipart_request_is_refused(self, import_dir: Path) -> None:
        """A raw body is not accepted as an upload envelope."""
        service = PcapUploadService(import_dir, 10_000_000)
        with pytest.raises(MalformedUpload):
            await service.store("application/octet-stream", _stream(pcap_bytes([1.0])))
        assert _files(import_dir) == []

    async def test_multipart_without_boundary_is_refused(self, import_dir: Path) -> None:
        """A multipart header without a boundary cannot be parsed."""
        service = PcapUploadService(import_dir, 10_000_000)
        with pytest.raises(MalformedUpload):
            await service.store("multipart/form-data", _stream(b"whatever"))
        assert _files(import_dir) == []
