"""B2 lazy bounded PCAPNG iteration with unchanged public time/dialect semantics."""

from __future__ import annotations

import inspect
import io
import struct
from datetime import datetime, timezone
from pathlib import Path

import pytest

from otalon_api.domain.pcap_import import SUPPORTED_MAGICS, is_supported_magic, read_capture_time_range
from otalon_api.domain.pcap_import.capture import _iter_pcapng_blocks
from tests.helpers.pcap_fixtures import pcapng_bytes

pytestmark = pytest.mark.unit
BLOCK_LIMIT = 16 * 1024 * 1024


def _block(kind: int, body: bytes, endian: str = "<") -> bytes:
    """Create genuine synthetic blocks with padding and matching trailers."""
    body += b"\x00" * (-len(body) % 4)
    length = len(body) + 12
    return struct.pack(f"{endian}II", kind, length) + body + struct.pack(f"{endian}I", length)


class _ObservedHandle(io.BytesIO):
    """Record read sizes and reject hidden unbounded reads."""

    def __init__(self, payload: bytes) -> None:
        super().__init__(payload)
        self.reads: list[int] = []

    def read(self, size: int = -1) -> bytes:
        assert 0 <= size <= BLOCK_LIMIT
        self.reads.append(size)
        return super().read(size)


def test_iterator_is_lazy_and_retains_no_block_list() -> None:
    """Requesting one block cannot read or retain later blocks."""
    first = _block(1, b"a" * 8)
    handle = _ObservedHandle(first + _block(6, b"b" * 24) * 100)
    blocks = _iter_pcapng_blocks(handle, "<")
    assert inspect.isgenerator(blocks)
    assert handle.reads == []
    assert next(blocks) == (1, b"a" * 8)
    assert handle.tell() == len(first)
    assert handle.reads == [8, 8, 4]
    assert blocks.gi_frame is not None
    assert not any(isinstance(value, list) for value in blocks.gi_frame.f_locals.values())
    blocks.close()
    assert handle.tell() == len(first)


@pytest.mark.parametrize("endian", ["<", ">"])
def test_exact_16_mib_block_is_yielded(endian: str) -> None:
    """The existing inclusive per-block cap remains exactly 16 MiB."""
    body = b"a" * (BLOCK_LIMIT - 12)
    handle = _ObservedHandle(_block(42, body, endian))
    blocks = iter(_iter_pcapng_blocks(handle, endian))
    assert next(blocks) == (42, body)
    assert list(blocks) == []
    assert max(handle.reads) == BLOCK_LIMIT - 12


@pytest.mark.parametrize("length", [0, 8, 11, BLOCK_LIMIT + 1, BLOCK_LIMIT + 4])
def test_bad_length_stops_before_body_read(length: int) -> None:
    """Malformed and oversized lengths terminate without reading claimed bodies."""
    handle = _ObservedHandle(struct.pack("<II", 42, length) + b"unread")
    assert list(_iter_pcapng_blocks(handle, "<")) == []
    assert handle.reads == [8]
    assert handle.tell() == 8


@pytest.mark.parametrize("cut", [1, 4, 8, 15, 19])
def test_truncated_next_block_preserves_prior_block(cut: int) -> None:
    """A cut header, body or trailer stops the same walk after prior valid blocks."""
    first = _block(1, b"a" * 8)
    second = _block(6, b"b" * 24)
    assert list(_iter_pcapng_blocks(io.BytesIO(first + second[:cut]), "<")) == [(1, b"a" * 8)]


def test_existing_trailer_semantics_not_tightened() -> None:
    """This iterator conversion does not add unrelated trailer equality checks."""
    body = b"a" * 8
    block = _block(1, body)[:-4] + struct.pack("<I", 99)
    assert list(_iter_pcapng_blocks(io.BytesIO(block), "<")) == [(1, body)]


@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("resolution,exponent", [(None, 6), (3, 3), (6, 6), (9, 9), (0x86, 6)])
@pytest.mark.parametrize("interface", [0, 7])
def test_resolution_endianness_and_interface_fallback(
    tmp_path: Path, endian: str, resolution: int | None, exponent: int, interface: int
) -> None:
    """Decimal, default and power-of-two fallback preserve first/last range truth."""
    shb = _block(0x0A0D0D0A, struct.pack(f"{endian}IHHq", 0x1A2B3C4D, 1, 0, -1), endian)
    idb = struct.pack(f"{endian}HHI", 1, 0, 65535)
    if resolution is not None:
        idb += struct.pack(f"{endian}HH", 9, 1) + bytes([resolution]) + b"\x00" * 3
    idb += struct.pack(f"{endian}HH", 0, 0)
    effective = exponent if interface == 0 else 6
    stamps = [20.125, 100.5, 10.25]
    packets = b""
    for stamp in stamps:
        ticks = int(stamp * 10**effective)
        packets += _block(
            6, struct.pack(f"{endian}IIIII", interface, ticks >> 32, ticks & 0xFFFFFFFF, 4, 4) + b"data", endian
        )
    path = tmp_path / "synthetic.pcapng"
    path.write_bytes(shb + _block(1, idb, endian) + packets)
    result = read_capture_time_range(path)
    assert result is not None
    assert result.time_start == datetime.fromtimestamp(stamps[-1], timezone.utc)
    assert result.time_end == datetime.fromtimestamp(stamps[0], timezone.utc)
    assert result.packet_count == 3


def test_public_fixture_and_truncated_range(tmp_path: Path) -> None:
    """Public fixture timestamps survive lazy iteration and malformed-tail termination."""
    path = tmp_path / "public.pcapng"
    path.write_bytes(pcapng_bytes([1.125, 2.25]) + b"cut")
    result = read_capture_time_range(path)
    assert result is not None
    assert result.time_start == datetime.fromtimestamp(1.125, timezone.utc)
    assert result.time_end == datetime.fromtimestamp(2.25, timezone.utc)
    assert result.packet_count == 2


def test_supported_dialects_remain_exact() -> None:
    """Neither nanosecond classic magic nor a different dialect is newly admitted."""
    assert SUPPORTED_MAGICS == (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1", b"\x0a\x0d\x0d\x0a")
    assert is_supported_magic(b"\xa1\xb2\x3c\x4d") is False
    assert is_supported_magic(b"\x4d\x3c\xb2\xa1") is False
