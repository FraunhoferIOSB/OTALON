"""Content-based capture-file identification and time-range extraction.

A capture upload is identified by its **leading bytes**, never by its
filename or declared content type — both are caller-controlled and carry
no assurance (see ``openspec/changes/pcap-import-replay`` §6.1).

Two container formats are recognised:

* classic **pcap** — ``0xa1b2c3d4`` (big-endian file) and ``0xd4c3b2a1``
  (little-endian file);
* **pcapng** — Section Header Block type ``0x0a0d0d0a``, whose byte order
  is resolved from the Byte-Order Magic at offset 8.

The time range is derived from the *packet* timestamps in the file, never
from the wall clock, because the whole point of an import is to place the
measurements at the time the traffic actually happened.
"""

from __future__ import annotations

import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO

from pydantic import BaseModel

MAGIC_PREFIX_LENGTH = 4

PCAP_MAGIC_BE = b"\xa1\xb2\xc3\xd4"
PCAP_MAGIC_LE = b"\xd4\xc3\xb2\xa1"
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

SUPPORTED_MAGICS: tuple[bytes, ...] = (PCAP_MAGIC_BE, PCAP_MAGIC_LE, PCAPNG_MAGIC)

_PCAP_GLOBAL_HEADER_LENGTH = 24
_PCAP_RECORD_HEADER_LENGTH = 16
_PCAPNG_BLOCK_TYPE_IDB = 0x00000001
_PCAPNG_BLOCK_TYPE_EPB = 0x00000006
_PCAPNG_MIN_BLOCK_LENGTH = 12
_PCAPNG_MAX_BLOCK_LENGTH = 16 * 1024 * 1024
_DEFAULT_TSRESOL = 6


class CaptureTimeRange(BaseModel):
    """Time span covered by a capture file, derived from packet timestamps."""

    time_start: datetime
    time_end: datetime
    packet_count: int


def is_supported_magic(prefix: bytes) -> bool:
    """Return whether *prefix* starts with a recognised capture magic.

    Args:
        prefix: The first bytes of the uploaded file (at least
            :data:`MAGIC_PREFIX_LENGTH`).

    Returns:
        ``True`` when the leading four bytes identify pcap or pcapng.
    """
    head = prefix[:MAGIC_PREFIX_LENGTH]
    return head in SUPPORTED_MAGICS


def read_capture_time_range(path: Path) -> CaptureTimeRange | None:
    """Read the first and last packet timestamps of a capture file.

    Performs blocking file IO and therefore must be called from a worker
    thread when invoked from an ``async def`` handler.

    Args:
        path: Absolute path to a stored capture file.

    Returns:
        The covered :class:`CaptureTimeRange`, or ``None`` when the file
        holds no timestamped packet (an empty but structurally valid
        capture) or cannot be parsed.
    """
    try:
        with path.open("rb") as handle:
            magic = handle.read(MAGIC_PREFIX_LENGTH)
            if magic in (PCAP_MAGIC_BE, PCAP_MAGIC_LE):
                return _read_pcap_range(handle, magic)
            if magic == PCAPNG_MAGIC:
                return _read_pcapng_range(handle)
    except (OSError, struct.error, ValueError):
        return None
    return None


def _to_utc(seconds: float) -> datetime:
    """Convert a POSIX timestamp to an aware UTC datetime."""
    return datetime.fromtimestamp(seconds, tz=timezone.utc)


def _range_from(first: float, last: float, count: int) -> CaptureTimeRange:
    """Build a :class:`CaptureTimeRange` from POSIX bounds."""
    low, high = (first, last) if first <= last else (last, first)
    return CaptureTimeRange(time_start=_to_utc(low), time_end=_to_utc(high), packet_count=count)


def _read_pcap_range(handle: BinaryIO, magic: bytes) -> CaptureTimeRange | None:
    """Walk classic pcap record headers, skipping payloads.

    Args:
        handle: Open binary handle positioned after the magic.
        magic: The four magic bytes, which fix the byte order.

    Returns:
        The covered range, or ``None`` for a capture without packets.
    """
    endian = ">" if magic == PCAP_MAGIC_BE else "<"
    handle.seek(_PCAP_GLOBAL_HEADER_LENGTH)
    first: float | None = None
    last: float | None = None
    count = 0
    while True:
        header = handle.read(_PCAP_RECORD_HEADER_LENGTH)
        if len(header) < _PCAP_RECORD_HEADER_LENGTH:
            break
        ts_sec, ts_frac, incl_len, _orig_len = struct.unpack(f"{endian}IIII", header)
        stamp = float(ts_sec) + float(ts_frac) / 1_000_000.0
        first = stamp if first is None else first
        last = stamp
        count += 1
        if handle.seek(incl_len, 1) <= 0 and incl_len:
            break
    if first is None or last is None:
        return None
    return _range_from(first, last, count)


def _pcapng_byte_order(handle: BinaryIO) -> str | None:
    """Resolve the pcapng byte order from the Section Header Block."""
    handle.seek(8)
    order_magic = handle.read(4)
    if order_magic == b"\x1a\x2b\x3c\x4d":
        return ">"
    if order_magic == b"\x4d\x3c\x2b\x1a":
        return "<"
    return None


def _read_pcapng_range(handle: BinaryIO) -> CaptureTimeRange | None:
    """Walk pcapng blocks and collect Enhanced Packet Block timestamps.

    Args:
        handle: Open binary handle on a pcapng file.

    Returns:
        The covered range, or ``None`` when no Enhanced Packet Block with
        a resolvable timestamp is present.
    """
    endian = _pcapng_byte_order(handle)
    if endian is None:
        return None
    resolutions: list[int] = []
    first: float | None = None
    last: float | None = None
    count = 0
    handle.seek(0)
    for block_type, body in _iter_pcapng_blocks(handle, endian):
        if block_type == _PCAPNG_BLOCK_TYPE_IDB:
            resolutions.append(_idb_tsresol(body, endian))
            continue
        if block_type != _PCAPNG_BLOCK_TYPE_EPB or len(body) < 20:
            continue
        interface_id, ts_high, ts_low = struct.unpack(f"{endian}III", body[:12])
        resolution = resolutions[interface_id] if interface_id < len(resolutions) else _DEFAULT_TSRESOL
        stamp = ((ts_high << 32) | ts_low) / float(10**resolution)
        first = stamp if first is None else first
        last = stamp
        count += 1
    if first is None or last is None:
        return None
    return _range_from(first, last, count)


def _iter_pcapng_blocks(handle: BinaryIO, endian: str) -> "list[tuple[int, bytes]]":
    """Return the ``(block_type, body)`` pairs of a pcapng file.

    Malformed or implausibly large blocks terminate the walk instead of
    raising, so a truncated upload degrades to "no time range" rather than
    to a server error.
    """
    blocks: list[tuple[int, bytes]] = []
    while True:
        header = handle.read(8)
        if len(header) < 8:
            return blocks
        block_type, total_length = struct.unpack(f"{endian}II", header)
        if total_length < _PCAPNG_MIN_BLOCK_LENGTH or total_length > _PCAPNG_MAX_BLOCK_LENGTH:
            return blocks
        body = handle.read(total_length - _PCAPNG_MIN_BLOCK_LENGTH)
        if len(body) < total_length - _PCAPNG_MIN_BLOCK_LENGTH:
            return blocks
        if len(handle.read(4)) < 4:
            return blocks
        blocks.append((block_type, body))


def _idb_tsresol(body: bytes, endian: str) -> int:
    """Return the ``if_tsresol`` exponent of an Interface Description Block.

    Only decimal resolutions are honoured; a power-of-two resolution (MSB
    set) falls back to the pcapng default of microseconds, which keeps the
    derived window in the right ballpark instead of failing the import.
    """
    offset = 8
    while offset + 4 <= len(body):
        code, length = struct.unpack(f"{endian}HH", body[offset : offset + 4])
        value = body[offset + 4 : offset + 4 + length]
        if code == 0:
            break
        if code == 9 and length >= 1 and not value[0] & 0x80:
            return int(value[0])
        offset += 4 + length + (-length % 4)
    return _DEFAULT_TSRESOL
