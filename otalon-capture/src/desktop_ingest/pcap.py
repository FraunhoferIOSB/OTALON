"""Bounded classic Ethernet PCAP framing; no protocol or metric reimplementation."""

from __future__ import annotations

import struct
from collections.abc import Iterator

MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1000),
    b"\xa1\xb2\xc3\xd4": (">", 1000),
    b"\x4d\x3c\xb2\xa1": ("<", 1),
    b"\xa1\xb2\x3c\x4d": (">", 1),
}


def records(data: bytes) -> Iterator[tuple[bytes, int, int]]:
    if len(data) < 24 or data[:4] not in MAGIC:
        raise ValueError("classic PCAP required")
    endian, scale = MAGIC[data[:4]]
    major, minor, zone, sig, snap, link = struct.unpack_from(endian + "HHIIII", data, 4)
    if (major, minor) != (2, 4) or not 14 <= snap <= 262144 or link != 1:
        raise ValueError("Ethernet PCAP required")
    offset = 24
    while offset < len(data):
        if len(data) - offset < 16:
            raise ValueError("truncated record header")
        sec, fraction, captured, original = struct.unpack_from(endian + "IIII", data, offset)
        offset += 16
        if (
            captured < 14
            or captured > snap
            or original < captured
            or fraction * scale >= 1000000000
            or captured > len(data) - offset
        ):
            raise ValueError("invalid or truncated record")
        yield data[offset : offset + captured], sec, fraction * scale
        offset += captured


def validate(data: bytes) -> tuple[int, int | None, int | None]:
    count = 0
    first = None
    last = None
    for _, sec, ns in records(data):
        stamp = sec * 1000000000 + ns
        count += 1
        first = stamp if first is None else min(first, stamp)
        last = stamp if last is None else max(last, stamp)
    return count, first, last
