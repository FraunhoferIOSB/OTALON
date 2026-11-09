"""Tests for content-based capture identification (UI-078 Wave B, B2/B5).

The rule under test is that a capture is recognised by its **leading
bytes** and that the covered window comes from the packet timestamps in
the file — never from the filename, the content type or the wall clock.
"""

from __future__ import annotations

import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

import pytest

from otalon_api.domain.pcap_import import (
    SUPPORTED_MAGICS,
    is_supported_magic,
    read_capture_time_range,
)
from tests.helpers.pcap_fixtures import (
    PCAP_MAGIC_BE,
    PCAP_MAGIC_LE,
    PCAPNG_MAGIC,
    pcap_bytes,
    pcapng_bytes,
)

pytestmark = pytest.mark.unit

_FIRST = datetime(2026, 6, 1, 10, 0, tzinfo=timezone.utc)
_LAST = datetime(2026, 6, 1, 10, 15, tzinfo=timezone.utc)


@pytest.fixture()
def tmp_capture_dir() -> Iterator[Path]:
    """Provide a temporary directory for capture fixtures."""
    with tempfile.TemporaryDirectory(prefix="capture-domain-") as name:
        yield Path(name)


class TestMagicDetection:
    """B2 — both pcap endiannesses and pcapng are recognised."""

    @pytest.mark.parametrize("magic", [PCAP_MAGIC_BE, PCAP_MAGIC_LE, PCAPNG_MAGIC])
    def test_supported_magics_are_accepted(self, magic: bytes) -> None:
        """Each documented magic identifies a capture."""
        assert is_supported_magic(magic + b"trailing bytes")

    def test_all_documented_magics_are_registered(self) -> None:
        """The module exposes exactly the three documented signatures."""
        assert set(SUPPORTED_MAGICS) == {PCAP_MAGIC_BE, PCAP_MAGIC_LE, PCAPNG_MAGIC}

    @pytest.mark.parametrize(
        "content",
        [b"PK\x03\x04zip", b"%PDF-1.7", b"\x7fELF", b"", b"\xd4\xc3", b"plain text file"],
    )
    def test_non_captures_are_rejected(self, content: bytes) -> None:
        """Anything else is not a capture, whatever it is named."""
        assert is_supported_magic(content) is False


class TestTimeRangeExtraction:
    """B5 — the window comes from the packets, not from the clock."""

    def test_pcap_window_matches_the_packet_timestamps(self, tmp_capture_dir: Path) -> None:
        """A classic pcap yields its first and last packet time."""
        path = tmp_capture_dir / "a.pcap"
        path.write_bytes(pcap_bytes([_FIRST.timestamp(), _LAST.timestamp()]))
        window = read_capture_time_range(path)
        assert window is not None
        assert window.time_start == _FIRST
        assert window.time_end == _LAST
        assert window.packet_count == 2

    def test_pcapng_window_matches_the_packet_timestamps(self, tmp_capture_dir: Path) -> None:
        """A pcapng file yields the same window as its pcap equivalent."""
        path = tmp_capture_dir / "a.pcapng"
        path.write_bytes(pcapng_bytes([_FIRST.timestamp(), _LAST.timestamp()]))
        window = read_capture_time_range(path)
        assert window is not None
        assert window.time_start == _FIRST
        assert window.time_end == _LAST

    def test_historical_capture_does_not_get_todays_timestamps(self, tmp_capture_dir: Path) -> None:
        """A 2020 capture stays in 2020 — the whole point of the import."""
        historic = datetime(2020, 3, 4, 5, 6, tzinfo=timezone.utc)
        path = tmp_capture_dir / "old.pcap"
        path.write_bytes(pcap_bytes([historic.timestamp()]))
        window = read_capture_time_range(path)
        assert window is not None
        assert window.time_start.year == 2020
        assert window.time_end < datetime.now(timezone.utc)

    def test_capture_without_packets_has_no_window(self, tmp_capture_dir: Path) -> None:
        """A header-only capture reports no window rather than guessing."""
        path = tmp_capture_dir / "empty.pcap"
        path.write_bytes(pcap_bytes([]))
        assert read_capture_time_range(path) is None

    def test_truncated_capture_degrades_instead_of_raising(self, tmp_capture_dir: Path) -> None:
        """A truncated file yields no window instead of a server error."""
        path = tmp_capture_dir / "cut.pcap"
        path.write_bytes(pcap_bytes([_FIRST.timestamp()])[:30])
        assert read_capture_time_range(path) is None

    def test_missing_file_yields_no_window(self, tmp_capture_dir: Path) -> None:
        """A vanished file is reported as "no window", not as a crash."""
        assert read_capture_time_range(tmp_capture_dir / "nope.pcap") is None
