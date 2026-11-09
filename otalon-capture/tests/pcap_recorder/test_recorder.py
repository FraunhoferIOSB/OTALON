"""PCAP-014: tcpdump stderr must reach the log instead of vanishing."""

from __future__ import annotations

import shutil
import sys
import time
from pathlib import Path
from typing import List

import pytest
from loguru import logger

from pcap_recorder.recorder import TcpdumpRecorder
from pcap_recorder.settings import ArchiveConfig, PcapConfig, RingbufferConfig


def _config(tmp_path: Path, interface: str) -> PcapConfig:
    """Minimal recorder config rooted in ``tmp_path``."""
    return PcapConfig(
        interface=interface,
        chunk_duration_sec=3600,
        ringbuffer=RingbufferConfig(directory=str(tmp_path / "buffer"), max_total_size_mb=1, max_file_count=1),
        archive=ArchiveConfig(directory=str(tmp_path / "archive")),
    )


def _run_and_collect_stderr(recorder: TcpdumpRecorder, timeout_s: float) -> List[str]:
    """Start the recorder and wait for its stderr lines to hit the log."""
    records: List[str] = []
    sink_id = logger.add(lambda message: records.append(message.record["message"]), level="ERROR")
    try:
        recorder.start()
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline and not records:
            time.sleep(0.05)
    finally:
        logger.remove(sink_id)
        recorder.stop()
    return records


def test_stderr_lines_are_logged(tmp_path: Path, monkeypatch) -> None:
    """A subprocess writing to stderr produces ERROR log lines (PCAP-014)."""
    recorder = TcpdumpRecorder(_config(tmp_path, "lo"))
    message = "tcpdump: fake0: No such device exists"
    monkeypatch.setattr(
        TcpdumpRecorder,
        "build_command",
        lambda self: [
            sys.executable,
            "-c",
            f"import sys; print({message!r}, file=sys.stderr)",
        ],
    )

    records = _run_and_collect_stderr(recorder, timeout_s=5.0)

    assert records, "stderr output never reached the log"
    assert any("tcpdump stderr" in line and "No such device exists" in line for line in records)


@pytest.mark.skipif(shutil.which("tcpdump") is None, reason="tcpdump not installed")
def test_invalid_interface_failure_is_logged(tmp_path: Path) -> None:
    """Starting with a bogus interface logs the tcpdump error (PCAP-014).

    Previously the failure vanished into DEVNULL and the recorder looked
    healthy while producing no packets.
    """
    recorder = TcpdumpRecorder(_config(tmp_path, "noexist0"))

    records = _run_and_collect_stderr(recorder, timeout_s=8.0)

    assert records, "tcpdump startup failure never reached the log"
    assert any("device" in line.lower() for line in records), records
