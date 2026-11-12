"""Collector owns immutable notified files; no capture/Windows hardware in unit tier."""

import importlib.util

import pytest


def test_persistent_spool_retry_and_no_ring_reuse(tmp_path):
    assert importlib.util.find_spec("windows_collector"), "Windows collector missing"
    from windows_collector.collector import Spool, command

    s = Spool(tmp_path)
    run = s.begin_run()
    from test_lifecycle import data

    file = tmp_path / (run + "_00001_20261112120000.pcap")
    file.write_bytes(data())
    s.closed_file(run, file)
    assert s.pending()[0]["ordinal"] == 0
    s.close()
    s = Spool(tmp_path)
    assert s.pending()[0]["run"] == run
    assert "files:10" not in command(
        "C:/dumpcap.exe", "\\Device\\NPF_{01234567-0123-0123-0123-012345678901}", tmp_path / "c.pcap", 2, 1024
    )
    args = command("C:/dumpcap.exe", "nic", tmp_path / "c.pcap", 2, 1024)
    assert "printname:stdout" in args and "-F" in args and "pcap" in args
    s.acknowledge(run, 0, s.pending()[0]["hash"])
    assert not s.pending() and not file.exists()


def test_spool_path_escape_and_mutated_file_refused(tmp_path):
    from windows_collector.collector import Spool

    s = Spool(tmp_path / "owned")
    run = s.begin_run()
    outside = tmp_path / "outside"
    outside.write_bytes(b"not-owned")
    with pytest.raises(ValueError):
        s.closed_file(run, outside)
    assert outside.exists()
