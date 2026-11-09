"""Tests fuer die Capture-Loss-Observability (PCAP-006)."""

from __future__ import annotations

from pathlib import Path

import pytest

from pcap_recorder.capture_stats import (
    CaptureLossMonitor,
    CaptureLossSnapshot,
    InterfaceCounters,
    describe_counters,
    read_interface_counters,
)

DEV_HEADER = (
    "Inter-|   Receive                                                |  Transmit\n"
    " face |bytes    packets errs drop fifo frame compressed multicast|bytes\n"
)


def _write_dev(tmp_path: Path, rows: str) -> Path:
    path = tmp_path / "net_dev"
    path.write_text(DEV_HEADER + rows, encoding="utf-8")
    return path


def _counters(packets: int, drop: int, fifo: int) -> InterfaceCounters:
    return InterfaceCounters(rx_packets=packets, rx_drop=drop, rx_fifo=fifo)


def test_read_interface_counters_parses_rx_fields(tmp_path: Path) -> None:
    path = _write_dev(tmp_path, "  enp5s0: 800 1250 0 1220 7 0 0 19\n")

    counters = read_interface_counters("enp5s0", proc_net_dev=path)

    assert counters == _counters(1250, 1220, 7)


def test_read_interface_counters_matches_real_mirror_port_row(tmp_path: Path) -> None:
    """Regression guard against the live enp5s0 shape (huge rx_drop, zero rx_fifo)."""

    path = _write_dev(tmp_path, "  enp5s0: 80329078099 1251474031 0 1225631172 0 0 0 1957904\n")

    counters = read_interface_counters("enp5s0", proc_net_dev=path)

    assert counters is not None
    assert counters.rx_drop == 1225631172
    assert counters.rx_fifo == 0


def test_read_interface_counters_ignores_other_interfaces(tmp_path: Path) -> None:
    rows = "  eno1: 800 10 0 5 4 0 0 0\n  enp5s0: 800 1250 0 1220 7 0 0 19\n"
    path = _write_dev(tmp_path, rows)

    counters = read_interface_counters("enp5s0", proc_net_dev=path)

    assert counters is not None
    assert counters.rx_packets == 1250


def test_read_interface_counters_unknown_interface(tmp_path: Path) -> None:
    path = _write_dev(tmp_path, "  eno1: 800 10 0 0 0 0 0 0\n")

    assert read_interface_counters("enp5s0", proc_net_dev=path) is None


def test_read_interface_counters_missing_file(tmp_path: Path) -> None:
    assert read_interface_counters("enp5s0", proc_net_dev=tmp_path / "absent") is None


def test_read_interface_counters_malformed_row(tmp_path: Path) -> None:
    path = _write_dev(tmp_path, "  enp5s0: 800 1250\n")

    assert read_interface_counters("enp5s0", proc_net_dev=path) is None


def test_read_interface_counters_non_numeric(tmp_path: Path) -> None:
    path = _write_dev(tmp_path, "  enp5s0: 800 abc 0 x 7 0 0 19\n")

    assert read_interface_counters("enp5s0", proc_net_dev=path) is None


def test_monitor_first_poll_returns_baseline_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "pcap_recorder.capture_stats.read_interface_counters",
        lambda _iface, **_kwargs: _counters(100, 10, 0),
    )
    monitor = CaptureLossMonitor("enp5s0")

    assert monitor.poll() is None


def test_monitor_reports_deltas(monkeypatch: pytest.MonkeyPatch) -> None:
    samples = [_counters(100, 10, 0), _counters(180, 25, 3)]
    monkeypatch.setattr(
        "pcap_recorder.capture_stats.read_interface_counters",
        lambda _iface, **_kwargs: samples.pop(0),
    )
    monitor = CaptureLossMonitor("enp5s0")

    assert monitor.poll() is None
    snapshot = monitor.poll()

    assert snapshot == CaptureLossSnapshot(interface="enp5s0", rx_packets=80, rx_drop=15, rx_fifo=3)
    assert snapshot.has_capture_loss is True


def test_monitor_counter_reset_clamps_to_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    samples = [_counters(500, 50, 9), _counters(10, 1, 0)]
    monkeypatch.setattr(
        "pcap_recorder.capture_stats.read_interface_counters",
        lambda _iface, **_kwargs: samples.pop(0),
    )
    monitor = CaptureLossMonitor("enp5s0")

    monitor.poll()
    snapshot = monitor.poll()

    assert snapshot == CaptureLossSnapshot(interface="enp5s0", rx_packets=0, rx_drop=0, rx_fifo=0)


def test_mirror_port_stack_drops_are_not_capture_loss() -> None:
    """The live capture NIC shows ~98% rx_drop with zero rx_fifo; that is benign."""

    snapshot = CaptureLossSnapshot(interface="enp5s0", rx_packets=15000, rx_drop=14800, rx_fifo=0)

    assert snapshot.has_capture_loss is False


def test_nic_level_miss_is_capture_loss() -> None:
    snapshot = CaptureLossSnapshot(interface="enp5s0", rx_packets=15000, rx_drop=0, rx_fifo=4)

    assert snapshot.has_capture_loss is True


def test_monitor_returns_none_when_counters_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "pcap_recorder.capture_stats.read_interface_counters",
        lambda _iface, **_kwargs: None,
    )
    monitor = CaptureLossMonitor("absent0")

    assert monitor.poll() is None
    assert monitor.poll_and_log() is None


def test_poll_and_log_warns_on_capture_loss(monkeypatch: pytest.MonkeyPatch) -> None:
    samples = [_counters(100, 10, 0), _counters(200, 20, 5)]
    monkeypatch.setattr(
        "pcap_recorder.capture_stats.read_interface_counters",
        lambda _iface, **_kwargs: samples.pop(0),
    )
    records: list[str] = []
    from loguru import logger

    sink_id = logger.add(lambda message: records.append(message.record["level"].name), level="DEBUG")
    try:
        monitor = CaptureLossMonitor("enp5s0")
        monitor.poll_and_log()
        monitor.poll_and_log()
    finally:
        logger.remove(sink_id)

    assert "WARNING" in records


def test_describe_counters_aggregates() -> None:
    snapshots = [
        CaptureLossSnapshot(interface="enp5s0", rx_packets=10, rx_drop=2, rx_fifo=1),
        CaptureLossSnapshot(interface="enp5s0", rx_packets=5, rx_drop=1, rx_fifo=0),
    ]

    assert describe_counters(snapshots) == {"rx_packets": 15, "rx_drop": 3, "rx_fifo": 1}
