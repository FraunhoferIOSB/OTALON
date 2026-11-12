"""Real compiled native stream contracts; no replacement packet parser or binding mock."""

import importlib

import pytest


def session(interval=1000):
    module = importlib.import_module("network_capture")
    assert hasattr(module, "NetworkCaptureSession"), "appendable native session is missing"
    return module.NetworkCaptureSession(interval, 10000, 1000000)


def frame(size=60):
    return bytes.fromhex("0200000000020200000000010806") + bytes(size - 14)


def feed(s, times):
    windows = []
    for ms, size in times:
        result = s.push_packet(frame(size), ms // 1000, (ms % 1000) * 1000000)
        if result is not None:
            windows.append(result)
    return windows


def test_file_seams_and_restore_preserve_full_native_metrics():
    packets = [(1000200, 60), (1000900, 80), (1001300, 100), (1001600, 120)]
    reference = session()
    expected = feed(reference, packets) + [reference.finish_stream()]
    for split in range(1, len(packets)):
        s = session()
        actual = feed(s, packets[:split])
        restored = session()
        restored.restore_state(s.export_state())
        actual += feed(restored, packets[split:]) + [restored.finish_stream()]
        assert actual == expected
    assert [w["record_start_ms"] for w in expected] == [1000200, 1001200]
    assert [w["metrics"][0]["packet_count"] for w in expected] == [2, 2]
    assert expected[0]["metrics"][0]["total_volume"] == 140
    assert expected[0]["metrics"][0]["mean_interarrival_time"] == 700


def test_equality_quiet_tail_and_long_gap_reference():
    s = session()
    assert feed(s, [(1000, 60), (2000, 60)]) == []
    assert s.export_state()["start_ms"] == 1000
    result = feed(s, [(9000, 60)])
    assert result[0]["metrics"][0]["packet_count"] == 2
    assert s.export_state()["start_ms"] == 2000
    assert s.finish_stream()["metrics"][0]["packet_count"] == 1
    assert s.finish_stream() is None


def test_faults_do_not_reset_or_flush_and_restore_checks_version():
    s = session()
    feed(s, [(1000, 60), (2200, 60)])
    state = s.export_state()
    with pytest.raises(ValueError):
        s.push_packet(frame(), 0, 0)
    assert s.export_state() == state
    bad = dict(state, version=99)
    with pytest.raises(ValueError):
        session().restore_state(bad)
    bounded = importlib.import_module("network_capture").NetworkCaptureSession(1000, 1, 1000)
    bounded.push_packet(frame(), 1, 0)
    with pytest.raises(ValueError):
        bounded.push_packet(frame(), 1, 1000000)
