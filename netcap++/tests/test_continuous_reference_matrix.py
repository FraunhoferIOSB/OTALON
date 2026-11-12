"""Independent packet-window transition plus actual native metric references."""

import importlib

from test_continuous_binding import frame


def reference_groups(times, interval):
    start = 0
    pending = []
    groups = []
    for stamp, size in times:
        if start == 0:
            start = stamp
        if start + interval < stamp:
            if pending:
                groups.append((start, pending))
            pending = []
            start += interval
        pending.append((stamp, size))
    if pending:
        groups.append((start, pending))
    return groups


def test_split_restore_threshold_zero_longgap_duplicates_matrix():
    cls = importlib.import_module("network_capture").NetworkCaptureSession
    fixtures = [
        [(0, 60), (500, 80), (1500, 100), (1501, 120)],
        [(1000, 60), (2000, 60), (2000, 80), (2001, 100)],
        [(1000, 60), (9000, 80), (9001, 100), (9002, 120)],
        [(1000, 60), (1100, 80), (1050, 100), (2200, 120)],
        [(1, 60)],
    ]
    for times in fixtures:
        expected = reference_groups(times, 1000)
        for split in range(len(times) + 1):
            session = cls(1000, 10000, 1000000)
            windows = []
            for index, (stamp, size) in enumerate(times):
                if index == split:
                    replacement = cls(1000, 10000, 1000000)
                    replacement.restore_state(session.export_state())
                    session = replacement
                result = session.push_packet(frame(size), stamp // 1000, stamp % 1000 * 1000000)
                if result is not None:
                    windows.append(result)
            result = session.finish_stream()
            if result is not None:
                windows.append(result)
            assert [window["record_start_ms"] for window in windows] == [start for start, _ in expected]
            for window, (_, packets) in zip(windows, expected, strict=True):
                metric = window["metrics"][0]
                assert metric["packet_count"] == len(packets)
                assert metric["total_volume"] == sum(size for _, size in packets)
                assert metric["min_packet_size"] == min(size for _, size in packets)
                assert metric["max_packet_size"] == max(size for _, size in packets)
