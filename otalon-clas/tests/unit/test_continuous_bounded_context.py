"""Historical context queries stay bounded after the live stream grows."""

import inspect

from otalon_clas.recovery.progress import LocalProgress


def test_previous_context_reads_only_the_requested_time_range(tmp_path):
    p = LocalProgress(tmp_path)
    for i in range(1, 31):
        minute = i - 1
        p.register(
            {
                "id": i,
                "chunk": str(i),
                "payload": [
                    {
                        "measurement": "network_metrics",
                        "records": [{"time": f"2020-01-01T00:{minute:02}:00+00:00", "uci": "s", "packet_count": i}],
                    }
                ],
            },
            ["conn"],
        )
    assert (
        "start_time" in inspect.signature(p.previous_records).parameters
    ), "historical context has no bounded lower timestamp"
    rows = p.previous_records("conn", "network_metrics", 30, start_time="2020-01-01T00:28:00+00:00", max_records=2)
    assert [r["packet_count"] for r in rows] == [29, 30]
