"""Historical outcomes must also survive the original portable-state reopen."""

from otalon_clas.recovery.progress import LocalProgress


def test_exact_retry_payload_reachable_after_reopen_and_other_module_backlog(tmp_path):
    progress = LocalProgress(tmp_path)
    for number in range(11):
        progress.put_outcome(str(number), "conn", {"number": number})
    progress.put_outcome("live_last", "__live__", {"records": []})
    progress.close()
    progress = LocalProgress(tmp_path)
    assert progress.outcome("10")["payload"] == {"number": 10}
    assert [row["id"] for row in progress.outcomes(module="__live__")] == ["live_last"]
    progress.ack_outcome("live_last")
    assert progress.outcome("live_last") is None
    assert not progress.outcomes(module="__live__")
