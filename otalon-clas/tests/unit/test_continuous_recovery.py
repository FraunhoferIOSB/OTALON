"""Historical recovery must not rewind or mutate the live frequency monitor."""

import importlib.util
from datetime import datetime, timezone

import polars as pl

from otalon_clas.detection.frequency_monitor import FrequencyMonitor, _SeriesFrequencyProfile


def test_historical_context_is_separate_and_never_inherits_future_last_seen():
    assert importlib.util.find_spec("otalon_clas.recovery.context"), "continuous recovery context missing"
    from otalon_clas.recovery.context import isolated_frequency

    live = FrequencyMonitor(module_name="conn")
    stamp = datetime(2026, 11, 12, tzinfo=timezone.utc)
    live._profiles = {"s1": _SeriesFrequencyProfile(1, 0.1, stamp)}
    historical = isolated_frequency(live)
    assert historical.repository is None
    assert historical._profiles["s1"].last_seen is None
    historical.check(pl.DataFrame({"time": [stamp], "uci": ["s1"]}), "uci", "2026-11-11T00:00:00+00:00")
    assert live._profiles["s1"].last_seen == stamp
    assert not live._dirty_last_seen and not live._absence_episodes


def test_progress_registration_and_completion_are_durable(tmp_path):
    assert importlib.util.find_spec("otalon_clas.recovery.progress"), "continuous module progress missing"
    from otalon_clas.recovery.progress import LocalProgress

    progress = LocalProgress(tmp_path)
    batch = {"id": 1, "chunk": "fixed-source-chunk", "payload": []}
    progress.register(batch, ["conn", "mac_traffic"])
    assert progress.next_work("conn")["batch"] == batch
    progress.complete("conn", 1, {"version": 1}, [], {"bounds": "evaluated", "frequency": "context_missing"})
    progress.close()
    progress = LocalProgress(tmp_path)
    assert progress.next_work("conn") is None
    assert progress.next_work("mac_traffic")["batch"] == batch
    assert progress.checkpoint("conn") == {"version": 1}
