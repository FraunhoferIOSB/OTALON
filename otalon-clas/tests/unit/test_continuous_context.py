"""Production connection preprocessors carry DB clients, never deepcopy engines."""

from otalon_clas.preprocessing.connection import ConnectionPreprocessor
from otalon_clas.preprocessing.sliding_window import SlidingWindowPreprocessor
from otalon_clas.recovery.context import isolated_frequency


def test_copy_connection_context_does_not_copy_database_lock():
    from otalon_clas.recovery import context

    assert hasattr(context, "isolated_preprocessor"), "historical preprocessor snapshot missing"

    class Repository:
        def __deepcopy__(self, memo):
            raise TypeError("database engines cannot be copied")

    live = ConnectionPreprocessor(rules_repository=Repository())
    live._protocol_to_code = {"arp": 42}
    historical = context.isolated_preprocessor(live)
    historical._protocol_to_code["tcp"] = 43
    assert live._protocol_to_code == {"arp": 42}
    assert historical._rules_repository is live._rules_repository
    rolling = context.isolated_preprocessor(SlidingWindowPreprocessor(live, 10))
    assert rolling._base is not live


def test_live_frequency_overrides_are_preserved_without_last_seen():
    from datetime import datetime, timezone

    from otalon_clas.detection.frequency_monitor import FrequencyMonitor, _SeriesFrequencyProfile

    live = FrequencyMonitor(module_name="conn")
    live._profiles = {"s": _SeriesFrequencyProfile(1, 0.2, datetime.now(timezone.utc), absence_factor_override=350)}
    historical = isolated_frequency(live)
    assert historical._profiles["s"].absence_factor_override == 350
    assert historical._profiles["s"].last_seen is None
