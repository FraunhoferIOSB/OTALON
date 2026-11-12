"""Copy learned frequency statistics without future live observation state."""

from copy import copy, deepcopy

from otalon_clas.detection.frequency_monitor import FrequencyMonitor


def isolated_frequency(live: FrequencyMonitor) -> FrequencyMonitor:
    historical = FrequencyMonitor(
        frequency_tolerance_factor=live._frequency_tolerance_factor,
        absence_timeout_factor=live._absence_timeout_factor,
        absence_timeout_std_factor=live._absence_timeout_std_factor,
        min_intervals=live._min_intervals,
        relative_floor_factor=live._relative_floor_factor,
        absence_recovery_cycles=live._absence_recovery_cycles,
        absence_timeout_floor_seconds=live._absence_timeout_floor_s,
        absence_interval_cap_seconds=live._absence_interval_cap_s,
        module_name=live._module_name,
        repository=None,
    )
    historical._profiles = {key: copy(profile) for key, profile in list(live._profiles.items())}
    for profile in historical._profiles.values():
        profile.last_seen = None
    historical._rebuild_profile_index()
    historical._blacklist = live._blacklist
    return historical


def isolated_preprocessor(live):
    """Copy mutable learned maps/caches, preserving external read-only repositories."""
    historical = copy(live)
    for key, value in live.__dict__.items():
        if key == "_base":
            setattr(historical, key, isolated_preprocessor(value))
        elif isinstance(value, (dict, list, set)):
            setattr(historical, key, deepcopy(value))
    return historical
