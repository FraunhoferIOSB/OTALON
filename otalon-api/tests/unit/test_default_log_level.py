"""SUITE-060: the API logging default must not be DEBUG (GB log volume)."""

from otalon_api.settings import LoggingConfig, Settings


def test_settings_logging_level_default_is_info(monkeypatch) -> None:
    monkeypatch.delenv("LOGGING_LEVEL", raising=False)
    assert Settings.model_fields["logging_level"].default == "INFO"


def test_logging_config_default_is_not_debug() -> None:
    assert LoggingConfig().level != "DEBUG"


def test_runtime_settings_from_shipped_config_is_not_debug(monkeypatch) -> None:
    # The runtime singleton (dependencies.get_settings) loads config/config.json,
    # not the bare field default. Test that path, or the shipped DEBUG value slips through.
    monkeypatch.delenv("LOGGING_LEVEL", raising=False)
    assert Settings.from_config_json().log_config.level != "DEBUG"
