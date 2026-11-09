"""CLAS-038/CLAS-071 regression: ``SERIES_BLACKLIST`` must reach ``conn`` as a list.

The ``blacklist`` field of the ``conn`` module is fed from the
``$SERIES_BLACKLIST`` placeholder in ``config/config.json`` (renamed from
``NETCAP_BLACKLIST`` in CLAS-071 D4 with no legacy fallback). The shared
resolver only parses a JSON-array-shaped value when ``json_arrays=True``;
without it the whole array arrives as one long string and every consumer
wraps that string as a *single* pattern, so no series is ever excluded.

These tests load the real ``config/config.json`` with a synthetic
environment value and assert the resolved pattern count, the matching
behaviour of the three consumers, and that the dead ``NETCAP_BLACKLIST``
name is not read as a fallback anywhere.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from otalon_common.config import MissingEnvVarPolicy

from otalon_clas.common.settings import AppConfig
from otalon_clas.detection.bounds_manager import BoundsManager, BoundsTrainer
from otalon_clas.detection.frequency_monitor import FrequencyMonitor

pytestmark = pytest.mark.unit

_CLAS_ROOT = Path(__file__).resolve().parents[2]
_CONFIG_PATH = _CLAS_ROOT / "config" / "config.json"

_PATTERN_COUNT = 3
"""Entry count of the synthetic blacklist array used by these tests."""

_SYNTHETIC_BLACKLIST = json.dumps(
    [
        "IPv6",
        "ff:ff:ff:ff:ff:ff",
        "8.8.8.8",
    ]
)
"""A valid pattern set covering the three entry forms used below."""

_MULTICAST_SERIES = "ff:ff:ff:ff:ff:ff"
"""A series name the blacklist is meant to exclude."""

_LEGITIMATE_SERIES = "a8:74:1d:02:99:8d/a8:74:1d:18:c6:96//IPv4/192.168.0.41/192.168.0.10/4840/*/Ethernet:IPv4:TCP"
"""A real OPC UA series name that must never be excluded."""


@pytest.fixture(autouse=True)
def _isolated_blacklist_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Install the synthetic SERIES_BLACKLIST and scrub the legacy name.

    Args:
        monkeypatch: Pytest environment patcher.
    """
    monkeypatch.setenv("SERIES_BLACKLIST", _SYNTHETIC_BLACKLIST)
    monkeypatch.delenv("NETCAP_BLACKLIST", raising=False)


def _conn_blacklist(config: AppConfig) -> str | list[str]:
    """Return the resolved ``blacklist`` value of the ``conn`` module.

    Args:
        config: A loaded application configuration.

    Returns:
        The ``conn`` module's blacklist as resolved by the loader.
    """
    return next(m for m in config.modules if m.name == "conn").blacklist


def test_series_blacklist_resolves_to_every_entry() -> None:
    """The conn blacklist carries one pattern per env-file entry."""
    config = AppConfig.from_json(_CONFIG_PATH)
    blacklist = _conn_blacklist(config)

    assert isinstance(blacklist, list)
    assert len(blacklist) == _PATTERN_COUNT


def test_every_consumer_builds_the_full_pattern_set() -> None:
    """All three blacklist consumers see the full pattern set."""
    blacklist = _conn_blacklist(AppConfig.from_json(_CONFIG_PATH))

    consumers = (
        BoundsTrainer(blacklist=blacklist),
        BoundsManager(module_name="conn", blacklist=blacklist),
        FrequencyMonitor(blacklist=blacklist),
    )

    for consumer in consumers:
        patterns = getattr(consumer, "_blacklist")
        assert len(patterns.patterns) == _PATTERN_COUNT


def test_blacklisted_series_is_excluded() -> None:
    """A blacklisted broadcast series name is recognised by every consumer."""
    blacklist = _conn_blacklist(AppConfig.from_json(_CONFIG_PATH))

    assert getattr(BoundsTrainer(blacklist=blacklist), "_is_blacklisted")(_MULTICAST_SERIES)
    assert getattr(BoundsManager(module_name="conn", blacklist=blacklist), "_is_blacklisted")(_MULTICAST_SERIES)
    assert getattr(FrequencyMonitor(blacklist=blacklist), "_is_blacklisted")(_MULTICAST_SERIES)


def test_legitimate_series_is_not_excluded() -> None:
    """A real OPC UA series name survives the blacklist."""
    blacklist = _conn_blacklist(AppConfig.from_json(_CONFIG_PATH))

    assert not getattr(BoundsTrainer(blacklist=blacklist), "_is_blacklisted")(_LEGITIMATE_SERIES)
    assert not getattr(BoundsManager(module_name="conn", blacklist=blacklist), "_is_blacklisted")(_LEGITIMATE_SERIES)
    assert not getattr(FrequencyMonitor(blacklist=blacklist), "_is_blacklisted")(_LEGITIMATE_SERIES)


def test_other_placeholders_keep_their_previous_types() -> None:
    """No placeholder other than the blacklist changes type or value.

    ``json_arrays=True`` applies to every ``$ENV_VAR`` in config.json, so
    this pins the effective value of the remaining placeholders.
    """
    config = AppConfig.from_json(_CONFIG_PATH)

    assert isinstance(config.influx.url, str)
    assert isinstance(config.influx.token, str)
    assert isinstance(config.postgres.dsn, str)
    assert isinstance(config.logging.file, str)
    assert isinstance(config.models.dir, str)
    assert isinstance(config.pcap_flagging.enabled, bool)
    assert isinstance(config.pcap_flagging.pcap_recorder_url, str)
    assert isinstance(config.frequency_monitor.persistence_enabled, bool)
    for module in config.modules:
        assert isinstance(module.classification.enabled, bool)
        assert isinstance(module.classification.mitre_technique_file, str)


def test_every_module_uses_the_one_series_blacklist_source() -> None:
    """One list for all modules: every module references the same placeholder.

    Regression for the two-list split (2026-11-02): ``mac_traffic`` carried a
    hard-coded multicast list and ``proto_traffic`` an empty one, so the runtime
    editor's single list silently replaced the protection for ``mac_traffic``.
    """
    raw = json.loads(_CONFIG_PATH.read_text(encoding="utf-8"))
    raw_by_name = {module["name"]: module for module in raw["modules"]}

    for name in ("conn", "mac_traffic", "proto_traffic"):
        assert raw_by_name[name]["blacklist"] == "$SERIES_BLACKLIST", name

    config = AppConfig.from_json(_CONFIG_PATH)
    config_by_name = {module.name: module for module in config.modules}

    for name in ("conn", "mac_traffic", "proto_traffic"):
        assert config_by_name[name].blacklist == config_by_name["conn"].blacklist, name


def test_config_json_uses_only_the_series_blacklist_placeholder() -> None:
    """The tracked config carries ``$SERIES_BLACKLIST`` and no legacy name."""
    raw_text = _CONFIG_PATH.read_text(encoding="utf-8")

    assert "$SERIES_BLACKLIST" in raw_text
    assert "NETCAP_BLACKLIST" not in raw_text


def test_legacy_netcap_blacklist_alone_does_not_resolve(monkeypatch: pytest.MonkeyPatch) -> None:
    """``NETCAP_BLACKLIST`` set alone is ignored — no legacy fallback (D4).

    With the legacy variable as the ONLY source, the loader must either
    raise (the documented RAISE policy for an unset variable) or — after
    CLAS-071, where the variable may be legitimately unset — resolve to
    the empty default. Either way it must NOT pick up the legacy value.

    Args:
        monkeypatch: Pytest environment patcher.
    """
    monkeypatch.delenv("SERIES_BLACKLIST", raising=False)
    monkeypatch.setenv("NETCAP_BLACKLIST", _SYNTHETIC_BLACKLIST)

    config = AppConfig.from_json(
        _CONFIG_PATH,
        env_policy=MissingEnvVarPolicy.USE_DEFAULT,
        default="[]",
    )
    blacklist = _conn_blacklist(config)

    assert blacklist == []
    assert all(entry not in str(blacklist) for entry in json.loads(_SYNTHETIC_BLACKLIST))


def test_unset_series_blacklist_resolves_empty_with_default_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unset ``SERIES_BLACKLIST`` plus a ``USE_DEFAULT`` policy yields ``[]``.

    The boot fallback is documented to resolve to an empty blacklist
    without raising when the variable is unset (spec:
    "An unset fallback variable yields an empty blacklist").

    Args:
        monkeypatch: Pytest environment patcher.
    """
    monkeypatch.delenv("SERIES_BLACKLIST", raising=False)

    config = AppConfig.from_json(
        _CONFIG_PATH,
        env_policy=MissingEnvVarPolicy.USE_DEFAULT,
        default="[]",
    )

    assert _conn_blacklist(config) == []


def test_production_boot_unset_series_blacklist_resolves_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The production boot path tolerates an unset ``SERIES_BLACKLIST``.

    ``main._load_config`` keeps the RAISE policy for every placeholder but
    injects an empty-list default for ``SERIES_BLACKLIST`` before loading,
    because the variable is legitimately optional under CLAS-071 — the
    ``runtime_config`` row is the primary source and the env var is only
    the boot fallback.

    Args:
        monkeypatch: Pytest environment patcher.
    """
    from otalon_clas.main import _load_config

    monkeypatch.delenv("SERIES_BLACKLIST", raising=False)
    monkeypatch.chdir(_CLAS_ROOT)

    config = _load_config()

    assert _conn_blacklist(config) == []
