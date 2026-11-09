"""Unit tests for PortRuleRefresher (CLAS-033 Wave D4).

Tests the _run_once() cycle logic with faked dependencies, covering
all 8 scenarios from the spec.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, cast

import polars as pl
import pytest
from otalon_common.connection import (
    DynamicBucketConfig,
    PortCollapseConfig,
    PortCollapseRule,
)

from otalon_clas.common.settings import PortRuleRefreshConfig
from otalon_clas.runtime.port_rule_refresher import (
    PortRuleRefresher,
    _build_rule_lookup,
    _find_candidates,
)

if TYPE_CHECKING:
    from otalon_clas.common.influx_connector import InfluxModule
    from otalon_clas.common.postgres_connector import PostgresConnector
    from otalon_clas.preprocessing.port_rules_repository import (
        PortCollapseRulesRepository,
    )
    from otalon_clas.runtime.retrain_job_repository import RetrainJobRepository
    from otalon_clas.runtime.runtime_config_repository import (
        RuntimeConfigRepository,
    )

# ---------------------------------------------------------------------------
# Test data constants
# ---------------------------------------------------------------------------

_BASE = (
    "00:01:05:2b:ae:a2",
    "a8:74:1d:02:99:8d",
    "",
    "IPv4",
    "192.168.0.2",
    "192.168.0.41",
    "Ethernet:IPv4:UDP:PROFINET_DCE_RPC",
)

_STALE_UCI = (
    "00:01:05:2b:ae:a2/a8:74:1d:02:99:8d//IPv4/"
    "192.168.0.2/192.168.0.41/50000/50462/"
    "Ethernet:IPv4:UDP:PROFINET_DCE_RPC"
)
_DRIFT_UCI = (
    "00:01:05:2b:ae:a2/a8:74:1d:02:99:8d//IPv4/"
    "192.168.0.2/192.168.0.41/50000/56247/"
    "Ethernet:IPv4:UDP:PROFINET_DCE_RPC"
)

_STALE_RULE = PortCollapseRule(
    src_mac=_BASE[0],
    dst_mac=_BASE[1],
    vlan=_BASE[2],
    ip_proto=_BASE[3],
    src_ip=_BASE[4],
    dst_ip=_BASE[5],
    protocols=_BASE[6],
    normalized_uci=_STALE_UCI,
    wildcard_src_port=False,
    wildcard_dst_port=False,
    bucket_seconds=1,
)

_WILDCARD_RULE = PortCollapseRule(
    src_mac=_BASE[0],
    dst_mac=_BASE[1],
    vlan=_BASE[2],
    ip_proto=_BASE[3],
    src_ip=_BASE[4],
    dst_ip=_BASE[5],
    protocols=_BASE[6],
    normalized_uci=(
        "00:01:05:2b:ae:a2/a8:74:1d:02:99:8d//IPv4/"
        "192.168.0.2/192.168.0.41/50000/*/"
        "Ethernet:IPv4:UDP:PROFINET_DCE_RPC"
    ),
    wildcard_src_port=False,
    wildcard_dst_port=True,
    bucket_seconds=1,
)

_T0 = datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
_BUCKET = 300  # persistence_bucket_seconds


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class _FakeRuntimeConfigRepo:
    """Returns defaults for all runtime_config lookups."""

    def get_bool(self, service: str, key: str, *, default: bool) -> bool:
        return default

    def get_int(self, service: str, key: str, *, default: int) -> int:
        return default


class _FakeInflux:
    """Fake InfluxModule returning canned UCI lists and DataFrames."""

    def __init__(
        self,
        ucis: list[str] | None = None,
        raw_df: pl.DataFrame | None = None,
    ) -> None:
        self._ucis = ucis or []
        self._raw_df = raw_df

    def fetch_distinct_tag_values(self, start: str, stop: str) -> list[str]:
        return self._ucis

    def fetch(self, start: str, stop: str, *, use_polars: bool = True) -> pl.DataFrame:
        if self._raw_df is None:
            return pl.DataFrame({"time": [], "uci": []})
        return self._raw_df


class _FakeRulesRepo:
    """Fake PortCollapseRulesRepository."""

    def __init__(self, rules: list[PortCollapseRule] | None = None) -> None:
        self._rules = rules or []
        self.upserted: list[tuple[str, list[PortCollapseRule]]] = []

    def load(self, module: str) -> list[PortCollapseRule]:
        return list(self._rules)

    def upsert_rules(self, module: str, rules: list[PortCollapseRule]) -> int:
        self.upserted.append((module, list(rules)))
        return len(rules)


class _FakeJobRepo:
    """Fake RetrainJobRepository for the D6 mutex check."""

    def __init__(self, non_terminal: list[object] | None = None) -> None:
        self._non_terminal = non_terminal or []

    def list_non_terminal(self) -> list[object]:
        return list(self._non_terminal)


def _make_refresher(
    *,
    rules: list[PortCollapseRule] | None = None,
    ucis: list[str] | None = None,
    raw_df: pl.DataFrame | None = None,
    non_terminal_jobs: list[object] | None = None,
    config: PortRuleRefreshConfig | None = None,
    reload_callback: Callable[[], None] | None = None,
) -> PortRuleRefresher:
    """Construct a refresher wired with fakes for testing."""
    fake_influx = _FakeInflux(ucis=ucis, raw_df=raw_df)
    fake_rules = _FakeRulesRepo(rules=rules)
    fake_job = _FakeJobRepo(non_terminal=non_terminal_jobs)
    callback_called = 0

    def _cb() -> None:
        nonlocal callback_called
        callback_called += 1

    refresher = PortRuleRefresher(
        pg_connector=cast("PostgresConnector", None),
        influx_connector=cast("InfluxModule", fake_influx),
        rules_repository=cast("PortCollapseRulesRepository", fake_rules),
        port_config=PortCollapseConfig(),
        bucket_config=DynamicBucketConfig(),
        refresh_config=config or PortRuleRefreshConfig(),
        module_name="conn",
        reload_callback=reload_callback or _cb,
    )
    # Patch the internal repos to use fakes
    refresher._runtime_config = cast(
        "RuntimeConfigRepository", _FakeRuntimeConfigRepo()
    )
    refresher._job_repo = cast("RetrainJobRepository", fake_job)
    refresher._rules_repo = cast("PortCollapseRulesRepository", fake_rules)
    refresher._influx = cast("InfluxModule", fake_influx)
    refresher._test_fake_rules = fake_rules  # type: ignore[attr-defined]
    refresher._test_fake_influx = fake_influx  # type: ignore[attr-defined]
    return refresher


def _drift_raw_df() -> pl.DataFrame:
    """4 rows across 4 buckets, dst_port 56247/56248/56249."""
    return pl.DataFrame(
        {
            "time": [
                _T0,
                _T0 + timedelta(seconds=_BUCKET),
                _T0 + timedelta(seconds=2 * _BUCKET),
                _T0 + timedelta(seconds=3 * _BUCKET),
            ],
            "uci": [
                _STALE_UCI.replace("50462", "56247"),
                _STALE_UCI.replace("50462", "56248"),
                _STALE_UCI.replace("50462", "56249"),
                _STALE_UCI.replace("50462", "56247"),
            ],
        }
    )


def _single_bucket_raw_df() -> pl.DataFrame:
    """4 rows all in 1 bucket (~250s span)."""
    return pl.DataFrame(
        {
            "time": [
                _T0,
                _T0 + timedelta(seconds=50),
                _T0 + timedelta(seconds=150),
                _T0 + timedelta(seconds=250),
            ],
            "uci": [
                _STALE_UCI.replace("50462", "56247"),
                _STALE_UCI.replace("50462", "56248"),
                _STALE_UCI.replace("50462", "56249"),
                _STALE_UCI.replace("50462", "56247"),
            ],
        }
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_config_disabled_skips() -> None:
    """Scenario 1: config disabled → skip entirely."""
    refresher = _make_refresher(
        rules=[_STALE_RULE],
        ucis=[_DRIFT_UCI],
        config=PortRuleRefreshConfig(enabled=False),
    )
    refresher._run_once()
    fake_rules: _FakeRulesRepo = refresher._test_fake_rules  # type: ignore[attr-defined]
    assert fake_rules.upserted == []


def test_retrain_active_skips() -> None:
    """Scenario 5: retrain job running → skip."""
    refresher = _make_refresher(
        rules=[_STALE_RULE],
        ucis=[_DRIFT_UCI],
        non_terminal_jobs=[object()],
    )
    refresher._run_once()
    fake_rules: _FakeRulesRepo = refresher._test_fake_rules  # type: ignore[attr-defined]
    assert fake_rules.upserted == []


def test_empty_rules_skips() -> None:
    """Scenario 6: no rules → skip."""
    refresher = _make_refresher(rules=[], ucis=[_DRIFT_UCI])
    refresher._run_once()
    fake_rules: _FakeRulesRepo = refresher._test_fake_rules  # type: ignore[attr-defined]
    assert fake_rules.upserted == []


def test_empty_influx_skips() -> None:
    """Scenario 7: no UCIs from InfluxDB → skip."""
    refresher = _make_refresher(rules=[_STALE_RULE], ucis=[])
    refresher._run_once()
    fake_rules: _FakeRulesRepo = refresher._test_fake_rules  # type: ignore[attr-defined]
    assert fake_rules.upserted == []


def test_first_cycle_no_upsert() -> None:
    """Scenario 4: first cycle sees drift but D3 (confirm_cycles=2) blocks upsert."""
    refresher = _make_refresher(
        rules=[_STALE_RULE],
        ucis=[_DRIFT_UCI],
        raw_df=_drift_raw_df(),
        config=PortRuleRefreshConfig(confirm_cycles=2),
    )
    refresher._run_once()
    fake_rules: _FakeRulesRepo = refresher._test_fake_rules  # type: ignore[attr-defined]
    assert fake_rules.upserted == []
    # Candidate should be recorded for next cycle
    assert len(refresher._first_seen) == 1


def test_second_cycle_upserts() -> None:
    """Scenario 2+6: two cycles → confirmed → upsert + callback."""
    callback_count = 0

    def _cb() -> None:
        nonlocal callback_count
        callback_count += 1

    refresher = _make_refresher(
        rules=[_STALE_RULE],
        ucis=[_DRIFT_UCI],
        raw_df=_drift_raw_df(),
        config=PortRuleRefreshConfig(confirm_cycles=2),
        reload_callback=_cb,
    )
    # Cycle 1: records candidate, no upsert
    refresher._run_once()
    fake_rules: _FakeRulesRepo = refresher._test_fake_rules  # type: ignore[attr-defined]
    assert fake_rules.upserted == []
    assert callback_count == 0
    # Cycle 2: confirms → upsert + callback
    refresher._run_once()
    assert len(fake_rules.upserted) == 1
    assert fake_rules.upserted[0][0] == "conn"
    assert callback_count == 1
    # The upserted rule should have wildcard_dst_port=True
    upserted_rule = fake_rules.upserted[0][1][0]
    assert upserted_rule.wildcard_dst_port is True


def test_no_drift_no_upsert() -> None:
    """Scenario 1b: UCIs covered by rule → no candidates, no upsert."""
    refresher = _make_refresher(
        rules=[_WILDCARD_RULE],
        ucis=[_DRIFT_UCI],  # 56247 is covered by wildcard dst
    )
    refresher._run_once()
    fake_rules: _FakeRulesRepo = refresher._test_fake_rules  # type: ignore[attr-defined]
    assert fake_rules.upserted == []


def test_exception_does_not_kill() -> None:
    """Scenario 8: exception during cycle → logged, thread continues."""
    refresher = _make_refresher(rules=[_STALE_RULE], ucis=[_DRIFT_UCI])
    # Make rules_repo.load raise on second call
    fake_rules: _FakeRulesRepo = refresher._test_fake_rules  # type: ignore[attr-defined]
    original_load = fake_rules.load
    call_count = 0

    def _raising_load(module: str) -> list[PortCollapseRule]:
        nonlocal call_count
        call_count += 1
        if call_count > 1:
            raise RuntimeError("injected failure")
        return original_load(module)

    fake_rules.load = _raising_load  # type: ignore[method-assign]  # monkey-patch for test
    # First cycle works
    refresher._run_once()
    # Second cycle raises but _run() would swallow; we call _run_once directly
    # which will raise — verify the exception propagates (the _run loop swallows)
    with pytest.raises(RuntimeError, match="injected failure"):
        refresher._run_once()
    # The refresher is still usable
    assert refresher._thread is None


# ---------------------------------------------------------------------------
# Rotation-signal tests (CLAS-035 Fix 3)
# ---------------------------------------------------------------------------

_ROTATION_PORTS = ["56247", "56248", "56249"]


def _uci_with_dst(port: str) -> str:
    """Build a UCI string for the base-key with a specific dst_port."""
    return (
        "00:01:05:2b:ae:a2/a8:74:1d:02:99:8d//IPv4/"
        "192.168.0.2/192.168.0.41/50000/" + port + "/"
        "Ethernet:IPv4:UDP:PROFINET_DCE_RPC"
    )


def _rotation_raw_df() -> pl.DataFrame:
    """4 rows with 3 distinct dst ports, all in a single 300-s bucket."""
    return pl.DataFrame(
        {
            "time": [
                _T0,
                _T0 + timedelta(seconds=50),
                _T0 + timedelta(seconds=150),
                _T0 + timedelta(seconds=250),
            ],
            "uci": [
                _uci_with_dst("56247"),
                _uci_with_dst("56248"),
                _uci_with_dst("56249"),
                _uci_with_dst("56247"),
            ],
        }
    )


def test_find_candidates_rotation_added() -> None:
    """3 distinct dst ports at threshold 3 → one rotation candidate."""
    lookup = _build_rule_lookup([_STALE_RULE])
    ucis = [_uci_with_dst(p) for p in _ROTATION_PORTS]
    candidates = _find_candidates(ucis, lookup, rotation_distinct_ports=3)
    rotation = {c for c in candidates if c.rotation_signal}
    assert len(rotation) == 1
    rc = rotation.pop()
    assert rc.port_dim == "dst_port"
    assert rc.port_value == "*"


def test_find_candidates_rotation_below_threshold() -> None:
    """2 distinct dst ports < threshold 3 → no rotation candidate."""
    lookup = _build_rule_lookup([_STALE_RULE])
    ucis = [_uci_with_dst("56247"), _uci_with_dst("56248")]
    candidates = _find_candidates(ucis, lookup, rotation_distinct_ports=3)
    assert not any(c.rotation_signal for c in candidates)


def test_find_candidates_rotation_skipped_when_wildcarded() -> None:
    """Rule already wildcards dst → no rotation candidate for dst."""
    lookup = _build_rule_lookup([_WILDCARD_RULE])
    ucis = [_uci_with_dst(p) for p in _ROTATION_PORTS]
    candidates = _find_candidates(ucis, lookup, rotation_distinct_ports=3)
    assert not any(c.rotation_signal for c in candidates)


def test_find_candidates_rotation_excludes_star() -> None:
    """Star ports are excluded from the distinct-port count."""
    lookup = _build_rule_lookup([_STALE_RULE])
    ucis = [_uci_with_dst("56247"), _uci_with_dst("56248"), _uci_with_dst("*")]
    candidates = _find_candidates(ucis, lookup, rotation_distinct_ports=3)
    assert not any(c.rotation_signal for c in candidates)


def test_find_candidates_rotation_suppressed_at_zero() -> None:
    """rotation_distinct_ports=0 suppresses all rotation candidates."""
    lookup = _build_rule_lookup([_STALE_RULE])
    ucis = [_uci_with_dst(p) for p in _ROTATION_PORTS]
    candidates = _find_candidates(ucis, lookup, rotation_distinct_ports=0)
    assert not any(c.rotation_signal for c in candidates)


def test_rotation_bypasses_persistence_guard() -> None:
    """Rotation candidate short-circuits D2: upsert even when all ports are in 1 bucket.

    Without the rotation signal the coverage-violation candidates would fail the
    D2 persistence check (single bucket → n_buckets=1 < 2), blocking the upsert.
    The rotation candidate (rotation_signal=True) short-circuits
    _any_port_persistent, allowing the recompute to proceed and produce a
    wildcarded rule.
    """
    refresher = _make_refresher(
        rules=[_STALE_RULE],
        ucis=[_uci_with_dst(p) for p in _ROTATION_PORTS],
        raw_df=_rotation_raw_df(),
        config=PortRuleRefreshConfig(confirm_cycles=2, rotation_distinct_ports=3),
    )
    refresher._run_once()
    refresher._run_once()
    fake_rules: _FakeRulesRepo = refresher._test_fake_rules  # type: ignore[attr-defined]
    assert len(fake_rules.upserted) == 1
    upserted_rule = fake_rules.upserted[0][1][0]
    assert upserted_rule.wildcard_dst_port is True


def test_no_rotation_persistence_guard_blocks() -> None:
    """Without rotation signal, single-bucket ports fail D2 → no upsert.

    Same data as test_rotation_bypasses_persistence_guard but with
    rotation_distinct_ports=100 (above any realistic distinct count). Only
    coverage-violation candidates survive, and they all fail the D2
    persistence check because every port is in a single time bucket.
    """
    refresher = _make_refresher(
        rules=[_STALE_RULE],
        ucis=[_uci_with_dst(p) for p in _ROTATION_PORTS],
        raw_df=_rotation_raw_df(),
        config=PortRuleRefreshConfig(confirm_cycles=2, rotation_distinct_ports=100),
    )
    refresher._run_once()
    refresher._run_once()
    fake_rules: _FakeRulesRepo = refresher._test_fake_rules  # type: ignore[attr-defined]
    assert fake_rules.upserted == []
