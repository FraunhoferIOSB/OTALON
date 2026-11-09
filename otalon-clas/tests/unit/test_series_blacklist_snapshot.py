"""Group-4 snapshot wiring tests: per-tick blacklist resolution (CLAS-071).

Covers the copy-on-write contract from the spec:

* while a worker thread matches against the snapshot instance of its
  tick, swapping in a new instance on the source never changes the
  worker's results and the worker never observes mutated internal
  state (task 4.5, spec 9.2);
* a persisted row overrides ALL module boot defaults, no row keeps
  per-module boot defaults, for every consumer
  (:class:`BoundsManager`, :class:`FrequencyMonitor`,
  :class:`BoundsTrainer`);
* the swap is a single reference assignment — workers of one tick all
  observe the same instance.
"""

from __future__ import annotations

import json
import threading

import pytest

from otalon_clas.detection.bounds_manager import BoundsManager, BoundsTrainer
from otalon_clas.detection.frequency_monitor import FrequencyMonitor
from otalon_clas.detection.series_blacklist import SeriesBlacklist
from otalon_clas.runtime.series_blacklist_source import (
    SERIES_BLACKLIST_KEY,
    SeriesBlacklistSource,
)

pytestmark = pytest.mark.unit

_BOOT_PATTERNS = ["01:00:5e:*"]
_ROW_ONE = json.dumps(["ff:ff:ff:ff:ff:ff"])
_MEMBER_SERIES = "ff:ff:ff:ff:ff:ff"
_NON_MEMBER_SERIES = "a8:74:1d:02:99:8d"

_WORKER_THREADS = 8
_WORKER_ITERATIONS = 1000


class _FakeRepository:
    """In-memory ``runtime_config`` reader double with failure control."""

    def __init__(self, value: str | None = None, fail: bool = False) -> None:
        self.value = value
        self.fail = fail
        self.calls = 0

    def get(self, service: str, key: str, default: str | None = None) -> str | None:
        """Return the configured row value or the default when absent."""
        assert service == "otalon-clas"
        assert key == SERIES_BLACKLIST_KEY
        self.calls += 1
        if self.fail:
            raise RuntimeError("database unavailable")
        return self.value


def _bounds_manager(boot: str | list[str] = _BOOT_PATTERNS) -> BoundsManager:
    """Build a manager with boot patterns only."""
    return BoundsManager(module_name="test", blacklist=boot)


def _freq_monitor(boot: str | list[str] = _BOOT_PATTERNS) -> FrequencyMonitor:
    """Build a monitor with boot patterns only."""
    return FrequencyMonitor(blacklist=boot)


def _trainer(boot: str | list[str] = _BOOT_PATTERNS) -> BoundsTrainer:
    """Build a trainer with boot patterns only."""
    return BoundsTrainer(blacklist=boot)


class TestUpdateBlacklistSwapsInstances:
    """``update_blacklist`` installs exactly the given instance."""

    def test_runtime_instance_becomes_active(self) -> None:
        manager = _bounds_manager()
        runtime = SeriesBlacklist(["ff:ff:ff:ff:ff:ff"])

        manager.update_blacklist(runtime)

        assert manager.blacklist is runtime

    def test_none_restores_boot_default(self) -> None:
        manager = _bounds_manager(boot=["33:33:*"])
        manager.update_blacklist(SeriesBlacklist(["ff:ff:ff:ff:ff:ff"]))

        manager.update_blacklist(None)

        assert manager.blacklist.patterns == frozenset({"33:33:*"})

    def test_monitor_and_trainer_share_the_same_instance(self) -> None:
        monitor = _freq_monitor()
        trainer = _trainer()
        runtime = SeriesBlacklist(["ff:ff:ff:ff:ff:ff"])

        monitor.update_blacklist(runtime)
        trainer.update_blacklist(runtime)

        assert monitor.blacklist is runtime
        assert trainer.blacklist is runtime

    def test_none_restores_monitor_boot_default(self) -> None:
        monitor = _freq_monitor(boot=["33:33:*"])

        monitor.update_blacklist(None)

        assert monitor.blacklist.patterns == frozenset({"33:33:*"})

    def test_none_restores_trainer_boot_default(self) -> None:
        trainer = _trainer(boot=["33:33:*"])

        trainer.update_blacklist(None)

        assert trainer.blacklist.patterns == frozenset({"33:33:*"})


class TestRunWithRowOverridesBootDefaults:
    """A persisted row overrides all boot defaults for every consumer."""

    def test_row_overrides_boot_for_all_consumers(self) -> None:
        source = SeriesBlacklistSource(
            repository=_FakeRepository(value=_ROW_ONE),
        )
        manager = _bounds_manager(boot=_BOOT_PATTERNS)
        monitor = _freq_monitor(boot=["33:33:*"])
        trainer = _trainer(boot=["IPv6"])

        current = source.current()
        manager.update_blacklist(current)
        monitor.update_blacklist(current)
        trainer.update_blacklist(current)

        assert current is not None
        for consumer in (manager.blacklist, monitor.blacklist, trainer.blacklist):
            assert consumer.patterns == frozenset({"ff:ff:ff:ff:ff:ff"})
            assert consumer.matches(_MEMBER_SERIES)
            assert not consumer.matches("01:00:5e:00:00:01")

    def test_no_row_keeps_per_module_boot_defaults(self) -> None:
        source = SeriesBlacklistSource(
            repository=_FakeRepository(value=None),
        )
        conn_manager = _bounds_manager(boot=[])
        mac_manager = _bounds_manager(boot=["33:33:*"])

        current = source.current()
        conn_manager.update_blacklist(current)
        mac_manager.update_blacklist(current)

        assert current is None
        assert conn_manager.blacklist.patterns == frozenset()
        assert mac_manager.blacklist.patterns == frozenset({"33:33:*"})


class TestCopyOnWriteRace:
    """Swapping while workers match never mutates an in-flight instance."""

    def test_swap_is_invisible_to_in_flight_workers(self) -> None:
        """A reload-driven swap never changes an in-flight worker's instance.

        Workers hold the instance resolved at their tick start while the
        source reloads through :meth:`current` (dirty-flag driven) with
        a different row. Copy-on-write keeps every worker's view stable;
        an in-place mutation of the shared instance would flip the
        workers' match results mid-flight.
        """
        repo = _FakeRepository(value=_ROW_ONE)
        source = SeriesBlacklistSource(repository=repo)
        snapshot = source.current()
        assert snapshot is not None

        errors: list[str] = []
        barrier = threading.Barrier(_WORKER_THREADS + 1)

        def worker() -> None:
            barrier.wait()
            for _ in range(_WORKER_ITERATIONS):
                if not snapshot.matches(_MEMBER_SERIES):
                    errors.append("member series stopped matching")
                if snapshot.matches("00:11:22:33:44:55"):
                    errors.append("foreign series started matching")
                if snapshot.patterns != frozenset({"ff:ff:ff:ff:ff:ff"}):
                    errors.append("internal state of the snapshot mutated")

        threads = [threading.Thread(target=worker) for _ in range(_WORKER_THREADS)]
        for thread in threads:
            thread.start()
        barrier.wait()

        for _ in range(200):
            repo.value = json.dumps(["00:11:22:33:44:55"])
            source.mark_dirty()
            swapped = source.current()
            assert swapped is not None and swapped.patterns != snapshot.patterns
            repo.value = _ROW_ONE
            source.mark_dirty()
            assert source.current() is not snapshot

        for thread in threads:
            thread.join()

        assert errors == []

    def test_concurrent_ticks_share_identical_instances(self) -> None:
        """Two ticks resolving concurrently both get one stable instance."""
        source = SeriesBlacklistSource(
            repository=_FakeRepository(value=_ROW_ONE),
        )
        results: list[SeriesBlacklist | None] = []
        lock = threading.Lock()

        def tick() -> None:
            current = source.current()
            with lock:
                results.append(current)

        threads = [threading.Thread(target=tick) for _ in range(_WORKER_THREADS)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert all(instance is not None for instance in results)
        assert len({id(instance) for instance in results}) == 1

    def test_in_place_list_mutation_is_impossible(self) -> None:
        """A worker cannot mutate a snapshot through its public surface."""
        snapshot = SeriesBlacklist(["ff:ff:ff:ff:ff:ff"])

        with pytest.raises((AttributeError, TypeError)):
            snapshot.patterns.add("33:33:*")  # type: ignore[attr-defined]

        assert snapshot.patterns == frozenset({"ff:ff:ff:ff:ff:ff"})


class TestConceptInternalsAreImmutable:
    """Pin the internal immutability that copy-on-write depends on.

    The public ``patterns`` surface alone does not catch a mutable internal
    container (a regression that made ``_value_tokens`` a plain ``set`` passed
    the public-surface test). These assertions pin the internal types directly.
    """

    def test_value_tokens_is_frozenset(self) -> None:
        snapshot = SeriesBlacklist(["ff:ff:ff:ff:ff:ff", "IPv6"])
        assert isinstance(snapshot._value_tokens, frozenset)  # noqa: SLF001

    def test_uci_patterns_is_tuple_of_tuples(self) -> None:
        snapshot = SeriesBlacklist(["7c:cb:e2:ea:0d:65/*/*/*/*/*/*/502/*"])
        assert isinstance(snapshot._uci_patterns, tuple)  # noqa: SLF001
        assert all(isinstance(p, tuple) for p in snapshot._uci_patterns)  # noqa: SLF001

    def test_constructor_does_not_retain_caller_list(self) -> None:
        caller = ["ff:ff:ff:ff:ff:ff"]
        snapshot = SeriesBlacklist(caller)
        caller.append("33:33:*")
        assert "33:33:*" not in snapshot.patterns


class TestConceptTableCoverageAgainstSnapshot:
    """Task 9.3: one concept-table case per entry type via the snapshot.

    The CLAS-071 concept table (``.dev/features/
    clas-series-blacklist-runtime.md`` § coverage) lists the matcher
    behaviour per entry type. Every case here resolves ONE
    ``detection.series_blacklist`` row through
    :class:`SeriesBlacklistSource.current` — the same snapshot instance
    the live wiring hands to the module workers — and asserts the
    documented hit/miss for that series shape.
    """

    _ROW = json.dumps(
        [
            "192.168.0.1",
            "10.9.9.9",
            "7c:cb:e2:ea:0d:65",
            "ff:ff:ff:ff:ff:ff",
            "IPv6",
            "Ethernet:ARP",
            "Ethernet:IPv4:*",
            "33:33:*",
            "7c:cb:e2:ea:0d:65/30:b8:51:31:06:84/0/IPv4/192.168.0.196/192.168.0.1/1234/502/Ethernet:IPv4:TCP:MODBUS",
            "50:61:d6:00:ba:b2/*/*/IPv4/192.168.0.51",
            "50:61:d6:06:3b:34/*/*/*/*/*/*/503/*",
            "11:22:33:44:55:66/11:22:33:44:55:66",
        ]
    )

    @pytest.mark.parametrize(
        ("series", "expected"),
        [
            ("00:11:22:33:44:55/00:11:22:33:44:66/0/IPv4/192.168.0.77/192.168.0.1/123/80/Ethernet:IPv4:TCP", True),
            ("00:aa:bb:cc:dd:ee/00:aa:bb:cc:dd:ff/0/IPv4/10.7.7.7/10.8.8.8/123/80/Ethernet:IPv4:TCP", False),
            ("7c:cb:e2:ea:0d:65/00:11:22:33:44:66/0/IPv4/192.168.9.9/192.168.9.10/123/80/Ethernet:IPv4:TCP", True),
            ("00:11:22:33:44:55/ff:ff:ff:ff:ff:ff/0/IPv4/192.168.5.5/192.168.5.6/123/80/Ethernet:IPv4:TCP", True),
            ("a8:74:1d:02:99:8d/33:33:00:00:00:02//IPv6/fe80::1/ff02::2/53/*/Ethernet:IPv6:UDP", True),
            ("aa:bb:cc:dd:ee:ff/00:11:22:33:44:55//IPv6/fe80::1/fe80::2/53/*/Ethernet:IPv6:UDP:DNS", False),
            ("Ethernet:ARP", True),
            ("00:11:22:33:44:66/00:11:22:33:44:77/0/IPv4/192.168.77.77/192.168.77.78/123/80/Ethernet:ARP", False),
            ("Ethernet:IPv4:TCP:DNS", True),
            (
                "7c:cb:e2:ea:0d:65/30:b8:51:31:06:84/0/IPv4/192.168.0.196/192.168.0.1/1234/502/Ethernet:IPv4:TCP:MODBUS",
                True,
            ),
            (
                "50:61:d6:00:ba:b2/50:61:d6:06:3b:34/0/IPv4/192.168.0.51/192.168.0.141/49152/8080/Ethernet:IPv4:TCP",
                True,
            ),
            ("50:61:d6:06:3b:34/50:61:d6:00:ef:b8/0/IPv4/192.168.0.10/192.168.0.20/123/502/Ethernet:IPv4:TCP", False),
            ("11:22:33:44:55:66/11:22:33:44:55:66/0/IPv4/10.1.1.1/10.2.2.2/123/80/Ethernet:IPv4:UDP", True),
            ("00:11:22:33:44:55/33:33:00:00:00:01/0/IPv6/192.168.0.196/192.168.0.99/1234/502/Ethernet:IPv4:TCP", True),
        ],
        ids=[
            "ip-endpoint-hit",
            "ip-other-miss",
            "mac-endpoint-hit",
            "mac-broadcast-hit",
            "l3-multicast-hit",
            "l3-unicast-miss-clas039-guard",
            "plain-tag-hit",
            "plain-tag-inside-uci-miss",
            "plain-tag-with-star-hit",
            "full-uci-exact-hit",
            "uci-star-fields-hit",
            "uci-star-wrong-port-miss",
            "uci-prefix-fields-hit",
            "wildcard-token-vs-uci-hit",
        ],
    )
    def test_entry_type_behaviour_via_snapshot(self, series: str, expected: bool) -> None:
        """Each concept-table entry type acts as documented via one snapshot."""
        source = SeriesBlacklistSource(repository=_FakeRepository(value=self._ROW))
        snapshot = source.current()
        assert snapshot is not None
        assert snapshot.matches(series) is expected
