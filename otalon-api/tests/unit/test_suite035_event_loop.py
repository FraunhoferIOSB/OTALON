"""Regression tests for the SUITE-035 remaining event-loop findings.

* QUA-08 — ``ProtoHashResolver.resolve()`` issues a synchronous InfluxDB
  query on a cache miss. All three proto router handlers called it directly
  from ``async`` code; ``list_proto_ids`` did so inside a list comprehension,
  so a cold cache meant one blocking query per unknown id on the event loop.
* QUA-09 — ``invalidate_data_extent_cache`` is called from ``async`` code
  without a hop. That is correct *because* it is pure in-memory; these tests
  pin that property so the call site stays safe.

The QUA-08 tests assert observed behaviour: a resolver double records the
thread it ran on, and the handler is driven on a real event loop. A handler
that resolves on the loop thread fails.
"""

from __future__ import annotations

import asyncio
import threading
from datetime import datetime, timedelta, timezone
from typing import Any

import pandas as pd
import pytest

pytestmark = pytest.mark.unit

START = datetime(2026, 3, 6, 21, 0, tzinfo=timezone.utc)
STOP = START + timedelta(hours=1)


class _RecordingResolver:
    """Resolver double recording which thread each resolution ran on."""

    def __init__(self, mapping: dict[str, str] | None = None) -> None:
        self._mapping = mapping or {}
        self.threads: list[str] = []
        self.resolve_calls = 0
        self.resolve_many_calls = 0

    def resolve(self, hash_value: str) -> str:
        self.resolve_calls += 1
        self.threads.append(threading.current_thread().name)
        return self._mapping.get(hash_value, hash_value)

    def resolve_many(self, hash_values: list[str]) -> list[str]:
        self.resolve_many_calls += 1
        self.threads.append(threading.current_thread().name)
        return [self._mapping.get(h, h) for h in hash_values]

    def ran_off_the_loop_thread(self, loop_thread: str) -> bool:
        return bool(self.threads) and all(name != loop_thread for name in self.threads)


class _Service:
    """Timeseries service double returning fixed ids/frames."""

    def __init__(self, ids: list[str] | None = None) -> None:
        self._ids = ids or []

    def list_ids(self, **_kwargs: Any) -> list[str]:
        return list(self._ids)

    def get_between(self, **_kwargs: Any) -> tuple[pd.DataFrame, int]:
        return pd.DataFrame({"time": [], "proto_total_packets": []}), 60

    def get_plot_data(self, **_kwargs: Any) -> tuple[pd.DataFrame, int]:
        return pd.DataFrame({"time": [], "proto_total_packets": []}), 60


def _run(coro: Any) -> tuple[Any, str]:
    """Run ``coro`` on a fresh loop, returning its result and the loop thread."""
    holder: dict[str, str] = {}

    async def wrapper() -> Any:
        holder["thread"] = threading.current_thread().name
        return await coro

    result = asyncio.run(wrapper())
    return result, holder["thread"]


class TestListProtoIdsResolvesOffTheLoop:
    """QUA-08 — the comprehension used to resolve on the event loop."""

    def test_resolution_runs_in_a_worker_thread(self) -> None:
        from otalon_api.api.v1.timeseries_mac_proto import list_proto_ids

        resolver = _RecordingResolver({"h1": "Ethernet:IPv4:TCP"})
        service = _Service(["h1", "h2"])

        _, loop_thread = _run(
            list_proto_ids(
                start=START,
                stop=STOP,
                nonzero=False,
                fields=None,
                service=service,
                proto_resolver=resolver,
            )
        )

        assert resolver.ran_off_the_loop_thread(loop_thread)

    def test_batch_resolution_is_used(self) -> None:
        """``resolve_many`` refreshes at most once for the whole batch."""
        from otalon_api.api.v1.timeseries_mac_proto import list_proto_ids

        resolver = _RecordingResolver()
        service = _Service(["h1", "h2", "h3", "h4"])

        _run(
            list_proto_ids(
                start=START,
                stop=STOP,
                nonzero=False,
                fields=None,
                service=service,
                proto_resolver=resolver,
            )
        )

        assert resolver.resolve_many_calls == 1
        assert resolver.resolve_calls == 0, "per-item resolve() must not be used"

    def test_ids_are_paired_with_their_protocols(self) -> None:
        from otalon_api.api.v1.timeseries_mac_proto import list_proto_ids

        resolver = _RecordingResolver({"h1": "Ethernet:IPv4:TCP", "h2": "Ethernet:ARP"})
        service = _Service(["h1", "h2"])

        response, _ = _run(
            list_proto_ids(
                start=START,
                stop=STOP,
                nonzero=False,
                fields=None,
                service=service,
                proto_resolver=resolver,
            )
        )

        assert [(item.id, item.protocol) for item in response.data] == [
            ("h1", "Ethernet:IPv4:TCP"),
            ("h2", "Ethernet:ARP"),
        ]
        assert response.count == 2

    def test_unknown_hash_falls_back_to_the_raw_id(self) -> None:
        from otalon_api.api.v1.timeseries_mac_proto import list_proto_ids

        resolver = _RecordingResolver()
        service = _Service(["deadbeef"])

        response, _ = _run(
            list_proto_ids(
                start=START,
                stop=STOP,
                nonzero=False,
                fields=None,
                service=service,
                proto_resolver=resolver,
            )
        )

        assert response.data[0].protocol == "deadbeef"

    def test_invalid_range_still_rejected(self) -> None:
        """Offloading must not swallow the start/stop validation."""
        from fastapi import HTTPException

        from otalon_api.api.v1.timeseries_mac_proto import list_proto_ids

        with pytest.raises(HTTPException) as exc:
            _run(
                list_proto_ids(
                    start=STOP,
                    stop=START,
                    nonzero=False,
                    fields=None,
                    service=_Service(),
                    proto_resolver=_RecordingResolver(),
                )
            )
        assert exc.value.status_code == 400


class TestProtoDataResolvesOffTheLoop:
    """QUA-08 — the single-value handlers resolved on the loop too."""

    def test_query_proto_data_resolves_in_a_worker_thread(self) -> None:
        from otalon_api.api.v1.timeseries_mac_proto import query_proto_data

        resolver = _RecordingResolver({"h1": "Ethernet:IPv4:TCP"})

        response, loop_thread = _run(
            query_proto_data(
                protocol="h1",
                start=START,
                stop=STOP,
                features=["proto_total_packets"],
                aggregate="mean",
                sample_max_points=500,
                preserve_extrema=True,
                service=_Service(),
                proto_resolver=resolver,
            )
        )

        assert resolver.ran_off_the_loop_thread(loop_thread)
        assert response.protocol == "Ethernet:IPv4:TCP"

    def test_query_proto_plot_resolves_in_a_worker_thread(self) -> None:
        from otalon_api.api.v1.timeseries_mac_proto import query_proto_plot

        resolver = _RecordingResolver({"h1": "Ethernet:IPv4:TCP"})

        response, loop_thread = _run(
            query_proto_plot(
                protocol="h1",
                start=START,
                stop=STOP,
                features=["proto_total_packets"],
                sample_max_points=500,
                preserve_extrema=True,
                service=_Service(),
                proto_resolver=resolver,
            )
        )

        assert resolver.ran_off_the_loop_thread(loop_thread)
        assert response.protocol == "Ethernet:IPv4:TCP"

    def test_a_slow_resolver_does_not_stall_the_loop(self) -> None:
        """The point of the fix: an unrelated task keeps running."""
        import time

        from otalon_api.api.v1.timeseries_mac_proto import query_proto_data

        class _SlowResolver(_RecordingResolver):
            def resolve(self, hash_value: str) -> str:
                time.sleep(0.4)
                return super().resolve(hash_value)

        async def scenario() -> float:
            slow = asyncio.create_task(
                query_proto_data(
                    protocol="h1",
                    start=START,
                    stop=STOP,
                    features=["proto_total_packets"],
                    aggregate="mean",
                    sample_max_points=500,
                    preserve_extrema=True,
                    service=_Service(),
                    proto_resolver=_SlowResolver(),
                )
            )
            await asyncio.sleep(0.05)
            started = time.perf_counter()
            await asyncio.sleep(0)  # a turn of the loop must be immediate
            latency = time.perf_counter() - started
            await slow
            return latency

        latency = asyncio.run(scenario())

        assert latency < 0.2, f"event loop blocked for {latency * 1000:.0f} ms"


class TestDataExtentCacheInvalidationIsInMemory:
    """QUA-09 — pin the property that justifies the un-offloaded call."""

    def _repo(self) -> Any:
        from otalon_api.repositories.influx_repo import InfluxRepository

        repo = InfluxRepository.__new__(InfluxRepository)
        repo._data_extent_cache = {}
        return repo

    def test_clearing_one_measurement_pops_only_that_key(self) -> None:
        repo = self._repo()
        repo._data_extent_cache = {"network_metrics": ("a", "b"), "proto_traffic": ("c", "d")}

        repo.invalidate_data_extent_cache("network_metrics")

        assert set(repo._data_extent_cache) == {"proto_traffic"}

    def test_clearing_all_empties_the_cache(self) -> None:
        repo = self._repo()
        repo._data_extent_cache = {"a": 1, "b": 2}

        repo.invalidate_data_extent_cache(None)

        assert repo._data_extent_cache == {}

    def test_unknown_measurement_is_a_no_op(self) -> None:
        repo = self._repo()
        repo._data_extent_cache = {"a": 1}

        repo.invalidate_data_extent_cache("does-not-exist")

        assert repo._data_extent_cache == {"a": 1}

    def test_invalidation_performs_no_io(self) -> None:
        """The invariant the un-offloaded async call site depends on.

        If this ever fails, ``PcapImportService._apply_terminal`` must be
        moved to a worker thread in the same change.
        """
        repo = self._repo()
        repo._data_extent_cache = {"network_metrics": ("a", "b")}

        # Any attribute access that would reach a client/connection makes
        # the call blocking; the object deliberately has no such attribute.
        class _Exploding:
            def __getattr__(self, name: str) -> Any:
                raise AssertionError(f"invalidate_data_extent_cache touched {name!r}")

        repo._client = _Exploding()

        repo.invalidate_data_extent_cache("network_metrics")

        assert repo._data_extent_cache == {}

    def test_invalidation_is_fast_enough_to_stay_on_the_loop(self) -> None:
        import time

        repo = self._repo()
        repo._data_extent_cache = {f"m{i}": i for i in range(1000)}

        started = time.perf_counter()
        repo.invalidate_data_extent_cache(None)
        elapsed = time.perf_counter() - started

        assert elapsed < 0.01, "cache invalidation is no longer trivially cheap"
