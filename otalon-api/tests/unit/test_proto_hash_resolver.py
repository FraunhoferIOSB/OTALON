"""Unit tests for ProtoHashResolver.

Covers cache hit/miss, refresh-on-miss, round-trip via proto_series_hash,
and graceful fallback when InfluxDB is unreachable.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from otalon_api.domain.netcap.models import proto_series_hash
from otalon_api.domain.netcap.proto_resolver import ProtoHashResolver


class TestProtoHashResolver:
    """ProtoHashResolver behaviour tests."""

    @pytest.mark.unit
    def test_resolve_round_trip(self) -> None:
        """A protocol hashed via proto_series_hash resolves back to itself."""
        repo = MagicMock()
        repo.query_distinct_tags.return_value = [
            "Ethernet:ARP",
            "Ethernet:IPv4:TCP",
        ]
        resolver = ProtoHashResolver(influx_repo=repo)

        arp_hash = proto_series_hash("Ethernet:ARP")
        assert resolver.resolve(arp_hash) == "Ethernet:ARP"

        tcp_hash = proto_series_hash("Ethernet:IPv4:TCP")
        assert resolver.resolve(tcp_hash) == "Ethernet:IPv4:TCP"

    @pytest.mark.unit
    def test_resolve_unknown_returns_raw_hash(self) -> None:
        """An unknown hash falls back to the raw hash value."""
        repo = MagicMock()
        repo.query_distinct_tags.return_value = ["Ethernet:ARP"]
        resolver = ProtoHashResolver(influx_repo=repo)

        unknown = "999999999"
        assert resolver.resolve(unknown) == "999999999"

    @pytest.mark.unit
    def test_resolve_many_parallel(self) -> None:
        """resolve_many refreshes once for a batch of missing hashes."""
        repo = MagicMock()
        repo.query_distinct_tags.return_value = ["Ethernet:ARP", "Ethernet:IPv4:UDP"]
        resolver = ProtoHashResolver(influx_repo=repo)

        hashes = [
            proto_series_hash("Ethernet:ARP"),
            proto_series_hash("Ethernet:IPv4:UDP"),
        ]
        protocols = resolver.resolve_many(hashes)
        assert protocols == ["Ethernet:ARP", "Ethernet:IPv4:UDP"]
        assert repo.query_distinct_tags.call_count == 1

    @pytest.mark.unit
    def test_refresh_failure_graceful(self) -> None:
        """If InfluxDB errors, resolve falls back without raising."""
        repo = MagicMock()
        repo.query_distinct_tags.side_effect = RuntimeError("influx down")
        resolver = ProtoHashResolver(influx_repo=repo)

        h = proto_series_hash("Ethernet:ARP")
        assert resolver.resolve(h) == h

    @pytest.mark.unit
    def test_refresh_uses_configured_ttl(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Configured TTL controls refresh throttling rather than a fixed value."""
        repo = MagicMock()
        repo.query_distinct_tags.return_value = ["Ethernet:ARP"]
        resolver = ProtoHashResolver(influx_repo=repo, ttl_seconds=60.0)
        clock = iter((100.0, 101.0, 162.0))
        monkeypatch.setattr("otalon_api.domain.netcap.proto_resolver.time.monotonic", lambda: next(clock))
        resolver.refresh()
        resolver.resolve("unknown")
        resolver.resolve("unknown")
        assert repo.query_distinct_tags.call_count == 2
