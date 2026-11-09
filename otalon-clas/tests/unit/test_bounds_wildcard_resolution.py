"""CLAS-057 regression tests: wildcard-port series resolve to concrete bounds.

The bounds training writes a series under its CONCRETE port pair (e.g.
``.../50000/56247/...``) while the live detector receives the same logical
connection with WILDCARD ports (``.../*/*/...``) or a partially wildcarded
pair (``.../56247/*/...``). The previous exact ``series_id in bounds`` lookup
missed every wildcard series and marked it ``NoBounds`` forever, producing a
permanent false positive for any connection whose ports are dynamic.

These tests pin the detector-side port-collapse resolution: an incoming
series with wildcard (or rotated) ports resolves to the trained concrete
series of the same logical connection instead of falling through to
``NoBounds``. The match semantics mirror the canonical UI logic in
``otalon-ui/app/utils/uci.ts`` (``matchesPortCollapseSibling``): same
port-stripped base key, or a direction swap between four unicast MACs.
Broadcast/multicast MACs never reverse-match.
"""

from __future__ import annotations

import polars as pl

from otalon_clas.detection.bounds_manager import BoundsManager

_FEATURE = "bytes"

# PROFINET DCE/RPC connection verified live on 2026-09-02: training stored it
# under the concrete port pair, the detector saw it wildcarded.
_SRC_MAC = "00:01:05:2b:ae:a2"
_DST_MAC = "a8:74:1d:02:99:8d"
_SRC_IP = "192.168.0.2"
_DST_IP = "192.168.0.41"
_STACK = "Ethernet:IPv4:UDP:PROFINET_DCE_RPC"

_CONCRETE_AB = f"{_SRC_MAC}/{_DST_MAC}//IPv4/{_SRC_IP}/{_DST_IP}/50000/56247/{_STACK}"
_WILDCARD_AB = f"{_SRC_MAC}/{_DST_MAC}//IPv4/{_SRC_IP}/{_DST_IP}/*/*/{_STACK}"
_REVERSE_BA_WILDCARD = f"{_DST_MAC}/{_SRC_MAC}//IPv4/{_DST_IP}/{_SRC_IP}/56247/*/{_STACK}"
_CONCRETE_AB_ALT_PORTS = f"{_SRC_MAC}/{_DST_MAC}//IPv4/{_SRC_IP}/{_DST_IP}/50001/56248/{_STACK}"
_UNRELATED_WILDCARD = "de:ad:be:ef:00:01/00:02:03:04:05:06//IPv4/10.0.0.1/10.0.0.2/*/*" "/Ethernet:IPv4:TCP:HTTP"

# Broadcast connection (A -> ff:ff:ff:ff:ff:ff) used for the reverse-guard.
_BCAST_MAC = "ff:ff:ff:ff:ff:ff"
_UNICAST_A = "38:4b:3c:00:00:01"
_CONCRETE_BCAST = f"{_UNICAST_A}/{_BCAST_MAC}//IPv4/192.168.1.5/192.168.1.255/0/0/Ethernet:IPv4:UDP"
_WILDCARD_BCAST_SAME = f"{_UNICAST_A}/{_BCAST_MAC}//IPv4/192.168.1.5/192.168.1.255/*/*/Ethernet:IPv4:UDP"
_WILDCARD_BCAST_REVERSE = f"{_BCAST_MAC}/{_UNICAST_A}//IPv4/192.168.1.255/192.168.1.5/*/*/Ethernet:IPv4:UDP"


def _manager(bounds: dict[str, dict[str, tuple[float, float]]]) -> BoundsManager:
    """Build an in-memory bounds manager seeded with ``bounds`` (no DB)."""
    manager = BoundsManager(module_name="conn", cache_ttl_seconds=3600)
    manager.load_bounds(bounds)
    return manager


def _check(
    manager: BoundsManager,
    series_id: str,
    value: float,
) -> pl.DataFrame:
    """Run a one-row check for ``series_id`` at feature value ``value``."""
    df = pl.DataFrame({"uci": [series_id], _FEATURE: [value]})
    return manager.check(df, tag_key="uci", features=[_FEATURE])


def test_exact_match_still_wins_over_sibling_merge() -> None:
    """An exact series_id key returns its own bounds, never a sibling merge."""
    bounds = {
        _CONCRETE_AB: {_FEATURE: (10.0, 100.0)},
        _CONCRETE_AB_ALT_PORTS: {_FEATURE: (5.0, 200.0)},
    }
    result = _check(_manager(bounds), _CONCRETE_AB, value=7.0)

    # 7.0 is inside the merged envelope (5, 200) but outside the exact AB
    # envelope (10, 100). Exact-match winning -> BoundViolation; a merge
    # would have suppressed it. This proves the exact fast path is used.
    assert result["is_anomaly"][0] is True
    assert result["anomaly_type"][0] == "BoundViolation"


def test_full_wildcard_resolves_to_concrete_bounds() -> None:
    """A ``*/*`` wildcard series resolves to the trained concrete series."""
    bounds = {_CONCRETE_AB: {_FEATURE: (10.0, 100.0)}}
    result = _check(_manager(bounds), _WILDCARD_AB, value=50.0)

    assert result["anomaly_type"][0] != "NoBounds"
    assert result["is_anomaly"][0] is False


def test_single_side_wildcard_resolves_to_concrete_bounds() -> None:
    """A ``56247/*`` partial-wildcard series resolves to the concrete series."""
    bounds = {_CONCRETE_AB: {_FEATURE: (10.0, 100.0)}}
    partial = f"{_SRC_MAC}/{_DST_MAC}//IPv4/{_SRC_IP}/{_DST_IP}/56247/*/{_STACK}"
    result = _check(_manager(bounds), partial, value=50.0)

    assert result["anomaly_type"][0] != "NoBounds"
    assert result["is_anomaly"][0] is False


def test_reverse_direction_wildcard_resolves_to_concrete_bounds() -> None:
    """A direction-swapped unicast wildcard series resolves to the concrete series."""
    bounds = {_CONCRETE_AB: {_FEATURE: (10.0, 100.0)}}
    result = _check(_manager(bounds), _REVERSE_BA_WILDCARD, value=50.0)

    assert result["anomaly_type"][0] != "NoBounds"
    assert result["is_anomaly"][0] is False


def test_no_match_when_identity_differs_stays_no_bounds() -> None:
    """A wildcard series whose MACs/IPs/protocol differ stays NoBounds."""
    bounds = {_CONCRETE_AB: {_FEATURE: (10.0, 100.0)}}
    result = _check(_manager(bounds), _UNRELATED_WILDCARD, value=50.0)

    assert result["anomaly_type"][0] == "NoBounds"
    assert result["is_anomaly"][0] is True


def test_broadcast_mac_is_not_reverse_matched() -> None:
    """A broadcast target has no reverse direction and must not cross-match."""
    bounds = {_CONCRETE_BCAST: {_FEATURE: (10.0, 100.0)}}
    result = _check(_manager(bounds), _WILDCARD_BCAST_REVERSE, value=50.0)

    assert result["anomaly_type"][0] == "NoBounds"
    assert result["is_anomaly"][0] is True


def test_broadcast_mac_same_direction_still_resolves() -> None:
    """A broadcast series with wildcard ports in the SAME direction still resolves."""
    bounds = {_CONCRETE_BCAST: {_FEATURE: (10.0, 100.0)}}
    result = _check(_manager(bounds), _WILDCARD_BCAST_SAME, value=50.0)

    assert result["anomaly_type"][0] != "NoBounds"
    assert result["is_anomaly"][0] is False


def test_multiple_siblings_merge_to_widest_envelope() -> None:
    """A wildcard series matching several concrete siblings gets the widest envelope.

    Two concrete siblings share the same connection identity with rotated
    ports: AB covers (40, 60) and AB_ALT covers (70, 90). The conservative
    merge is the union (40, 90). A value of 65 lies inside the union but
    outside BOTH individual envelopes, so only the merged envelope can keep
    it clean -- neither sibling alone would.
    """
    bounds = {
        _CONCRETE_AB: {_FEATURE: (40.0, 60.0)},
        _CONCRETE_AB_ALT_PORTS: {_FEATURE: (70.0, 90.0)},
    }
    result = _check(_manager(bounds), _WILDCARD_AB, value=65.0)

    assert result["anomaly_type"][0] != "NoBounds"
    assert result["is_anomaly"][0] is False

    # The same value must violate the individual envelopes, confirming the
    # clean result above comes from the merged envelope and not a no-op.
    solo_ab = _check(_manager({_CONCRETE_AB: {_FEATURE: (40.0, 60.0)}}), _CONCRETE_AB, value=65.0)
    solo_alt = _check(
        _manager({_CONCRETE_AB_ALT_PORTS: {_FEATURE: (70.0, 90.0)}}),
        _CONCRETE_AB_ALT_PORTS,
        value=65.0,
    )
    assert solo_ab["is_anomaly"][0] is True
    assert solo_alt["is_anomaly"][0] is True
