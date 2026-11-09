"""Unit tests for BoundsService proto-hash handling in the chart endpoint.

Round-4 regression: the UI sends the *canonical numeric proto hash* as the
chart ``uci``. The service must resolve that hash to the plaintext protocol
for the InfluxDB tag query, keep the original hash for the PostgreSQL bounds
lookup, expose the plaintext ``protocol`` in the response, and never hash an
already-hashed identifier a second time.

Round-4 audit fix: these tests now exercise the **production default**
``normalize=True`` (the generic ``/api/v1/anomalies/bounds`` route never
passes ``normalize=False``). Under the prior code the default normalisation
ran ``normalize_uci`` on the bare numeric hash first, turning ``"12345678"``
into ``"12345678////////"`` and corrupting the Influx tag and PG key. The
service must now skip slash normalisation for ``proto_traffic`` regardless of
the flag. One test contrasts the default path against an explicit
``normalize=False`` to prove the behaviour is identical for proto.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pandas as pd
import pytest

from otalon_api.domain.netcap.models import proto_series_hash
from otalon_api.services.bounds_service import BoundsService
from otalon_api.settings import Settings

_START = datetime(2026, 3, 6, 21, 0, 0, tzinfo=timezone.utc)
_STOP = datetime(2026, 3, 6, 22, 0, 0, tzinfo=timezone.utc)
_PROTOCOL = "Ethernet:IPv4:UDP:DNS"
_METRIC = "proto_total_packets"


class _StubResolver:
    """Resolver stub that maps exactly the known hash to its plaintext."""

    def __init__(self, protocol: str) -> None:
        self._map = {proto_series_hash(protocol): protocol}
        self.resolve_calls: list[str] = []

    def resolve(self, hash_value: str) -> str:
        self.resolve_calls.append(hash_value)
        return self._map.get(hash_value, hash_value)


def _influx_with_rows() -> MagicMock:
    influx = MagicMock()
    influx.query_timeseries.return_value = pd.DataFrame(
        {
            "time": [_START],
            _METRIC: [7.0],
        }
    )
    return influx


def _make_service(mock_settings: Settings, resolver: _StubResolver) -> tuple[BoundsService, MagicMock, MagicMock]:
    influx = _influx_with_rows()
    postgres = MagicMock()
    postgres.query_bounds.return_value = []
    service = BoundsService(
        influx,
        postgres,
        mock_settings,
        aggregation_service=None,
        proto_resolver=resolver,  # type: ignore[arg-type]
    )
    return service, influx, postgres


@pytest.mark.unit
async def test_numeric_proto_hash_resolves_plaintext_for_influx_and_keeps_hash_for_pg(
    mock_settings: Settings,
) -> None:
    """A canonical numeric proto hash resolves to plaintext for Influx, hash for PG.

    Uses the production default ``normalize=True`` — the numeric hash must NOT
    be slash-normalised.
    """
    canonical_hash = proto_series_hash(_PROTOCOL)
    resolver = _StubResolver(_PROTOCOL)
    service, influx, postgres = _make_service(mock_settings, resolver)

    result = await service.get_timeseries_with_bounds(
        uci=canonical_hash,
        metric=_METRIC,
        start=_START,
        stop=_STOP,
        module="proto_traffic",
    )

    # Influx tag query uses the resolved plaintext protocol, not the hash.
    influx.query_timeseries.assert_called_once()
    influx_kwargs = influx.query_timeseries.call_args.kwargs
    assert influx_kwargs["tags"] == {"protocol": _PROTOCOL}
    assert influx_kwargs["measurement"] == "proto_traffic"
    assert influx_kwargs["id_tag"] == "protocol"

    # PostgreSQL bounds are queried by the canonical hash unchanged.
    postgres.query_bounds.assert_called_once()
    pg_kwargs = postgres.query_bounds.call_args.kwargs
    assert pg_kwargs["module"] == "proto_traffic"
    assert pg_kwargs["series_id"] == canonical_hash

    # The input hash is NOT hashed again (no double-hash) and not corrupted.
    assert pg_kwargs["series_id"] != proto_series_hash(canonical_hash)
    assert "/" not in pg_kwargs["series_id"]

    # The response exposes the readable protocol stack.
    assert result["protocol"] == _PROTOCOL


@pytest.mark.unit
async def test_numeric_proto_hash_default_normalize_matches_explicit_no_normalize(
    mock_settings: Settings,
) -> None:
    """Proto path is identical under default normalize=True and normalize=False.

    Regression guard for the P1 corruption: normalisation must be a no-op for
    proto series_ids, so both flag values produce the same Influx tag and PG
    key for the same numeric hash.
    """
    canonical_hash = proto_series_hash(_PROTOCOL)

    default_service, default_influx, default_pg = _make_service(mock_settings, _StubResolver(_PROTOCOL))
    await default_service.get_timeseries_with_bounds(
        uci=canonical_hash,
        metric=_METRIC,
        start=_START,
        stop=_STOP,
        module="proto_traffic",
    )

    explicit_service, explicit_influx, explicit_pg = _make_service(mock_settings, _StubResolver(_PROTOCOL))
    await explicit_service.get_timeseries_with_bounds(
        uci=canonical_hash,
        metric=_METRIC,
        start=_START,
        stop=_STOP,
        module="proto_traffic",
        normalize=False,
    )

    assert default_influx.query_timeseries.call_args.kwargs["tags"] == {"protocol": _PROTOCOL}
    assert (
        default_influx.query_timeseries.call_args.kwargs["tags"]
        == explicit_influx.query_timeseries.call_args.kwargs["tags"]
    )
    assert (
        default_pg.query_bounds.call_args.kwargs["series_id"]
        == explicit_pg.query_bounds.call_args.kwargs["series_id"]
        == canonical_hash
    )


@pytest.mark.unit
async def test_numeric_proto_hash_response_parameters_stay_canonical(
    mock_settings: Settings,
) -> None:
    """The diagnostic ``parameters.uci`` echoes the caller's canonical hash."""
    canonical_hash = proto_series_hash(_PROTOCOL)
    resolver = _StubResolver(_PROTOCOL)
    service, _influx, _postgres = _make_service(mock_settings, resolver)

    result = await service.get_timeseries_with_bounds(
        uci=canonical_hash,
        metric=_METRIC,
        start=_START,
        stop=_STOP,
        module="proto_traffic",
    )

    # Caller identity remains canonical: the resolved plaintext is used only
    # internally for the Influx tag, never leaked into the response identity.
    assert result["parameters"]["uci"] == canonical_hash
    assert result["parameters"]["uci"] != _PROTOCOL


@pytest.mark.unit
async def test_unknown_numeric_proto_hash_stays_canonical_for_pg(
    mock_settings: Settings,
) -> None:
    """An unknown numeric persisted hash stays canonical for PG and is not re-hashed.

    The resolver does not know this hash, so Influx is queried by the raw
    numeric (fail-empty, since the ``protocol`` tag is plaintext) while the PG
    bounds key remains the canonical numeric hash — never double-hashed and
    never slash-corrupted.
    """
    unknown_hash = "2071234567"
    resolver = _StubResolver(_PROTOCOL)  # maps a *different* protocol only
    service, influx, postgres = _make_service(mock_settings, resolver)

    await service.get_timeseries_with_bounds(
        uci=unknown_hash,
        metric=_METRIC,
        start=_START,
        stop=_STOP,
        module="proto_traffic",
    )

    influx_kwargs = influx.query_timeseries.call_args.kwargs
    assert influx_kwargs["tags"] == {"protocol": unknown_hash}
    pg_kwargs = postgres.query_bounds.call_args.kwargs
    assert pg_kwargs["series_id"] == unknown_hash
    assert pg_kwargs["series_id"] != proto_series_hash(unknown_hash)


@pytest.mark.unit
async def test_plaintext_proto_input_is_hashed_for_pg_bounds(
    mock_settings: Settings,
) -> None:
    """A plaintext protocol input is hashed for the PG bounds lookup (legacy path).

    Exercised under the production default ``normalize=True``; the colon-
    delimited plaintext must not be slash-normalised.
    """
    resolver = _StubResolver(_PROTOCOL)
    service, influx, postgres = _make_service(mock_settings, resolver)

    await service.get_timeseries_with_bounds(
        uci=_PROTOCOL,
        metric=_METRIC,
        start=_START,
        stop=_STOP,
        module="proto_traffic",
    )

    # Plaintext in → Influx by plaintext, PG by the hash of that plaintext.
    influx_kwargs = influx.query_timeseries.call_args.kwargs
    assert influx_kwargs["tags"] == {"protocol": _PROTOCOL}
    pg_kwargs = postgres.query_bounds.call_args.kwargs
    assert pg_kwargs["series_id"] == proto_series_hash(_PROTOCOL)
