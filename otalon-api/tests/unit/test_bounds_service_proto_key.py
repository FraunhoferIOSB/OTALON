"""Isolated tests for the proto PG-bounds-key decision helper.

Round-4 audit finding C: the choice between "already a persisted hash" and
"plaintext to hash" was a bare ``.isdigit()`` heuristic. It is now an explicit,
resolver-derived decision in :meth:`BoundsService._proto_pg_bounds_key`. These
tests isolate that decision from the Influx/PG round-trip and prove:

* a resolver-known hash stays canonical (no re-hash);
* an unknown but purely numeric persisted hash stays canonical (fail-empty on
  Influx, honest key for PG);
* a colon-delimited plaintext stack is hashed;
* the decision is independent of slash normalisation (which never runs for
  proto), i.e. a slash-corrupted input can never reach this helper on the proto
  path, and even if hypothetically passed it is not silently treated as a hash.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from otalon_api.domain.netcap.models import proto_series_hash
from otalon_api.services.bounds_service import BoundsService
from otalon_api.settings import Settings

_PROTOCOL = "Ethernet:IPv4:UDP:DNS"


def _service(mock_settings: Settings) -> BoundsService:
    return BoundsService(
        MagicMock(),
        MagicMock(),
        mock_settings,
        aggregation_service=None,
        proto_resolver=MagicMock(),
    )


@pytest.mark.unit
def test_resolver_known_hash_stays_canonical(mock_settings: Settings) -> None:
    """A hash the resolver mapped (resolved != requested) is used verbatim."""
    service = _service(mock_settings)
    canonical_hash = proto_series_hash(_PROTOCOL)

    key = service._proto_pg_bounds_key(canonical_hash, _PROTOCOL)

    assert key == canonical_hash
    assert key != proto_series_hash(canonical_hash)


@pytest.mark.unit
def test_unknown_numeric_hash_stays_canonical(mock_settings: Settings) -> None:
    """An unresolved but all-digit id is treated as an already-persisted hash."""
    service = _service(mock_settings)
    unknown_hash = "2071234567"

    # resolver did not map it: resolved_plaintext == requested_series
    key = service._proto_pg_bounds_key(unknown_hash, unknown_hash)

    assert key == unknown_hash
    assert key != proto_series_hash(unknown_hash)


@pytest.mark.unit
def test_plaintext_stack_is_hashed(mock_settings: Settings) -> None:
    """A colon-delimited plaintext stack (unresolved) is hashed for PG."""
    service = _service(mock_settings)

    key = service._proto_pg_bounds_key(_PROTOCOL, _PROTOCOL)

    assert key == proto_series_hash(_PROTOCOL)


@pytest.mark.unit
def test_slash_corrupted_input_is_not_treated_as_hash(mock_settings: Settings) -> None:
    """A slash-bearing value is never silently accepted as a canonical hash.

    Normalisation is confined to conn sources, so proto ids never acquire
    trailing slashes; this asserts the helper itself would not mistake such a
    value for a persisted hash (it would hash it instead of using it verbatim).
    """
    service = _service(mock_settings)
    corrupted = "12345678////////"

    key = service._proto_pg_bounds_key(corrupted, corrupted)

    assert key == proto_series_hash(corrupted)
    assert key != corrupted
