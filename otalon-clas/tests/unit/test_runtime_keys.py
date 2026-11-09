"""Tests for otalon-clas runtime-key registry declarations."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from otalon_common.runtime import (
    OTALON_CLAS_SERVICE,
    all_specs,
    manifest_for_service,
    reset_registry,
)

from otalon_clas.runtime.runtime_keys import register_runtime_keys


@pytest.fixture(autouse=True)
def _isolated_runtime_registry() -> Iterator[None]:
    """Reset registry state and register otalon-clas keys for each test."""
    reset_registry()
    register_runtime_keys()
    yield
    reset_registry()


def test_registrations_match_manifest_slice() -> None:
    """Registered declarations equal otalon-clas manifest declarations."""
    registered = sorted(
        (spec.declaration() for spec in all_specs() if spec.service == OTALON_CLAS_SERVICE),
        key=lambda entry: entry.key,
    )
    expected = sorted(manifest_for_service(OTALON_CLAS_SERVICE), key=lambda entry: entry.key)
    assert registered == expected
