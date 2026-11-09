"""Shared fixtures for the passive-seeder unit tests.

The runtime-configuration registry is module-global process state. Without
isolation, a test that registers keys leaks them into every later test in the
session and produces order-dependent failures, so each test starts from an
empty registry and re-registers the seeder's own keys.
"""

from __future__ import annotations

from typing import Iterator

import pytest
from otalon_common.runtime import reset_registry

from otalon_scan.passive_source.runtime_keys import register_runtime_keys


@pytest.fixture(autouse=True)
def _isolated_runtime_registry() -> Iterator[None]:
    """Reset the shared registry around every test and register seeder keys."""
    reset_registry()
    register_runtime_keys()
    yield
    reset_registry()
