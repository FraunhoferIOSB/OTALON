"""Regression tests for FastAPI dependency-provider wiring.

Guards the protocol-resolver singleton against the UI-088 Phase-7
live-blocking defect: ``get_detection_readiness_service`` is ``@lru_cache``d
and constructs the shared :class:`ProtoHashResolver` by calling
``get_proto_hash_resolver`` manually. When that manual call passed no
argument, the provider's ``Depends(get_influx_repo)`` default leaked into
the module-global singleton, so ``ProtoHashResolver._influx_repo`` became a
FastAPI ``Depends`` marker. Every later (correctly injected) request then
reused the poisoned singleton, whose ``_refresh`` raised
``'Depends' object has no attribute 'query_distinct_tags'`` and left proto
rows displaying their raw hash.

These tests drive the real production provider path (no internal mocks): a
test ``Settings`` override lets ``get_influx_repo``/``get_postgres_repo``
build genuine repositories (both connect lazily, so no live DB is needed),
and assert the shared resolver ends up bound to the real singleton
:class:`InfluxRepository`, never a ``Depends`` object.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.params import Depends as DependsMarker

from otalon_api import dependencies
from otalon_api.dependencies import (
    get_detection_readiness_service,
    get_influx_repo,
    get_proto_hash_resolver,
    get_settings,
)
from otalon_api.domain.netcap.proto_resolver import ProtoHashResolver
from otalon_api.repositories.dashboard_user_state_repo import DashboardUserStateRepository
from otalon_api.repositories.influx_repo import InfluxRepository
from otalon_api.settings import Settings


@pytest.fixture()
def isolated_dependency_caches(monkeypatch: pytest.MonkeyPatch, mock_settings: Settings) -> Iterator[None]:
    """Clear the singleton caches/global and restore them after the test.

    Snapshots and restores every ``@lru_cache`` and the module-global
    ``_proto_hash_resolver`` that these tests perturb, so wiring assertions
    run against a clean slate and never contaminate other suite modules
    that share the same process-wide singletons. The shared ``mock_settings``
    fixture provides harmless localhost settings so ``get_influx_repo`` and
    ``get_postgres_repo`` build genuine repositories without a live backend.
    """
    caches = (get_settings, get_influx_repo, dependencies.get_postgres_repo, get_detection_readiness_service)
    for cache in caches:
        cache.cache_clear()
    previous_resolver = dependencies._proto_hash_resolver
    dependencies._proto_hash_resolver = None
    monkeypatch.setattr(dependencies, "get_settings", lambda: mock_settings)
    try:
        yield
    finally:
        for cache in caches:
            cache.cache_clear()
        dependencies._proto_hash_resolver = previous_resolver


@pytest.mark.unit
class TestProtoResolverWiring:
    """The shared proto resolver must always hold a real InfluxRepository."""

    def test_readiness_service_wires_real_influx_repo_into_resolver(self, isolated_dependency_caches: None) -> None:
        """Production construction binds the resolver to the singleton repo.

        Reproduces the poisoning scenario: build the readiness service the
        exact way production does, then prove the shared resolver's
        ``_influx_repo`` is the real singleton ``InfluxRepository`` and never
        an unresolved FastAPI ``Depends`` object.
        """
        service = get_detection_readiness_service()

        resolver = service._proto_resolver
        assert isinstance(resolver, ProtoHashResolver)
        assert isinstance(resolver._influx_repo, InfluxRepository)
        assert not isinstance(resolver._influx_repo, DependsMarker)
        assert resolver._influx_repo is get_influx_repo()
        assert service._influx is get_influx_repo()

    def test_subsequent_injected_call_returns_same_healthy_resolver(self, isolated_dependency_caches: None) -> None:
        """A later injected request reuses the same, non-poisoned singleton.

        After production construction, a correctly injected
        ``get_proto_hash_resolver(real_repo)`` call (as FastAPI performs it)
        must return the identical shared instance still bound to the real
        repository.
        """
        service = get_detection_readiness_service()
        shared = service._proto_resolver

        real_repo = get_influx_repo()
        reused = get_proto_hash_resolver(real_repo)

        assert reused is shared
        assert reused._influx_repo is real_repo
        assert isinstance(reused._influx_repo, InfluxRepository)

    def test_manual_call_without_repo_fails_fast_and_does_not_poison(self, isolated_dependency_caches: None) -> None:
        """Calling the provider with the Depends default raises, no poisoning.

        This is the red anchor for the original defect: a manual no-argument
        call leaves the ``Depends`` sentinel in place. The provider now
        rejects it with ``TypeError`` and the shared global stays ``None``,
        so a correct call afterwards still yields a healthy resolver.
        """
        with pytest.raises(TypeError, match="resolved InfluxRepository"):
            get_proto_hash_resolver()

        assert dependencies._proto_hash_resolver is None

        real_repo = get_influx_repo()
        resolver = get_proto_hash_resolver(real_repo)
        assert resolver._influx_repo is real_repo
        assert not isinstance(resolver._influx_repo, DependsMarker)


@pytest.mark.unit
class TestDashboardUserStateWiring:
    """The per-account dashboard state repository wiring (UI-199 wave A)."""

    def test_state_repo_binds_shared_postgres_singleton(self, isolated_dependency_caches: None) -> None:
        """The state repository is built over the shared PostgreSQL singleton.

        Drives the real production provider path: with a test ``Settings``
        override, ``get_dashboard_user_state_repo`` must construct a genuine
        :class:`DashboardUserStateRepository` over the same singleton
        :class:`PostgresRepository` every caller shares, never a
        ``Depends`` marker or a per-request throwaway backend.
        """
        repo = dependencies.get_dashboard_user_state_repo()

        assert isinstance(repo, DashboardUserStateRepository)
        assert repo._postgres is dependencies.get_postgres_repo()

    def test_retired_layout_store_dependency_is_gone(self) -> None:
        """The JSON-file layout store singleton is fully retired (A7)."""
        assert not hasattr(dependencies, "get_dashboard_layout_store")
        assert not hasattr(dependencies, "DashboardLayoutStore")
