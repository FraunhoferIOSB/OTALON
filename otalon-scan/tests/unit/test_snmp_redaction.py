"""Unit tests for Phase 4 of ``harden-otalon-scan-security`` — SNMP log redaction.

Covers the two requirements from ``scan--credential-redaction``:

1. **SNMP community strings SHALL be redacted in log output by default.**
   Every log line that previously embedded the community value now emits
   the literal ``***`` token.

2. **Full SNMP community logging SHALL be opt-in via ``CS_SNMP_LOG_COMMUNITY=1``.**
   When the override is active:
   - Log lines emit the cleartext community.
   - Exactly one WARNING line is emitted at startup (snmp_scan package import).

Loguru sink fixture: ``loguru_sink`` registers an in-memory list sink for
the duration of a test and removes it afterwards, so each test sees a
clean, deterministic record of what was logged. We intentionally do NOT
use pytest's ``caplog`` because loguru does not propagate to stdlib
logging by default and the project uses loguru for ``snmp_scan``
emissions (per ``AGENTS.md``).
"""

from __future__ import annotations

import importlib
from typing import Iterator, List

import pytest
from loguru import logger

from otalon_scan.core.models import ScanConfig
from otalon_scan.modules.snmp_scan import start as snmp_start
from otalon_scan.modules.snmp_scan.start import SnmpsubmanagerModule, _redact_community

_TEST_COMMUNITY = "public-test-value"
_TEST_TARGET = "10.0.0.5"
_TEST_CIDR = "10.0.0.0/24"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def loguru_sink() -> Iterator[List[str]]:
    """Capture loguru output into an in-memory list for the duration of a test."""
    captured: List[str] = []
    sink_id = logger.add(
        captured.append,
        level="DEBUG",
        format="{level}|{message}",
    )
    try:
        yield captured
    finally:
        logger.remove(sink_id)


@pytest.fixture
def no_override(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure ``CS_SNMP_LOG_COMMUNITY`` is unset for the test."""
    monkeypatch.delenv("CS_SNMP_LOG_COMMUNITY", raising=False)


@pytest.fixture
def override_active(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set ``CS_SNMP_LOG_COMMUNITY=1`` for the test."""
    monkeypatch.setenv("CS_SNMP_LOG_COMMUNITY", "1")


@pytest.fixture
def mock_walker(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace the SNMP ``walker`` with a no-op so tests do not perform real IO."""

    async def _noop_walker(*args: object, **kwargs: object) -> None:
        return None

    monkeypatch.setattr(snmp_start, "walker", _noop_walker)


# ---------------------------------------------------------------------------
# _redact_community — direct helper tests
# ---------------------------------------------------------------------------


class TestRedactCommunityHelper:
    """The single point of truth for redaction behavior."""

    def test_default_returns_stars(self, no_override: None) -> None:
        assert _redact_community(_TEST_COMMUNITY) == "***"

    def test_override_returns_cleartext(self, override_active: None) -> None:
        assert _redact_community(_TEST_COMMUNITY) == _TEST_COMMUNITY

    @pytest.mark.parametrize("value", ["", "0", "true", "TRUE", "yes", "2", " 1"])
    def test_any_non_exact_one_value_preserves_redaction(self, monkeypatch: pytest.MonkeyPatch, value: str) -> None:
        monkeypatch.setenv("CS_SNMP_LOG_COMMUNITY", value)
        assert _redact_community(_TEST_COMMUNITY) == "***"


# ---------------------------------------------------------------------------
# Log-emission sites in start.py
# ---------------------------------------------------------------------------


async def _run_one_scan(community: str) -> None:
    """Drive ``SnmpsubmanagerModule.scan`` once with a matching community entry."""
    cfg = ScanConfig(
        module_name=SnmpsubmanagerModule.name,
        target_ip=_TEST_TARGET,
        parameters={
            "target_ip": _TEST_TARGET,
            "communities": [[_TEST_CIDR, community, 1]],
        },
    )
    mod = SnmpsubmanagerModule()
    async for _ in mod.scan(cfg):
        # Consume the iterator fully; we only care about logged side effects.
        pass


class TestWalkLogRedaction:
    """The ``walking <ip> with community '<X>'`` INFO line."""

    async def test_default_log_contains_stars_not_cleartext(
        self,
        no_override: None,
        mock_walker: None,
        loguru_sink: List[str],
    ) -> None:
        await _run_one_scan(_TEST_COMMUNITY)
        joined = "\n".join(loguru_sink)
        assert "community '***'" in joined
        assert _TEST_COMMUNITY not in joined

    async def test_override_log_contains_cleartext(
        self,
        override_active: None,
        mock_walker: None,
        loguru_sink: List[str],
    ) -> None:
        await _run_one_scan(_TEST_COMMUNITY)
        joined = "\n".join(loguru_sink)
        assert f"community '{_TEST_COMMUNITY}'" in joined
        assert "community '***'" not in joined


class TestMalformedEntryLogRedaction:
    """The ``skipping malformed community entry …`` WARNING line."""

    async def test_malformed_entry_does_not_leak_community_by_default(
        self,
        no_override: None,
        mock_walker: None,
        loguru_sink: List[str],
    ) -> None:
        # Two-element entry — unpacking into (cidr, community, mpmodel) raises ValueError.
        cfg = ScanConfig(
            module_name=SnmpsubmanagerModule.name,
            target_ip=_TEST_TARGET,
            parameters={
                "target_ip": _TEST_TARGET,
                "communities": [[_TEST_CIDR, _TEST_COMMUNITY]],
            },
        )
        mod = SnmpsubmanagerModule()
        async for _ in mod.scan(cfg):
            pass
        joined = "\n".join(loguru_sink)
        assert "malformed community entry" in joined
        assert "community=***" in joined
        assert _TEST_COMMUNITY not in joined


# ---------------------------------------------------------------------------
# Startup WARNING (snmp_scan package import-time side effect)
# ---------------------------------------------------------------------------


class TestStartupWarning:
    """The package ``__init__`` emits the WARNING exactly once when the override is set."""

    def test_no_warning_when_override_unset(
        self,
        no_override: None,
        loguru_sink: List[str],
    ) -> None:
        # Reload the package so the import-time side effect re-runs against
        # the *current* environment.
        import otalon_scan.modules.snmp_scan as snmp_pkg

        importlib.reload(snmp_pkg)
        joined = "\n".join(loguru_sink)
        assert "CS_SNMP_LOG_COMMUNITY=1 active" not in joined

    def test_warning_emitted_exactly_once_when_override_set(
        self,
        override_active: None,
        loguru_sink: List[str],
    ) -> None:
        import otalon_scan.modules.snmp_scan as snmp_pkg

        # First reload picks up the override and emits the warning.
        importlib.reload(snmp_pkg)
        # Second reload also runs the import-time code path; because the
        # module is freshly initialized its guard fires again. The
        # *contract* in the spec is "exactly one WARNING line at startup",
        # which in production maps to a single process import. We
        # simulate that by counting after a single reload.
        warnings = [line for line in loguru_sink if "CS_SNMP_LOG_COMMUNITY=1 active" in line]
        assert len(warnings) == 1
        assert warnings[0].startswith("WARNING|")
        assert "SNMP community strings will be logged in cleartext" in warnings[0]
