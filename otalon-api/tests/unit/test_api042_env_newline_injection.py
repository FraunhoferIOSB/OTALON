"""Regression tests for API-02 — ``.env.compose`` newline injection.

The audit PoC set an allowed key to ``x"\\nPOSTGRES_PASSWORD=pwned``, which
the old ``_format_value`` wrote verbatim: the embedded newline ended the
line and the remainder became a second, attacker-chosen assignment. Chained
with the (separately fixed) authorization gap this was a persistent
compromise of the compose environment.

These tests drive the public ``update_and_save`` path against a real
temporary ``.env.compose`` and assert the file is never corrupted.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from otalon_api.services.env_compose_service import (
    ENV_VALUE_MAX_LENGTH,
    EnvComposeService,
    _check_value_safe,
    _format_value,
)
from otalon_api.settings import Settings

pytestmark = pytest.mark.unit

BASE_ENV = "TZ=Europe/Berlin\nPOSTGRES_PASSWORD=original-secret\n"


@pytest.fixture()
def env_service(tmp_path: Path) -> EnvComposeService:
    """An EnvComposeService bound to a throwaway ``.env.compose``."""
    env_file = tmp_path / ".env.compose"
    env_file.write_text(BASE_ENV, encoding="utf-8")
    service = EnvComposeService(Settings(env_compose_path=str(env_file)))
    service.load()
    return service


def _password_of(env_file: Path) -> str | None:
    for line in env_file.read_text(encoding="utf-8").splitlines():
        if line.startswith("POSTGRES_PASSWORD="):
            return line.split("=", 1)[1]
    return None


class TestNewlineInjectionIsRejected:
    """The audit PoC and its variants must not reach the file."""

    def test_audit_poc_payload_is_rejected(self, env_service: EnvComposeService, tmp_path: Path) -> None:
        env_file = tmp_path / ".env.compose"

        with pytest.raises(ValueError) as exc:
            env_service.update_and_save(updates={"TZ": 'x"\nPOSTGRES_PASSWORD=pwned'})

        assert "single-line" in str(exc.value) or "double quotes" in str(exc.value)
        assert _password_of(env_file) == "original-secret", "password must be untouched"
        assert "pwned" not in env_file.read_text(encoding="utf-8")

    def test_bare_newline_is_rejected(self, env_service: EnvComposeService, tmp_path: Path) -> None:
        with pytest.raises(ValueError):
            env_service.update_and_save(updates={"TZ": "Europe/Berlin\nINJECTED=1"})

        assert "INJECTED" not in (tmp_path / ".env.compose").read_text(encoding="utf-8")

    def test_carriage_return_is_rejected(self, env_service: EnvComposeService, tmp_path: Path) -> None:
        with pytest.raises(ValueError):
            env_service.update_and_save(updates={"TZ": "Europe/Berlin\rINJECTED=1"})

        assert "INJECTED" not in (tmp_path / ".env.compose").read_text(encoding="utf-8")

    def test_file_still_has_exactly_two_assignments(self, env_service: EnvComposeService, tmp_path: Path) -> None:
        """An injection attempt must not add a line to the file."""
        env_file = tmp_path / ".env.compose"
        before = [ln for ln in env_file.read_text(encoding="utf-8").splitlines() if "=" in ln]

        with pytest.raises(ValueError):
            env_service.update_and_save(updates={"TZ": 'x"\nPOSTGRES_PASSWORD=pwned'})

        after = [ln for ln in env_file.read_text(encoding="utf-8").splitlines() if "=" in ln]
        assert after == before


class TestOtherUnsafeCharacters:
    def test_double_quote_is_rejected(self) -> None:
        assert _check_value_safe("TZ", 'has"quote') is not None

    def test_dollar_is_rejected(self) -> None:
        """``$`` would trigger compose variable interpolation."""
        assert _check_value_safe("TZ", "$POSTGRES_PASSWORD") is not None

    def test_overlong_value_is_rejected(self) -> None:
        assert _check_value_safe("TZ", "a" * (ENV_VALUE_MAX_LENGTH + 1)) is not None

    def test_format_value_raises_on_unsafe_input(self) -> None:
        with pytest.raises(ValueError):
            _format_value("a\nb")


class TestLegitimateValuesStillWork:
    """The guard must not break ordinary configuration changes."""

    def test_plain_value_is_written(self, env_service: EnvComposeService, tmp_path: Path) -> None:
        _, changed, _ = env_service.update_and_save(updates={"TZ": "UTC"})

        assert changed == ["TZ"]
        content = (tmp_path / ".env.compose").read_text(encoding="utf-8")
        assert "TZ=UTC" in content

    def test_value_with_spaces_is_quoted(self) -> None:
        assert _format_value("two words") == '"two words"'

    def test_safe_value_passes_the_check(self) -> None:
        assert _check_value_safe("TZ", "Europe/Berlin") is None


class TestWriteAtomicGuard:
    """Defence in depth: the writer itself refuses multi-line content."""

    def test_write_atomic_rejects_embedded_newline(self, env_service: EnvComposeService) -> None:
        with pytest.raises(ValueError, match="multi-line"):
            env_service._write_atomic(["TZ=ok", "EVIL=1\nMORE=2"])
