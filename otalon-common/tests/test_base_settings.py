"""Tests for BaseSettings Pydantic class with JSON loading."""

import json
from pathlib import Path

import pydantic
import pytest
from otalon_common.config.base_settings import BaseSettings
from otalon_common.config.env_resolver import MissingEnvVarPolicy


class AppSettings(BaseSettings):
    """Test settings subclass."""

    host: str
    port: int
    debug: bool = False


class TestBaseSettings:
    """Tests for BaseSettings.from_json()."""

    def test_load_from_json(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("APP_HOST", "localhost")
        monkeypatch.setenv("APP_PORT", "8080")
        config_file = tmp_path / "config.json"
        config_file.write_text(
            json.dumps({"host": "$APP_HOST", "port": "$APP_PORT", "debug": False})
        )

        settings = AppSettings.from_json(config_file)
        assert settings.host == "localhost"
        assert settings.port == 8080
        assert settings.debug is False

    def test_env_resolution_with_coercion(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("APP_HOST", "0.0.0.0")
        monkeypatch.setenv("APP_PORT", "9090")
        monkeypatch.setenv("APP_DEBUG", "true")
        config_file = tmp_path / "config.json"
        config_file.write_text(
            json.dumps(
                {"host": "$APP_HOST", "port": "$APP_PORT", "debug": "$APP_DEBUG"}
            )
        )

        settings = AppSettings.from_json(config_file)
        assert settings.host == "0.0.0.0"
        assert settings.port == 9090
        assert settings.debug is True

    def test_pydantic_validation_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("APP_HOST", "localhost")
        monkeypatch.setenv("APP_PORT", "abc")
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({"host": "$APP_HOST", "port": "$APP_PORT"}))

        with pytest.raises(pydantic.ValidationError):
            AppSettings.from_json(config_file)

    def test_missing_file_raises(self) -> None:
        with pytest.raises(FileNotFoundError):
            AppSettings.from_json("/nonexistent/config.json")

    def test_extra_fields_forbidden(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.json"
        config_file.write_text(
            json.dumps({"host": "localhost", "port": 8080, "extra": "bad"})
        )

        with pytest.raises(pydantic.ValidationError):
            AppSettings.from_json(config_file)

    def test_warn_and_skip_policy(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import os

        os.environ.pop("OPT_HOST", None)
        monkeypatch.setenv("APP_PORT", "8080")
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({"host": "$OPT_HOST", "port": "$APP_PORT"}))

        settings = AppSettings.from_json(
            config_file, env_policy=MissingEnvVarPolicy.WARN_AND_SKIP
        )
        assert settings.host == "$OPT_HOST"
        assert settings.port == 8080
