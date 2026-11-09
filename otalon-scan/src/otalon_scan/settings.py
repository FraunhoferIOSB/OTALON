"""Settings loader for the CyberScan-ICS server.

Provides a centralized configuration model parsed from config/config.json, with
environment placeholder resolution and sensible defaults. Exposes a cached
getter to load the default configuration once per process.

Placeholder resolution uses the shared ``otalon_common.config`` resolver
(SUITE-038); a missing variable is a hard error, as it was before.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Self

from dotenv import load_dotenv
from otalon_common.config import BaseSettings, MissingEnvVarPolicy
from pydantic import BaseModel, ConfigDict, Field

ENV_PATH = Path(__file__).resolve().parents[3] / ".env.compose"
load_dotenv(dotenv_path=str(ENV_PATH), override=True)


class ServerConfig(BaseModel):
    """API server runtime configuration."""

    host: str = "0.0.0.0"
    port: int = 8091


class PostgresConfig(BaseModel):
    """PostgreSQL connection configuration."""

    dsn: str


class ModulesConfig(BaseModel):
    """Scanner modules configuration."""

    path: str  # root path to modules, e.g. "/app/src/otalon_scan/modules" or local path


class LoggingConfig(BaseModel):
    """Extended logging configuration for the server and modules."""

    # Legacy/simple fields (kept for compatibility)
    level: str = "DEBUG"
    file: str = "otalon-scan.log"

    # Console/file specifics used by core.log_config
    level_console: str = "DEBUG"
    level_file: str = "DEBUG"
    file_path: str = "logs/application.log"
    file_rotation: str = "1 week"
    file_retention: str = "4 weeks"
    file_compression: str = "zip"

    # Formats
    format: str = "{time} {level} {file}:{line} {message}"
    format_console: str = (
        "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
        "<level>{level: <8}</level> | "
        "<white>{file}:{line}</white> | "
        "<cyan>{message}</cyan>"
    )


class NetworkConfig(BaseModel):
    """Network defaults for scanner modules."""

    default_interface: str = "enp4s0"


class SystemConfig(BaseModel):
    """System paths and OS-specific settings."""

    arp_table_path: str = "/proc/net/arp"


class Settings(BaseSettings):
    """Root configuration model parsed from config/config.json."""

    # ``extra='ignore'`` keeps Settings.from_json backward
    # compatible with legacy config files that still carry the retired
    # activity-log block (F-02 / scan--dependency-management Requirement
    # for retiring the legacy activity log; see README for details).
    # Declared explicitly: the shared base forbids extra keys (SUITE-038).
    model_config = ConfigDict(extra="ignore")

    server: ServerConfig = Field(default_factory=ServerConfig)
    postgres: PostgresConfig
    modules: ModulesConfig
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    system: SystemConfig = Field(default_factory=SystemConfig)

    @staticmethod
    def default_config_path() -> str:
        """Resolve config/config.json relative to project structure (both local and container)."""
        src_dir = Path(__file__).resolve().parents[1]
        cfg_path = src_dir.parent / "config" / "config.json"
        return str(cfg_path)

    @classmethod
    def from_json(
        cls,
        path: str | Path,
        env_policy: MissingEnvVarPolicy = MissingEnvVarPolicy.RAISE,
        default: str | None = None,
        json_arrays: bool = True,
        expand_nested: bool = True,
    ) -> Self:
        """Load settings from a JSON config file, resolving ``$ENV_VAR``.

        Args:
            path: Path to the JSON configuration file.
            env_policy: Policy for missing variables; RAISE by default.
            default: Fallback value when env_policy is USE_DEFAULT.
            json_arrays: Parse JSON-looking values as JSON.
            expand_nested: Expand nested ``$`` references in resolved values.

        Returns:
            A validated settings instance.
        """
        return super().from_json(
            path,
            env_policy=env_policy,
            default=default,
            json_arrays=json_arrays,
            expand_nested=expand_nested,
        )

    @classmethod
    def load_default(cls) -> "Settings":
        """Load the default configuration from the standard config path."""
        return cls.from_json(cls.default_config_path())


# Cached default settings instance
_DEFAULT_SETTINGS: Optional[Settings] = None


def get_default_settings() -> Settings:
    """Return the cached default Settings instance, loading it on first access."""
    global _DEFAULT_SETTINGS
    if _DEFAULT_SETTINGS is None:
        _DEFAULT_SETTINGS = Settings.load_default()
    return _DEFAULT_SETTINGS
