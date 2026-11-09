"""Pydantic-based settings with JSON loading and environment variable resolution."""

import json
from pathlib import Path
from typing import Self

import pydantic

from otalon_common.config.env_resolver import (
    MissingEnvVarPolicy,
    resolve_env_placeholders,
)


class BaseSettings(pydantic.BaseModel):
    """Base settings class with JSON loading and environment variable resolution.

    Subprojects extend this class with their own typed config fields.
    Extra fields are forbidden to catch configuration errors early.
    """

    model_config = pydantic.ConfigDict(extra="forbid")

    @classmethod
    def from_json(
        cls,
        path: str | Path,
        env_policy: MissingEnvVarPolicy = MissingEnvVarPolicy.RAISE,
        default: str | None = None,
        json_arrays: bool = False,
        expand_nested: bool = False,
    ) -> Self:
        """Load settings from a JSON config file with environment variable resolution.

        Subclasses may override this to pin a subproject-wide loader policy
        once instead of repeating the options at every call site.

        Args:
            path: Path to the JSON configuration file.
            env_policy: Policy for handling missing environment variables.
            default: Fallback value when env_policy is USE_DEFAULT.
            json_arrays: Parse resolved values that look like JSON as JSON.
            expand_nested: Expand nested ``$`` references in resolved values.

        Returns:
            A validated settings instance.

        Raises:
            FileNotFoundError: If the config file does not exist.
            json.JSONDecodeError: If the file contains invalid JSON.
            RuntimeError: If env_policy is RAISE and a variable is not set.
            pydantic.ValidationError: If resolved values fail Pydantic validation.
        """
        config_path = Path(path)
        raw_data = json.loads(config_path.read_text(encoding="utf-8"))
        resolved_data = resolve_env_placeholders(
            raw_data,
            policy=env_policy,
            default=default,
            json_arrays=json_arrays,
            expand_nested=expand_nested,
        )
        return cls.model_validate(resolved_data)
