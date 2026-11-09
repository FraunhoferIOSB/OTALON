"""Settings for the CVE lookup auto-loop worker.

Follows the ``Environment Variables Contract`` pattern established by
:mod:`otalon_scan.passive_source.settings` (passive_seeder).  All configuration is
read from environment variables only — no ``config.json``.
"""

from __future__ import annotations

from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class CveLookupSettings(BaseSettings):
    """Strongly-typed settings for the CVE lookup background worker.

    Field names mirror the env-var names in upper case; the
    ``env_prefix=''`` and ``case_sensitive=False`` config below makes
    the binding case-insensitive.
    """

    enabled: bool = Field(
        default=False,
        validation_alias="CVE_LOOKUP_ENABLED",
        description="Feature-flag default-OFF; set to true to start the lookup loop.",
    )
    interval_s: int = Field(
        default=86400,
        validation_alias="CVE_LOOKUP_INTERVAL_S",
        description="Seconds between consecutive lookup cycles (default 1 day).",
    )
    nvd_api_key: Optional[str] = Field(
        default=None,
        validation_alias="NVD_API_KEY",
        description="Optional NVD API key for higher-rate throttling.",
    )

    model_config = SettingsConfigDict(
        env_prefix="",
        case_sensitive=False,
        extra="ignore",
    )
