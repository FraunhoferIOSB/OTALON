"""Settings for the passive asset seeder.

Implements the ``Environment Variables Contract`` requirement from
``openspec/changes/add-passive-asset-seeder/specs/passive-asset-seeding/spec.md``
and the env-var defaults pinned by ``design.md`` decision
``D-WORKER-PLACEMENT``.

All configuration is read from environment variables only — there is
no ``config.json`` for this worker (it would not survive the
"separate process, principle-of-least-privilege" design pick).
Pydantic v2 ``BaseSettings`` provides validation; invalid values raise
``ValidationError`` at instantiation time so the process can log one
ERROR line identifying the offending field and exit with code 2.
"""

from __future__ import annotations

from typing import Optional

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class PassiveSeederSettings(BaseSettings):
    """Strongly-typed settings for the passive seeder process.

    Field names mirror the env-var names in upper case; the
    ``env_prefix=''`` and ``case_sensitive=False`` config below makes
    the binding case-insensitive so ``PASSIVE_SEEDER_ENABLED`` (env)
    and ``enabled`` (Python attribute) refer to the same value.

    See ``add-passive-asset-seeder/specs/passive-asset-seeding/spec.md``
    requirement ``Environment Variables Contract`` for the exhaustive
    list of variables, defaults, and validation rules.
    """

    enabled: bool = Field(
        default=False,
        validation_alias="PASSIVE_SEEDER_ENABLED",
        description="Feature-flag default-OFF; set to true to start the poll loop.",
    )
    poll_interval_s: int = Field(
        default=60,
        validation_alias="PASSIVE_SEEDER_POLL_INTERVAL_S",
        description="Seconds between consecutive poll cycles.",
    )
    lookback_window_s: int = Field(
        default=300,
        validation_alias="PASSIVE_SEEDER_LOOKBACK_WINDOW_S",
        description="Seconds the Influx queries look back from now().",
    )
    influx_url: str = Field(
        default="http://influxdb3:8181",
        validation_alias="PASSIVE_SEEDER_INFLUX_URL",
        description="Base URL of the InfluxDB v3 instance to read from.",
    )
    influx_token: Optional[str] = Field(
        default=None,
        validation_alias="PASSIVE_SEEDER_INFLUX_TOKEN",
        description="API token; required when enabled=True.",
    )
    influx_bucket: str = Field(
        default="netcap",
        validation_alias="PASSIVE_SEEDER_INFLUX_BUCKET",
        description="InfluxDB v3 database/bucket name carrying netcap measurements.",
    )
    drop_laa: bool = Field(
        default=False,
        validation_alias="PASSIVE_SEEDER_DROP_LAA",
        description=(
            "When true, drop locally-administered MACs (random-MAC " "Wi-Fi addresses). Off by default in ICS labs."
        ),
    )

    model_config = SettingsConfigDict(
        env_prefix="",
        case_sensitive=False,
        extra="ignore",
    )

    @model_validator(mode="after")
    def _validate(self) -> "PassiveSeederSettings":
        """Cross-field validation per ``Environment Variables Contract``.

        - ``poll_interval_s`` MUST be strictly positive.
        - ``lookback_window_s`` MUST be >= ``poll_interval_s`` so no
          MAC observed between cycles can fall outside the window.
        - When ``enabled=True``, ``influx_token`` MUST be set (an
          empty token guarantees a 401 against the Influx instance,
          which is worse than a clear startup error).
        """
        if self.poll_interval_s <= 0:
            raise ValueError("PASSIVE_SEEDER_POLL_INTERVAL_S must be > 0; " f"got {self.poll_interval_s}")
        if self.lookback_window_s < self.poll_interval_s:
            raise ValueError(
                "PASSIVE_SEEDER_LOOKBACK_WINDOW_S must be >= "
                "PASSIVE_SEEDER_POLL_INTERVAL_S; "
                f"got window={self.lookback_window_s} < "
                f"interval={self.poll_interval_s}"
            )
        if self.enabled and not self.influx_token:
            raise ValueError("PASSIVE_SEEDER_INFLUX_TOKEN is required when " "PASSIVE_SEEDER_ENABLED=true")
        return self
