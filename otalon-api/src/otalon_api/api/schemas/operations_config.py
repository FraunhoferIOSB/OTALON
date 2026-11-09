"""Schemas for the Operations configuration surface.

None of these models carry a secret value: boot secrets are masked by the
service before they reach :class:`BootConfigResponse`, and the AI key is
never represented as a readable field (only ``key_configured`` +
write-only replacement input).
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

ConnectionState = Literal["not-configured", "ready", "failed", "testing"]


class BootConfigResponse(BaseModel):
    """Masked boot values and per-key service impact metadata."""

    env: dict[str, str]
    editable_keys: list[str]
    readonly_keys: list[str] = Field(default_factory=list)
    sensitive_keys: list[str]
    affected_services: dict[str, list[str]]


class ConfigApplyRequest(BaseModel):
    """Explicit non-secret boot update with a mandatory audit reason."""

    key: str
    value: str
    reason: str = Field(min_length=3, max_length=500)


class ConfigApplyResponse(BootConfigResponse):
    """Result of an audited boot update."""

    changed_keys: list[str]
    restart_required: bool


class AIConnectionResponse(BaseModel):
    """AI connection state without any credential value."""

    provider: str
    endpoint: str
    chat_model: str
    job_model: str
    context_window: int = 128000
    state: ConnectionState
    key_configured: bool


class AIConnectionUpdate(BaseModel):
    """Non-secret AI connection fields plus an audit reason.

    ``allow_unlisted_model`` lets an operator bypass the proxy model-list
    check (AI-045). It is opt-in per save and defaults to ``False``: a
    chat/job model not in the proxy list is then rejected with 422.
    """

    provider: str = Field(min_length=1, max_length=100)
    endpoint: str = Field(max_length=500)
    chat_model: str = Field(max_length=200)
    job_model: str = Field(max_length=200)
    # AI-046: maximum chat context window in tokens. Optional; a missing value keeps the
    # currently saved one, so older callers stay valid. The range matches the manifest.
    context_window: int | None = Field(default=None, ge=4096, le=1000000)
    # Optional audit note (AI-045 operator decision: never mandatory). Empty
    # is allowed; the audit row still records actor, action and changed keys.
    reason: str = Field(default="", max_length=500)
    allow_unlisted_model: bool = False


class AIConnectionSaveResult(BaseModel):
    """Result of a save: persisted metadata plus the live-push outcome.

    ``live_applied`` states whether the pushed configuration reached a
    running otalon-ai (its 200/422 contract); ``live_detail`` names the
    failed step otherwise. No key material is ever included.
    """

    provider: str
    endpoint: str
    chat_model: str
    job_model: str
    # AI-046: the persisted chat context window after the save (never a replacement default).
    context_window: int
    state: ConnectionState
    key_configured: bool
    live_applied: bool
    live_detail: str


class AIModelListResponse(BaseModel):
    """Validated model identifiers offered by the proxy (no key ever)."""

    models: list[str] = Field(default_factory=list)


class AIConnectionDriftResponse(BaseModel):
    """Persisted AI connection plus the active models reported by otalon-ai.

    The persisted fields (provider, endpoint, models, state, key_configured)
    are returned so the configuration form can pre-fill from the server; the
    drift fields compare the active models against them. ``active_*_model`` is
    ``None`` when otalon-ai could not be reached; ``drift`` compares only the
    models that are actually known. No credential value is ever included.
    """

    provider: str = ""
    endpoint: str = ""
    chat_model: str = ""
    job_model: str = ""
    context_window: int = 128000
    state: ConnectionState = "not-configured"
    key_configured: bool = False
    active_chat_model: str | None = None
    active_job_model: str | None = None
    drift: bool = False


class AIKeyReplace(BaseModel):
    """Write-only AI credential replacement."""

    key: str = Field(min_length=1, max_length=2000)
    reason: str = Field(min_length=3, max_length=500)


class AIConnectionTest(BaseModel):
    """Explicit AI connectivity test request using server-side configuration."""

    model_config = {"extra": "forbid"}


class AIConnectionTestResult(BaseModel):
    """Result of a bounded server-side AI connectivity test (no secret)."""

    success: bool
    state: ConnectionState


class ConfigRollbackRequest(BaseModel):
    """Confirmed rollback request with an audit reason."""

    reason: str = Field(min_length=3, max_length=500)
    confirmed: bool = False


class ConfigRollbackResult(BaseModel):
    """Result of a confirmed configuration rollback."""

    success: bool
    target: str
    changed_keys: list[str]


class ConfigHistoryItem(BaseModel):
    """Safe configuration audit row with explicit rollback eligibility.

    ``detail`` is intentionally omitted so a snapshot ``prior_value`` can
    never leak to the browser; eligibility is computed server-side.
    """

    id: int | None = None
    at: str
    actor: str
    action: str
    target: str
    reason: str | None = None
    rollback_eligible: bool = False
