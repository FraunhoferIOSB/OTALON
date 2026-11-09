"""Settings loader for otalon-ai.

    Reads ``config/config.json`` and resolves ``$ENV_VAR`` placeholders against the
    process environment. Modelled on inherited agent settings (the
inherited jobs surface) but extended with a ``litellm`` section, a ``chat``
section, and a renamed ``jobs`` section (formerly the top-level ``agent``
block).

Per design.md § "Per-surface env-var matrix", chat and jobs keep separate
``llm_model`` / ``llm_reasoning_effort`` variables so they can be tuned
independently.

Since SUITE-038 the placeholders are resolved by the shared
``otalon_common.config`` resolver under ``MissingEnvVarPolicy.USE_NONE``:
a variable that is unset *or empty* resolves to ``None`` so optional fields
stay unset, and required fields are enforced by Pydantic at validation time.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Self

from otalon_common.config import BaseSettings, MissingEnvVarPolicy
from pydantic import BaseModel, ConfigDict, Field, model_validator


class ServerConfig(BaseModel):
    """HTTP server configuration."""

    name: str = "otalon-ai"
    host: str = "0.0.0.0"
    port: int = 9100


class LiteLLMConfig(BaseModel):
    """LiteLLM proxy connection.

    Both chat and jobs surfaces issue chat-completion requests against this
    proxy via the OpenAI Python SDK. The ``base_url`` MUST end in ``/v1`` so
    the OpenAI SDK routes correctly.

    Per Cluster d / B8 (fail-fast on missing LLM env): both fields are
    REQUIRED — there are no defaults. The previous implementation
    defaulted to ``http://host.docker.internal:4000/v1`` + ``sk-no-key``,
    which silently sent classifier traffic to the operator's localhost
    if the env was forgotten. otalon-ai is a greenfield service,
    so we trade a friendly default for a clear startup failure. The
    ``model_validator`` below also rejects empty strings, which the shared
    resolver can produce for a variable that is set but blank.
    """

    base_url: str
    api_key: str

    @model_validator(mode="after")
    def _require_non_empty(self) -> "LiteLLMConfig":
        if not self.base_url or not self.base_url.strip():
            raise ValueError(
                "litellm.base_url must be set (env LITELLM_BASE_URL). "
                "Per Cluster d / B8 OTALON-AI fails fast rather than "
                "defaulting to http://host.docker.internal:4000/v1."
            )
        if not self.api_key or not self.api_key.strip():
            raise ValueError(
                "litellm.api_key must be set (env LITELLM_API_KEY). "
                "Per Cluster d / B8 OTALON-AI fails fast rather than "
                "defaulting to sk-no-key."
            )
        return self


class McpServerEntry(BaseModel):
    """One MCP server endpoint.

    ``api_key`` is the server-to-server consumer credential presented to
    otalon-mcp as an ``X-API-Key`` request header. It MUST equal the
    opaque ``:key`` component of one entry in the MCP-side, producer-owned
    ``OTALON_MCP_ALLOWED_KEYS`` allow-list (see
    ``otalon-mcp/src/otalon_mcp/server.py``). otalon-mcp is fail-closed on
    that allow-list, so a session without a valid key receives HTTP 503
    ``API key authentication unavailable``. ``None`` means "no credential
    configured" (dev / faked transport only); it is not sent as a header.

    The field is excluded from ``repr``/``str`` so the secret value never
    leaks into logs, tracebacks or debug output.
    """

    name: str
    url: str
    api_key: Optional[str] = Field(default=None, repr=False)


class McpConfig(BaseModel):
    """MCP servers visible to both chat and jobs surfaces.

    ``require_api_key`` turns the consumer credential into a fail-fast
    startup requirement: when set, every configured server MUST carry a
    non-empty ``api_key`` or model validation raises with an actionable
    ``OTALON_MCP_API_KEY`` message. Production deployments enable it
    so a forgotten credential fails loudly instead of silently degrading
    chat/jobs into a no-tools state against the fail-closed MCP route.
    """

    servers: List[McpServerEntry] = Field(default_factory=list)
    request_timeout_seconds: int = 60
    require_api_key: bool = False

    @model_validator(mode="after")
    def _require_credential_when_enforced(self) -> "McpConfig":
        if not self.require_api_key:
            return self
        for server in self.servers:
            if not server.api_key or not server.api_key.strip():
                raise ValueError(
                    "OTALON_MCP_API_KEY must be set for MCP server "
                    f"{server.name!r}: otalon-mcp is fail-closed on "
                    "OTALON_MCP_ALLOWED_KEYS, so a missing consumer "
                    "credential makes every discovery/tool-call return "
                    "HTTP 503 and silently disables all MCP tools. Set "
                    "OTALON_MCP_API_KEY to the :key component of one "
                    "OTALON_MCP_ALLOWED_KEYS entry."
                )
        return self

    @property
    def api_key(self) -> Optional[str]:
        """First-server credential.

        Transitional shim mirroring :attr:`url` for the inherited jobs
        surface (``worker_pool``), which addresses a single MCP server.
        The chat surface reads per-entry ``api_key`` off ``servers``.
        """
        if not self.servers:
            raise RuntimeError("mcp.servers is empty; expected at least one entry")
        return self.servers[0].api_key

    @property
    def url(self) -> str:
        """First-server URL.

        Transitional shim for the inherited jobs surface (worker_pool /
        ``_probe_mcp``) which expects a single-server config. The chat
        surface uses ``servers`` directly. Removed when the jobs surface is
        ported to ``McpRegistry`` (Phase 5) — until then both readers
        coexist.
        """
        if not self.servers:
            raise RuntimeError("mcp.servers is empty; expected at least one entry")
        return self.servers[0].url


class DbConfig(BaseModel):
    """PostgreSQL connection. Shared by chat session-store and jobs writer."""

    dsn: str


class ChatConfig(BaseModel):
    """Chat surface configuration.

    ``allowed_tools`` semantics (matches :class:`McpRegistry.list_openai_tools`):

    - ``None`` (default) → passthrough; the chat LLM sees the full
      discovered MCP tool catalogue. This is the design.md § Open
      Question Q2 default ("no allow-list in chat (full passthrough)").
    - ``[]`` → strict default-deny opt-in (Cluster d / B5). ZERO tools
      advertised; the LLM has no callable surface. Operators who want
      to lock chat down explicitly set this.
    - ``["a.b", "c.d"]`` → curated allow-list; only matching tools are
      advertised and callable.

    Prior to 2026-05-19 the default was an empty list, which the
    registry interpreted as strict default-deny — silently disabling
    MCP tool execution in chat. See the corresponding regression test
    in ``tests/unit/test_chat_mcp_tool_loop_regression.py``.
    """

    llm_model: str = "azure/gpt-5.4"
    llm_reasoning_effort: Optional[Literal["low", "medium", "high"]] = None
    history_window: int = 20
    retention_days: int = 30
    max_tool_rounds: int = 12
    fallback_message: str = (
        "I cannot reach my language model right now. Please try again in a moment."
    )
    model_context_window: int = 128000
    allowed_tools: Optional[List[str]] = None

    @model_validator(mode="before")
    @classmethod
    def _coerce_none_context_window(cls, data: Any) -> Any:
        """Treat a missing-env ``None`` as the default context window."""
        if isinstance(data, dict) and data.get("model_context_window") is None:
            data = {**data, "model_context_window": 128000}
        return data


class JobsConfig(BaseModel):
    """Subagent classification jobs surface configuration.

    Inherited from the old ``otalon-agent`` ``AgentConfig``; field names
    kept identical so the inherited worker code does not need refactoring.
    """

    llm_model: str = "azure/gpt-5.4"
    llm_reasoning_effort: Optional[Literal["low", "medium", "high"]] = None
    default_prompt: Literal["open", "expert", "forensic"] = "expert"
    timeout_seconds: int = 600
    n_workers: int = 4
    log_level: str = "INFO"
    allowed_tools: List[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_allowed_tools(self) -> "JobsConfig":
        if not self.allowed_tools:
            raise ValueError("jobs.allowed_tools must not be empty")
        return self


class LoggingConfig(BaseModel):
    """Logging configuration."""

    level: str = "INFO"
    file: Optional[str] = "/app/logs/otalon-ai.log"


class Settings(BaseSettings):
    """Root settings model."""

    # Declared explicitly: the shared base forbids extra keys, while this
    # model has always ignored them — config.json carries a top-level
    # ``llm`` block this model does not declare (SUITE-038).
    model_config = ConfigDict(extra="ignore")

    server: ServerConfig = Field(default_factory=ServerConfig)
    # Per Cluster d / B8: ``litellm`` is required — no default factory.
    # The previous implementation defaulted to host.docker.internal +
    # sk-no-key, which silently sent classifier traffic to the
    # operator's localhost when the env was forgotten.
    litellm: LiteLLMConfig
    mcp: McpConfig = Field(default_factory=McpConfig)
    db: DbConfig
    chat: ChatConfig = Field(default_factory=ChatConfig)
    jobs: JobsConfig
    logging: LoggingConfig = Field(default_factory=LoggingConfig)

    # --- helpers ---------------------------------------------------------

    def with_llm_overrides(
        self,
        *,
        base_url: Optional[str] = None,
        chat_model: Optional[str] = None,
        chat_reasoning_effort: Optional[Literal["low", "medium", "high"]] = None,
        job_model: Optional[str] = None,
        job_reasoning_effort: Optional[Literal["low", "medium", "high"]] = None,
        context_window: Optional[int] = None,
    ) -> "Settings":
        """Return a copy of these settings with LLM overrides applied (AI-045 D3).

        The original instance stays unchanged — the live-config swap is a
        pure reference change. ``model_copy`` on the root keeps validators
        from re-running on unrelated sections; the ``litellm`` override is
        the one that MUST re-validate (empty base_url would otherwise pass
        unnoticed and only blow up at request time), so a fresh
        :class:`LiteLLMConfig` is constructed for it.

        Args:
            base_url: New LiteLLM proxy base URL. ``None`` keeps the current one.
            chat_model: New chat-surface model identifier. ``None`` keeps current.
            chat_reasoning_effort: New chat reasoning effort. ``None`` keeps current.
            job_model: New jobs-surface model identifier. ``None`` keeps current.
            job_reasoning_effort: New jobs reasoning effort. ``None`` keeps current.

        Returns:
            A new :class:`Settings` instance with the overrides applied.

        Raises:
            ValueError: When an overridden value fails model validation
                (e.g. an empty ``base_url``). The caller keeps the previous
                settings in that case.
        """
        updates: Dict[str, Any] = {}
        if base_url is not None:
            updates["litellm"] = LiteLLMConfig(
                base_url=base_url, api_key=self.litellm.api_key
            )
        if (
            chat_model is not None
            or chat_reasoning_effort is not None
            or context_window is not None
        ):
            chat_updates: Dict[str, Any] = {}
            if chat_model is not None:
                chat_updates["llm_model"] = chat_model
            if chat_reasoning_effort is not None:
                chat_updates["llm_reasoning_effort"] = chat_reasoning_effort
            if context_window is not None:
                # AI-046: live chat context window (router.py and sse.py read this value).
                chat_updates["model_context_window"] = context_window
            updates["chat"] = self.chat.model_copy(update=chat_updates)
        if job_model is not None or job_reasoning_effort is not None:
            job_updates: Dict[str, Any] = {}
            if job_model is not None:
                job_updates["llm_model"] = job_model
            if job_reasoning_effort is not None:
                job_updates["llm_reasoning_effort"] = job_reasoning_effort
            updates["jobs"] = self.jobs.model_copy(update=job_updates)
        return self.model_copy(update=updates)

    @staticmethod
    def _apply_legacy_env_fallbacks() -> None:
        """Bridge legacy AGENT_* env names to the new JOBS_* names.

        Per design.md § Decision 8 the chat-LLM-cut release renames the
        ``AGENT_*`` envs to ``JOBS_*`` (atomic cut in Phase 12 of tasks.md).
        During Phases 2 through 11 both flavours coexist on operator hosts.

        Raises a clear startup error when neither new nor legacy variable is
        set for required jobs fields, per Task 1.6.
        """
        legacy_map = {
            "JOBS_LLM_MODEL": "AGENT_LLM_MODEL",
            "JOBS_LLM_REASONING_EFFORT": "AGENT_LLM_REASONING_EFFORT",
            "JOBS_DEFAULT_PROMPT": "AGENT_DEFAULT_PROMPT",
            "JOBS_TIMEOUT_SECONDS": "AGENT_TIMEOUT_SECONDS",
            "JOBS_N_WORKERS": "AGENT_N_WORKERS",
            "JOBS_LOG_LEVEL": "AGENT_LOG_LEVEL",
        }
        for new_name, legacy_name in legacy_map.items():
            if not os.environ.get(new_name) and os.environ.get(legacy_name):
                os.environ[new_name] = os.environ[legacy_name]

        # Required: at least one of JOBS_LLM_MODEL / AGENT_LLM_MODEL must be set.
        if not os.environ.get("JOBS_LLM_MODEL") and not os.environ.get(
            "AGENT_LLM_MODEL"
        ):
            raise RuntimeError(
                "otalon-ai: neither JOBS_LLM_MODEL nor AGENT_LLM_MODEL is set. "
                "Set JOBS_LLM_MODEL (preferred) in your .env / .env.compose. "
                "See openspec/changes/replace-n8n-chat-orchestration/design.md § 'Per-surface env-var matrix'."
            )

        # Per Cluster d / B8: the LiteLLM proxy endpoint and API key are
        # required at startup; defaulting to the operator's localhost is
        # a footgun. Surface a clear, actionable error here BEFORE
        # Pydantic raises a less-helpful generic validation error.
        missing: List[str] = []
        if not os.environ.get("LITELLM_BASE_URL"):
            missing.append("LITELLM_BASE_URL")
        if not os.environ.get("LITELLM_API_KEY"):
            missing.append("LITELLM_API_KEY")
        if missing:
            raise RuntimeError(
                "otalon-ai: required LLM env var(s) not set: "
                f"{', '.join(missing)}. Set them in your .env / .env.compose. "
                "Per Cluster d / B8 the service fails fast instead of defaulting "
                "to http://host.docker.internal:4000/v1 + sk-no-key."
            )

    @classmethod
    def from_json(
        cls,
        path: str | Path,
        env_policy: MissingEnvVarPolicy = MissingEnvVarPolicy.USE_NONE,
        default: str | None = None,
        json_arrays: bool = True,
        expand_nested: bool = True,
    ) -> Self:
        """Load and validate settings from a JSON file.

        Args:
            path: Path to the JSON configuration file.
            env_policy: Policy for missing variables. USE_NONE by default, so
                an unset or empty variable leaves its optional field unset.
            default: Fallback value when env_policy is USE_DEFAULT.
            json_arrays: Parse JSON-looking values as JSON.
            expand_nested: Expand nested ``$`` references in resolved values.

        Returns:
            A validated settings instance.
        """
        cls._apply_legacy_env_fallbacks()
        return super().from_json(
            path,
            env_policy=env_policy,
            default=default,
            json_arrays=json_arrays,
            expand_nested=expand_nested,
        )
