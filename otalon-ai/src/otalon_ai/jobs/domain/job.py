"""Job-related domain models for OTALON-AI."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, List, Literal, Optional
from uuid import UUID

from pydantic import BaseModel, Field


class JobStatus(str, Enum):
    """Lifecycle states of a subagent job.

    ``DEGRADED`` (AI-036) is terminal like ``COMPLETED`` but signals that
    the run finished without a MITRE technique because an evidence tool
    namespace (typically ``pcap.*``) was unavailable. The named reason is
    persisted in ``error_message``.
    """

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    DEGRADED = "degraded"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


class TraceEntry(BaseModel):
    """One MCP tool-call entry within a job's tool trace."""

    round: int
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    result_chars: int = 0
    result_preview: Optional[str] = None
    duration_ms: int = 0
    error: Optional[str] = None
    ts: Optional[datetime] = None


class CreateJobRequest(BaseModel):
    """Body schema for ``POST /jobs``.

    Per Cluster d / B1 (SSRF close): ``llm_endpoint`` has been removed
    from the public request shape. The server resolves the endpoint from
    ``settings.litellm.base_url`` exclusively so a caller cannot redirect
    the classifier's LLM traffic to an attacker-controlled host. Unknown
    fields are silently ignored by Pydantic by default; any caller-supplied
    ``llm_endpoint`` therefore never reaches the worker.

    Per tasks.md Phase 9 (replace-n8n-chat-orchestration): ``llm_model``
    is now a LiteLLM identifier (e.g. ``litellm/gpt-5.4``,
    ``litellm/claude-opus-4-7``, ``litellm/gpt-5.5-2``). ``llm_provider``
    is legacy/optional and accepted only for payload backward-compat with
    chat-MCP callers — the field is no longer used to dispatch between
    backends, every request is served by the same ``LiteLLMProvider``.
    """

    alarm_id: str = Field(min_length=1, max_length=64)
    prompt_variant: Optional[Literal["open", "expert", "forensic"]] = None
    llm_provider: Optional[str] = None
    llm_model: Optional[str] = None
    reasoning_effort: Optional[Literal["low", "medium", "high"]] = None
    baseline_id: Optional[UUID] = None
    timeout_seconds: Optional[int] = Field(default=None, gt=0, le=3600)
    trigger_source: Literal["ui", "chat", "api"] = "api"


class CreateJobResponse(BaseModel):
    """Response schema for ``POST /jobs``."""

    job_id: UUID
    status: JobStatus
    eta_seconds: int
    events_url: str


class JobRecord(BaseModel):
    """Full job record as persisted in PostgreSQL ``subagent_jobs``."""

    id: UUID
    alarm_id: str
    status: JobStatus
    prompt_variant: Literal["open", "expert", "forensic"]
    prompt_hash: str
    llm_provider: str
    llm_model: str
    llm_endpoint: Optional[str] = None
    reasoning_effort: Optional[str] = None
    baseline_id: Optional[UUID] = None
    timeout_seconds: int
    trigger_source: str = "api"
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    step1_technical: Optional[dict[str, Any]] = None
    step2_classification: Optional[dict[str, Any]] = None
    verdict: Optional[dict[str, Any]] = None
    tool_trace: List[TraceEntry] = Field(default_factory=list)
    tokens_prompt: int = 0
    tokens_completion: int = 0
    error_message: Optional[str] = None
    created_at: datetime


class JobSummary(BaseModel):
    """Summarised job record for list views (no full tool trace)."""

    id: UUID
    alarm_id: str
    status: JobStatus
    prompt_variant: str
    llm_provider: str
    llm_model: str
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    tool_trace_count: int = 0
    tokens_total: int = 0
    top_step2: Optional[dict[str, Any]] = None
    step1_method: Optional[str] = None
    verdict_outcome: Optional[str] = None
    created_at: datetime


class JobListResponse(BaseModel):
    """Response shape for ``GET /jobs``."""

    items: List[JobSummary | JobRecord]
    total: int
    limit: int
    offset: int


class JobFilter(BaseModel):
    """Filter parameters for ``GET /jobs``."""

    alarm_id: Optional[str] = None
    status: Optional[JobStatus] = None
    limit: int = Field(default=50, ge=1, le=200)
    offset: int = Field(default=0, ge=0)
    summary: bool = True
