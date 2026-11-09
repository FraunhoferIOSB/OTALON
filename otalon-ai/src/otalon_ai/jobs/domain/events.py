"""SSE event models emitted by the worker loop."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


def _now() -> datetime:
    return datetime.now(timezone.utc)


class _BaseEvent(BaseModel):
    ts: datetime = Field(default_factory=_now)
    job_id: str


class ToolCallStartedEvent(_BaseEvent):
    """Emitted just before the worker invokes an MCP tool."""

    type: Literal["tool_call_started"] = "tool_call_started"
    round: int
    tool: str
    args_summary: str


class ToolCallCompletedEvent(_BaseEvent):
    """Emitted after an MCP tool call returns (success or error)."""

    type: Literal["tool_call_completed"] = "tool_call_completed"
    round: int
    tool: str
    args: dict[str, Any]
    result_chars: int
    result_preview: Optional[str] = None
    duration_ms: int
    error: Optional[str] = None


class ProgressEvent(_BaseEvent):
    """Periodic round-level heartbeat carrying current context size."""

    type: Literal["progress"] = "progress"
    round: int
    context_chars: int


class ForceClassifyEvent(_BaseEvent):
    """Emitted when the worker forces the LLM into the classification phase."""

    type: Literal["force_classify"] = "force_classify"
    context_chars_before: int
    context_chars_after: int


class FinalEvent(_BaseEvent):
    """Terminal event with the job's outcome, classifications, and token totals.

    ``degraded`` (AI-036) marks a job that produced no MITRE technique
    while an evidence tool namespace was unavailable; the named reason
    travels in :attr:`error`.
    """

    type: Literal["final"] = "final"
    status: Literal["completed", "degraded", "timeout", "failed", "cancelled"]
    step1_technical: Optional[dict[str, Any]] = None
    step2_classification: Optional[dict[str, Any]] = None
    verdict: Optional[dict[str, Any]] = None
    duration_seconds: float
    tokens_prompt: int
    tokens_completion: int
    error: Optional[str] = None


class ErrorEvent(_BaseEvent):
    """Terminal failure event with a short reason and optional detail."""

    type: Literal["error"] = "error"
    reason: str
    detail: Optional[str] = None


SubagentEvent = (
    ToolCallStartedEvent | ToolCallCompletedEvent | ProgressEvent | ForceClassifyEvent | FinalEvent | ErrorEvent
)
