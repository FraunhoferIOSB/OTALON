"""Agent-proxy tools for the chat workflow.

These three tools let the chat agent trigger and observe subagent
classifications running in the ``otalon-ai`` service (formerly
``otalon-agent``). All tools return immediately — never block on
the worker run.

Per ``replace-n8n-chat-orchestration`` Phase 9: the jobs surface of
``otalon-ai`` is now backed exclusively by the LiteLLM proxy.
``llm_model`` is therefore a LiteLLM identifier (e.g.
``litellm/gpt-5.4``, ``litellm/claude-opus-4-7``, ``litellm/gpt-5.5-2``).
``llm_provider`` is legacy/optional — the field is forwarded verbatim on
the request body for backward-compat but is no longer used by the
service to dispatch between Azure / OpenAI-compat / LiteLLM backends.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

import httpx
from loguru import logger

_state: Dict[str, Any] = {"url": "", "timeout": 5.0}


def init(agent_url: str = "", timeout: float = 5.0) -> None:
    """Initialise the proxy tools with the agent service URL.

    The URL is resolved once in ``otalon_mcp.settings`` from ``AGENT_URL``
    (legacy) or ``AI_URL`` (``otalon-ai``) and injected here; an empty
    value disables the agent tools. Phase 13 of
    ``replace-n8n-chat-orchestration`` drops the ``AGENT_URL`` alias.

    Args:
        agent_url: Base URL of the otalon-ai service.
        timeout: Proxy-call timeout in seconds.
    """
    _state["url"] = agent_url.rstrip("/")
    _state["timeout"] = float(timeout) if timeout else 5.0
    logger.info(
        "tools.agent.init: url={} timeout={}s",
        _state["url"] or "(disabled)",
        _state["timeout"],
    )


def _ok_url() -> Optional[str]:
    return _state["url"] or None


def classify_alert(
    alarm_id: str,
    prompt_variant: str = "expert",
    llm_provider: Optional[str] = None,
    llm_model: Optional[str] = None,
    baseline_id: Optional[str] = None,
    timeout_seconds: int = 600,
) -> Dict[str, Any]:
    """Trigger an asynchronous subagent classification on the given alarm.

    Returns immediately with the assigned ``job_id`` — the worker runs in
    the background. Use :func:`get_classification_status` to poll, or
    listen on the agent's SSE endpoint for live progress.

    Args:
        alarm_id: Alarm row id to classify.
        prompt_variant: ``"open"`` (free-form reasoning) or ``"expert"``
            (paper-validated structured prompt). Defaults to ``"expert"``.
        llm_provider: **Legacy/optional.** Forwarded verbatim on the
            request body for payload backward-compat. Since Phase 9 of
            ``replace-n8n-chat-orchestration`` the ``otalon-ai``
            jobs surface routes every classification through the LiteLLM
            proxy regardless of this value; the chat agent should leave
            it unset.
        llm_model: A LiteLLM model identifier (e.g.
            ``litellm/gpt-5.4``, ``litellm/claude-opus-4-7``,
            ``litellm/gpt-5.5-2``). When omitted, the service falls back
            to ``settings.jobs.llm_model`` (``JOBS_LLM_MODEL`` env).
        baseline_id: Optional baseline UUID for context.
        timeout_seconds: Hard wall-clock budget on the worker run.
    """
    base = _ok_url()
    if base is None:
        return {"ok": False, "error": "agent service URL is not configured (AI_URL)"}

    body: Dict[str, Any] = {
        "alarm_id": alarm_id,
        "prompt_variant": prompt_variant,
        "trigger_source": "chat",
        "timeout_seconds": int(timeout_seconds),
    }
    if llm_provider:
        body["llm_provider"] = llm_provider
    if llm_model:
        body["llm_model"] = llm_model
    if baseline_id:
        body["baseline_id"] = baseline_id

    try:
        with httpx.Client(timeout=_state["timeout"]) as client:
            resp = client.post(f"{base}/jobs", json=body)
        if resp.status_code == 404:
            return {"ok": False, "error": "alarm not found", "alarm_id": alarm_id}
        if resp.status_code >= 400:
            return {
                "ok": False,
                "error": f"agent returned {resp.status_code}",
                "detail": resp.text[:500],
            }
        data = resp.json()
        return {
            "ok": True,
            "job_id": data.get("job_id"),
            "status": data.get("status"),
            "eta_seconds": data.get("eta_seconds"),
            "events_url": data.get("events_url"),
            "hint": (
                "The subagent runs asynchronously (typical: 2-7 minutes). "
                f"Embed the token [subagent-job:{data.get('job_id')}] in your "
                "reply so the UI can render the live trace card. Use "
                "agent.get_classification_status to poll the result."
            ),
        }
    except httpx.HTTPError as exc:
        logger.error("agent.classify_alert: agent unreachable: {}", exc)
        return {"ok": False, "error": "agent service unreachable", "detail": str(exc)}


def get_classification_status(job_id: str) -> Dict[str, Any]:
    """Get the current state of a subagent job (status + last classification)."""
    base = _ok_url()
    if base is None:
        return {"ok": False, "error": "agent service URL is not configured (AI_URL)"}
    try:
        with httpx.Client(timeout=_state["timeout"] * 4) as client:
            resp = client.get(f"{base}/jobs/{job_id}")
        if resp.status_code == 404:
            return {"ok": False, "error": "job not found", "job_id": job_id}
        if resp.status_code >= 400:
            return {
                "ok": False,
                "error": f"agent returned {resp.status_code}",
                "detail": resp.text[:500],
            }
        data = resp.json()
        # Strip very large tool_trace if it would blow up chat context
        trace = data.get("tool_trace") or []
        if isinstance(trace, list) and len(trace) > 30:
            data["tool_trace"] = trace[-10:]
            data["tool_trace_truncated"] = True
            data["tool_trace_total"] = len(trace)
        return {"ok": True, "job": data}
    except httpx.HTTPError as exc:
        logger.error("agent.get_classification_status: agent unreachable: {}", exc)
        return {"ok": False, "error": "agent service unreachable", "detail": str(exc)}


def list_classifications_for_alert(alarm_id: str, limit: int = 10) -> Dict[str, Any]:
    """List prior subagent classifications for one alarm (newest first, summary mode)."""
    base = _ok_url()
    if base is None:
        return {"ok": False, "error": "agent service URL is not configured (AI_URL)"}
    try:
        with httpx.Client(timeout=_state["timeout"] * 2) as client:
            resp = client.get(
                f"{base}/jobs",
                params={
                    "alarm_id": alarm_id,
                    "summary": "true",
                    "limit": int(limit),
                    "offset": 0,
                },
            )
        if resp.status_code >= 400:
            return {
                "ok": False,
                "error": f"agent returned {resp.status_code}",
                "detail": resp.text[:500],
            }
        return {"ok": True, **resp.json()}
    except httpx.HTTPError as exc:
        logger.error("agent.list_classifications_for_alert: agent unreachable: {}", exc)
        return {"ok": False, "error": "agent service unreachable", "detail": str(exc)}
