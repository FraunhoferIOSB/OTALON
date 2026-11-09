"""Prometheus metrics for otalon-ai.

Exposes a tiny set of process-wide counters surfaced through the
``/metrics`` FastAPI endpoint. The set is intentionally minimal — only
LLM token usage for now (see .dev/TODO_otalon-ai.md § "Token-Usage-
Metrik exportieren"); other indicators can be added incrementally.

Counters
--------

* ``otalon_ai_chat_tokens_total{type="prompt|completion"}`` —
  cumulative number of tokens billed by the chat surface, split by
  prompt vs completion. Incremented from :class:`ChatAgentLoop` on
  every LLM round that returns a ``usage`` payload.

* ``otalon_ai_jobs_tokens_total{type="prompt|completion"}`` —
  same shape for the jobs / subagent classification surface. Wiring
  TBD; placeholder so the registry already advertises the metric.

The collectors live in the **default** Prometheus registry so the same
``/metrics`` page can later carry additional metrics from other modules
without further coordination.
"""

from __future__ import annotations

from typing import Optional

from prometheus_client import CONTENT_TYPE_LATEST, REGISTRY, Counter, generate_latest

# Labels are intentionally limited to {prompt, completion} — adding a
# per-model or per-session label would explode cardinality without a
# downstream consumer asking for it. Operators who need a per-model
# breakdown can read the audited per-row data from the chat_sessions /
# subagent_jobs tables.
chat_tokens_total = Counter(
    "otalon_ai_chat_tokens_total",
    "Cumulative LLM tokens consumed by the chat surface.",
    labelnames=("type",),
)

jobs_tokens_total = Counter(
    "otalon_ai_jobs_tokens_total",
    "Cumulative LLM tokens consumed by the subagent jobs surface.",
    labelnames=("type",),
)


def record_chat_tokens(prompt_tokens: Optional[int], completion_tokens: Optional[int]) -> None:
    """Increment the chat token counters. ``None``/negative values are ignored.

    The chat agent loop calls this at the end of every successful LLM
    round (synchronously, no I/O). ``None`` is the documented signal
    that the LiteLLM proxy did not return usage information for the
    round — treat it as 0 rather than crashing the request.
    """
    if prompt_tokens is not None and prompt_tokens > 0:
        chat_tokens_total.labels(type="prompt").inc(prompt_tokens)
    if completion_tokens is not None and completion_tokens > 0:
        chat_tokens_total.labels(type="completion").inc(completion_tokens)


def record_jobs_tokens(prompt_tokens: Optional[int], completion_tokens: Optional[int]) -> None:
    """Increment the jobs token counters. Same contract as
    :func:`record_chat_tokens`."""
    if prompt_tokens is not None and prompt_tokens > 0:
        jobs_tokens_total.labels(type="prompt").inc(prompt_tokens)
    if completion_tokens is not None and completion_tokens > 0:
        jobs_tokens_total.labels(type="completion").inc(completion_tokens)


def render_metrics() -> tuple[bytes, str]:
    """Serialise the current registry as Prometheus text-format bytes.

    Returns:
        A pair ``(body, content_type)`` ready for a FastAPI ``Response``.
    """
    return generate_latest(REGISTRY), CONTENT_TYPE_LATEST
