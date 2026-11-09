"""Unit tests for :mod:`src.metrics`.

Covers the Prometheus counter wiring used by the chat and jobs surfaces.
The counters live in the **default** Prometheus registry, so tests must
either snapshot baseline values before incrementing or use
``Counter._value.get()`` deltas — we go with the snapshot approach for
clarity.

Behaviours covered:

- :func:`record_chat_tokens` increments prompt / completion separately;
- ``None`` / 0 / negative inputs are ignored without raising;
- :func:`record_jobs_tokens` mirrors the chat contract;
- :func:`render_metrics` returns Prometheus text-format bytes containing
  the configured metric names with the expected labels.
"""

from __future__ import annotations

from otalon_ai.metrics import (
    chat_tokens_total,
    jobs_tokens_total,
    record_chat_tokens,
    record_jobs_tokens,
    render_metrics,
)


def _snapshot(counter, label: str) -> float:
    """Read the current value of a labelled Counter."""
    return counter.labels(type=label)._value.get()  # type: ignore[no-any-return]


def test_record_chat_tokens_increments_prompt_and_completion() -> None:
    base_p = _snapshot(chat_tokens_total, "prompt")
    base_c = _snapshot(chat_tokens_total, "completion")

    record_chat_tokens(123, 45)

    assert _snapshot(chat_tokens_total, "prompt") == base_p + 123
    assert _snapshot(chat_tokens_total, "completion") == base_c + 45


def test_record_chat_tokens_ignores_none_and_zero_and_negative() -> None:
    base_p = _snapshot(chat_tokens_total, "prompt")
    base_c = _snapshot(chat_tokens_total, "completion")

    # None / 0 / negative MUST be no-ops (the LiteLLM proxy occasionally
    # omits usage; the counter SHALL NOT decrement or crash).
    record_chat_tokens(None, None)
    record_chat_tokens(0, 0)
    record_chat_tokens(-5, -10)

    assert _snapshot(chat_tokens_total, "prompt") == base_p
    assert _snapshot(chat_tokens_total, "completion") == base_c


def test_record_jobs_tokens_increments_independently_from_chat() -> None:
    base_chat_p = _snapshot(chat_tokens_total, "prompt")
    base_jobs_p = _snapshot(jobs_tokens_total, "prompt")
    base_jobs_c = _snapshot(jobs_tokens_total, "completion")

    record_jobs_tokens(7, 3)

    assert _snapshot(jobs_tokens_total, "prompt") == base_jobs_p + 7
    assert _snapshot(jobs_tokens_total, "completion") == base_jobs_c + 3
    # Chat counter MUST NOT be affected by jobs activity.
    assert _snapshot(chat_tokens_total, "prompt") == base_chat_p


def test_render_metrics_advertises_token_counters() -> None:
    """The /metrics body MUST contain HELP/TYPE lines for both counters."""
    # Increment once so the counter is non-zero in the output even if no
    # other test ran first.
    record_chat_tokens(1, 1)
    record_jobs_tokens(1, 1)

    body, content_type = render_metrics()
    assert content_type.startswith("text/plain")
    text = body.decode("utf-8")

    assert "otalon_ai_chat_tokens_total" in text
    assert "otalon_ai_jobs_tokens_total" in text
    # Labels are present in the exposition format as `metric{type="prompt"}`
    assert 'type="prompt"' in text
    assert 'type="completion"' in text
