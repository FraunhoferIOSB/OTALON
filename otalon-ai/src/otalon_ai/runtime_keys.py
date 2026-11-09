"""Runtime-configuration key declarations for otalon-ai (AI-045).

The AI connection values (provider, proxy endpoint, chat and job model) live in
the ``runtime_config`` table, the same store the other services use, so the
settings page can save them without a container restart. The API key is NOT
here: it is a secret and stays in ``.env.compose``.

Each key is registered at startup so the runtime-config write path accepts it.
The matching manifest entries in ``otalon_common.runtime.manifest`` are checked
by a cross-check test, so drift fails the build instead of surfacing at runtime.
"""

from __future__ import annotations

from otalon_common.runtime import (
    OTALON_AI_SERVICE,
    RuntimeKeySpec,
    register,
)
from otalon_common.runtime.registry import int_range


def _non_empty(value: str) -> None:
    """Reject an empty or whitespace-only string value."""
    if not value.strip():
        raise ValueError("value must not be empty")


def _http_url(value: str) -> None:
    """Accept only an absolute http(s) URL, with a host, as the proxy endpoint."""
    from urllib.parse import urlsplit

    parts = urlsplit(value.strip())
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        raise ValueError("endpoint must be an absolute http(s) URL")


SPECS: tuple[RuntimeKeySpec, ...] = (
    RuntimeKeySpec(
        service=OTALON_AI_SERVICE,
        key="ai.provider",
        value_type="str",
        validator=_non_empty,
        domain=None,
        description="AI model provider (AI-045). Non-secret connection setting.",
    ),
    RuntimeKeySpec(
        service=OTALON_AI_SERVICE,
        key="ai.endpoint",
        value_type="str",
        validator=_http_url,
        domain=None,
        description="AI proxy base URL, e.g. http://host.docker.internal:4000/v1 (AI-045).",
    ),
    RuntimeKeySpec(
        service=OTALON_AI_SERVICE,
        key="ai.chat_model",
        value_type="str",
        validator=_non_empty,
        domain=None,
        description="Model used for interactive chat turns (AI-045).",
    ),
    RuntimeKeySpec(
        service=OTALON_AI_SERVICE,
        key="ai.context_window",
        value_type="int",
        validator=int_range(4096, 1000000),
        domain="[4096, 1000000]",
        description="Maximum chat context window in tokens (AI-046). Was hard-coded to 128000.",
    ),
    RuntimeKeySpec(
        service=OTALON_AI_SERVICE,
        key="ai.job_model",
        value_type="str",
        validator=_non_empty,
        domain=None,
        description="Model used for background jobs (AI-045).",
    ),
)


def register_runtime_keys() -> None:
    """Register every otalon-ai key; idempotent for identical specifications."""
    for spec in SPECS:
        register(spec)


AI_RUNTIME_OVERRIDE_KEYS = (
    "ai.provider",
    "ai.endpoint",
    "ai.chat_model",
    "ai.job_model",
    "ai.context_window",
)


def load_saved_ai_values(database) -> dict[str, str]:
    """Return saved ai.* values from runtime_config at startup (empty dict on any failure).

    AI-045: without this read the process boots with the env value and ignores the
    model the operator saved, so a restart silently reverts the live configuration.
    A missing row or an unreachable database keeps the env value; startup never fails here.
    """
    try:
        with database.chat_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT key, value FROM runtime_config WHERE service = %s AND key = ANY(%s)",
                    ("otalon-ai", list(AI_RUNTIME_OVERRIDE_KEYS)),
                )
                return {
                    row[0]: row[1] for row in cur.fetchall() if row[1] not in (None, "")
                }
    except Exception:  # noqa: BLE001 - startup must not fail on a config read
        return {}


CONTEXT_WINDOW_MIN = 4096
CONTEXT_WINDOW_MAX = 1000000


def saved_context_window(raw: str | None) -> int | None:
    """Return the saved chat context window, or ``None`` when absent or out of range.

    AI-046: a stored value is text; a corrupt or out-of-range row must not change the
    env default, so the caller only applies a value this returns.
    """
    if raw in (None, ""):
        return None
    try:
        value = int(str(raw).strip())
    except ValueError:
        return None
    return value if CONTEXT_WINDOW_MIN <= value <= CONTEXT_WINDOW_MAX else None
