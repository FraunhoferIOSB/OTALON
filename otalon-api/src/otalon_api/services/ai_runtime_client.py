"""Client for the otalon-ai internal live-configuration endpoint (AI-045).

Pushes a saved LLM configuration to ``PUT {ai_url}/internal/v1/llm-config``
(Wave 1 of OpenSpec change ``ai-045-litellm-connection``), authenticated
with the ``OTALON_AI_INTERNAL_KEY`` X-API-Key (design.md D2/D4). The
push happens AFTER the ``.env.compose`` write, so a failed push keeps the
file as the source for the next start; the save response reports the
outcome through ``live_applied``/``live_detail`` instead of raising.

Failure details are deliberately coarse: exceptions carry only a safe
step name plus the exception type, never response bodies or key material
(D6).
"""

from __future__ import annotations

import httpx

_PUSH_TIMEOUT_SECONDS: float = 5.0

_INTERNAL_LLM_CONFIG_PATH: str = "/internal/v1/llm-config"


class AIRuntimePushError(Exception):
    """The live push to otalon-ai could not be applied.

    The message is safe to return as the save response's ``live_detail``:
    it names the failed step and the exception class, never a response
    body or key value (D6).
    """


class AIRuntimeClient:
    """Minimal authenticated client for the otalon-ai internal surface."""

    def __init__(self, base_url: str, timeout_s: float = _PUSH_TIMEOUT_SECONDS) -> None:
        """Store the otalon-ai base URL and the request timeout.

        Args:
            base_url: e.g. ``http://otalon-ai:9100``.
            timeout_s: Timeout for a single push request.
        """
        self._base_url = base_url.rstrip("/")
        self._timeout_s = timeout_s

    async def push_llm_config(
        self,
        *,
        api_key: str,
        chat_model: str,
        job_model: str,
        base_url: str | None = None,
        context_window: int | None = None,
    ) -> dict[str, str]:
        """Push a live configuration to ``PUT /internal/v1/llm-config``.

        Args:
            api_key: The internal key (``OTALON_AI_INTERNAL_KEY``) sent as
                the ``X-API-Key`` header.
            chat_model: New chat model identifier.
            job_model: New jobs model identifier.
            base_url: Optional new LiteLLM proxy base URL; ``None`` keeps
                the current one on the otalon-ai side.

        Returns:
            The parsed JSON body of a 200 response (``chat_model``,
            ``job_model``, ``applied_at`` and friends).

        Raises:
            AIRuntimePushError: On transport failure, non-2xx status or an
                unusable JSON reply. The message names the failed step
                only (design.md D4/D6).
        """
        payload: dict[str, str] = {"chat_model": chat_model, "job_model": job_model}
        if base_url is not None:
            payload["base_url"] = base_url
        if context_window is not None:
            payload["context_window"] = context_window  # type: ignore[assignment]
        try:
            async with httpx.AsyncClient(
                timeout=self._timeout_s, follow_redirects=False
            ) as client:
                response = await client.put(
                    f"{self._base_url}{_INTERNAL_LLM_CONFIG_PATH}",
                    json=payload,
                    headers={"X-API-Key": api_key},
                )
        except httpx.HTTPError as exc:
            raise AIRuntimePushError(
                f"push request failed: {type(exc).__name__}"
            ) from exc
        if not response.is_success:
            raise AIRuntimePushError(
                f"push rejected with status {response.status_code}"
            )
        try:
            parsed: dict = response.json()
        except ValueError as exc:
            raise AIRuntimePushError("push response is not valid JSON") from exc
        if not isinstance(parsed, dict):
            raise AIRuntimePushError("push response is not a JSON object")
        return parsed

    async def get_llm_config_status(self, api_key: str) -> dict[str, str]:
        """Fetch the active configuration from ``GET /internal/v1/llm-config``.

        Returns:
            The validated ``{"chat_model": ..., "job_model": ...}`` subset
            of the status body.

        Raises:
            AIRuntimePushError: On transport failure or a non-2xx/unusable
                reply; the message never contains the response body.
        """
        async with httpx.AsyncClient(
            base_url=self._base_url, timeout=self._timeout_s, follow_redirects=False
        ) as client:
            try:
                response = await client.get(
                    _INTERNAL_LLM_CONFIG_PATH, headers={"X-API-Key": api_key}
                )
            except httpx.HTTPError as exc:
                raise AIRuntimePushError(
                    f"runtime status unavailable: {type(exc).__name__}"
                ) from exc
        if not response.is_success:
            raise AIRuntimePushError(
                f"runtime status rejected with status {response.status_code}"
            )
        try:
            parsed: dict = response.json()
        except ValueError as exc:
            raise AIRuntimePushError("runtime status is not valid JSON") from exc
        chat = parsed.get("chat_model") if isinstance(parsed, dict) else None
        job = parsed.get("job_model") if isinstance(parsed, dict) else None
        if not isinstance(chat, str) or not isinstance(job, str):
            raise AIRuntimePushError("runtime status is not a usable JSON object")
        return {"chat_model": chat, "job_model": job}
