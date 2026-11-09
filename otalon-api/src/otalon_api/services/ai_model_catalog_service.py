"""Server-side model-catalog service for the LiteLLM proxy (AI-045).

Calls ``GET {base}/models`` with the stored proxy key and returns only
validated model identifiers (design.md D5): the upstream response is
untrusted input, so only string entries in ``data[].id`` within a bounded
length and character set are adopted. Any transport error, non-2xx reply or
malformed shape raises :class:`ModelCatalogError` — the proxy response body
is never propagated so it can never leak into an API response or log.
"""

from __future__ import annotations

import re
from typing import Any

import httpx

from otalon_api.services.ai_connection_service import is_placeholder_key
from otalon_api.services.env_compose_service import EnvComposeService

_CATALOG_TIMEOUT_SECONDS: float = 5.0

_MODEL_ID_MAX_LENGTH: int = 200
"""Mirrors ``AIConnectionUpdate.chat_model``/``job_model`` max_length."""

_MODEL_ID_PATTERN: re.Pattern[str] = re.compile(r"^[A-Za-z0-9._:/+-]+$")
"""Conservative identifier charset: RFC 3986 path/pchar-like model names."""


class ModelCatalogError(Exception):
    """The model list could not be retrieved or parsed.

    The message is safe to surface in an HTTP ``detail`` (D6): it never
    contains the proxy response body or the key value.
    """


class AIModelCatalogService:
    """Retrieve the model identifiers offered by the LiteLLM proxy."""

    def __init__(self, env_service: EnvComposeService, runtime_repo: object | None = None) -> None:
        """Store the shared env-compose service and the optional runtime_config repo.

        Args:
            env_service: Shared env-compose service (singleton).
            runtime_repo: Optional runtime_config repository (AI-045). When given, the
                endpoint the operator saved is used; the key always comes from the file.
        """
        self._env = env_service
        self._runtime_repo = runtime_repo

    def _proxy_params(self) -> tuple[str, str]:
        """Resolve endpoint and key from ``.env.compose``.

        Returns:
            ``(endpoint, key)`` where endpoint has no trailing slash.

        Raises:
            ModelCatalogError: If endpoint or key is unset/placeholder.
        """
        self._env.load()
        values = self._env.to_dict()
        endpoint = self._saved_endpoint(values).rstrip("/")
        key = values.get("LITELLM_API_KEY", "")
        if not endpoint or is_placeholder_key(key):
            raise ModelCatalogError("AI connection is not configured")
        return endpoint, key

    def _saved_endpoint(self, file_values: dict[str, str]) -> str:
        """Return the saved AI endpoint: runtime_config first, .env.compose as fallback."""
        if self._runtime_repo is not None:
            row = self._runtime_repo.get("otalon-ai", "ai.endpoint")  # type: ignore[attr-defined]
            if row is not None and row.get("value"):
                return str(row["value"])
        return file_values.get("LITELLM_BASE_URL", "")

    async def list_models(self) -> list[str]:
        """Fetch and validate the proxy model list (no cache, per F2/D5).

        Returns:
            Sorted unique validated model identifiers.

        Raises:
            ModelCatalogError: On transport failure, non-2xx status or a
                malformed / unusable response shape. The proxy response
                body is never part of the message.
        """
        endpoint, key = self._proxy_params()
        try:
            async with httpx.AsyncClient(timeout=_CATALOG_TIMEOUT_SECONDS, follow_redirects=False) as client:
                response = await client.get(
                    f"{endpoint}/models",
                    headers={"Authorization": f"Bearer {key}"},
                )
        except httpx.HTTPError as exc:
            raise ModelCatalogError(f"model catalog request failed: {type(exc).__name__}") from exc
        if not response.is_success:
            raise ModelCatalogError(f"model catalog request failed with status {response.status_code}")
        try:
            payload: Any = response.json()
        except ValueError as exc:
            raise ModelCatalogError("model catalog response is not valid JSON") from exc
        return self._validated_ids(payload)

    @staticmethod
    def _validated_ids(payload: Any) -> list[str]:
        """Adopt only ``data[].id`` strings that pass length/charset checks.

        Args:
            payload: The parsed JSON body from ``GET /models``.

        Returns:
            Sorted unique validated identifiers.

        Raises:
            ModelCatalogError: On any other response shape.
        """
        if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
            raise ModelCatalogError("model catalog response has no data list")
        accepted: list[str] = []
        for entry in payload["data"]:
            if not isinstance(entry, dict):
                continue
            model_id = entry.get("id")
            if not isinstance(model_id, str):
                continue
            if not model_id or len(model_id) > _MODEL_ID_MAX_LENGTH:
                continue
            if _MODEL_ID_PATTERN.fullmatch(model_id) is None:
                continue
            accepted.append(model_id)
        return sorted(set(accepted))
