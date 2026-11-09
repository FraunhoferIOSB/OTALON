"""OTALON-AI llm subpackage.

Public surface after Phase 9 of ``replace-n8n-chat-orchestration``:

- :class:`src.llm.base.LlmProvider` — Protocol both surfaces depend on.
- :class:`src.llm.litellm_provider.LiteLLMProvider` — single concrete
  provider routing all chat + jobs traffic through the LiteLLM proxy.
- :mod:`src.llm.factory` — ``build_chat_provider`` and
  ``build_jobs_provider`` helpers.

The previous Azure / OpenAI-compat providers and their ``LegacyLlmConfig``
shim were removed in Phase 9 (tasks.md 9.2-9.4).
"""

from otalon_ai.llm.base import LlmProvider
from otalon_ai.llm.factory import build_chat_provider, build_jobs_provider
from otalon_ai.llm.litellm_provider import LiteLLMProvider

__all__ = [
    "LlmProvider",
    "LiteLLMProvider",
    "build_chat_provider",
    "build_jobs_provider",
]
