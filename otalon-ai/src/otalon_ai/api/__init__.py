"""Internal REST surface for otalon-ai (AI-045: live LLM configuration)."""

from otalon_ai.api.llm_config import router as llm_config_router

__all__ = ["llm_config_router"]
