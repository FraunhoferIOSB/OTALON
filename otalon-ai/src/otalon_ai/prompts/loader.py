"""System-prompt loader — shared across chat and jobs surfaces.

Two responsibilities live here:

1. :func:`load_system_prompt` — chat-surface lookup that reads the
   canonical mounted prompt at startup. Per spec ``chat--orchestration``
   § "Chat service SHALL load its system prompt from a mounted file",
   resolution order is:

   - ``/app/prompts/system_prompt.md`` (container mount; the
     docker-compose entry bind-mounts
      ``otalon-mcp/docs/system_promt_agent.md`` here read-only).
    - ``../otalon-mcp/docs/system_promt_agent.md`` relative to the
     ``otalon-ai/`` subproject root (dev fallback when running
     ``uvicorn`` outside Docker).

   If neither path exists, :class:`FileNotFoundError` is raised with
   both paths in the message so the service fails loudly at startup
   (design.md § Decision 7: "Fails loudly if neither exists").

2. :class:`PromptLoader` and :data:`PromptVariant` — jobs-surface
   loader that caches the two paper-validated system prompts (Open /
   Expert) and computes a stable 16-char SHA-256 prefix for tracing.
   Lives here (rather than under ``otalon_ai/jobs/``) so chat + jobs share a
   single prompt-loading module per Cluster b / A5.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Dict, List, Literal

from loguru import logger

CONTAINER_PATH = Path("/app/prompts/system_prompt.md")


def _dev_fallback_path() -> Path:
    """The dev path: ``<subproject-root>/../otalon-mcp/docs/system_promt_agent.md``."""
    subproject_root = Path(__file__).resolve().parents[3]
    return subproject_root / ".." / "otalon-mcp" / "docs" / "system_promt_agent.md"


def candidate_paths() -> List[Path]:
    """Return the ordered list of paths the loader will try."""
    return [CONTAINER_PATH, _dev_fallback_path()]


def load_system_prompt() -> str:
    """Read the canonical system prompt. Raise ``FileNotFoundError`` if absent.

    Both paths are tried in order; the first existing file wins. The file
    content is returned verbatim — no templating, no editing.
    """
    paths = candidate_paths()
    for path in paths:
        try:
            resolved = path.resolve()
        except OSError:
            continue
        if resolved.is_file():
            text = resolved.read_text(encoding="utf-8")
            logger.info("system prompt loaded from {} ({} chars)", resolved, len(text))
            return text
    tried = ", ".join(str(p) for p in paths)
    raise FileNotFoundError(
        f"otalon-ai: system prompt not found. Tried: {tried}. "
        "Mount the canonical prompt at /app/prompts/system_prompt.md or "
        "ensure the dev fallback path exists."
    )


# --- Jobs surface: variant-aware loader ---------------------------------

PromptVariant = Literal["open", "expert", "forensic"]

_VARIANT_FILES: Dict[PromptVariant, str] = {
    "open": "system_prompt_open.md",
    "expert": "system_prompt_expert.md",
    "forensic": "system_prompt_forensic.md",
}


class PromptLoader:
    """Load and cache the Open and Expert system prompts for the jobs surface.

    Both variants live as code-adjacent markdowns under
    ``otalon_ai/jobs/prompts_data/``. The class reads them once at startup,
    caches the verbatim text, and exposes a 16-char SHA-256 prefix for
    traceability. No template substitution is performed — the prompts
    are verbatim copies of the paper's experimental contract.

    Raises :class:`FileNotFoundError` if either variant file is missing
    so the worker pool fails loudly rather than running with a partial
    contract.

    :raises KeyError: when :meth:`get` / :meth:`get_hash` is called with
        a variant name outside :data:`PromptVariant` (e.g. a typo from
        config). This preserves the inherited error path so the worker
        rejects unknown variants at the boundary.
    """

    def __init__(self, prompts_dir: Path) -> None:
        self._dir = prompts_dir
        self._cache: Dict[PromptVariant, str] = {}
        self._hashes: Dict[PromptVariant, str] = {}
        self._load_all()

    def _load_all(self) -> None:
        for variant, filename in _VARIANT_FILES.items():
            path = self._dir / filename
            if not path.is_file():
                raise FileNotFoundError(f"Prompt file '{path}' missing for variant '{variant}'")
            text = path.read_text(encoding="utf-8").strip()
            digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
            self._cache[variant] = text
            self._hashes[variant] = digest
            logger.info(
                "Loaded prompt variant={} chars={} hash={}",
                variant,
                len(text),
                digest,
            )

    def get(self, variant: PromptVariant) -> str:
        """Return the prompt text for the given variant."""
        return self._cache[variant]

    def get_hash(self, variant: PromptVariant) -> str:
        """Return the first 16 hex chars of sha256 of the prompt content."""
        return self._hashes[variant]
