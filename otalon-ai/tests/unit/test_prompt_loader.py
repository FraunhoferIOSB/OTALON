"""Unit tests for :mod:`src.prompts.loader`.

Validates the two-path lookup contract from spec ``chat--orchestration``
§ "Chat service SHALL load its system prompt from a mounted file":

- Both paths tried in order.
- Dev fallback works when the container path is absent.
- Container path wins when both exist.
- ``FileNotFoundError`` raised with both paths in the message when neither
  resolves.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from otalon_ai.prompts import loader as loader_mod


def test_prefers_container_path_when_present(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    container = tmp_path / "container_prompt.md"
    container.write_text("CONTAINER PROMPT", encoding="utf-8")
    dev = tmp_path / "dev_prompt.md"
    dev.write_text("DEV PROMPT", encoding="utf-8")

    monkeypatch.setattr(loader_mod, "CONTAINER_PATH", container)
    monkeypatch.setattr(loader_mod, "_dev_fallback_path", lambda: dev)

    assert loader_mod.load_system_prompt() == "CONTAINER PROMPT"


def test_falls_back_to_dev_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    container_missing = tmp_path / "missing.md"  # never created
    dev = tmp_path / "dev_prompt.md"
    dev.write_text("DEV PROMPT", encoding="utf-8")

    monkeypatch.setattr(loader_mod, "CONTAINER_PATH", container_missing)
    monkeypatch.setattr(loader_mod, "_dev_fallback_path", lambda: dev)

    assert loader_mod.load_system_prompt() == "DEV PROMPT"


def test_raises_file_not_found_when_neither_path_exists(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(loader_mod, "CONTAINER_PATH", tmp_path / "missing-a.md")
    monkeypatch.setattr(loader_mod, "_dev_fallback_path", lambda: tmp_path / "missing-b.md")

    with pytest.raises(FileNotFoundError) as exc_info:
        loader_mod.load_system_prompt()
    msg = str(exc_info.value)
    # Both candidate paths must appear in the error message per design.md §
    # "Fails loudly".
    assert "missing-a.md" in msg
    assert "missing-b.md" in msg


def test_candidate_paths_returns_both_in_order() -> None:
    paths = loader_mod.candidate_paths()
    assert len(paths) == 2
    assert paths[0] == loader_mod.CONTAINER_PATH
    # Second is the dev fallback under ../otalon-mcp/docs/
    assert "otalon-mcp" in str(paths[1])
    assert "system_promt_agent.md" in str(paths[1])
