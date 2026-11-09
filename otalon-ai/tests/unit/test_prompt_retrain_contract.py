"""Prompt-contract regression for the boundary-retrain tool section.

The canonical operator system prompt is authored in
``otalon-mcp/docs/system_promt_agent.md`` and mounted read-only into
otalon-ai at ``/app/prompts/system_prompt.md``; the chat surface
loads it once at startup through :func:`src.prompts.loader.load_system_prompt`
(container path, dev-fallback to the mcp doc). Because the LLM only ever
sees this text, a stale ``training.retrain_boundaries`` description
overrides the real live tool schema.

The live producer contract is unambiguous (source of truth):

- ``otalon-mcp/src/mcp_tools.py`` — ``training.retrain_boundaries``
  advertises optional ``intervals``, runs in-process, does NOT restart or
  recreate otalon-clas, keeps detection online, terminal
  ``succeeded``/``failed``.
- ``otalon-mcp/src/tools/training.py`` — accepts and forwards
  disjoint ``intervals`` alongside legacy ``window_start``/``window_stop``.
- ``otalon-api/src/api/v1/training.py`` +
  ``otalon-api/src/domain/time/intervals.py`` — accept ``intervals``,
  normalize Europe/Berlin wall time to UTC, merge overlaps, and unite them
  into one logical job.

These tests read the prompt through the real loader/fallback path and pin
the section to that contract. They FAIL against the legacy text (which
claims a single contiguous window, ``.env.compose`` mutation, two
otalon-clas restarts, multi-minute detection downtime and ``live`` /
``failed`` terminal states) and pass once the section is corrected.
"""

from __future__ import annotations

import re

import pytest

from otalon_ai.prompts.loader import load_system_prompt


def _retrain_section(prompt: str) -> str:
    """Return the boundary-retraining section of the canonical prompt.

    Slices from the ``Boundary retraining`` heading to the next
    ``training.get_retrain_status`` tool block (inclusive of the status
    tool so state-alphabet claims are covered), so the assertions target
    only the chat-tool contract and not unrelated prompt sections.
    """
    lower = prompt.lower()
    start = lower.find("boundary retraining")
    assert start != -1, "canonical prompt is missing the 'Boundary retraining' section"
    tail = lower.find("postgres.add_anomaly_suppression", start)
    end = tail if tail != -1 else len(prompt)
    return prompt[start:end]


def test_canonical_prompt_loads_through_real_loader() -> None:
    """The loader/fallback path resolves the canonical mounted prompt."""
    prompt = load_system_prompt()
    assert "training.retrain_boundaries" in prompt


def test_retrain_section_documents_disjoint_intervals() -> None:
    """The section MUST describe optional multiple disjoint ``intervals``.

    The live tool (``mcp_tools.py`` / ``training.py``) accepts an
    ``intervals=[[start, stop], ...]`` list forming one logical job; the
    legacy text that only offered a single contiguous
    ``[window_start, window_stop]`` window is the P7 defect.
    """
    section = _retrain_section(load_system_prompt())
    assert "intervals" in section, (
        "boundary-retrain section MUST document the optional multiple "
        "disjoint 'intervals' parameter (live tool schema in "
        "otalon-mcp/src/mcp_tools.py); the legacy single-window text "
        "is the Phase-7 defect."
    )
    assert re.search(r"disjoint|multiple|union", section, re.IGNORECASE), (
        "section MUST state that multiple disjoint intervals form one " "logical retrain job (their union)."
    )


def test_retrain_section_documents_berlin_utc_normalization() -> None:
    """Europe/Berlin wall-time normalization belongs to the API contract."""
    section = _retrain_section(load_system_prompt())
    assert re.search(r"europe/berlin", section, re.IGNORECASE), (
        "section MUST state Europe/Berlin wall-time input is normalized by "
        "the API (otalon-api/src/domain/time/intervals.py)."
    )
    assert "UTC" in section, "section MUST state the API normalizes local input to UTC."


def test_retrain_section_documents_in_process_no_restart() -> None:
    """Runtime retrain is in-process, no otalon-clas restart, detection online."""
    section = _retrain_section(load_system_prompt())
    lower = section.lower()
    assert "in-process" in lower or "in process" in lower, (
        "section MUST state the retrain runs in-process (mcp_tools.py: "
        "'executed in-process and detection stays online')."
    )
    assert re.search(
        r"stays online|remains online|detection.*online", lower
    ), "section MUST state detection stays online during the retrain."
    assert re.search(
        r"does not restart|not restart|no restart|without restart", lower
    ), "section MUST state otalon-clas is NOT restarted/recreated."


def test_retrain_section_uses_succeeded_failed_terminal_states() -> None:
    """Terminal states are ``succeeded``/``failed`` — not ``live``/``failed``."""
    section = _retrain_section(load_system_prompt())
    assert "succeeded" in section, (
        "section MUST use terminal state 'succeeded' (runtime-retrain " "control plane), not the legacy 'live'."
    )
    assert "failed" in section


def test_retrain_section_has_no_obsolete_downtime_or_env_claims() -> None:
    """The obsolete restart/downtime/env-mutation/live-state claims are gone."""
    section = _retrain_section(load_system_prompt())
    lower = section.lower()
    assert not re.search(
        r"`\.env\.compose` is updated|`\.env\.compose`.*written back|updates `\.env\.compose`", lower
    ), (
        "section MUST NOT claim the chat tool rewrites '.env.compose' — the "
        "runtime retrain does not mutate compose env (obsolete legacy claim)."
    )
    assert "training_enabled" not in lower, (
        "section MUST NOT describe a TRAINING_ENABLED restart workflow as the "
        "chat tool behaviour (obsolete legacy claim)."
    )
    assert not re.search(
        r"cause detection downtime|detection is unavailable|downtime for several", lower
    ), "section MUST NOT claim the retrain causes detection downtime (obsolete legacy claim)."
    assert not re.search(
        r"restarted twice|restarts twice|restart.*twice", lower
    ), "section MUST NOT claim otalon-clas restarts twice (obsolete)."
    assert not re.search(r"\bsetting_env\b|\bresetting\b", lower), (
        "section MUST NOT advertise the legacy 'setting_env'/'resetting' " "state-machine values."
    )


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
