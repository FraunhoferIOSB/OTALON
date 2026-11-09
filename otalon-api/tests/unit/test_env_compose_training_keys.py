"""Unit tests for ``EnvComposeService.update_training_keys``.

Verifies the bounded micro-allowlist the boundary-retrain orchestrator
relies on (OpenSpec change ``add-chat-triggered-boundary-retraining`` §
1.2). The public ``PUT /api/v1/admin/env/{key}`` endpoint MUST NOT be
able to toggle ``TRAINING_ENABLED`` via the standard
:meth:`update_and_save` path; ``update_training_keys`` is the only
sanctioned writer.
"""

from __future__ import annotations

import os
import textwrap
from pathlib import Path

import pytest

from otalon_api.services.env_compose_service import TRAINING_ENV_KEYS, EnvComposeService
from otalon_api.settings import Settings


@pytest.fixture()
def env_service(tmp_path: Path) -> EnvComposeService:
    """Return a service bound to a throw-away .env.compose file."""
    env_path = tmp_path / ".env.compose"
    env_path.write_text(
        textwrap.dedent(
            """\
            # otalon test env file
            INFLUX_URL=http://localhost:8181
            POSTGRES_PASSWORD=changeme
            TRAINING_ENABLED=false
            TRAINING_BOUNDARY_TRAIN_WINDOW_START=2026-01-01 00:00:00
            TRAINING_BOUNDARY_TRAIN_WINDOW_STOP=2026-01-01 01:00:00
            """
        ),
        encoding="utf-8",
    )
    settings = Settings(env_compose_path=str(env_path))
    svc = EnvComposeService(settings)
    svc.load()
    return svc


def test_update_training_keys_writes_only_the_allowed_keys(
    env_service: EnvComposeService,
) -> None:
    """The micro-allowlist covers all TRAINING_* keys touched by the
    boundary- AND classifier-retrain orchestrators.

    Extended from the original three-key allowlist by the ML-training
    decoupling change (see ``.dev/concepts/ml-training-decoupling.md``):
    a classifier retrain must be able to flip
    ``TRAINING_CLASSIFICATION_ENABLED`` and write the corresponding
    window / MITRE-file keys.
    """
    assert set(TRAINING_ENV_KEYS) == {
        "TRAINING_ENABLED",
        "TRAINING_BOUNDARY_TRAIN_WINDOW_START",
        "TRAINING_BOUNDARY_TRAIN_WINDOW_STOP",
        "TRAINING_CLASSIFICATION_ENABLED",
        "TRAINING_CLASSIFICATION_WINDOW_START",
        "TRAINING_CLASSIFICATION_WINDOW_STOP",
        "TRAINING_CLASSIFICATION_MITRE_TECHNIQUE_FILE",
    }

    new_env, changed, backup = env_service.update_training_keys(
        {
            "TRAINING_ENABLED": "true",
            "TRAINING_BOUNDARY_TRAIN_WINDOW_START": "2026-05-08 12:15:00",
            "TRAINING_BOUNDARY_TRAIN_WINDOW_STOP": "2026-05-08 12:30:00",
        }
    )
    assert set(changed) == {
        "TRAINING_ENABLED",
        "TRAINING_BOUNDARY_TRAIN_WINDOW_START",
        "TRAINING_BOUNDARY_TRAIN_WINDOW_STOP",
    }
    assert new_env["TRAINING_ENABLED"] == "true"
    assert new_env["TRAINING_BOUNDARY_TRAIN_WINDOW_START"] == "2026-05-08 12:15:00"
    assert new_env["TRAINING_BOUNDARY_TRAIN_WINDOW_STOP"] == "2026-05-08 12:30:00"
    # Other keys untouched.
    assert new_env["INFLUX_URL"] == "http://localhost:8181"
    assert new_env["POSTGRES_PASSWORD"] == "changeme"
    # Backup made.
    assert backup is not None and os.path.exists(backup)


def test_update_training_keys_rejects_non_training_key(
    env_service: EnvComposeService,
) -> None:
    """A key outside the training micro-allowlist is rejected."""
    with pytest.raises(ValueError, match="not a training control key"):
        env_service.update_training_keys({"POSTGRES_PASSWORD": "leaked"})


def test_update_training_keys_rejects_invalid_enabled_value(
    env_service: EnvComposeService,
) -> None:
    """TRAINING_ENABLED must be the literal 'true' or 'false'."""
    with pytest.raises(ValueError, match="TRAINING_ENABLED must be"):
        env_service.update_training_keys({"TRAINING_ENABLED": "yes"})


def test_update_training_keys_rejects_blank_window(
    env_service: EnvComposeService,
) -> None:
    """A whitespace-only window timestamp is rejected.

    Phase-6 F3 (audit ``add-chat-triggered-boundary-retraining``):
    an empty string is now accepted (the orchestrator clears the window
    keys during its FINALLY reset so a stale, fully-armed retrain config
    is not left on disk), but a non-empty but blank value is still
    rejected.
    """
    with pytest.raises(ValueError, match="empty .cleared. or a non-blank"):
        env_service.update_training_keys({"TRAINING_BOUNDARY_TRAIN_WINDOW_START": "   "})


def test_update_training_keys_accepts_empty_window_to_clear(
    env_service: EnvComposeService,
) -> None:
    """Phase-6 F3: an empty-string window clears the on-disk value.

    The boundary-retrain orchestrator's FINALLY reset writes
    ``TRAINING_BOUNDARY_TRAIN_WINDOW_START``/``STOP`` to ``""`` so a
    stale window does not persist on disk next to
    ``TRAINING_ENABLED=false``. otalon-clas's ``TrainWindowConfig``
    defaults both fields to ``""`` and never reads them when training
    is disabled, so an empty window on disk is safe.
    """
    new_env, changed, _ = env_service.update_training_keys(
        {
            "TRAINING_ENABLED": "false",
            "TRAINING_BOUNDARY_TRAIN_WINDOW_START": "",
            "TRAINING_BOUNDARY_TRAIN_WINDOW_STOP": "",
        }
    )
    assert "TRAINING_BOUNDARY_TRAIN_WINDOW_START" in changed
    assert "TRAINING_BOUNDARY_TRAIN_WINDOW_STOP" in changed
    assert new_env["TRAINING_BOUNDARY_TRAIN_WINDOW_START"] == ""
    assert new_env["TRAINING_BOUNDARY_TRAIN_WINDOW_STOP"] == ""


def test_update_training_keys_no_op_when_values_match_disk(
    env_service: EnvComposeService,
) -> None:
    """Idempotent: writing the current value records zero changes."""
    new_env, changed, _ = env_service.update_training_keys({"TRAINING_ENABLED": "false"})
    assert changed == []
    assert new_env["TRAINING_ENABLED"] == "false"


def test_update_and_save_still_rejects_training_keys_through_admin_path(
    env_service: EnvComposeService,
) -> None:
    """Regression: the public admin path does NOT accept training keys.

    The single-flight retrain orchestration is the only sanctioned route
    for those keys; the public ``PUT /api/v1/admin/env/{key}`` endpoint
    MUST keep rejecting them so a chat-triggered run is not
    side-stepped.
    """
    with pytest.raises(ValueError, match="not allowed"):
        env_service.update_and_save({"TRAINING_ENABLED": "true"})
