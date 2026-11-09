"""Security-negative tests for the otalon-ai HTTP boundary."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from otalon_common.auth.api_key import KeyRegistry
from otalon_common.auth.fastapi import make_api_key_middleware


@pytest.fixture
def protected_app(monkeypatch: pytest.MonkeyPatch) -> FastAPI:
    """Build a small app with the same chat/jobs protection contract."""
    monkeypatch.setenv("OTALON_AI_ALLOWED_KEYS", "test:viewer:test-ai-key")
    app = FastAPI()
    app.add_middleware(
        make_api_key_middleware(
            registry=KeyRegistry.from_env("OTALON_AI_ALLOWED_KEYS"),
            protected_prefixes=("/api/v1/chat", "/jobs"),
        )
    )

    @app.post("/api/v1/chat")
    async def chat() -> dict[str, bool]:
        return {"ok": True}

    @app.get("/jobs")
    async def jobs() -> dict[str, bool]:
        return {"ok": True}

    @app.get("/health")
    async def health() -> dict[str, bool]:
        return {"ok": True}

    return app


def test_chat_and_jobs_reject_missing_or_invalid_key(protected_app: FastAPI) -> None:
    """Protected AI surfaces reject anonymous and invalid callers."""
    with TestClient(protected_app) as client:
        assert client.post("/api/v1/chat").status_code == 401
        assert client.get("/jobs").status_code == 401


def test_chat_and_jobs_accept_valid_key_and_health_stays_open(protected_app: FastAPI) -> None:
    """Valid internal callers work while health remains unauthenticated."""
    with TestClient(protected_app, headers={"X-API-Key": "test-ai-key"}) as client:
        assert client.post("/api/v1/chat").status_code == 200
        assert client.get("/jobs").status_code == 200
    with TestClient(protected_app) as client:
        assert client.get("/health").status_code == 200


def test_missing_ai_key_configuration_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Missing configuration produces service-unavailable, not open access."""
    monkeypatch.delenv("OTALON_AI_ALLOWED_KEYS", raising=False)
    app = FastAPI()
    app.add_middleware(
        make_api_key_middleware(
            registry=KeyRegistry.from_env("OTALON_AI_ALLOWED_KEYS"),
            protected_prefixes=("/jobs",),
        )
    )

    @app.get("/jobs")
    async def jobs() -> dict[str, Any]:
        return {"ok": True}

    with TestClient(app) as client:
        assert client.get("/jobs").status_code == 503
