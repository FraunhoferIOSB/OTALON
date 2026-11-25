"""Bounded source-only ingress. Custody, metric ACK and coverage stay separate."""

from __future__ import annotations

import asyncio
import hashlib
import secrets
import sqlite3
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from capture_runtime import CaptureIntent
from capture_settings_base import OperatorAuthSettings


class RunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: Literal[1]
    interface_id: str = Field(min_length=1, max_length=256)
    capture_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    predecessor: str | None = None


class RunEnd(BaseModel):
    model_config = ConfigDict(extra="forbid")
    last_ordinal: int = Field(ge=-1, le=2**31 - 1)


class Observation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    interface: str = Field(min_length=1, max_length=250)
    recording: bool


def create_ingest_app(
    ledger,
    source_key,
    operator_key,
    app=None,
    max_upload=32_000_000,
    *,
    intent=CaptureIntent.LIVE,
    source_key_file=None,
):
    disabled = CaptureIntent(intent) is CaptureIntent.NONE
    if not disabled and (not source_key or not operator_key or source_key == operator_key):
        raise ValueError("separate source/operator credentials required")
    app = app or FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    gate = asyncio.Lock()

    def auth(request, key, header):
        if not key:
            raise HTTPException(503, "Credential unavailable")
        supplied = request.headers.get(header, "")
        if not secrets.compare_digest(supplied.encode(), key.encode()):
            raise HTTPException(401, "Invalid or missing credential")

    def receipt_key():
        if not disabled:
            return source_key
        if source_key_file is None:
            raise HTTPException(503, "Source receipt authentication unavailable")
        try:
            path = Path(source_key_file).absolute()
            if any(part.is_symlink() for part in (path, *path.parents)) or not path.is_file():
                raise ValueError("unsafe source key file")
            key = path.read_text().strip()
            operator_auth = OperatorAuthSettings.from_env()
            if len(key) < 32 or key == operator_key or operator_auth.matches(key):
                raise ValueError("separate source credential required")
        except (OSError, ValueError) as exc:
            raise HTTPException(503, "Source receipt authentication unavailable") from exc
        return key

    def operator_history_auth(request):
        if operator_key:
            auth(request, operator_key, "X-API-Key")
        else:
            operator_auth = OperatorAuthSettings.from_env()
            if not operator_auth.is_configured:
                raise HTTPException(503, "API key authentication unavailable")
            if not operator_auth.matches(request.headers.get("X-API-Key", "")):
                raise HTTPException(401, "Invalid or missing credential")

    @app.get("/ingest/v1/runs/{run}/chunks/{ordinal}")
    def receipt(run: str, ordinal: int, request: Request):
        auth(request, receipt_key(), "X-Source-Key")
        try:
            value = ledger.receipt(run, ordinal)
        except (OSError, sqlite3.Error, ValueError, TypeError, KeyError) as exc:
            if not disabled:
                raise
            raise HTTPException(503, "Historical custody unavailable") from exc
        if value is None:
            raise HTTPException(404, "receipt not found")
        return value

    @app.get("/internal/continuous/batches")
    def batches(request: Request, after: int = 0, limit: int = 1):
        operator_history_auth(request)
        try:
            return {"batches": ledger.committed_batches(after, min(limit, 1))}
        except (OSError, sqlite3.Error, ValueError, TypeError, KeyError) as exc:
            if not disabled:
                raise
            raise HTTPException(503, "Historical custody unavailable") from exc

    @app.get("/internal/continuous/status")
    def status(request: Request):
        operator_history_auth(request)
        try:
            return ledger.historical_status()
        except (OSError, sqlite3.Error, ValueError, TypeError, KeyError) as exc:
            if not disabled:
                raise
            raise HTTPException(503, "Historical custody unavailable") from exc

    if disabled:

        async def refuse(request: Request):
            raise HTTPException(
                503,
                "Automatic capture is disabled (CAPTURE_TYPE=NONE); stop the Windows collector explicitly. "
                "Pending custody is retained.",
            )

        for path, method in (
            ("/ingest/v1/runs/{run}", "PUT"),
            ("/ingest/v1/runs/{run}/end", "POST"),
            ("/ingest/v1/runs/{run}/chunks/{ordinal}", "PUT"),
            ("/ingest/v1/observation", "POST"),
        ):
            app.add_api_route(path, refuse, methods=[method])
        return app

    @app.put("/ingest/v1/runs/{run}")
    def register(run: str, body: RunRequest, request: Request):
        auth(request, source_key, "X-Source-Key")
        try:
            ledger.register_run(run, body.predecessor, body.interface_id, body.capture_fingerprint)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        return {"registered": True, "logical_stream_end": False}

    @app.post("/ingest/v1/runs/{run}/end")
    def end(run: str, body: RunEnd, request: Request):
        auth(request, source_key, "X-Source-Key")
        try:
            ledger.close_run(run, body.last_ordinal)
        except (ValueError, sqlite3.IntegrityError) as exc:
            raise HTTPException(409, "run end conflict") from exc
        return {"closed": True, "logical_stream_end": False}

    @app.put("/ingest/v1/runs/{run}/chunks/{ordinal}")
    async def upload(run: str, ordinal: int, request: Request):
        auth(request, source_key, "X-Source-Key")
        expected = request.headers.get("X-Chunk-SHA256", "")
        if len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
            raise HTTPException(422, "chunk SHA256 required")
        try:
            length = int(request.headers.get("content-length", "-1"))
        except ValueError:
            raise HTTPException(400, "invalid content length")
        if length < 0:
            raise HTTPException(411, "content length required")
        if length > max_upload:
            raise HTTPException(413, "chunk too large")
        if gate.locked():
            raise HTTPException(429, "one upload at a time")
        async with gate:
            size = 0
            parts = []
            digest = hashlib.sha256()
            try:
                async with asyncio.timeout(30):
                    iterator = request.stream().__aiter__()
                    while True:
                        try:
                            part = await asyncio.wait_for(anext(iterator), timeout=5)
                        except StopAsyncIteration:
                            break
                        size += len(part)
                        if size > max_upload:
                            raise HTTPException(413, "chunk too large")
                        parts.append(part)
                        digest.update(part)
            except TimeoutError:
                raise HTTPException(408, "upload deadline exceeded")
            if size != length or digest.hexdigest() != expected:
                raise HTTPException(422, "length or digest mismatch")
            try:
                return await run_in_threadpool(ledger.receive, run, ordinal, b"".join(parts))
            except ValueError as exc:
                code = 429 if "full" in str(exc) else 409 if "conflict" in str(exc) else 422
                raise HTTPException(code, str(exc)) from exc
            except OSError as exc:
                raise HTTPException(503, "custody storage unavailable") from exc

    @app.post("/ingest/v1/observation")
    def observation(body: Observation, request: Request):
        auth(request, source_key, "X-Source-Key")
        ledger.observe(body.model_dump())
        return {"observed": True}

    return app
