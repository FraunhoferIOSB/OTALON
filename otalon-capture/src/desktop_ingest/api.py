"""Bounded source-only ingress. Custody, metric ACK and coverage stay separate."""

from __future__ import annotations

import asyncio
import hashlib
import secrets
import sqlite3
from typing import Literal

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool


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


def create_ingest_app(ledger, source_key, operator_key, app=None, max_upload=32_000_000):
    if not source_key or not operator_key or source_key == operator_key:
        raise ValueError("separate source/operator credentials required")
    app = app or FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    gate = asyncio.Lock()

    def auth(request, key, header):
        supplied = request.headers.get(header, "")
        if not secrets.compare_digest(supplied.encode(), key.encode()):
            raise HTTPException(401, "Invalid or missing credential")

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

    @app.get("/ingest/v1/runs/{run}/chunks/{ordinal}")
    def receipt(run: str, ordinal: int, request: Request):
        auth(request, source_key, "X-Source-Key")
        value = ledger.receipt(run, ordinal)
        if value is None:
            raise HTTPException(404, "receipt not found")
        return value

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

    @app.get("/internal/continuous/batches")
    def batches(request: Request, after: int = 0, limit: int = 1):
        auth(request, operator_key, "X-API-Key")
        return {"batches": ledger.committed_batches(after, min(limit, 1))}

    @app.get("/internal/continuous/status")
    def status(request: Request):
        auth(request, operator_key, "X-API-Key")
        with ledger.lock:
            return {
                "received": ledger.db.execute("SELECT count(*) FROM chunks").fetchone()[0],
                "pending_writes": ledger.db.execute("SELECT count(*) FROM batches WHERE committed=0").fetchone()[0],
                "checkpoint_present": ledger.load_checkpoint() is not None,
            }

    return app
