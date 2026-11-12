"""Receiver entrypoint: existing recorder APIs plus continuous upload and processor."""

from __future__ import annotations

import asyncio
import json
import os
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

import uvicorn
from loguru import logger
from pcap_recorder.api import CaptureStatusProvider, CaptureStatusResponse, PcapService, create_app
from pcap_recorder.index import PcapChunkMeta, PcapIndex
from pcap_recorder.ringbuffer import RingbufferManager
from pcap_recorder.settings import ApiConfig

from .api import create_ingest_app
from .ledger import Ledger
from .pipeline import ContinuousPipeline


class ReceivedRing(RingbufferManager):
    """The index pins evidence in place; custody blobs are never moved."""

    def __init__(self, index):
        self._index = index

    def archive_chunks(self, chunk_ids):
        return {meta.filename: meta.path for meta in self._index.list_all() if meta.filename in chunk_ids}


class Status(CaptureStatusProvider):
    def __init__(self, ledger):
        self.ledger = ledger

    def get_status(self):
        observation = self.ledger.observation()
        return CaptureStatusResponse(
            interface=observation.get("interface") if observation else None,
            recording=observation.get("recording") if observation else None,
            link_up=None,
            drops_24h_pct=None,
            overflows=None,
        )


def load_settings(path):
    raw = json.loads(Path(path).read_text())
    from otalon_common.config import MissingEnvVarPolicy, resolve_env_placeholders

    from .settings import ReliablePipelineSettings

    selected = {key: raw[key] for key in ReliablePipelineSettings.model_fields if key in raw}
    selected["interval_ms"] = raw["capture"]["interval"]
    return ReliablePipelineSettings.model_validate(resolve_env_placeholders(selected, policy=MissingEnvVarPolicy.RAISE))


def build_app(settings, ledger, source_key, operator_key):
    index = PcapIndex(ledger.root / "pcap_index.json")

    def refresh_index():
        with ledger.lock, index.batch():
            for row in ledger.db.execute("SELECT * FROM chunks WHERE packets>0"):
                name = Path(row["path"]).name
                if name in index._entries:
                    continue
                meta = PcapChunkMeta(
                    name,
                    Path(row["path"]),
                    datetime.fromtimestamp(row["first_ns"] / 1e9, timezone.utc),
                    datetime.fromtimestamp(row["last_ns"] / 1e9, timezone.utc),
                    row["size"],
                )
                index._entries[name] = meta
                index._persist()

    service = PcapService(index, ReceivedRing(index), ApiConfig(host="0.0.0.0", port=9090))
    app = create_app(service, Status(ledger))
    for route in list(app.routes):
        if getattr(route, "path", None) == "/health":
            app.routes.remove(route)

    @app.get("/health")
    def health():
        from fastapi.responses import JSONResponse

        error = getattr(app.state, "processor_error", None)
        return JSONResponse({"status": "blocked" if error else "ok"}, status_code=503 if error else 200)

    create_ingest_app(ledger, source_key, operator_key, app)

    @asynccontextmanager
    async def lifespan(_):
        stop = asyncio.Event()
        last_success = time.monotonic()

        async def loop():
            nonlocal last_success
            pipeline = None
            while not stop.is_set():
                try:
                    if pipeline is None:
                        pipeline = await asyncio.to_thread(ContinuousPipeline, settings, ledger)
                    await asyncio.to_thread(refresh_index)
                    worked = await asyncio.to_thread(pipeline.process_one)
                    last_success = time.monotonic()
                    app.state.processor_error = None
                except Exception as exc:
                    app.state.processor_error = type(exc).__name__
                    logger.error("Continuous processing blocked: {}", type(exc).__name__)
                    if pipeline is not None:
                        await asyncio.to_thread(pipeline.close)
                    pipeline = None
                    worked = False
                try:
                    await asyncio.wait_for(stop.wait(), timeout=0.1 if worked else 1)
                except asyncio.TimeoutError:
                    pass
            if pipeline is not None:
                await asyncio.to_thread(pipeline.close)

        task = asyncio.create_task(loop())
        app.state.processor_error = None
        try:
            yield
        finally:
            stop.set()
            await task
            index.flush()

    app.router.lifespan_context = lifespan
    return app


def main():
    root = Path(os.environ.get("CONTINUOUS_ROOT", "/app/continuous"))
    source_key_file = Path(os.environ.get("CONTINUOUS_SOURCE_KEY_FILE", "/run/secrets/continuous-source-key"))
    key = source_key_file.read_text().strip()
    if len(key) < 32:
        raise ValueError("source key missing")
    ledger = Ledger(
        root,
        max_bytes=int(os.environ.get("CONTINUOUS_MAX_BYTES", "2000000000")),
        min_free=int(os.environ.get("CONTINUOUS_MIN_FREE_BYTES", "1000000000")),
    )
    settings = load_settings(os.environ.get("NETCAP_CONFIG_FILE", "/app/config/config.json"))
    from capture_settings_base import OperatorAuthSettings

    operator_auth = OperatorAuthSettings.from_env()
    if not operator_auth.is_configured:
        raise ValueError("operator credentials missing")
    operator_key = operator_auth.operator_keys[0].get_secret_value()
    uvicorn.run(build_app(settings, ledger, key, operator_key), host="0.0.0.0", port=9090, access_log=False)


if __name__ == "__main__":
    main()
