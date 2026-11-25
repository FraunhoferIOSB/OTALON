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

from capture_runtime import CaptureIntent, resolve_capture_intent
from pcap_recorder.api import CaptureStatusProvider, CaptureStatusResponse, PcapService, create_app
from pcap_recorder.index import PcapChunkMeta, PcapIndex
from pcap_recorder.ringbuffer import RingbufferManager
from pcap_recorder.settings import ApiConfig

from .api import create_ingest_app
from .ledger import Ledger


class ReceivedRing(RingbufferManager):
    """The index pins evidence in place; custody blobs are never moved."""

    def __init__(self, index):
        self._index = index

    def archive_chunks(self, chunk_ids):
        return {meta.filename: meta.path for meta in self._index.list_all() if meta.filename in chunk_ids}


class Status(CaptureStatusProvider):
    def __init__(self, ledger, *, intent=CaptureIntent.LIVE):
        self.ledger = ledger
        self.intent = intent

    def get_status(self):
        observation = self.ledger.observation() if self.intent is CaptureIntent.LIVE else None
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


def build_app(settings, ledger, source_key, operator_key, *, intent=CaptureIntent.LIVE, source_key_file=None):
    intent = CaptureIntent(intent)
    if intent is CaptureIntent.NONE:
        from fastapi import HTTPException

        # Keep the actual recorder service/index, loading only on evidence use.
        # Failure stays local to evidence, not fake empty history or quarantine.
        class RetainedService(PcapService):
            def __init__(self):
                self._index = None
                self._api_config = ApiConfig(host="0.0.0.0", port=9090)

            def existing(self):
                try:
                    index_path = ledger.root / "pcap_index.json"
                    if any(p.is_symlink() for p in (index_path, *index_path.parents)):
                        raise ValueError("unsafe retained index")
                    if not index_path.exists() and ledger.raw.is_dir() and any(ledger.raw.iterdir()):
                        raise ValueError("retained index missing")
                    if self._index is None:
                        self._index = PcapIndex(index_path, auto_write=False)
                        self._ringbuffer = ReceivedRing(self._index)
                    for meta in self._index.list_all():
                        path = meta.path
                        if (
                            path.parent != ledger.raw
                            or path.name != meta.filename
                            or any(p.is_symlink() for p in (path, *path.parents))
                            or not path.is_file()
                            or path.stat().st_nlink != 1
                        ):
                            raise ValueError("unsafe retained evidence")
                except (OSError, ValueError, TypeError, KeyError) as exc:
                    self._index = None
                    raise HTTPException(503, "Historical evidence unavailable") from exc

            def get_chunks_by_time(self, time_start, time_end):
                self.existing()
                return super().get_chunks_by_time(time_start, time_end)

            def get_chunks_by_id(self, chunk_ids):
                self.existing()
                return super().get_chunks_by_id(chunk_ids)

            def flag_anomaly(self, time_start, time_end, labels=None):
                self.existing()
                try:
                    return super().flag_anomaly(time_start, time_end, labels)
                except OSError as exc:
                    raise HTTPException(503, "Historical evidence unavailable") from exc

        app = create_app(RetainedService(), Status(ledger, intent=intent))
        create_ingest_app(ledger, source_key, operator_key, app, intent=intent, source_key_file=source_key_file)

        @asynccontextmanager
        async def idle_lifespan(_):
            try:
                yield
            finally:
                ledger.close()

        app.router.lifespan_context = idle_lifespan
        return app

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
        from .pipeline import ContinuousPipeline

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
    intent = resolve_capture_intent()
    root = Path(os.environ.get("CONTINUOUS_ROOT", "/app/continuous"))
    if intent is CaptureIntent.NONE:
        ledger = Ledger.open_existing_readonly(root)
        source_key_file = os.environ.get("CONTINUOUS_SOURCE_KEY_FILE")
        app = build_app(None, ledger, None, None, intent=intent, source_key_file=source_key_file)
        try:
            uvicorn.run(app, host="0.0.0.0", port=9090, access_log=False)
        finally:
            ledger.close()
        return

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
