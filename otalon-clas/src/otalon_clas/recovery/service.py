"""Automatic discovery and bounded historical work, independent of live ticks."""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from loguru import logger

from .progress import LocalProgress
from .repository import RecoveryRepository
from .worker import RecoveryWorker


class CaptureBatchClient:
    def __init__(self, url, key):
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password or not key:
            raise ValueError("invalid internal capture client")
        self.url = url.rstrip("/")
        self.key = key

    def get_batches(self, after):
        request = Request(
            self.url + "/internal/continuous/batches?limit=1&after=" + str(after), headers={"X-API-Key": self.key}
        )
        with urlopen(request, timeout=10) as response:
            body = response.read(32_000_001)
            if len(body) > 32_000_000:
                raise ValueError("capture manifest too large")
        value = json.loads(body)
        if set(value) != {"batches"} or not isinstance(value["batches"], list) or len(value["batches"]) > 1:
            raise ValueError("capture batch protocol mismatch")
        for batch in value["batches"]:
            if (
                not isinstance(batch.get("id"), int)
                or batch["id"] <= after
                or not isinstance(batch.get("payload"), list)
            ):
                raise ValueError("capture cursor conflict")
        return value["batches"]


class CaptureRecovery:
    def __init__(self, bundles, pg, pipeline, runtime_config, persistence_policy=None):
        self.bundles = bundles
        self.progress = LocalProgress(Path(os.environ.get("CONTINUOUS_RECOVERY_ROOT", "/app/recovery")))
        self.client = CaptureBatchClient(
            os.environ.get("CONTINUOUS_CAPTURE_URL", "http://otalon-capture:9090"), os.environ.get("ADMIN_API_KEY", "")
        )
        self.worker = RecoveryWorker(
            bundles,
            self.progress,
            RecoveryRepository(pg.engine, os.environ.get("CONTINUOUS_SOURCE_ID", "windows-local")),
            pipeline,
            runtime_config,
            persistence_policy=persistence_policy,
        )
        self.stop_event = threading.Event()
        self.thread = None

    def discover(self):
        batches = self.client.get_batches(self.progress.cursor())
        for batch in batches:
            self.progress.register(batch, [b.config.name for b in self.bundles])
        return len(batches)

    def start(self):
        if self.thread is not None:
            raise ValueError("recovery service already started")

        def loop():
            while not self.stop_event.is_set():
                worked = False
                try:
                    discovered = self.discover()
                    worked = self.worker.process_one() or bool(discovered)
                except Exception as exc:
                    logger.error("Continuous discovery/recovery blocked: {}", type(exc).__name__)
                self.stop_event.wait(0.1 if worked else 1)

        self.thread = threading.Thread(target=loop, name="capture-recovery", daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=30)
        if self.thread is None or not self.thread.is_alive():
            self.progress.close()
