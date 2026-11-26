"""No-write release of the inspected synchronous Client3 ownership slots."""

from __future__ import annotations

import threading
from typing import Any

from influxdb_client_3 import InfluxDBClient3 as _Client3


class ClientReleaseError(RuntimeError):
    """Sanitized release failure; component evidence is held separately."""

    def __init__(self) -> None:
        super().__init__("InfluxDB client release failed.")


def release_client_no_write(client: Any) -> tuple[str, ...]:
    if client is None:
        return ()
    if isinstance(client, SynchronousClient3):
        return client.release_no_write()
    if isinstance(client, _Client3):
        # Client3.close is sequential; synchronous WriteApi.close has no subject to flush.
        resources = [
            ("write_api", getattr(client, "_write_api", None)),
            ("query_api", getattr(client, "_query_api", None)),
            ("http_client", getattr(client, "_client", None)),
        ]
    else:
        resources = [("client", client)]
    failures = []
    for name, resource in resources:
        if resource is None:
            continue
        try:
            resource.close()
        except BaseException:
            failures.append(name)
    return tuple(failures)


class SynchronousClient3(_Client3):
    """Retain assigned handles when the real Client3 initializer does not return."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self._owner_release_lock = threading.Lock()
        self._owner_released = False
        self.release_failures: tuple[str, ...] = ()
        self._client = self._write_api = self._query_api = None
        try:
            super().__init__(*args, **kwargs)
        except BaseException:
            self.release_no_write()
            raise

    def release_no_write(self) -> tuple[str, ...]:
        with self._owner_release_lock:
            if self._owner_released:
                return self.release_failures
            self._owner_released = True
            # Detach before calling user/dependency close code, including on partial construction.
            resources = self._write_api, self._query_api, self._client
            self._client = self._write_api = self._query_api = None
            failures = []
            for name, resource in zip(("write_api", "query_api", "http_client"), resources):
                if resource is None:
                    continue
                try:
                    resource.close()
                except BaseException:
                    failures.append(name)
            self.release_failures = tuple(failures)
            return self.release_failures

    def close(self) -> None:
        if self.release_no_write():
            raise ClientReleaseError() from None
