"""Bounded AUTH1 refusal, synchronous transport and returned-client ownership tests."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import traceback
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Callable
from urllib.parse import urlsplit

import httpx
import pytest
from influxdb_client_3 import InfluxDBClient3, InfluxDBError, WriteType
from influxdb_client_3.write_client.rest import ApiException
from urllib3 import HTTPResponse

from otalon_capture import influxdb_writer as writer_module
from otalon_capture.settings import InfluxConfig, WriteOptionsConfig


def diagnostic() -> str:
    return "NONSECRET" + "-AUTH1-" + "DIAGNOSTIC"


class PrivateLogs:
    def __init__(self) -> None:
        self.messages: list[str] = []

    def record(self, message: str, **kwargs: Any) -> None:
        self.messages.append(message.format(**kwargs))

    error = warning = debug = success = record


@pytest.fixture
def private_logs(monkeypatch: pytest.MonkeyPatch) -> PrivateLogs:
    logs = PrivateLogs()
    monkeypatch.setattr(writer_module, "logger", logs)
    return logs


def config(host: str = "http://127.0.0.1:1") -> InfluxConfig:
    return InfluxConfig(
        host=host,
        token="synthetic-unused",
        database="synthetic",
        measurement_name="synthetic",
        tags=["uci"],
        fields={"packet_count": "get_total_packet_count", "total_volume": "get_total_volume"},
    )


def options(batch_size: int = 1) -> WriteOptionsConfig:
    return WriteOptionsConfig(batch_size=batch_size, flush_interval=60_000, jitter_interval=0, precision="ms")


def record() -> dict[str, Any]:
    return {"uci": "synthetic", "packet_count": 2, "total_volume": 71, "time": 4_123}


def error_shape(shape: str, status: Any) -> Exception:
    if shape == "influx":
        response = HTTPResponse(status=status, body=json.dumps({"message": diagnostic()}).encode())
        return InfluxDBError(response=response)
    if shape == "api":
        return ApiException(status=status, reason=diagnostic())
    if shape == "httpx":
        request = httpx.Request("POST", "http://127.0.0.1/synthetic/" + diagnostic())
        response = httpx.Response(status, request=request, json={"message": diagnostic()})
        return httpx.HTTPStatusError(diagnostic(), request=request, response=response)
    raise AssertionError("unsupported test shape")


def observe(call: Callable[[], Any]) -> BaseException | None:
    try:
        call()
    except BaseException as failure:
        return failure
    return None


def assert_terminal(failure: BaseException | None, status: int) -> None:
    # Boolean assertions keep constructed diagnostics out of failing test output.
    assert bool(failure is not None)
    assert bool(type(failure).__name__ == "TerminalWriteError")
    assert bool(getattr(failure, "status", None) == status)
    assert bool(getattr(failure, "category", None) == "permanent_auth_refusal")
    assert bool(failure.__cause__ is None and failure.__context__ is None)
    rendered = "".join(traceback.format_exception(failure))
    assert bool(diagnostic() not in rendered)


class ClientDouble:
    def __init__(self, failure: BaseException | None = None) -> None:
        self.failure = failure
        self.writes: list[list[Any]] = []
        self.closes = 0
        self.flushes = 0

    def write(self, points: list[Any]) -> None:
        self.writes.append(list(points))
        if self.failure is not None:
            raise self.failure

    def flush(self) -> None:
        self.flushes += 1

    def close(self) -> None:
        self.closes += 1


def make_writer(monkeypatch: pytest.MonkeyPatch, client: Any, batch_size: int = 1) -> writer_module.InfluxDBWriter:
    monkeypatch.setattr(writer_module, "InfluxDBClient3", lambda **kwargs: client)
    return writer_module.InfluxDBWriter(config(), options(batch_size), window_interval_ms=375)


@pytest.mark.parametrize("status", [401, 403])
@pytest.mark.parametrize("shape", ["influx", "api", "httpx"])
def test_first_refusal_latches_before_build_append_or_retry(monkeypatch, private_logs, shape, status):
    client = ClientDouble(error_shape(shape, status))
    writer = make_writer(monkeypatch, client)
    first = observe(lambda: writer.write(record()))
    buffered = list(writer._buffer)
    client.failure = error_shape(shape, 401 if status == 403 else 403)
    builds = []
    monkeypatch.setattr(writer, "_build_point", lambda value: builds.append(value))
    later = [
        observe(lambda: writer.write(object())),
        observe(writer.flush),
        observe(lambda: writer.flush(force=True)),
        observe(writer.close),
        observe(writer.close),
        observe(lambda: writer.flush(force=True)),
    ]
    assert len(client.writes) == 1
    assert client.closes == 1
    assert client.flushes == 0
    assert len(buffered) == 1
    assert writer._buffer == buffered
    assert builds == []
    assert_terminal(first, status)
    for failure in later:
        assert_terminal(failure, status)
    assert bool(diagnostic() not in "\n".join(private_logs.messages))


@pytest.mark.parametrize("status", [401, 403])
def test_close_only_refusal_preserves_all_unwritten_points_and_releases(monkeypatch, private_logs, status):
    client = ClientDouble(error_shape("influx", status))
    writer = make_writer(monkeypatch, client, batch_size=10)
    writer.write(record())
    writer.write({**record(), "time": 4_187})
    buffered = list(writer._buffer)
    first = observe(writer.close)
    second = observe(writer.close)
    assert len(client.writes) == 1
    assert client.closes == 1
    assert writer._buffer == buffered
    assert len(buffered) == 2
    assert_terminal(first, status)
    assert_terminal(second, status)


@pytest.mark.parametrize("link", ["cause", "context", "cycle"])
def test_wrapped_and_cyclic_numeric_refusal(monkeypatch, private_logs, link):
    raw = error_shape("influx", 403)
    wrapper = RuntimeError(diagnostic())
    if link == "context":
        wrapper.__context__ = raw
    else:
        wrapper.__cause__ = raw
        if link == "cycle":
            raw.__context__ = wrapper
    client = ClientDouble(wrapper)
    writer = make_writer(monkeypatch, client)
    failure = observe(lambda: writer.write(record()))
    observe(writer.close)
    assert len(client.writes) == 1
    assert_terminal(failure, 403)
    assert bool(diagnostic() not in "\n".join(private_logs.messages))


@pytest.mark.parametrize("case", ["message", "arbitrary", "influx_arbitrary", "string", "server", "cycle", "bounded"])
def test_unconfirmed_auth_remains_transient_and_recovers(monkeypatch, private_logs, case):
    if case == "message":
        failure = RuntimeError("write failed with 401/403")
    elif case == "arbitrary":
        failure = RuntimeError("unrelated")
        failure.status = 401
        failure.response = type("UnrelatedResponse", (), {"status": 403, "status_code": 401})()
    elif case == "string":
        failure = ApiException(status="401", reason="unconfirmed")
    elif case == "influx_arbitrary":
        failure = InfluxDBError(message="unconfirmed")
        failure.response = type("UnrelatedResponse", (), {"status": 401})()
    elif case == "server":
        failure = error_shape("influx", 503)
    elif case == "cycle":
        failure = RuntimeError("unrelated cycle")
        failure.__cause__ = failure
    else:
        failure = error_shape("influx", 401)
        for _ in range(80):
            wrapper = RuntimeError("bounded wrapper")
            wrapper.__cause__ = failure
            failure = wrapper
    client = ClientDouble(failure)
    writer = make_writer(monkeypatch, client)
    writer.write(record())
    assert len(writer._buffer) == 1
    client.failure = None
    writer.flush(force=True)
    writer.close()
    assert len(client.writes) == 2
    assert writer._buffer == []
    assert client.closes == 1


class ReleaseHandle:
    def __init__(self, failure: BaseException | None = None) -> None:
        self.closes = 0
        self.failure = failure

    def close(self) -> None:
        self.closes += 1
        if self.failure is not None:
            raise self.failure


@pytest.mark.parametrize("failed_handle", ["none", "write", "query", "http", "all", "base"])
def test_auth_release_attempts_each_assigned_component_once(monkeypatch, private_logs, failed_handle):
    # Real Client3 identity, with owned assigned resource doubles, not its sequential close double.
    client = InfluxDBClient3.__new__(InfluxDBClient3)
    handles = []
    for name in ("write", "query", "http"):
        failure = None
        if failed_handle in (name, "all"):
            failure = RuntimeError(diagnostic())
        if failed_handle == "base" and name == "write":
            failure = KeyboardInterrupt(diagnostic())
        handles.append(ReleaseHandle(failure))
    client._write_api, client._query_api, client._client = handles
    writes = []

    def refused(points):
        writes.append(list(points))
        raise error_shape("api", 401)

    monkeypatch.setattr(client, "write", refused)
    writer = make_writer(monkeypatch, client)
    first = observe(lambda: writer.write(record()))
    closed = observe(writer.close)
    repeated = observe(writer.close)
    assert [handle.closes for handle in handles] == [1, 1, 1]
    assert len(writes) == 1
    assert_terminal(first, 401)
    assert_terminal(closed, 401)
    assert_terminal(repeated, 401)
    expected = tuple(name for name, handle in zip(("write_api", "query_api", "http_client"), handles) if handle.failure)
    assert getattr(writer, "release_failures", None) == expected
    assert bool(diagnostic() not in "\n".join(private_logs.messages))


def test_generic_close_release_failure_is_truthful_and_idempotent(monkeypatch, private_logs):
    class FailingClose(ClientDouble):
        def close(self):
            super().close()
            raise RuntimeError(diagnostic())

    client = FailingClose()
    writer = make_writer(monkeypatch, client)
    writer.write(record())
    first = observe(writer.close)
    repeated = observe(writer.close)
    assert client.closes == 1
    assert len(client.writes) == 1
    assert bool(type(first).__name__ == "ClientReleaseError")
    assert bool(type(repeated).__name__ == "ClientReleaseError")
    assert getattr(writer, "release_failures", None) == ("client",)
    assert bool(diagnostic() not in "".join(traceback.format_exception(first)))


def test_close_releases_even_when_flush_raises_baseexception(monkeypatch, private_logs):
    class FailingClose(ClientDouble):
        def close(self):
            super().close()
            raise RuntimeError(diagnostic())

    client = FailingClose(KeyboardInterrupt("synthetic interruption"))
    writer = make_writer(monkeypatch, client, batch_size=10)
    writer.write(record())
    buffered = list(writer._buffer)
    failure = observe(writer.close)
    observe(writer.close)
    assert client.closes == 1
    assert len(client.writes) == 1
    assert bool(isinstance(failure, KeyboardInterrupt))
    assert writer._buffer == buffered
    assert writer.release_failures == ("client",)


def test_terminal_release_failure_on_generic_client_does_not_mask_auth(monkeypatch, private_logs):
    class FailingClose(ClientDouble):
        def close(self):
            super().close()
            raise RuntimeError(diagnostic())

    client = FailingClose(error_shape("api", 403))
    writer = make_writer(monkeypatch, client, batch_size=10)
    writer.write(record())
    first = observe(writer.close)
    repeated = observe(writer.close)
    assert client.closes == 1
    assert len(client.writes) == 1
    assert writer.release_failures == ("client",)
    assert_terminal(first, 403)
    assert_terminal(repeated, 403)


def test_numeric_classifier_never_stringifies_supported_exception(private_logs):
    class NoRenderingError(InfluxDBError):
        def __str__(self):
            raise AssertionError("numeric classification must not render errors")

    raw = NoRenderingError(response=HTTPResponse(status=401, body=b'{"message":"synthetic"}'))
    wrapper = RuntimeError("synthetic wrapper")
    wrapper.__cause__ = RuntimeError("synthetic unrelated cause")
    wrapper.__context__ = raw
    assert writer_module.permanent_auth_status(wrapper) == 401


def test_public_terminal_signal_drops_ambient_exception_context(monkeypatch, private_logs):
    client = ClientDouble(error_shape("api", 403))
    writer = make_writer(monkeypatch, client)
    observe(lambda: writer.write(record()))
    try:
        raise RuntimeError(diagnostic())
    except RuntimeError:
        failure = observe(writer.close)
    assert_terminal(failure, 403)


def test_successful_close_is_idempotent_and_refuses_later_enqueue(monkeypatch, private_logs):
    client = ClientDouble()
    writer = make_writer(monkeypatch, client, batch_size=10)
    writer.write(record())
    writer.close()
    writer.close()
    writer.flush(force=True)
    failure = observe(lambda: writer.write(record()))
    assert client.closes == 1
    assert len(client.writes) == 1
    assert writer._buffer == []
    assert bool(isinstance(failure, RuntimeError))


@pytest.mark.parametrize("callback", ["_error_callback", "_retry_callback"])
@pytest.mark.parametrize("shape", ["influx", "api", "httpx"])
def test_auth_callbacks_do_not_render_diagnostics(private_logs, callback, shape):
    getattr(writer_module, callback)(config(), "synthetic", error_shape(shape, 403))
    assert bool(diagnostic() not in "\n".join(private_logs.messages))
    assert bool("403" in "\n".join(private_logs.messages))


@pytest.mark.parametrize("callback", ["_error_callback", "_retry_callback"])
def test_non_auth_callbacks_keep_legacy_diagnostics(private_logs, callback):
    getattr(writer_module, callback)(config(), "synthetic", RuntimeError("legacy transient"))
    assert bool("legacy transient" in "\n".join(private_logs.messages))


def test_registered_callbacks_match_real_inactive_batching_arity(monkeypatch, private_logs):
    registered = []

    def factory(**kwargs):
        registered.append(kwargs["write_client_options"])
        return ClientDouble()

    monkeypatch.setattr(writer_module, "InfluxDBClient3", factory)
    writer = writer_module.InfluxDBWriter(config(), options(), window_interval_ms=375)
    callbacks = registered[0]
    assert callbacks["write_options"].write_type is WriteType.synchronous
    key = ("synthetic", "synthetic", "ms")
    failures = [
        observe(lambda: callbacks["success_callback"](key, "synthetic")),
        observe(lambda: callbacks["error_callback"](key, "synthetic", error_shape("api", 401))),
        observe(lambda: callbacks["retry_callback"](key, "synthetic", error_shape("api", 403))),
    ]
    writer.close()
    assert bool(all(failure is None for failure in failures))
    assert bool(diagnostic() not in "\n".join(private_logs.messages))


@pytest.mark.parametrize("status", [401, 403])
@pytest.mark.parametrize("close_only", [False, True])
def test_real_synchronous_client_loopback_refuses_exactly_once(private_logs, caplog, status, close_only):
    requests: list[tuple[int, bool, bool, bool]] = []
    response_body = json.dumps({"message": diagnostic()}).encode()

    class RefusalHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(length)
            requests.append((status, self.command == "POST", urlsplit(self.path).path == "/api/v2/write", length > 0))
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response_body)))
            self.end_headers()
            self.wfile.write(response_body)

        def log_message(self, format, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), RefusalHandler)
    thread = threading.Thread(target=server.serve_forever)
    writer = None
    thread.start()
    try:
        writer = writer_module.InfluxDBWriter(
            config(f"http://127.0.0.1:{server.server_port}"), options(10 if close_only else 1), window_interval_ms=375
        )
        client = writer.client
        assert isinstance(client, InfluxDBClient3)
        assert client._write_api._write_options.write_type is WriteType.synchronous
        assert client._write_api._subject is None
        closes = [0, 0, 0]
        original_closes = [client._write_api.close, client._query_api.close, client._client.close]
        for index, handle in enumerate((client._write_api, client._query_api, client._client)):

            def counted_close(index=index):
                closes[index] += 1
                original_closes[index]()

            handle.close = counted_close
        first = observe(lambda: writer.write(record()))
        buffered = list(writer._buffer)
        if close_only:
            assert first is None
            first = observe(writer.close)
        later = [
            observe(writer.flush),
            observe(lambda: writer.flush(force=True)),
            observe(writer.close),
            observe(writer.close),
        ]
        assert requests == [(status, True, True, True)]
        assert closes == [1, 1, 1]
        assert writer._buffer == buffered
        assert len(buffered) == 1
        assert_terminal(first, status)
        for failure in later:
            assert_terminal(failure, status)
        assert bool(diagnostic() not in "\n".join(private_logs.messages))
        assert bool(diagnostic() not in caplog.text)
    finally:
        if writer is not None:
            observe(writer.close)
        server.shutdown()
        server.server_close()
        thread.join()
    assert not thread.is_alive()


def test_auth_owner_module_import_does_not_require_optional_httpx(tmp_path):
    """The declared capture install must import without an undeclared client."""
    code = """\
import importlib.abc
import sys

class NoHttpx(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'httpx' or fullname.startswith('httpx.'):
            raise ModuleNotFoundError('optional httpx is not installed')
        return None

sys.meta_path.insert(0, NoHttpx())
from otalon_capture import write_failure
from otalon_capture.influxdb_writer import InfluxDBWriter
assert write_failure.permanent_auth_status(RuntimeError('transient')) is None
print('CAPTURE_IMPORT_WITHOUT_OPTIONAL_HTTPX')
"""
    result = subprocess.run(
        [sys.executable, "-c", code], cwd=tmp_path, env=dict(os.environ), capture_output=True, text=True
    )
    assert result.returncode == 0
    assert result.stdout.strip() == "CAPTURE_IMPORT_WITHOUT_OPTIONAL_HTTPX"
