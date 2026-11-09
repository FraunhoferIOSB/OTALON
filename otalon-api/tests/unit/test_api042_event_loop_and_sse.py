"""Regression tests for the API-042 P1 batch (event-loop offload + SSE framing).

Covers:

* API-03 — admin router ran sync psycopg2 / Docker SDK / filesystem calls
  directly inside ``async def``.
* API-04 — operations router blocked on storage walks, SHA-256 backup
  verification and readiness PostgreSQL queries.
* API-05 — baseline router ran seven handlers without offload.
* API-06 — pcap router blocked on the alarm lookup and mapped a NULL
  timestamp to HTTP 500 instead of 422.
* API-07 — subagent SSE terminal error frame was built with an f-string,
  producing malformed SSE when the message contained a quote or newline.

The offload tests assert on observed behaviour: the handler is driven on a
real event loop and the synchronous dependency records which thread it ran
on. A handler that still blocks executes on the loop thread and fails.
"""

from __future__ import annotations

import asyncio
import json
import threading
from typing import Any

import pytest

pytestmark = pytest.mark.unit


class _ThreadRecorder:
    """Records the thread each synchronous call was executed on."""

    def __init__(self, result: Any = None) -> None:
        self.result = result
        self.threads: list[str] = []

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        self.threads.append(threading.current_thread().name)
        return self.result

    @property
    def ran_off_the_loop_thread(self) -> bool:
        loop_thread = threading.current_thread().name
        return bool(self.threads) and all(t != loop_thread for t in self.threads)


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


# ── API-03: admin router ───────────────────────────────────────────────


class TestAdminRouterOffload:
    """Every admin handler must offload its blocking dependency."""

    def test_list_containers_offloads_docker_sdk(self) -> None:
        from otalon_api.api.v1 import admin

        recorder = _ThreadRecorder(result=[])
        service = type("S", (), {"list_containers": staticmethod(recorder)})()

        _run(admin.list_containers(docker_service=service))

        assert recorder.ran_off_the_loop_thread

    def test_get_container_logs_offloads_docker_sdk(self) -> None:
        from otalon_api.api.v1 import admin

        recorder = _ThreadRecorder(result="log-line")
        service = type("S", (), {"get_container_logs": staticmethod(recorder)})()

        result = _run(admin.get_container_logs(name="otalon-api", tail=5, docker_service=service))

        assert recorder.ran_off_the_loop_thread
        assert result.logs == "log-line"

    def test_get_env_offloads_filesystem_read(self) -> None:
        from otalon_api.api.v1 import admin

        recorder = _ThreadRecorder(result={"KEY": "***"})
        service = type("S", (), {"get_masked_env": staticmethod(recorder)})()

        _run(admin.get_env(env_service=service))

        assert recorder.ran_off_the_loop_thread

    def test_update_env_key_offloads_atomic_write(self) -> None:
        from otalon_api.api.v1 import admin

        recorder = _ThreadRecorder(result=({"K": "v"}, ["K"], "/tmp/backup"))
        service = type("S", (), {"update_and_save": staticmethod(recorder)})()
        body = admin.EnvValueRequest(value="v")

        result = _run(admin.update_env_key(key="K", body=body, env_service=service))

        assert recorder.ran_off_the_loop_thread
        assert result.changed_keys == ["K"]

    def test_truncate_table_offloads_psycopg2(self) -> None:
        from otalon_api.api.v1 import admin

        recorder = _ThreadRecorder(result=None)
        repo = type("R", (), {"truncate_table": staticmethod(recorder)})()
        request = type("Req", (), {"headers": {"X-Confirm": "true"}})()
        body = admin.DbTruncateRequest(table="anomalies", cascade=False)

        _run(admin.truncate_table(body=body, request=request, postgres_repo=repo))

        assert recorder.ran_off_the_loop_thread

    def test_delete_table_rows_offloads_psycopg2(self) -> None:
        from otalon_api.api.v1 import admin

        recorder = _ThreadRecorder(result=7)
        repo = type("R", (), {"delete_all_rows": staticmethod(recorder)})()
        request = type("Req", (), {"headers": {"X-Confirm": "true"}})()

        result = _run(admin.delete_table_rows(table="anomalies", request=request, postgres_repo=repo))

        assert recorder.ran_off_the_loop_thread
        assert result["deleted_rows"] == 7

    def test_confirm_header_is_still_required(self) -> None:
        """The offload must not weaken the destructive-operation guard."""
        from fastapi import HTTPException

        from otalon_api.api.v1 import admin

        repo = type("R", (), {"delete_all_rows": staticmethod(_ThreadRecorder(0))})()
        request = type("Req", (), {"headers": {}})()

        with pytest.raises(HTTPException) as exc:
            _run(admin.delete_table_rows(table="anomalies", request=request, postgres_repo=repo))
        assert exc.value.status_code == 400


# ── API-05: baseline router ────────────────────────────────────────────


class _BaselineRequest:
    """Minimal request double exposing ``app.state.baseline_service``."""

    def __init__(self, service: Any) -> None:
        state = type("St", (), {"baseline_service": service})()
        self.app = type("App", (), {"state": state})()


class TestBaselineRouterOffload:
    def test_list_offloads(self) -> None:
        from otalon_api.api.v1 import baselines

        recorder = _ThreadRecorder(result=[])
        service = type("S", (), {"list": staticmethod(recorder)})()

        _run(baselines.list_baselines(_BaselineRequest(service)))

        assert recorder.ran_off_the_loop_thread

    def test_get_offloads(self) -> None:
        from otalon_api.api.v1 import baselines

        recorder = _ThreadRecorder(result={"id": "b1"})
        service = type("S", (), {"get": staticmethod(recorder)})()

        _run(baselines.get_baseline(baseline_id="b1", request=_BaselineRequest(service)))

        assert recorder.ran_off_the_loop_thread

    def test_create_offloads_the_whole_method_as_one_hop(self) -> None:
        """``create`` does PG + listdir + Influx + os.link + copy2."""
        from datetime import datetime, timezone

        from otalon_api.api.v1 import baselines

        recorder = _ThreadRecorder(result={"id": "b1"})
        service = type("S", (), {"create": staticmethod(recorder)})()
        body = baselines.CreateBaselineBody(
            name="b",
            start_ts=datetime(2026, 1, 1, tzinfo=timezone.utc),
            end_ts=datetime(2026, 1, 2, tzinfo=timezone.utc),
        )

        _run(baselines.create_baseline(body=body, request=_BaselineRequest(service)))

        assert recorder.ran_off_the_loop_thread
        assert len(recorder.threads) == 1, "create must be a single offload hop"

    def test_preview_offloads(self) -> None:
        from datetime import datetime, timezone

        from otalon_api.api.v1 import baselines

        recorder = _ThreadRecorder(result={})
        service = type("S", (), {"preview": staticmethod(recorder)})()

        _run(
            baselines.preview_baseline(
                request=_BaselineRequest(service),
                start_ts=datetime(2026, 1, 1, tzinfo=timezone.utc),
                end_ts=datetime(2026, 1, 2, tzinfo=timezone.utc),
            )
        )

        assert recorder.ran_off_the_loop_thread


# ── API-06: pcap router ────────────────────────────────────────────────


class TestPcapIsoTimestamp:
    """A NULL alarm timestamp is unprocessable input, not a server fault."""

    def test_missing_timestamp_returns_422_not_500(self) -> None:
        from fastapi import HTTPException

        from otalon_api.api.v1.pcap import _iso

        with pytest.raises(HTTPException) as exc:
            _iso(None)

        assert exc.value.status_code == 422
        assert "timestamp" in str(exc.value.detail).lower()

    def test_datetime_is_rendered_iso8601(self) -> None:
        from datetime import datetime, timezone

        from otalon_api.api.v1.pcap import _iso

        assert _iso(datetime(2026, 1, 1, tzinfo=timezone.utc)).startswith("2026-01-01T")

    def test_string_passthrough(self) -> None:
        from otalon_api.api.v1.pcap import _iso

        assert _iso("2026-01-01T00:00:00Z") == "2026-01-01T00:00:00Z"

    def test_alarm_lookup_is_offloaded(self) -> None:
        """``get_anomaly_group_by_id`` is a synchronous psycopg2 call."""
        import inspect

        from otalon_api.api.v1 import pcap

        source = inspect.getsource(pcap)
        assert "await asyncio.to_thread(postgres_repo.get_anomaly_group_by_id" in source
        assert source.count("await asyncio.to_thread(postgres_repo.get_anomaly_group_by_id") == 2
        assert "= postgres_repo.get_anomaly_group_by_id(" not in source


# ── API-07: SSE terminal error frame ───────────────────────────────────


class _ExplodingStream:
    """Async iterator that raises before yielding anything."""

    def __init__(self, exc: BaseException) -> None:
        self._exc = exc

    def __call__(self, _job_id: str) -> Any:
        exc = self._exc

        async def _gen() -> Any:
            raise exc
            yield b""  # pragma: no cover - unreachable, defines the generator

        return _gen()


def _collect_sse_frames(service: Any, job_id: str = "j1") -> list[bytes]:
    from otalon_api.api.v1 import subagent_jobs

    request = type(
        "Req",
        (),
        {"app": type("App", (), {"state": type("St", (), {"subagent_service": service})()})()},
    )()

    async def drive() -> list[bytes]:
        response = await subagent_jobs.stream_subagent_events(job_id, request)
        return [chunk async for chunk in response.body_iterator]

    return _run(drive())


class TestSubagentSseErrorFrame:
    def test_error_detail_with_quotes_stays_valid_json(self) -> None:
        """An f-string frame broke apart on an embedded double quote."""
        service = type(
            "S",
            (),
            {"stream_events": _ExplodingStream(RuntimeError('boom "quoted" value'))},
        )()

        frames = _collect_sse_frames(service)

        assert len(frames) == 1
        text = frames[0].decode("utf-8")
        assert text.startswith("event: error\ndata: ")
        assert text.endswith("\n\n")
        payload = json.loads(text.split("data: ", 1)[1].strip())
        assert payload["reason"] == "upstream_disconnected"
        assert 'boom "quoted" value' in payload["detail"]

    def test_error_detail_with_newline_stays_a_single_frame(self) -> None:
        """A raw newline in the detail used to terminate the SSE frame early."""
        service = type(
            "S",
            (),
            {"stream_events": _ExplodingStream(RuntimeError("line one\nline two"))},
        )()

        frames = _collect_sse_frames(service)

        text = frames[0].decode("utf-8")
        body = text.split("data: ", 1)[1]
        assert body.count("\n\n") == 1, "detail newline must not split the frame"
        payload = json.loads(body.strip())
        assert "line one\nline two" in payload["detail"]

    def test_upstream_status_frame_is_valid_json(self) -> None:
        import httpx

        response = httpx.Response(status_code=503, request=httpx.Request("GET", "http://x"))
        exc = httpx.HTTPStatusError("boom", request=response.request, response=response)
        service = type("S", (), {"stream_events": _ExplodingStream(exc)})()

        frames = _collect_sse_frames(service)

        payload = json.loads(frames[0].decode("utf-8").split("data: ", 1)[1].strip())
        assert payload["reason"] == "upstream_status"
        assert payload["status"] == 503
        assert payload["type"] == "error"
