"""B2 deterministic intake budgets and pre-job thread ownership regressions."""

from __future__ import annotations

import asyncio
import hashlib
import threading
from collections.abc import AsyncIterator, Callable, Sequence
from pathlib import Path
from typing import Any

import pytest
from fastapi import HTTPException
from starlette.requests import ClientDisconnect, Request

from otalon_api.api.v1.pcap_import import _store_upload
from otalon_api.services import pcap_upload_service as intake
from tests.helpers.pcap_fixtures import pcap_bytes

pytestmark = pytest.mark.unit

BOUNDARY = b"b2-boundary"
CONTENT_TYPE = "multipart/form-data; boundary=b2-boundary"
ENVELOPE = 65_536


def _part(name: bytes, value: bytes, filename: bytes | None = None, extra: bytes = b"") -> bytes:
    """Build a public synthetic part without normalising malformed metadata."""
    disposition = b'Content-Disposition: form-data; name="' + name + b'"'
    if filename is not None:
        disposition += b'; filename="' + filename + b'"'
    return b"--" + BOUNDARY + b"\r\n" + disposition + b"\r\n" + extra + b"\r\n" + value + b"\r\n"


def _body(payload: bytes, fields: Sequence[tuple[bytes, bytes]] = (), filename: bytes = b"capture.pcap") -> bytes:
    """Frame one capture and ordinary metadata with a complete closing boundary."""
    return (
        b"".join(_part(name, value) for name, value in fields)
        + _part(b"file", payload, filename)
        + b"--"
        + BOUNDARY
        + b"--\r\n"
    )


async def _stream(body: bytes, chunk_size: int = 1024) -> AsyncIterator[bytes]:
    """Yield deterministic ASGI-sized chunks, including arbitrarily large ones."""
    for offset in range(0, len(body), chunk_size):
        yield body[offset : offset + chunk_size]


@pytest.mark.parametrize("delta", [-1, 0])
async def test_payload_minus_one_and_exact(tmp_path: Path, delta: int) -> None:
    """Configured payload accounting is independent of multipart framing."""
    payload = pcap_bytes([1.0], payload_size=1024 + delta)
    limit = len(pcap_bytes([1.0], payload_size=1024))
    stored = await intake.PcapUploadService(tmp_path, limit).store(CONTENT_TYPE, _stream(_body(payload)))
    assert stored.size_bytes == limit + delta
    assert stored.path.read_bytes() == payload
    assert stored.sha256 == hashlib.sha256(payload).hexdigest()
    assert len(stored.path.stem) == 32
    assert stored.original_filename == "capture.pcap"


async def test_payload_plus_one_accurate_rejection(tmp_path: Path) -> None:
    """Payload refusal names the configured file limit, not request headroom."""
    payload = pcap_bytes([1.0], payload_size=1025)
    limit = len(payload) - 1
    with pytest.raises(intake.UploadTooLarge, match=f"configured limit of {limit} bytes"):
        await intake.PcapUploadService(tmp_path, limit).store(CONTENT_TYPE, _stream(_body(payload)))
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("delta", [-1, 0])
@pytest.mark.parametrize("chunk_size", [1, 65_536, 1_000_000])
async def test_envelope_minus_one_and_exact(tmp_path: Path, delta: int, chunk_size: int) -> None:
    """Closing framing and epilogue contribute to exact total minus payload."""
    payload = pcap_bytes([1.0])
    body = _body(payload)
    body += b"e" * (ENVELOPE + delta - (len(body) - len(payload)))
    assert len(body) == len(payload) + ENVELOPE + delta
    stored = await intake.PcapUploadService(tmp_path, len(payload)).store(CONTENT_TYPE, _stream(body, chunk_size))
    assert stored.size_bytes == len(payload)
    assert stored.path.read_bytes() == payload


@pytest.mark.parametrize("chunk_size", [127, 65_536, 1_000_000])
async def test_epilogue_envelope_plus_one(tmp_path: Path, chunk_size: int) -> None:
    """Even ignored parser epilogue is actual non-file request data."""
    payload = pcap_bytes([1.0])
    body = _body(payload)
    body += b"e" * (ENVELOPE + 1 - (len(body) - len(payload)))
    with pytest.raises(intake.UploadTooLarge, match="envelope"):
        await intake.PcapUploadService(tmp_path, 1_000_000).store(CONTENT_TYPE, _stream(body, chunk_size))
    assert list(tmp_path.iterdir()) == []


async def test_total_request_budget(tmp_path: Path) -> None:
    """Actual total bytes are bounded independently of declared or parsed bytes."""
    payload = pcap_bytes([1.0])
    body = _body(payload) + b"e" * ENVELOPE
    with pytest.raises(intake.UploadTooLarge, match="total|envelope"):
        await intake.PcapUploadService(tmp_path, len(payload)).store(CONTENT_TYPE, _stream(body, len(body)))
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("declared", [None, b"1"])
@pytest.mark.parametrize("kind,status", [("payload", 413), ("envelope", 413), ("incomplete", 400), ("magic", 422)])
async def test_actual_request_route_mapping(tmp_path: Path, declared: bytes | None, kind: str, status: int) -> None:
    """The real Request stream and route intake mapper never trust Content-Length."""
    payload = pcap_bytes([1.0])
    bodies = {
        "payload": _body(pcap_bytes([1.0], payload_size=128)),
        "envelope": _body(payload) + b"e" * ENVELOPE,
        "incomplete": _body(payload)[: -len(BOUNDARY) - 6],
        "magic": _body(b"not a capture"),
    }
    headers = [(b"content-type", CONTENT_TYPE.encode())]
    if declared is not None:
        headers.append((b"content-length", declared))
    messages = iter([{"type": "http.request", "body": bodies[kind], "more_body": False}])

    async def receive() -> Any:
        return next(messages)

    request = Request({"type": "http", "headers": headers}, receive)
    with pytest.raises(HTTPException) as caught:
        await _store_upload(request, intake.PcapUploadService(tmp_path, len(payload)))
    assert caught.value.status_code == status
    assert list(tmp_path.iterdir()) == []


async def test_single_large_chunk_has_bounded_feeds_and_pending(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No parser feed or pending join holds the original single request chunk."""
    feeds: list[int] = []
    pending: list[int] = []
    take_pending = intake._UploadCollector.take_pending

    class ObservedParser(intake.MultipartParser):
        def write(self, data: bytes) -> int:
            feeds.append(len(data))
            return super().write(data)

    def observed_pending(collector: intake._UploadCollector) -> bytes:
        result = take_pending(collector)
        pending.append(len(result))
        return result

    monkeypatch.setattr(intake, "MultipartParser", ObservedParser)
    monkeypatch.setattr(intake._UploadCollector, "take_pending", observed_pending)
    payload = pcap_bytes([1.0], payload_size=400_000)
    body = _body(payload)
    stored = await intake.PcapUploadService(tmp_path, len(payload)).store(CONTENT_TYPE, _stream(body, len(body)))
    assert len(feeds) >= 7
    assert max(feeds) <= 65_536
    assert max(pending) <= 65_536 + len(BOUNDARY) + 8
    assert stored.size_bytes == len(payload)
    assert stored.path.read_bytes() == payload
    assert stored.sha256 == hashlib.sha256(payload).hexdigest()


@pytest.mark.parametrize("suffix", [b"", b"\r\n--b2-boundary", b"\r\n--b2-boundary-"])
async def test_incomplete_closing_boundary(tmp_path: Path, suffix: bytes) -> None:
    """The installed parser's no-op finalize cannot prove on_end occurred."""
    body = _part(b"file", pcap_bytes([1.0]), b"capture.pcap")[:-2] + suffix
    with pytest.raises(intake.MalformedUpload):
        await intake.PcapUploadService(tmp_path, 10_000).store(CONTENT_TYPE, _stream(body))
    assert list(tmp_path.iterdir()) == []


async def test_second_file_rejected_before_its_bytes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A second filename-bearing part is rejected at headers, never concatenated."""
    writes: list[bytes] = []
    write = intake._CaptureSink.write

    def record(sink: intake._CaptureSink, payload: bytes) -> None:
        writes.append(payload)
        write(sink, payload)

    monkeypatch.setattr(intake._CaptureSink, "write", record)
    first = _part(b"file", pcap_bytes([1.0]), b"one.pcap")
    second = _part(b"anything", b"SECOND-FILE-BYTES", b"two.pcap")
    with pytest.raises(intake.MalformedUpload, match="file"):
        await intake.PcapUploadService(tmp_path, 10_000).store(
            CONTENT_TYPE, _stream(first + second + b"--" + BOUNDARY + b"--\r\n", len(first))
        )
    assert b"SECOND-FILE-BYTES" not in b"".join(writes)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "boundary", ["", "x" * 71, "invalid@", "invalid\\", "invalid\t", "\u00e9", "\u20ac", "trailing "]
)
async def test_invalid_boundaries(tmp_path: Path, boundary: str) -> None:
    """Only 1..70 ASCII MIME boundary characters are accepted."""
    with pytest.raises(intake.MalformedUpload):
        await intake.PcapUploadService(tmp_path, 10_000).store(
            f'multipart/form-data; boundary="{boundary}"', _stream(_body(pcap_bytes([1.0])))
        )
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("chunk_size", [1, 65_536, 1_000_000])
async def test_exact_envelope_metadata_after_file(tmp_path: Path, chunk_size: int) -> None:
    """File-before-field ordering and delimiter lookbehind do not alter actual totals."""
    payload = pcap_bytes([1.0], payload_size=100_000)
    body = _part(b"different-file-name", payload, b"")
    body += _part(b"force", b"true") + b"--" + BOUNDARY + b"--\r\n"
    body += b"e" * (ENVELOPE - (len(body) - len(payload)))
    stored = await intake.PcapUploadService(tmp_path, len(payload)).store(CONTENT_TYPE, _stream(body, chunk_size))
    assert stored.size_bytes == len(payload)
    assert stored.path.read_bytes() == payload
    assert stored.original_filename == ""
    assert stored.fields == {"force": "true"}
    assert stored.force is True


@pytest.mark.parametrize("boundary", [b"x", b"x" * 70, b"'()+_,-./:=? space"])
async def test_valid_boundary_edges(tmp_path: Path, boundary: bytes) -> None:
    """MIME bchars, including internal spaces, retain valid boundary edges."""
    body = _body(pcap_bytes([1.0])).replace(BOUNDARY, boundary)
    stored = await intake.PcapUploadService(tmp_path, 10_000).store(
        f'multipart/form-data; boundary="{boundary.decode()}"', _stream(body, 3)
    )
    assert stored.path.read_bytes() == pcap_bytes([1.0])


@pytest.mark.parametrize("size", [4095, 4096])
async def test_field_value_edges(tmp_path: Path, size: int) -> None:
    """Ordinary metadata is retained exactly rather than silently truncated."""
    stored = await intake.PcapUploadService(tmp_path, 10_000).store(
        CONTENT_TYPE, _stream(_body(pcap_bytes([1.0]), [(b"note", b"v" * size)]), 13)
    )
    assert stored.fields == {"note": "v" * size}


@pytest.mark.parametrize(
    "fields,filename",
    [
        ([(b"note", b"v" * 4097)], b"ok"),
        ([(b"n" * 129, b"v")], b"ok"),
        ([("\u00e9".encode() * 65, b"v")], b"ok"),
        ([], b"f" * 1025),
        ([], "\u00e9".encode() * 513),
    ],
)
async def test_metadata_budget_overflow(tmp_path: Path, fields: list[tuple[bytes, bytes]], filename: bytes) -> None:
    """Name and filename limits count UTF-8 bytes, not Unicode characters."""
    with pytest.raises(intake.UploadTooLarge):
        await intake.PcapUploadService(tmp_path, 10_000).store(
            CONTENT_TYPE, _stream(_body(pcap_bytes([1.0]), fields, filename), 17)
        )
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "name,filename", [(b"n" * 128, b"f" * 1024), ("\u00e9".encode() * 64, "\u00e9".encode() * 512)]
)
async def test_utf8_metadata_exact_edges(tmp_path: Path, name: bytes, filename: bytes) -> None:
    """Exact byte limits preserve valid multibyte metadata and original filename."""
    stored = await intake.PcapUploadService(tmp_path, 10_000).store(
        CONTENT_TYPE, _stream(_body(pcap_bytes([1.0]), [(name, b"value")], filename), 7)
    )
    assert stored.fields == {name.decode(): "value"}
    assert stored.original_filename == filename.decode()


@pytest.mark.parametrize("fields,filename", [([(b"\xff", b"v")], b"ok"), ([(b"note", b"\xff")], b"ok"), ([], b"\xff")])
async def test_invalid_utf8_is_malformed(tmp_path: Path, fields: list[tuple[bytes, bytes]], filename: bytes) -> None:
    """Replacement decoding cannot silently admit malformed metadata."""
    with pytest.raises(intake.MalformedUpload):
        await intake.PcapUploadService(tmp_path, 10_000).store(
            CONTENT_TYPE, _stream(_body(pcap_bytes([1.0]), fields, filename))
        )
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "fields", [[(b"note", b"a"), (b"note", b"b")], [(str(i).encode(), b"v") for i in range(9)], [(b"", b"v")]]
)
async def test_malformed_text_part_counts_and_names(tmp_path: Path, fields: list[tuple[bytes, bytes]]) -> None:
    """Duplicates, nameless fields and ninth text parts are malformed, not metadata."""
    with pytest.raises(intake.MalformedUpload):
        await intake.PcapUploadService(tmp_path, 10_000).store(CONTENT_TYPE, _stream(_body(pcap_bytes([1.0]), fields)))
    assert list(tmp_path.iterdir()) == []


async def test_force_and_eight_ordinary_fields(tmp_path: Path) -> None:
    """Force retains existing semantics and unknown ordinary metadata remains supported."""
    fields = [(b"force", b" yes ")] + [(str(i).encode(), b"value") for i in range(7)]
    stored = await intake.PcapUploadService(tmp_path, 10_000).store(
        CONTENT_TYPE, _stream(_body(pcap_bytes([1.0]), fields))
    )
    assert stored.force is True
    assert stored.fields == {name.decode(): value.decode() for name, value in fields}


@pytest.mark.parametrize("delta", [-1, 0])
async def test_part_header_exact_budget(tmp_path: Path, delta: int) -> None:
    """All raw header bytes, including separators and blank line, fit the budget."""
    prefix = b'Content-Disposition: form-data; name="file"; filename="ok"\r\n'
    extra = b"X-Padding: " + b"p" * (8192 + delta - len(prefix) - len(b"X-Padding: \r\n\r\n")) + b"\r\n"
    body = _part(b"file", pcap_bytes([1.0]), b"ok", extra) + b"--" + BOUNDARY + b"--\r\n"
    stored = await intake.PcapUploadService(tmp_path, 10_000).store(CONTENT_TYPE, _stream(body, 11))
    assert stored.path.read_bytes() == pcap_bytes([1.0])


@pytest.mark.parametrize("complete", [False, True])
async def test_header_growth_rejected_before_part_end(tmp_path: Path, complete: bool) -> None:
    """Unfinished header growth is refused while streaming, never after part end."""
    body = b"--" + BOUNDARY + b"\r\nX-Padding: " + b"p" * 8192
    if complete:
        body += b'\r\nContent-Disposition: form-data; name="file"; filename="ok"\r\n\r\n' + pcap_bytes([1.0])
    consumed = 0

    async def chunks() -> AsyncIterator[bytes]:
        nonlocal consumed
        for offset in range(0, len(body), 128):
            consumed += 1
            yield body[offset : offset + 128]
        raise AssertionError("oversized header must reject before requesting stream EOF")

    with pytest.raises(intake.UploadTooLarge, match="header"):
        await intake.PcapUploadService(tmp_path, 1_000_000).store(CONTENT_TYPE, chunks())
    assert consumed <= 65
    assert list(tmp_path.iterdir()) == []


async def test_preamble_envelope_overflow_before_headers(tmp_path: Path) -> None:
    """Leading parser-tolerated CRLF bytes still exhaust the actual envelope."""
    body = b"\r\n" * (ENVELOPE // 2 + 1)
    with pytest.raises(intake.UploadTooLarge, match="envelope"):
        await intake.PcapUploadService(tmp_path, 1_000_000).store(CONTENT_TYPE, _stream(body, 1024))
    assert list(tmp_path.iterdir()) == []


async def test_envelope_overflow_in_unfinished_small_header(tmp_path: Path) -> None:
    """Aggregate envelope accounting runs before a small final header completes."""
    parts = b"".join(
        _part(str(i).encode(), b"v" * 4096, extra=b"X-Padding: " + b"p" * 4200 + b"\r\n") for i in range(7)
    )
    body = parts + b"--" + BOUNDARY + b"\r\nX-Unfinished: " + b"h" * 819
    # Bring total framing/fields just above the envelope without exceeding headers.
    body += b"h" * (ENVELOPE + 1 - len(body))

    async def chunks() -> AsyncIterator[bytes]:
        for offset in range(0, len(body), 127):
            yield body[offset : offset + 127]
        raise AssertionError("envelope overflow must be caught before stream EOF")

    with pytest.raises(intake.UploadTooLarge, match="envelope"):
        await intake.PcapUploadService(tmp_path, 1_000_000).store(CONTENT_TYPE, chunks())
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("filename,payload", [(b"", b""), (b"ok", b""), (b"ok", b"\xd4\xc3")])
async def test_missing_empty_or_short_capture(tmp_path: Path, filename: bytes, payload: bytes) -> None:
    """Empty files are malformed and insufficient magic remains unsupported."""
    error = intake.MalformedUpload if not payload else intake.UnsupportedCapture
    with pytest.raises(error):
        await intake.PcapUploadService(tmp_path, 10_000).store(CONTENT_TYPE, _stream(_body(payload, filename=filename)))
    assert list(tmp_path.iterdir()) == []


async def test_disconnect_closes_partial_sink(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A real ASGI disconnect removes a partially written file and closes its handle."""
    sinks: list[intake._CaptureSink] = []
    construct = intake._CaptureSink.__init__

    def record(sink: intake._CaptureSink, path: Path, max_bytes: int) -> None:
        construct(sink, path, max_bytes)
        sinks.append(sink)

    monkeypatch.setattr(intake._CaptureSink, "__init__", record)
    messages = iter(
        [
            {"type": "http.request", "body": _part(b"file", pcap_bytes([1.0]), b"ok")[:-2], "more_body": True},
            {"type": "http.disconnect"},
        ]
    )

    async def receive() -> Any:
        return next(messages)

    request = Request({"type": "http", "headers": []}, receive)
    with pytest.raises(intake.MalformedUpload, match=ClientDisconnect.__name__):
        await intake.PcapUploadService(tmp_path, 10_000).store(CONTENT_TYPE, request.stream())
    assert len(sinks) == 1
    assert sinks[0]._handle is None
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("phase", ["mkdir", "allocate", "write", "finish", "discard"])
@pytest.mark.parametrize("cancellations", [1, 3])
async def test_cancel_joins_held_threads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str, cancellations: int
) -> None:
    """Cancellation must join held allocation/write/finish/discard, even when repeated."""
    loop = asyncio.get_running_loop()
    entered = asyncio.Event()
    release = threading.Event()
    exited = threading.Event()
    sinks: list[intake._CaptureSink] = []
    constructor = intake._CaptureSink.__init__

    def hold(operation: Callable[[], Any]) -> Any:
        loop.call_soon_threadsafe(entered.set)
        try:
            assert release.wait(2), "test must explicitly release its held operation"
            return operation()
        finally:
            exited.set()

    def construct(sink: intake._CaptureSink, path: Path, max_bytes: int) -> None:
        def allocate() -> None:
            constructor(sink, path, max_bytes)
            sinks.append(sink)

        if phase == "allocate":
            hold(allocate)
        else:
            allocate()

    monkeypatch.setattr(intake._CaptureSink, "__init__", construct)
    if phase == "mkdir":
        mkdir = Path.mkdir

        def held_mkdir(path: Path, *args: Any, **kwargs: Any) -> None:
            hold(lambda: mkdir(path, *args, **kwargs))

        monkeypatch.setattr(Path, "mkdir", held_mkdir)
    if phase in ("write", "finish", "discard"):
        operation = getattr(intake._CaptureSink, phase)

        def held_operation(sink: intake._CaptureSink, *args: Any) -> Any:
            return hold(lambda: operation(sink, *args))

        monkeypatch.setattr(intake._CaptureSink, phase, held_operation)
    payload = b"not a capture" if phase == "discard" else pcap_bytes([1.0])
    task = asyncio.create_task(intake.PcapUploadService(tmp_path, 10_000).store(CONTENT_TYPE, _stream(_body(payload))))
    abandoned = False
    try:
        await asyncio.wait_for(entered.wait(), 2)
        for _ in range(cancellations):
            task.cancel()
            await asyncio.sleep(0)
        abandoned = task.done()
    finally:
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        await asyncio.to_thread(exited.wait, 2)
    assert abandoned is False
    assert exited.is_set()
    assert all(sink._handle is None for sink in sinks)
    assert list(tmp_path.iterdir()) == []


async def test_cancel_during_body_wait(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Cancellation while awaiting the next ASGI chunk also settles and discards."""
    entered = asyncio.Event()
    sinks: list[intake._CaptureSink] = []
    constructor = intake._CaptureSink.__init__

    def construct(sink: intake._CaptureSink, path: Path, max_bytes: int) -> None:
        constructor(sink, path, max_bytes)
        sinks.append(sink)

    monkeypatch.setattr(intake._CaptureSink, "__init__", construct)

    async def chunks() -> AsyncIterator[bytes]:
        yield _part(b"file", pcap_bytes([1.0]), b"ok")[:-2]
        entered.set()
        await asyncio.Event().wait()

    task = asyncio.create_task(intake.PcapUploadService(tmp_path, 10_000).store(CONTENT_TYPE, chunks()))
    await asyncio.wait_for(entered.wait(), 2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert len(sinks) == 1
    assert sinks[0]._handle is None
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("phase", ["allocate", "write", "finish"])
async def test_ordinary_operation_failure_cleanup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str) -> None:
    """Ordinary allocation, write and finish failures retain 400 cleanup semantics."""
    sinks: list[intake._CaptureSink] = []
    constructor = intake._CaptureSink.__init__

    def construct(sink: intake._CaptureSink, path: Path, max_bytes: int) -> None:
        if phase == "allocate":
            raise OSError("synthetic allocation refusal")
        constructor(sink, path, max_bytes)
        sinks.append(sink)

    def fail(sink: intake._CaptureSink, *args: Any) -> Any:
        raise OSError("synthetic operation refusal")

    monkeypatch.setattr(intake._CaptureSink, "__init__", construct)
    if phase != "allocate":
        monkeypatch.setattr(intake._CaptureSink, phase, fail)
    with pytest.raises(intake.MalformedUpload, match="OSError: synthetic"):
        await intake.PcapUploadService(tmp_path, 10_000).store(CONTENT_TYPE, _stream(_body(pcap_bytes([1.0]))))
    assert all(sink._handle is None for sink in sinks)
    assert list(tmp_path.iterdir()) == []


async def test_cancel_at_parser_finalize_handoff(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A cancel requested at synchronous parser finalization cannot orphan finish."""
    task = asyncio.current_task()
    assert task is not None
    finished: list[intake._CaptureSink] = []
    finish = intake._CaptureSink.finish

    class CancelParser(intake.MultipartParser):
        def finalize(self) -> None:
            super().finalize()
            task.cancel()

    def record_finish(sink: intake._CaptureSink) -> str:
        result = finish(sink)
        finished.append(sink)
        return result

    monkeypatch.setattr(intake, "MultipartParser", CancelParser)
    monkeypatch.setattr(intake._CaptureSink, "finish", record_finish)
    with pytest.raises(asyncio.CancelledError):
        await intake.PcapUploadService(tmp_path, 10_000).store(CONTENT_TYPE, _stream(_body(pcap_bytes([1.0]))))
    assert len(finished) == 1
    assert finished[0]._handle is None
    assert list(tmp_path.iterdir()) == []
