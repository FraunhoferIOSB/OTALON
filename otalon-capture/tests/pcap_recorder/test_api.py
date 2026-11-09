"""Tests fuer PcapService und REST-Endpunkte."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from pcap_recorder.api import PcapService, create_app
from pcap_recorder.index import PcapChunkMeta


class DummyIndex:
    def __init__(self, entries: Optional[List[PcapChunkMeta]] = None) -> None:
        self._entries = {entry.filename: entry for entry in entries or []}
        self.marked: List[List[str]] = []
        self.labels: List[Dict[str, str]] = []

    def add(self, meta: PcapChunkMeta) -> None:
        self._entries[meta.filename] = meta

    def find_by_timerange(
        self, _start: datetime, _end: datetime, include_non_archive: bool = True
    ) -> List[PcapChunkMeta]:
        entries = list(self._entries.values())
        if include_non_archive:
            return entries
        return [entry for entry in entries if entry.is_anomaly]

    def list_all(self) -> List[PcapChunkMeta]:
        return list(self._entries.values())

    def mark_anomaly(self, chunk_ids: Iterable[str], labels: Optional[Dict[str, str]] = None) -> List[PcapChunkMeta]:
        labels = labels or {}
        self.marked.append(list(chunk_ids))
        self.labels.append(labels)
        updated: List[PcapChunkMeta] = []
        for chunk_id in chunk_ids:
            meta = self._entries.get(chunk_id)
            if not meta:
                continue
            meta.is_anomaly = True
            meta.labels.update(labels)
            updated.append(meta)
        return updated


class DummyRingbuffer:
    def __init__(self) -> None:
        self.archived: List[List[str]] = []

    def archive_chunks(self, chunk_ids: Iterable[str]) -> Dict[str, Path]:
        chunk_ids = list(chunk_ids)
        self.archived.append(chunk_ids)
        return {chunk_id: Path(f"/archive/{chunk_id}") for chunk_id in chunk_ids}


@pytest.fixture
def chunk_meta(tmp_path: Path) -> PcapChunkMeta:
    file_path = tmp_path / "pcap_20260213_120000.pcap"
    file_path.write_bytes(b"demo")
    start = datetime(2026, 2, 13, 12, 0, 0)
    return PcapChunkMeta(
        filename=file_path.name,
        path=file_path,
        start_ts=start,
        end_ts=start + timedelta(seconds=60),
        size_bytes=file_path.stat().st_size,
    )


def test_flag_anomaly_archives_and_marks(chunk_meta: PcapChunkMeta) -> None:
    index = DummyIndex([chunk_meta])
    ringbuffer = DummyRingbuffer()
    service = PcapService(index=index, ringbuffer=ringbuffer)

    chunk_ids = service.flag_anomaly(chunk_meta.start_ts, chunk_meta.end_ts, labels={"uci": "demo"})

    assert chunk_ids == [chunk_meta.filename]
    assert ringbuffer.archived == [[chunk_meta.filename]]
    assert index.marked == [[chunk_meta.filename]]
    assert chunk_meta.is_anomaly is True
    assert chunk_meta.labels["uci"] == "demo"


def _build_test_client(index: DummyIndex) -> TestClient:
    import os

    os.environ["ADMIN_API_KEY"] = "test-pcap-key"
    ringbuffer = DummyRingbuffer()
    service = PcapService(index=index, ringbuffer=ringbuffer)
    app = create_app(service)
    return TestClient(app, headers={"X-API-Key": "test-pcap-key"})


def test_get_chunks_endpoint_returns_json(chunk_meta: PcapChunkMeta) -> None:
    index = DummyIndex([chunk_meta])
    client = _build_test_client(index)

    response = client.get(
        "/chunks",
        params={
            "start_ts": chunk_meta.start_ts.isoformat(),
            "end_ts": chunk_meta.end_ts.isoformat(),
            "format": "json",
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload[0]["chunk_id"] == chunk_meta.filename
    assert "path" not in payload[0]


def test_chunk_routes_require_api_key(chunk_meta: PcapChunkMeta) -> None:
    index = DummyIndex([chunk_meta])
    service = PcapService(index=index, ringbuffer=DummyRingbuffer())
    client = TestClient(create_app(service))
    params = {"start_ts": chunk_meta.start_ts.isoformat(), "end_ts": chunk_meta.end_ts.isoformat()}

    assert client.get("/chunks", params=params).status_code in {401, 503}
    assert client.get(f"/chunks/{chunk_meta.filename}").status_code in {401, 503}
    assert client.get("/docs").status_code == 404
    assert client.get("/redoc").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_security_headers_are_present_and_technology_headers_absent() -> None:
    """Jede Antwort enthaelt die Security-Header und keinen x-process-time/x-powered-by."""
    client = _build_test_client(DummyIndex([]))

    response = client.get("/health")

    assert response.status_code == 200
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["content-security-policy"] == "frame-ancestors 'none'"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "x-process-time" not in response.headers
    assert "x-powered-by" not in response.headers


def test_get_chunks_endpoint_returns_404_for_missing_files() -> None:
    index = DummyIndex([])
    client = _build_test_client(index)

    response = client.get(
        "/chunks",
        params={
            "start_ts": datetime.now(timezone.utc).isoformat(),
            "end_ts": (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat(),
            "format": "pcap",
        },
    )

    assert response.status_code == 404


def test_get_chunk_by_id_endpoint(chunk_meta: PcapChunkMeta) -> None:
    index = DummyIndex([chunk_meta])
    client = _build_test_client(index)

    response = client.get(f"/chunks/{chunk_meta.filename}")

    assert response.status_code == 200
    assert response.content == chunk_meta.path.read_bytes()

    # A well-formed but unknown identifier is still a 404. ``unknown.pcap``
    # no longer qualifies: SUITE-044/V2 constrains the path parameter to the
    # recorder's own filename shape, so it is rejected as 422 before any
    # lookup happens (covered in test_suite044_validation_bounds.py).
    missing_response = client.get("/chunks/20260101_000000.pcap")
    assert missing_response.status_code == 404


def test_get_chunks_text_format_returns_plaintext(chunk_meta: PcapChunkMeta) -> None:
    index = DummyIndex([chunk_meta])
    client = _build_test_client(index)
    fake_output = "1740000000.000000 IP 10.0.0.1.443 > 10.0.0.2.12345: Flags [S], seq 0, win 65535"

    with patch("pcap_recorder.api._tcpdump_read_text", return_value=fake_output):
        response = client.get(
            "/chunks",
            params={
                "start_ts": chunk_meta.start_ts.isoformat(),
                "end_ts": chunk_meta.end_ts.isoformat(),
                "format": "text",
            },
        )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert "10.0.0.1.443" in response.text


def test_get_chunks_text_format_returns_404_when_empty() -> None:
    index = DummyIndex([])
    client = _build_test_client(index)

    response = client.get(
        "/chunks",
        params={
            "start_ts": datetime.now(timezone.utc).isoformat(),
            "end_ts": (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat(),
            "format": "text",
        },
    )

    assert response.status_code == 404


def test_get_chunks_text_format_handles_tcpdump_error(
    chunk_meta: PcapChunkMeta,
) -> None:
    index = DummyIndex([chunk_meta])
    client = _build_test_client(index)

    with patch(
        "pcap_recorder.api._tcpdump_read_text",
        side_effect=RuntimeError("tcpdump not found"),
    ):
        response = client.get(
            "/chunks",
            params={
                "start_ts": chunk_meta.start_ts.isoformat(),
                "end_ts": chunk_meta.end_ts.isoformat(),
                "format": "text",
            },
        )

    assert response.status_code == 500
    assert "tcpdump not found" in response.json()["detail"]


def test_get_chunks_unsupported_format_returns_422(chunk_meta: PcapChunkMeta) -> None:
    """SUITE-044/V2: ``format`` is a Literal, so FastAPI rejects it as 422.

    It used to be an unvalidated string answered with a hand-built 400 at the
    bottom of the handler; the allowed set is now part of the contract.
    """
    index = DummyIndex([chunk_meta])
    client = _build_test_client(index)

    response = client.get(
        "/chunks",
        params={
            "start_ts": chunk_meta.start_ts.isoformat(),
            "end_ts": chunk_meta.end_ts.isoformat(),
            "format": "xml",
        },
    )

    assert response.status_code == 422


def test_get_chunk_by_id_text_format(chunk_meta: PcapChunkMeta) -> None:
    index = DummyIndex([chunk_meta])
    client = _build_test_client(index)
    fake_output = "1740000000.000000 IP 10.0.0.1 > 10.0.0.2: ICMP echo request"

    with patch("pcap_recorder.api._tcpdump_read_text", return_value=fake_output):
        response = client.get(f"/chunks/{chunk_meta.filename}", params={"format": "text"})

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert "ICMP echo request" in response.text


def test_get_chunk_by_id_json_format(chunk_meta: PcapChunkMeta) -> None:
    index = DummyIndex([chunk_meta])
    client = _build_test_client(index)

    response = client.get(f"/chunks/{chunk_meta.filename}", params={"format": "json"})

    assert response.status_code == 200
    payload = response.json()
    assert payload["chunk_id"] == chunk_meta.filename
    assert payload["size_bytes"] == chunk_meta.size_bytes


def test_get_chunks_detail_format_returns_tshark_output(
    chunk_meta: PcapChunkMeta,
) -> None:
    index = DummyIndex([chunk_meta])
    client = _build_test_client(index)
    fake_output = (
        "Frame 1: 74 bytes on wire\n"
        "  Ethernet II, Src: 00:11:22:33:44:55\n"
        "  Internet Protocol Version 4, Src: 10.0.0.1\n"
    )

    with patch("pcap_recorder.api._tshark_read", return_value=fake_output):
        response = client.get(
            "/chunks",
            params={
                "start_ts": chunk_meta.start_ts.isoformat(),
                "end_ts": chunk_meta.end_ts.isoformat(),
                "format": "detail",
            },
        )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert "Frame 1:" in response.text
    assert "Ethernet II" in response.text


def test_get_chunks_detail_format_uses_fixed_tshark_args(
    chunk_meta: PcapChunkMeta,
) -> None:
    index = DummyIndex([chunk_meta])
    client = _build_test_client(index)
    fake_fields = "10.0.0.1\t10.0.0.2\n192.168.1.1\t192.168.1.2\n"

    with patch("pcap_recorder.api._tshark_read", return_value=fake_fields) as mock_tshark:
        response = client.get(
            "/chunks",
            params={
                "start_ts": chunk_meta.start_ts.isoformat(),
                "end_ts": chunk_meta.end_ts.isoformat(),
                "format": "detail",
            },
        )

    assert response.status_code == 200
    assert "10.0.0.1" in response.text
    mock_tshark.assert_called_once()
    call_args = mock_tshark.call_args
    assert call_args.kwargs["extra_args"] == []


def test_get_chunks_detail_format_returns_404_when_empty() -> None:
    index = DummyIndex([])
    client = _build_test_client(index)

    response = client.get(
        "/chunks",
        params={
            "start_ts": datetime.now(timezone.utc).isoformat(),
            "end_ts": (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat(),
            "format": "detail",
        },
    )

    assert response.status_code == 404


def test_get_chunks_detail_format_handles_tshark_error(
    chunk_meta: PcapChunkMeta,
) -> None:
    index = DummyIndex([chunk_meta])
    client = _build_test_client(index)

    with patch(
        "pcap_recorder.api._tshark_read",
        side_effect=RuntimeError("tshark executable not found on PATH."),
    ):
        response = client.get(
            "/chunks",
            params={
                "start_ts": chunk_meta.start_ts.isoformat(),
                "end_ts": chunk_meta.end_ts.isoformat(),
                "format": "detail",
            },
        )

    assert response.status_code == 500
    assert "tshark" in response.json()["detail"]


def test_get_chunk_by_id_detail_format(chunk_meta: PcapChunkMeta) -> None:
    index = DummyIndex([chunk_meta])
    client = _build_test_client(index)
    fake_output = "Frame 1: 74 bytes on wire\n  Protocol: PROFINET\n"

    with patch("pcap_recorder.api._tshark_read", return_value=fake_output):
        response = client.get(f"/chunks/{chunk_meta.filename}", params={"format": "detail"})

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert "PROFINET" in response.text


def test_get_chunk_by_id_detail_format_rejects_unlisted_args(
    chunk_meta: PcapChunkMeta,
) -> None:
    """A flag outside the allow-list is a 400 and never reaches tshark."""
    index = DummyIndex([chunk_meta])
    client = _build_test_client(index)

    with patch("pcap_recorder.api._tshark_read", return_value="") as mock_tshark:
        response = client.get(
            f"/chunks/{chunk_meta.filename}",
            params={"format": "detail", "tshark_args": "-r /etc/hostname"},
        )

    assert response.status_code == 400
    assert "-r" in response.json()["detail"]
    mock_tshark.assert_not_called()


@pytest.mark.parametrize(
    "raw",
    [
        "-w /tmp/exfil.pcap",
        "-X lua_script:/tmp/evil.lua",
        "-o uat:user_dlts",
        "-z io,stat,1; rm -rf /",
        "--help",
    ],
)
def test_get_chunk_by_id_detail_format_rejects_dangerous_args(
    chunk_meta: PcapChunkMeta,
    raw: str,
) -> None:
    """Write/exec/preference flags stay rejected (audit HC1)."""
    index = DummyIndex([chunk_meta])
    client = _build_test_client(index)

    with patch("pcap_recorder.api._tshark_read", return_value="") as mock_tshark:
        response = client.get(
            f"/chunks/{chunk_meta.filename}",
            params={"format": "detail", "tshark_args": raw},
        )

    assert response.status_code == 400
    mock_tshark.assert_not_called()


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("-q -z io,phs", ["-q", "-z", "io,phs"]),
        ("-q -z conv,eth", ["-q", "-z", "conv,eth"]),
        ("-q -z io,stat,1", ["-q", "-z", "io,stat,1"]),
        ("-c 50", ["-c", "50"]),
        ("-Y lldp", ["-Y", "lldp"]),
        (
            '-Y "frame.time_relative>=0.0 and frame.time_relative<=5.0" -T fields -e frame.number -e eth.src',
            [
                "-Y",
                "frame.time_relative>=0.0 and frame.time_relative<=5.0",
                "-T",
                "fields",
                "-e",
                "frame.number",
                "-e",
                "eth.src",
            ],
        ),
    ],
)
def test_get_chunk_by_id_detail_format_forwards_tshark_args(
    chunk_meta: PcapChunkMeta,
    raw: str,
    expected: list[str],
) -> None:
    """The MCP argument strings reach ``_tshark_read`` as validated argv."""
    index = DummyIndex([chunk_meta])
    client = _build_test_client(index)

    with patch("pcap_recorder.api._tshark_read", return_value="stats\n") as mock_tshark:
        response = client.get(
            f"/chunks/{chunk_meta.filename}",
            params={"format": "detail", "tshark_args": raw},
        )

    assert response.status_code == 200
    mock_tshark.assert_called_once()
    assert mock_tshark.call_args.kwargs["extra_args"] == expected


def test_get_chunk_by_id_detail_format_without_args_stays_bare(
    chunk_meta: PcapChunkMeta,
) -> None:
    """Omitting ``tshark_args`` keeps the historical bare ``tshark -r`` call."""
    index = DummyIndex([chunk_meta])
    client = _build_test_client(index)

    with patch("pcap_recorder.api._tshark_read", return_value="Frame 1\n") as mock_tshark:
        response = client.get(f"/chunks/{chunk_meta.filename}", params={"format": "detail"})

    assert response.status_code == 200
    assert mock_tshark.call_args.kwargs["extra_args"] == []


def test_tshark_read_default_args_used_when_none(
    chunk_meta: PcapChunkMeta,
) -> None:
    index = DummyIndex([chunk_meta])
    client = _build_test_client(index)
    fake_output = "Frame 1: verbose output\n"

    with patch("pcap_recorder.api._tshark_read", return_value=fake_output) as mock_tshark:
        response = client.get(
            "/chunks",
            params={
                "start_ts": chunk_meta.start_ts.isoformat(),
                "end_ts": chunk_meta.end_ts.isoformat(),
                "format": "detail",
            },
        )

    assert response.status_code == 200
    mock_tshark.assert_called_once()
    call_args = mock_tshark.call_args
    assert call_args.kwargs["extra_args"] == []


def test_flag_anomaly_equal_timestamps_accepted(chunk_meta: PcapChunkMeta) -> None:
    """Flagging with start_ts == end_ts is a valid point-in-time query."""
    index = DummyIndex([chunk_meta])
    client = _build_test_client(index)
    ts = chunk_meta.start_ts.isoformat()

    response = client.post(
        "/anomalies/flag",
        json={"start_ts": ts, "end_ts": ts},
    )

    assert response.status_code == 200


def test_flag_anomaly_start_after_end_rejected(chunk_meta: PcapChunkMeta) -> None:
    """Flagging with start_ts > end_ts must return 400."""
    index = DummyIndex([chunk_meta])
    client = _build_test_client(index)
    start = chunk_meta.end_ts.isoformat()
    end = chunk_meta.start_ts.isoformat()

    response = client.post(
        "/anomalies/flag",
        json={"start_ts": start, "end_ts": end},
    )

    assert response.status_code == 400
    assert "start_ts must not be after end_ts" in response.json()["detail"]


def test_get_chunks_equal_timestamps_accepted(chunk_meta: PcapChunkMeta) -> None:
    """Querying chunks with start_ts == end_ts is a valid point-in-time query."""
    index = DummyIndex([chunk_meta])
    client = _build_test_client(index)
    ts = chunk_meta.start_ts.isoformat()

    response = client.get("/chunks", params={"start_ts": ts, "end_ts": ts, "format": "json"})

    assert response.status_code == 200


def test_get_chunks_start_after_end_rejected(chunk_meta: PcapChunkMeta) -> None:
    """Querying chunks with start_ts > end_ts must return 400."""
    index = DummyIndex([chunk_meta])
    client = _build_test_client(index)

    response = client.get(
        "/chunks",
        params={
            "start_ts": chunk_meta.end_ts.isoformat(),
            "end_ts": chunk_meta.start_ts.isoformat(),
            "format": "json",
        },
    )

    assert response.status_code == 400
    assert "start_ts must not be after end_ts" in response.json()["detail"]
