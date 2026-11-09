"""Regression tests for the SUITE-044 validation/bounds findings.

Four defects, each covered in both directions — the invalid input is
rejected *and* a realistic valid input still works:

* V1 — ``format`` was an unvalidated free string on both chunk routes,
  compared against four literals in an if-chain and rejected only by a
  hand-built 400 at the bottom. The allowed set was invisible in the
  request contract.
* V2 — ``chunk_id`` was an unconstrained path parameter with nothing but an
  emptiness check before it reached an index lookup.
* V3 — ``ImportRequest.file_path`` carried ``min_length=1`` and no ceiling
  and no shape constraint, so a malformed value failed late in the runner
  instead of being answered with a 422.
* V4 — ``hmac.compare_digest`` was called on ``str`` operands. Starlette
  decodes headers as latin-1, so a non-ASCII ``X-API-Key`` raised
  ``TypeError`` inside the auth dependency and produced a 500 instead of a
  401.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional

import pytest
from fastapi.testclient import TestClient

from pcap_import.models import FILE_PATH_MAX_LENGTH, ImportRequest
from pcap_recorder.api import (
    CHUNK_ID_MAX_LENGTH,
    SUPPORTED_FORMAT_VALUES,
    SUPPORTED_FORMATS,
    PcapService,
    create_app,
)
from pcap_recorder.index import PcapChunkMeta

API_KEY = "test-suite044-key"

LIVE_CHUNK_IDS = [
    "20260213_120000.pcap",
    "20260831_141703.pcap",
    "20260513_223218.pcap.gz",
    "20260513_223218.pcap.zst",
    "20260513_223218.pcap.l9.zst",
    "20260513_223218.pcap.l19.zst",
    "pcap_20260213_120000.pcap",
]
"""Every filename shape found under the live ringbuffer/archive/baseline dirs.

The bare and compressed forms are taken verbatim from ``shared/pcap``; the
``pcap_``-prefixed form is the recorder's legacy shape, which
``PcapIndex._parse_timestamp`` still strips and the existing test corpus
still uses.
"""

MALFORMED_CHUNK_IDS = [
    "unknown.pcap",
    "../pcap_index.json",
    "..%2fpcap_index.json",
    "pcap_index.json",
    "20260213_120000",
    "20260213_120000.pcap.exe",
    "2026021_120000.pcap",
    "20260213_1200000.pcap",
    "20260213_120000.pcap.l999.zst",
    "20260213_120000.pcap.bz2",
    " 20260213_120000.pcap",
    "20260213_120000.pcap ",
]


class _Index:
    """Index double keyed by filename, mirroring the real index contract."""

    def __init__(self, entries: Optional[List[PcapChunkMeta]] = None) -> None:
        self._entries = {entry.filename: entry for entry in entries or []}
        self.lookups: List[List[str]] = []

    def find_by_timerange(
        self, _start: datetime, _end: datetime, include_non_archive: bool = True
    ) -> List[PcapChunkMeta]:
        return list(self._entries.values())

    def list_all(self) -> List[PcapChunkMeta]:
        return list(self._entries.values())

    def mark_anomaly(self, chunk_ids: Iterable[str], labels: Optional[Dict[str, str]] = None) -> List[PcapChunkMeta]:
        return []


class _Ringbuffer:
    def archive_chunks(self, chunk_ids: Iterable[str]) -> Dict[str, Path]:
        return {}


class _RecordingService(PcapService):
    """Service that records whether an id lookup happened at all."""

    def __init__(self, index: _Index, ringbuffer: _Ringbuffer) -> None:
        super().__init__(index=index, ringbuffer=ringbuffer)
        self.id_lookups: List[List[str]] = []

    def get_chunks_by_id(self, chunk_ids: Iterable[str]) -> List[PcapChunkMeta]:
        ids = list(chunk_ids)
        self.id_lookups.append(ids)
        return super().get_chunks_by_id(ids)


@pytest.fixture()
def chunk(tmp_path: Path) -> PcapChunkMeta:
    start = datetime(2026, 2, 13, 12, 0, 0)
    path = tmp_path / "20260213_120000.pcap"
    path.write_bytes(b"\xd4\xc3\xb2\xa1")
    return PcapChunkMeta(
        filename=path.name,
        path=path,
        start_ts=start,
        end_ts=start + timedelta(seconds=60),
        size_bytes=path.stat().st_size,
    )


@pytest.fixture()
def service(chunk: PcapChunkMeta) -> _RecordingService:
    return _RecordingService(_Index([chunk]), _Ringbuffer())


@pytest.fixture()
def client(service: _RecordingService, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    monkeypatch.setenv("ADMIN_API_KEY", API_KEY)
    with TestClient(create_app(service), headers={"X-API-Key": API_KEY}) as test_client:
        yield test_client


def _range(chunk: PcapChunkMeta) -> Dict[str, str]:
    return {"start_ts": chunk.start_ts.isoformat(), "end_ts": chunk.end_ts.isoformat()}


class TestV1ChunkFormatIsConstrained:
    """``format`` is a Literal on both routes, with the defaults preserved."""

    @pytest.mark.parametrize("bad_format", ["xml", "JSON", "pcapng", "", "json,pcap"])
    def test_list_route_rejects_an_unknown_format(
        self, client: TestClient, chunk: PcapChunkMeta, bad_format: str
    ) -> None:
        response = client.get("/chunks", params={**_range(chunk), "format": bad_format})
        assert response.status_code == 422

    @pytest.mark.parametrize("bad_format", ["xml", "JSON", "pcapng", ""])
    def test_by_id_route_rejects_an_unknown_format(
        self, client: TestClient, chunk: PcapChunkMeta, bad_format: str
    ) -> None:
        response = client.get(f"/chunks/{chunk.filename}", params={"format": bad_format})
        assert response.status_code == 422

    def test_an_unknown_format_never_reaches_the_service(
        self, client: TestClient, chunk: PcapChunkMeta, service: _RecordingService
    ) -> None:
        client.get(f"/chunks/{chunk.filename}", params={"format": "xml"})
        assert service.id_lookups == []

    def test_json_format_still_works(self, client: TestClient, chunk: PcapChunkMeta) -> None:
        response = client.get("/chunks", params={**_range(chunk), "format": "json"})
        assert response.status_code == 200
        assert response.json()[0]["chunk_id"] == chunk.filename

    def test_the_list_route_still_defaults_to_json(self, client: TestClient, chunk: PcapChunkMeta) -> None:
        """The two routes have different defaults; both must be preserved."""
        response = client.get("/chunks", params=_range(chunk))
        assert response.status_code == 200
        assert response.json()[0]["chunk_id"] == chunk.filename

    def test_the_by_id_route_still_defaults_to_pcap(self, client: TestClient, chunk: PcapChunkMeta) -> None:
        response = client.get(f"/chunks/{chunk.filename}")
        assert response.status_code == 200
        assert response.content == chunk.path.read_bytes()

    def test_the_supported_set_is_the_documented_one(self) -> None:
        assert set(SUPPORTED_FORMAT_VALUES) == {"json", "pcap", "text", "detail"}

    def test_the_prose_string_is_derived_not_duplicated(self) -> None:
        """``SUPPORTED_FORMATS`` must follow the Literal, not restate it."""
        for value in SUPPORTED_FORMAT_VALUES:
            assert f"'{value}'" in SUPPORTED_FORMATS


class TestV2ChunkIdIsConstrained:
    """The path parameter is pinned to the recorder's own filename shape."""

    @pytest.mark.parametrize("chunk_id", LIVE_CHUNK_IDS)
    def test_every_live_filename_shape_is_accepted(self, client: TestClient, chunk_id: str) -> None:
        """A live id must not be rejected — 404 means it passed validation."""
        response = client.get(f"/chunks/{chunk_id}")
        assert response.status_code in {200, 404}

    @pytest.mark.parametrize("chunk_id", MALFORMED_CHUNK_IDS)
    def test_a_malformed_identifier_is_rejected(self, client: TestClient, chunk_id: str) -> None:
        response = client.get(f"/chunks/{chunk_id}")
        assert response.status_code in {404, 422}
        assert response.status_code != 200

    def test_a_malformed_identifier_never_reaches_the_index(
        self, client: TestClient, service: _RecordingService
    ) -> None:
        """A mismatched id must never become a lookup or a filesystem path."""
        client.get("/chunks/pcap_index.json")
        assert service.id_lookups == []

    def test_an_overlong_identifier_is_rejected(self, client: TestClient) -> None:
        overlong = "2" * (CHUNK_ID_MAX_LENGTH + 10) + "0213_120000.pcap"
        assert client.get(f"/chunks/{overlong}").status_code in {404, 422}

    def test_the_length_ceiling_clears_the_longest_live_shape(self) -> None:
        assert max(len(value) for value in LIVE_CHUNK_IDS) < CHUNK_ID_MAX_LENGTH

    def test_a_known_identifier_still_resolves(self, client: TestClient, chunk: PcapChunkMeta) -> None:
        response = client.get(f"/chunks/{chunk.filename}", params={"format": "json"})
        assert response.status_code == 200
        assert response.json()["chunk_id"] == chunk.filename

    def test_an_unknown_but_well_formed_identifier_is_a_404(self, client: TestClient) -> None:
        """Rejection and absence stay distinct failure modes."""
        assert client.get("/chunks/20260101_000000.pcap").status_code == 404


class TestV3ImportFilePathHasBounds:
    """The model layer rejects a malformed path before the runner does."""

    def test_a_realistic_upload_path_is_accepted(self) -> None:
        job = ImportRequest(display_id="job-1", file_path="/import/0f9c2b1a4e.pcap")
        assert job.file_path == "/import/0f9c2b1a4e.pcap"

    def test_a_nested_path_is_accepted(self) -> None:
        job = ImportRequest(display_id="job-1", file_path="/import/sub/capture.pcap")
        assert job.file_path.endswith("capture.pcap")

    def test_a_relative_path_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="absolute"):
            ImportRequest(display_id="job-1", file_path="import/capture.pcap")

    def test_a_dotdot_segment_is_rejected(self) -> None:
        with pytest.raises(ValueError, match=r"\.\."):
            ImportRequest(display_id="job-1", file_path="/import/../etc/shadow")

    def test_a_single_dot_segment_is_rejected(self) -> None:
        with pytest.raises(ValueError, match=r"\.\."):
            ImportRequest(display_id="job-1", file_path="/import/./capture.pcap")

    def test_an_empty_segment_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="empty path segment"):
            ImportRequest(display_id="job-1", file_path="/import//capture.pcap")

    def test_a_trailing_separator_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="empty path segment"):
            ImportRequest(display_id="job-1", file_path="/import/")

    def test_a_nul_byte_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="NUL"):
            ImportRequest(display_id="job-1", file_path="/import/capture.pcap\x00.txt")

    def test_an_overlong_path_is_rejected(self) -> None:
        overlong = "/import/" + "a" * FILE_PATH_MAX_LENGTH + ".pcap"
        with pytest.raises(ValueError):
            ImportRequest(display_id="job-1", file_path=overlong)

    def test_a_path_at_the_ceiling_is_accepted(self) -> None:
        """The bound must not reject a plausible long path — only an absurd one."""
        name = "a" * (FILE_PATH_MAX_LENGTH - len("/import/") - len(".pcap"))
        job = ImportRequest(display_id="job-1", file_path=f"/import/{name}.pcap")
        assert len(job.file_path) == FILE_PATH_MAX_LENGTH

    def test_the_runner_containment_is_not_replaced(self) -> None:
        """V3 is defence in depth; CAP-02's real boundary must still exist."""
        from pcap_import.runner import ImportPathError, resolve_capture_path

        with pytest.raises(ImportPathError):
            resolve_capture_path("/etc/shadow", "/import")


class TestV3RejectionIsAValidationError:
    """A malformed path is answered as 422, not as a late runtime failure."""

    @pytest.fixture()
    def import_client(self, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
        from pcap_import.api import create_app as create_import_app
        from pcap_import.service import ImportService

        class _Runner:
            def __init__(self) -> None:
                self.calls: List[Any] = []

            def run(self, job: Any, progress: Any, cancel_event: Any) -> Dict[str, Any]:
                self.calls.append(job)
                return {}

        monkeypatch.setenv("ADMIN_API_KEY", API_KEY)
        runner = _Runner()
        service = ImportService(runner=runner)
        with TestClient(create_import_app(service), headers={"X-API-Key": API_KEY}) as test_client:
            test_client.runner = runner  # type: ignore[attr-defined]
            yield test_client

    def test_a_traversal_path_is_a_422(self, import_client: TestClient) -> None:
        response = import_client.post(
            "/import",
            json={"display_id": "job-1", "file_path": "/import/../etc/shadow"},
        )
        assert response.status_code == 422

    def test_a_traversal_path_never_reaches_the_runner(self, import_client: TestClient) -> None:
        import_client.post(
            "/import",
            json={"display_id": "job-1", "file_path": "/import/../etc/shadow"},
        )
        assert import_client.runner.calls == []  # type: ignore[attr-defined]

    def test_a_valid_job_is_still_accepted(self, import_client: TestClient) -> None:
        response = import_client.post(
            "/import",
            json={"display_id": "job-1", "file_path": "/import/capture.pcap"},
        )
        assert response.status_code == 202


class TestV4NonAsciiApiKeyIsRejectedNotCrashed:
    """QUA-C5 recorder-side copy: a crafted header must answer 401."""

    @pytest.mark.parametrize(
        "supplied",
        [b"\xe4", b"\xff", b"key-\xe4", b"\xe4" * 32, b"\xe4\xfc"],
    )
    def test_a_non_ascii_key_returns_401(self, client: TestClient, chunk: PcapChunkMeta, supplied: bytes) -> None:
        """This raised TypeError inside the dependency and became a 500.

        The header value is sent as raw bytes because that is how the crafted
        request arrives on the wire; Starlette decodes them as latin-1, which
        is what produced the non-ASCII ``str`` the comparison choked on.
        """
        response = client.get(
            "/chunks",
            params=_range(chunk),
            headers={"X-API-Key": supplied},
        )
        assert response.status_code == 401

    def test_a_non_ascii_key_is_not_a_500(self, client: TestClient, chunk: PcapChunkMeta) -> None:
        response = client.get("/chunks", params=_range(chunk), headers={"X-API-Key": b"\xe4"})
        assert response.status_code != 500

    def test_a_non_ascii_key_never_reaches_the_service(
        self, client: TestClient, chunk: PcapChunkMeta, service: _RecordingService
    ) -> None:
        client.get(f"/chunks/{chunk.filename}", headers={"X-API-Key": b"\xe4"})
        assert service.id_lookups == []

    def test_a_non_ascii_pair_compares_equal(self) -> None:
        """Encoding is applied to both operands, so equal keys still match.

        Asserted on the encoder rather than through the client: the test
        transport re-encodes byte header values, so a round trip would pin
        httpx's behaviour instead of the recorder's.
        """
        import hmac

        from pcap_recorder.api import _encode_api_key

        supplied = _encode_api_key("schlüssel-ä")
        configured = _encode_api_key("schlüssel-ä")

        assert hmac.compare_digest(supplied, configured)

    def test_a_non_ascii_pair_that_differs_does_not_match(self) -> None:
        import hmac

        from pcap_recorder.api import _encode_api_key

        assert not hmac.compare_digest(_encode_api_key("schlüssel-ä"), _encode_api_key("schlüssel-ö"))

    def test_the_encoder_never_raises_on_a_latin1_decoded_header(self) -> None:
        """Every byte Starlette can hand over must survive encoding."""
        from pcap_recorder.api import _encode_api_key

        for byte in range(256):
            assert _encode_api_key(bytes([byte]).decode("latin-1"))

    def test_the_valid_ascii_key_still_authenticates(self, client: TestClient, chunk: PcapChunkMeta) -> None:
        assert client.get("/chunks", params=_range(chunk)).status_code == 200

    def test_a_wrong_ascii_key_is_still_401(self, client: TestClient, chunk: PcapChunkMeta) -> None:
        response = client.get("/chunks", params=_range(chunk), headers={"X-API-Key": "not-the-key"})
        assert response.status_code == 401

    def test_the_comparison_stays_constant_time(self) -> None:
        """``compare_digest`` must not have been swapped for ``==``.

        PCAP-007 moved the comparison out of ``create_app`` into the shared
        ``OperatorAuthSettings.matches``, which both capture-side services
        now call — so the guard follows it there.
        """
        import inspect

        from capture_settings_base import OperatorAuthSettings

        source = inspect.getsource(OperatorAuthSettings.matches)
        assert "hmac.compare_digest" in source

    def test_the_recorder_authenticates_through_the_shared_model(self) -> None:
        """The dependency must delegate, not re-implement the comparison."""
        import inspect

        from pcap_recorder import api as api_mod

        source = inspect.getsource(api_mod.create_app)
        assert "OperatorAuthSettings.from_env()" in source
        assert "auth.matches(" in source
