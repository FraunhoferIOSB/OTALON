"""Contract tests for managed shared classifier label sources."""

from __future__ import annotations

import json
from collections.abc import Generator
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from otalon_api.dependencies import get_label_source_service
from otalon_api.main import app
from otalon_api.services.label_source_service import (
    LABEL_SOURCE_MAX_BASENAME_CHARS,
    LABEL_SOURCE_MAX_BYTES,
    LabelSourceConflictError,
    LabelSourceService,
    LabelSourceTooLargeError,
    LabelSourceValidationError,
    validate_filename,
    validate_label_content,
)
from otalon_api.settings import Settings

# Deterministic operator/viewer keys so the label-endpoint route tests do NOT
# depend on the ambient ADMIN_API_KEY / OTALON_API_ALLOWED_KEYS env. The
# ``/api/v1/training`` prefix is auth-protected: missing/invalid key -> 401,
# any valid key passes the middleware. We patch ``otalon_api.middleware.auth.get_settings``
# (the registry source) exactly as the dashboard-layout role-gate tests do.
_OPERATOR_KEY = "label-op-secret-key"
_VIEWER_KEY = "label-view-secret-key"
_ALLOWED_KEYS = f"ops:operator:{_OPERATOR_KEY},watcher:viewer:{_VIEWER_KEY}"


@pytest.fixture
def _configured_auth() -> Generator[None, None, None]:
    """Force a configured key registry for the label-endpoint route tests."""
    with patch(
        "otalon_api.middleware.auth.get_settings",
        return_value=Settings(otalon_api_allowed_keys=_ALLOWED_KEYS),
    ):
        yield


@pytest.fixture
def _unconfigured_auth() -> Generator[None, None, None]:
    """Force an UNCONFIGURED key registry (no keys at all) for fail-closed tests."""
    with patch(
        "otalon_api.middleware.auth.get_settings",
        return_value=Settings(otalon_api_allowed_keys="", admin_api_key=""),
    ):
        yield


def valid_label() -> dict[str, object]:
    """Return one structurally valid ground-truth entry."""
    return {
        "module_name": "T0846/arp_scan",
        "technical_method": "arp_scan",
        "start_time": "2026-07-22T08:00:00Z",
        "end_time": "2026-07-22T08:10:00Z",
        "target_ip": ["192.0.2.10"],
        "target_mac": ["00:11:22:33:44:55"],
        "technique_id": ["T0846"],
        "protocol": "arp",
        "source_ip": "192.0.2.1",
        "source_mac": "00:aa:bb:cc:dd:ee",
    }


def test_service_accepts_root_object_and_list(tmp_path: Path) -> None:
    """Both worker-supported root shapes return label counts."""
    service = LabelSourceService(tmp_path)
    object_source = service.save_upload("object.json", json.dumps(valid_label()).encode())
    assert object_source.label_count == 1
    list_source = service.save_upload("list.json", json.dumps([valid_label(), valid_label()]).encode())
    assert list_source.label_count == 2
    assert list_source.worker_path == "/app/models/list.json"


@pytest.mark.parametrize(
    ("filename", "payload", "message"),
    [
        ("../escape.json", [valid_label()], "safe basename"),
        ("labels.txt", [valid_label()], "safe basename"),
        ("labels.json", [], "non-empty"),
        ("labels.json", [{"module_name": "x"}], "start_time"),
        ("labels.json", [{**valid_label(), "target_ip": "not-a-list"}], "list of strings"),
        (
            "labels.json",
            [{**valid_label(), "start_time": "not-a-time"}],
            "ISO-8601",
        ),
        (
            "labels.json",
            [{**valid_label(), "end_time": "2026-07-22T07:00:00Z"}],
            "must not be after",
        ),
    ],
)
def test_service_rejects_invalid_uploads(tmp_path: Path, filename: str, payload: object, message: str) -> None:
    """Unsafe, malformed, and downstream-unsafe content fails closed."""
    with pytest.raises(LabelSourceValidationError, match=message):
        LabelSourceService(tmp_path).save_upload(filename, json.dumps(payload).encode())


def test_service_rejects_duplicate_symlink_and_cleans_temp(tmp_path: Path) -> None:
    """Existing files and symlinks cannot be overwritten or selected."""
    service = LabelSourceService(tmp_path)
    content = json.dumps(valid_label()).encode()
    service.save_upload("labels.json", content)
    with pytest.raises(LabelSourceConflictError):
        service.save_upload("labels.json", content)
    symlink = tmp_path / "linked.json"
    symlink.symlink_to(tmp_path / "labels.json")
    listing = service.list_sources()
    assert [item.filename for item in listing.items] == ["labels.json"]
    assert listing.invalid_file_count == 1
    assert not list(tmp_path.glob(".label-source.*.tmp"))


def test_service_rejects_malformed_and_oversized_content_without_partial_files(tmp_path: Path) -> None:
    """Malformed or oversized uploads leave no destination or temporary file."""
    service = LabelSourceService(tmp_path)
    with pytest.raises(LabelSourceValidationError, match="UTF-8 JSON"):
        service.save_upload("malformed.json", b"{")
    # Oversized *decoded* content raises the dedicated too-large subclass so the
    # route can answer 413 (not 422) for a clearly-excessive file.
    with pytest.raises(LabelSourceTooLargeError, match="5 MiB"):
        service.save_upload("oversized.json", b"x" * (LABEL_SOURCE_MAX_BYTES + 1))
    assert not (tmp_path / "malformed.json").exists()
    assert not (tmp_path / "oversized.json").exists()
    assert not list(tmp_path.glob(".label-source.*.tmp"))


def test_label_source_routes_require_a_valid_key(tmp_path: Path, _configured_auth: None) -> None:
    """Missing and bad keys are rejected 401 on both label endpoints."""
    service = LabelSourceService(tmp_path)
    app.dependency_overrides[get_label_source_service] = lambda: service
    try:
        client = TestClient(app, raise_server_exceptions=False)
        payload = {"filename": "managed.json", "content": json.dumps([valid_label()])}
        no_key_post = client.post("/api/v1/training/label-sources/upload", json=payload)
        assert no_key_post.status_code == 401
        bad_key_post = client.post(
            "/api/v1/training/label-sources/upload",
            json=payload,
            headers={"X-API-Key": "wrong-key"},
        )
        assert bad_key_post.status_code == 401
        no_key_get = client.get("/api/v1/training/label-sources")
        assert no_key_get.status_code == 401
        bad_key_get = client.get(
            "/api/v1/training/label-sources",
            headers={"X-API-Key": "wrong-key"},
        )
        assert bad_key_get.status_code == 401
        # Neither key value leaks into any response body.
        assert _OPERATOR_KEY not in bad_key_post.text
        assert _VIEWER_KEY not in bad_key_post.text
    finally:
        app.dependency_overrides.pop(get_label_source_service, None)


def test_label_source_routes_validate_and_hide_host_path(tmp_path: Path, _configured_auth: None) -> None:
    """With a valid operator key the API returns canonical worker paths and codes."""
    service = LabelSourceService(tmp_path)
    app.dependency_overrides[get_label_source_service] = lambda: service
    try:
        client = TestClient(app, headers={"X-API-Key": _OPERATOR_KEY}, raise_server_exceptions=False)
        invalid = client.post(
            "/api/v1/training/label-sources/upload",
            json={"filename": "invalid.json", "content": "[]"},
        )
        assert invalid.status_code == 422
        valid = client.post(
            "/api/v1/training/label-sources/upload",
            json={"filename": "managed.json", "content": json.dumps([valid_label()])},
        )
        assert valid.status_code == 201
        assert valid.json()["worker_path"] == "/app/models/managed.json"
        listed = client.get("/api/v1/training/label-sources")
        assert listed.status_code == 200
        assert listed.json()["items"][0]["filename"] == "managed.json"
        assert str(tmp_path) not in listed.text
    finally:
        app.dependency_overrides.pop(get_label_source_service, None)


def test_upload_denies_a_valid_viewer_key_but_allows_operator(tmp_path: Path, _configured_auth: None) -> None:
    """The upload write is operator-only; a valid viewer key is 403 (A-F2)."""
    service = LabelSourceService(tmp_path)
    app.dependency_overrides[get_label_source_service] = lambda: service
    try:
        client = TestClient(app, raise_server_exceptions=False)
        payload = {"filename": "managed.json", "content": json.dumps([valid_label()])}
        # A valid VIEWER key passes the prefix middleware (key is valid) but the
        # operator-role dependency rejects the write with 403.
        viewer_post = client.post(
            "/api/v1/training/label-sources/upload",
            json=payload,
            headers={"X-API-Key": _VIEWER_KEY},
        )
        assert viewer_post.status_code == 403
        assert _VIEWER_KEY not in viewer_post.text
        assert _OPERATOR_KEY not in viewer_post.text
        assert not (tmp_path / "managed.json").exists()
        # The same valid viewer key MAY read the list (authenticated read).
        viewer_get = client.get(
            "/api/v1/training/label-sources",
            headers={"X-API-Key": _VIEWER_KEY},
        )
        assert viewer_get.status_code == 200
        # An operator key completes the write.
        operator_post = client.post(
            "/api/v1/training/label-sources/upload",
            json=payload,
            headers={"X-API-Key": _OPERATOR_KEY},
        )
        assert operator_post.status_code == 201
        assert operator_post.json()["worker_path"] == "/app/models/managed.json"
    finally:
        app.dependency_overrides.pop(get_label_source_service, None)


def test_upload_fails_closed_when_no_keys_configured(tmp_path: Path, _unconfigured_auth: None) -> None:
    """An unconfigured deployment must never accept the filesystem write (A-F3)."""
    service = LabelSourceService(tmp_path)
    app.dependency_overrides[get_label_source_service] = lambda: service
    try:
        client = TestClient(app, raise_server_exceptions=False)
        payload = {"filename": "managed.json", "content": json.dumps([valid_label()])}
        # With no keys configured the write surface is fail-closed: the operator
        # dependency raises 503 even though the prefix middleware would otherwise
        # accept an unconfigured deployment. No file is persisted, no key leaks.
        unconfigured_post = client.post("/api/v1/training/label-sources/upload", json=payload)
        assert unconfigured_post.status_code == 503
        assert _OPERATOR_KEY not in unconfigured_post.text
        assert _VIEWER_KEY not in unconfigured_post.text
        assert not (tmp_path / "managed.json").exists()
        assert not list(tmp_path.glob(".label-source.*.tmp"))
    finally:
        app.dependency_overrides.pop(get_label_source_service, None)


def _escape_heavy_source(target_decoded_bytes: int) -> tuple[str, int]:
    """Build a valid label file whose JSON-string escaping inflates the wire body.

    Returns the decoded file content (as a ``str``) and its encoded byte length.
    The ``technical_method`` field is padded with ``"`` characters: each is one
    decoded byte but escapes to ``\\"`` in the file JSON and again on the wire,
    so a valid <=5 MiB decoded file becomes multiples larger as a request body.
    """
    quote_count = max(target_decoded_bytes // 2, 1)
    entry = {**valid_label(), "technical_method": '"' * quote_count}
    decoded = json.dumps([entry])
    return decoded, len(decoded.encode("utf-8"))


def test_upload_accepts_valid_content_whose_escaped_transport_exceeds_old_ceiling(
    tmp_path: Path, _configured_auth: None
) -> None:
    """A valid <=5 MiB file must succeed even when its escaped body exceeds ~5 MiB."""
    service = LabelSourceService(tmp_path)
    app.dependency_overrides[get_label_source_service] = lambda: service
    try:
        decoded, decoded_bytes = _escape_heavy_source(target_decoded_bytes=4 * 1024 * 1024)
        assert decoded_bytes <= LABEL_SOURCE_MAX_BYTES
        body = json.dumps({"filename": "escaped.json", "content": decoded})
        # The encoded request body exceeds the OLD ~5 MiB ceiling (5 MiB + 8192)
        # that previously rejected this structurally valid upload.
        assert len(body.encode("utf-8")) > LABEL_SOURCE_MAX_BYTES + 8192
        client = TestClient(app, headers={"X-API-Key": _OPERATOR_KEY}, raise_server_exceptions=False)
        response = client.post(
            "/api/v1/training/label-sources/upload",
            content=body,
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 201, response.text
        assert response.json()["worker_path"] == "/app/models/escaped.json"
        assert response.json()["size_bytes"] == decoded_bytes
    finally:
        app.dependency_overrides.pop(get_label_source_service, None)


def test_upload_returns_413_for_excessive_transport_and_content(tmp_path: Path, _configured_auth: None) -> None:
    """Clearly excessive transport and clearly excessive decoded content both 413."""
    service = LabelSourceService(tmp_path)
    app.dependency_overrides[get_label_source_service] = lambda: service
    try:
        client = TestClient(app, headers={"X-API-Key": _OPERATOR_KEY}, raise_server_exceptions=False)
        # Clearly excessive raw transport (just past the 6x + envelope ceiling)
        # is rejected 413. The body is a syntactically-plausible JSON envelope so
        # the rejection is unambiguously the size guard, not a parse error.
        huge_content = "x" * (6 * LABEL_SOURCE_MAX_BYTES + 4096)
        oversized_body = json.dumps({"filename": "huge.json", "content": huge_content})
        assert len(oversized_body.encode("utf-8")) > 6 * LABEL_SOURCE_MAX_BYTES
        oversized_transport = client.post(
            "/api/v1/training/label-sources/upload",
            content=oversized_body,
            headers={"Content-Type": "application/json"},
        )
        assert oversized_transport.status_code == 413
        # Excessive *decoded* content (valid JSON string, > 5 MiB decoded) is
        # rejected 413 even though its transport size is under the ceiling.
        big_content = "x" * (LABEL_SOURCE_MAX_BYTES + 1024)
        body = json.dumps({"filename": "toobig.json", "content": big_content})
        assert len(body.encode("utf-8")) < 6 * LABEL_SOURCE_MAX_BYTES
        oversized_content = client.post(
            "/api/v1/training/label-sources/upload",
            content=body,
            headers={"Content-Type": "application/json"},
        )
        assert oversized_content.status_code == 413
    finally:
        app.dependency_overrides.pop(get_label_source_service, None)


@pytest.mark.parametrize(
    "timestamp",
    [
        "2026-07-22T08:00:00Z",
        "2026-07-22T08:00:00+00:00",
        "2026-07-22T08:00:00.123456Z",
        "2026-07-22 08:00:00",
        "2026-07-22",
        "20260722",
        "20260722T080000",
        "20260722T080000Z",
    ],
)
def test_service_accepts_downstream_safe_timestamp_forms(tmp_path: Path, timestamp: str) -> None:
    """Standard Z/offset/fractional/space/compact forms pandas also parses stay valid (A-F1)."""
    entry = {**valid_label(), "start_time": timestamp, "end_time": timestamp}
    source = LabelSourceService(tmp_path).save_upload("ts.json", json.dumps([entry]).encode())
    assert source.label_count == 1


@pytest.mark.parametrize(
    "timestamp",
    [
        "2026-W30-3T08:00:00",  # ISO week-date: fromisoformat accepts, pandas rejects.
        "2026-W30-3",
        "2026-100",  # ordinal date.
        "2026-100T08:00:00",
    ],
)
def test_service_rejects_non_calendar_timestamp_forms(tmp_path: Path, timestamp: str) -> None:
    """ISO week-date/ordinal forms pandas cannot parse are rejected before persistence (A-F1)."""
    entry = {**valid_label(), "start_time": timestamp, "end_time": timestamp}
    with pytest.raises(LabelSourceValidationError):
        LabelSourceService(tmp_path).save_upload("bad-ts.json", json.dumps([entry]).encode())


def test_filename_basename_length_boundary_matches_regex() -> None:
    """The max-basename contract accepts exactly 128 chars and rejects 129 (A-F4)."""
    max_base = "a" * LABEL_SOURCE_MAX_BASENAME_CHARS
    accepted = f"{max_base}.json"
    assert validate_filename(accepted) == accepted
    too_long = f"{'a' * (LABEL_SOURCE_MAX_BASENAME_CHARS + 1)}.json"
    with pytest.raises(LabelSourceValidationError, match="safe basename"):
        validate_filename(too_long)
    # The accepted maximum basename stays within the documented byte ceiling; the
    # ASCII-only class guarantees char count == byte count (no Unicode inflation).
    assert len(accepted.encode("utf-8")) == LABEL_SOURCE_MAX_BASENAME_CHARS + len(".json")


def test_list_sources_filters_and_counts_deterministically(tmp_path: Path) -> None:
    """Only valid regular JSON files appear, sorted by name; invalid ones counted (C-02)."""
    service = LabelSourceService(tmp_path)
    # Multiple valid files with distinct names and DIFFERENT internal time spans:
    # list order must be deterministic filename sort, not chronological.
    early = {**valid_label(), "start_time": "2026-01-01T00:00:00Z", "end_time": "2026-01-01T01:00:00Z"}
    late = {**valid_label(), "start_time": "2026-12-31T00:00:00Z", "end_time": "2026-12-31T01:00:00Z"}
    (tmp_path / "zeta.json").write_bytes(json.dumps([late]).encode())
    (tmp_path / "alpha.json").write_bytes(json.dumps([early]).encode())
    # Invalid JSON, wrong-shape JSON, and a symlink are each counted invalid.
    (tmp_path / "malformed.json").write_bytes(b"{")
    (tmp_path / "wrong-shape.json").write_bytes(json.dumps({"nope": 1}).encode())
    (tmp_path / "linked.json").symlink_to(tmp_path / "alpha.json")
    # A non-JSON file and a subdirectory are irrelevant and must be ignored, not
    # counted as invalid JSON.
    (tmp_path / "notes.txt").write_bytes(b"ignore me")
    (tmp_path / "subdir").mkdir()

    listing = service.list_sources()
    assert [item.filename for item in listing.items] == ["alpha.json", "zeta.json"]
    # malformed.json + wrong-shape.json + linked.json == 3 invalid; txt/subdir ignored.
    assert listing.invalid_file_count == 3
    assert listing.warning is not None and "3 JSON file(s)" in listing.warning
    assert all(item.worker_path.startswith("/app/models/") for item in listing.items)


def test_multi_entry_timestamp_ordering_is_per_entry_not_chronological(tmp_path: Path) -> None:
    """Per-entry start<=end is enforced; entries need not be chronologically ordered (C-02)."""
    service = LabelSourceService(tmp_path)
    # Two valid entries whose order is 'later window first' — this is accepted:
    # the contract is per-entry start<=end, NOT a chronological list reordering.
    later = {**valid_label(), "start_time": "2026-12-31T00:00:00Z", "end_time": "2026-12-31T01:00:00Z"}
    earlier = {**valid_label(), "start_time": "2026-01-01T00:00:00Z", "end_time": "2026-01-01T01:00:00Z"}
    source = service.save_upload("multi.json", json.dumps([later, earlier]).encode())
    assert source.label_count == 2
    # A single reversed entry (start_time after end_time) is rejected.
    reversed_entry = {**valid_label(), "start_time": "2026-07-22T09:00:00Z", "end_time": "2026-07-22T08:00:00Z"}
    with pytest.raises(LabelSourceValidationError, match="must not be after"):
        service.save_upload("reversed.json", json.dumps([reversed_entry]).encode())


def test_validate_label_content_counts_multiple_entries(tmp_path: Path) -> None:
    """A multi-entry list returns its entry count for label metadata (C-02)."""
    entries = [valid_label(), valid_label(), valid_label()]
    assert validate_label_content(json.dumps(entries).encode()) == 3


def test_route_upload_duplicate_returns_409(tmp_path: Path, _configured_auth: None) -> None:
    """A duplicate filename through the route maps to 409 (C-02)."""
    service = LabelSourceService(tmp_path)
    app.dependency_overrides[get_label_source_service] = lambda: service
    try:
        client = TestClient(app, headers={"X-API-Key": _OPERATOR_KEY}, raise_server_exceptions=False)
        payload = {"filename": "dupe.json", "content": json.dumps([valid_label()])}
        first = client.post("/api/v1/training/label-sources/upload", json=payload)
        assert first.status_code == 201
        second = client.post("/api/v1/training/label-sources/upload", json=payload)
        assert second.status_code == 409
    finally:
        app.dependency_overrides.pop(get_label_source_service, None)


def test_route_upload_invalid_utf8_and_small_invalid_json(tmp_path: Path, _configured_auth: None) -> None:
    """Invalid UTF-8 body and small malformed JSON map to 422 at the HTTP boundary (C-02/C-05)."""
    service = LabelSourceService(tmp_path)
    app.dependency_overrides[get_label_source_service] = lambda: service
    try:
        client = TestClient(app, headers={"X-API-Key": _OPERATOR_KEY}, raise_server_exceptions=False)
        # Invalid UTF-8 raw HTTP body: not decodable JSON → 422 (not 5xx).
        invalid_utf8 = client.post(
            "/api/v1/training/label-sources/upload",
            content=b"\xff\xfe\x00",
            headers={"Content-Type": "application/json"},
        )
        assert invalid_utf8.status_code == 422
        # Small malformed HTTP JSON body → 422.
        small_malformed = client.post(
            "/api/v1/training/label-sources/upload",
            content=b"{",
            headers={"Content-Type": "application/json"},
        )
        assert small_malformed.status_code == 422
    finally:
        app.dependency_overrides.pop(get_label_source_service, None)
