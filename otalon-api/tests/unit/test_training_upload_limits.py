"""B1 source/config contracts only; no nginx process or live-service acceptance."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from otalon_api.settings import Settings

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[3]
CONFIGS = ("nginx.conf", "nginx.wsl.conf")
IMPORT_LOCATION = ("location", "=", "/api/v1/operations/pcap-import")
_TOKEN = re.compile(r"""\#[^\n]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[{};]|[^\s{};\#]+""")

_TLS_DIRECTIVES = [
    ("server_name", "_"),
    ("ssl_certificate", "/etc/nginx/tls/tls.crt"),
    ("ssl_certificate_key", "/etc/nginx/tls/tls.key"),
    ("add_header", "Strict-Transport-Security", '"max-age=31536000"', "always"),
]
_FORWARDING = [
    ("proxy_http_version", "1.1"),
    ("proxy_set_header", "Host", "$host"),
    ("proxy_set_header", "X-Real-IP", "$remote_addr"),
    ("proxy_set_header", "X-Forwarded-For", "$proxy_add_x_forwarded_for"),
    ("proxy_set_header", "X-Forwarded-Proto", "https"),
    ("proxy_set_header", "Upgrade", "$http_upgrade"),
    ("proxy_set_header", "Connection", "$connection_upgrade"),
]
_UI_NORMAL = [
    ("set", "$ui_upstream", "http://otalon-ui:8080"),
    ("proxy_pass", "$ui_upstream"),
    *_FORWARDING,
]
_API_NORMAL = [
    ("set", "$api_upstream", "http://otalon-api:8090"),
    ("proxy_pass", "$api_upstream"),
    *_FORWARDING,
    ("proxy_read_timeout", "120s"),
    ("proxy_buffering", "off"),
]
_MANUAL_SERVERS = [("8443", _UI_NORMAL), ("8493", _API_NORMAL)]

# Independent byte-for-byte baseline oracles, including distinct collector topology.
_NATIVE_COLLECTOR = """server {
        listen 9493 ssl;
        server_name _;
        ssl_certificate /etc/nginx/tls/tls.crt;
        ssl_certificate_key /etc/nginx/tls/tls.key;
        add_header Strict-Transport-Security "max-age=31536000" always;
        location / {
            proxy_pass http://pcap;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto https;
        }
    }"""
_WSL_COLLECTOR = """server {
        listen 9493 ssl;
        server_name _;
        ssl_certificate /etc/nginx/tls/tls.crt;
        ssl_certificate_key /etc/nginx/tls/tls.key;
        add_header Strict-Transport-Security "max-age=31536000" always;
        location / {
            set $capture_upstream http://otalon-capture:9090;
            proxy_pass $capture_upstream;
            client_max_body_size 32m;
            client_body_timeout 5s;
            proxy_read_timeout 40s;
            proxy_request_buffering off;
            access_log off;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto https;
        }
    }"""
_LIVENESS = """server {
        listen 127.0.0.1:8099;
        server_name _;
        access_log off;
        default_type text/plain;
        location = /healthz {
            return 200 "ok\\n";
        }
    }"""


@dataclass
class _Block:
    header: tuple[str, ...]
    raw: str
    directives: list[tuple[str, ...]] = field(default_factory=list)
    children: list[_Block] = field(default_factory=list)


def _parse_nginx(text: str) -> _Block:
    """Parse balanced scopes without counting braces in comments/quoted tokens."""
    tokens = [match for match in _TOKEN.finditer(text) if not match.group().startswith("#")]
    position = 0

    def scope(header: tuple[str, ...], start: int) -> _Block:
        nonlocal position
        block = _Block(header, "")
        pending: list[str] = []
        statement_start = start
        while position < len(tokens):
            match = tokens[position]
            token = match.group()
            position += 1
            if token == "{":
                assert pending, "Block has no header"
                block.children.append(scope(tuple(pending), statement_start))
                pending = []
            elif token == "}":
                assert header, "Unexpected closing brace"
                assert not pending, "Unterminated directive"
                block.raw = text[start : match.end()]
                return block
            elif token == ";":
                assert pending, "Empty directive"
                block.directives.append(tuple(pending))
                pending = []
            else:
                if not pending:
                    statement_start = match.start()
                pending.append(token)
        assert not header, "Unclosed block"
        assert not pending, "Unterminated directive"
        block.raw = text
        return block

    return scope((), 0)


def _one(block: _Block, header: tuple[str, ...]) -> _Block:
    matches = [child for child in block.children if child.header == header]
    assert len(matches) == 1, f"Expected exactly one {header}, found {len(matches)}"
    return matches[0]


def _http(config: str) -> _Block:
    return _one(_parse_nginx((ROOT / "tls-proxy" / config).read_text(encoding="utf-8")), ("http",))


def _server(http: _Block, port: str) -> _Block:
    matches = [child for child in http.children if ("listen", port, "ssl") in child.directives]
    assert len(matches) == 1, f"Expected exactly one TLS server on {port}"
    return matches[0]


def test_settings_default_is_1024_mib_file_payload() -> None:
    with patch.dict(os.environ, {}, clear=True):
        settings = Settings(_env_file=None)
    assert settings.pcap_import_max_upload_bytes == 1_073_741_824 == 1024 * 1024 * 1024
    assert Settings.model_fields["pcap_import_max_upload_bytes"].default == 1_073_741_824


def test_settings_description_distinguishes_streamed_file_payload() -> None:
    assert Settings.model_fields["pcap_import_max_upload_bytes"].description == (
        "Hard server-side file payload limit in bytes (default 1024 MiB, 1 GiB). "
        "Enforced against received file bytes while streaming, not the client-declared Content-Length."
    )


@pytest.mark.parametrize("limit", [1024, 8_388_608, 536_870_912])
def test_explicit_smaller_and_old_settings_limits_are_preserved(limit: int) -> None:
    with patch.dict(os.environ, {}, clear=True):
        settings = Settings(_env_file=None, pcap_import_max_upload_bytes=limit)
    assert settings.pcap_import_max_upload_bytes == limit


@pytest.mark.parametrize("limit", [0, -1])
def test_settings_payload_limit_stays_strictly_positive(limit: int) -> None:
    with patch.dict(os.environ, {}, clear=True), pytest.raises(ValidationError) as raised:
        Settings(_env_file=None, pcap_import_max_upload_bytes=limit)
    errors = raised.value.errors()
    assert len(errors) == 1
    assert errors[0]["loc"] == ("pcap_import_max_upload_bytes",)
    assert errors[0]["type"] == "greater_than"
    assert errors[0]["ctx"] == {"gt": 0}


def test_tracked_sample_exact_budget_and_public_aliases() -> None:
    sample = (ROOT / ".env.compose.sample").read_text(encoding="utf-8")
    assignments = re.findall(r"(?m)^PCAP_IMPORT_MAX_UPLOAD_BYTES=(.*)$", sample)
    assert assignments == ["1073741824"]
    assert int(assignments[0]) + 65_536 == 1_073_807_360
    assert "PCAP_IMPORT_WORKER_HOST=otalon-capture-pcap-import\n" in sample
    assert "PCAP_IMPORT_API_BASE_URL=http://otalon-api:8090\n" in sample
    assert "PCAP_IMPORT_DIR=/import\n" in sample
    assert "PASSIVE_SEEDER_INFLUX_TOKEN=${INFLUX_TOKEN}\n" in sample
    assert (
        "OTALON_API_ALLOWED_KEYS=ui:operator:${ADMIN_API_KEY},mcp:operator:${OTALON_API_KEY},"
        "scan-ui:viewer:${OTALON_API_SCAN_UI_KEY}\n"
    ) in sample
    assert (
        "OTALON_SCAN_ALLOWED_KEYS=ui-prod:viewer:${OTALON_SCAN_VIEWER_KEY},mcp-prod:operator:${OTALON_SCAN_API_KEY}\n"
    ) in sample
    assert "OTALON_MCP_ALLOWED_KEYS=otalon-ai:operator:${OTALON_MCP_API_KEY}\n" in sample
    assert (
        "OTALON_AI_ALLOWED_KEYS=ui:viewer:${OTALON_AI_UI_KEY},internal:operator:${OTALON_AI_INTERNAL_KEY}\n"
    ) in sample


@pytest.mark.parametrize("config", CONFIGS)
@pytest.mark.parametrize("port,normal", _MANUAL_SERVERS)
def test_manual_server_default_and_tls_are_exact(config: str, port: str, normal: list[tuple[str, ...]]) -> None:
    server = _server(_http(config), port)
    assert server.directives == [("listen", port, "ssl"), *_TLS_DIRECTIVES, ("client_max_body_size", "1024m")]
    assert [child.header for child in server.children] == [IMPORT_LOCATION, ("location", "/")]
    root = _one(server, ("location", "/"))
    assert root.directives == normal
    assert root.children == []


@pytest.mark.parametrize("config", CONFIGS)
@pytest.mark.parametrize("port,normal", _MANUAL_SERVERS)
def test_exact_import_location_streams_to_existing_upstream(
    config: str, port: str, normal: list[tuple[str, ...]]
) -> None:
    location = _one(_server(_http(config), port), IMPORT_LOCATION)
    assert location.directives == [
        ("client_max_body_size", "1073807360"),
        ("proxy_request_buffering", "off"),
        *normal,
    ]
    assert location.children == []
    assert int(location.directives[0][1]) == 1_073_741_824 + 65_536


@pytest.mark.parametrize("config", CONFIGS)
@pytest.mark.parametrize("port,normal", _MANUAL_SERVERS)
def test_query_matches_exact_route_but_other_routes_inherit_default(
    config: str, port: str, normal: list[tuple[str, ...]]
) -> None:
    server = _server(_http(config), port)
    assert [child.header for child in server.children] == [IMPORT_LOCATION, ("location", "/")]
    exact = _one(server, IMPORT_LOCATION)
    root = _one(server, ("location", "/"))
    # nginx selects exact locations by URI path, without the query string.
    for request in (
        "/api/v1/operations/pcap-import",
        "/api/v1/operations/pcap-import?force=true",
        "/api/v1/operations/pcap-import?limit=200&state=running",
    ):
        assert request.partition("?")[0] == exact.header[2]
        assert ("client_max_body_size", "1073807360") in exact.directives
    for request in (
        "/api/v1/operations/jobs",
        "/api/v1/operations/pcap-import/",
        "/api/v1/operations/pcap-import/J-1/cancel",
        "/api/v1/operations/pcap-import-other?force=true",
        "/",
    ):
        assert request.partition("?")[0] != exact.header[2]
        assert request.startswith(root.header[1])
        assert root.directives == normal
        assert ("client_max_body_size", "1024m") in server.directives


@pytest.mark.parametrize("config,baseline", [("nginx.conf", _NATIVE_COLLECTOR), ("nginx.wsl.conf", _WSL_COLLECTOR)])
def test_entire_collector_server_is_byte_for_byte_unchanged(config: str, baseline: str) -> None:
    assert _server(_http(config), "9493").raw == baseline


@pytest.mark.parametrize("config,upstreams", [("nginx.conf", [("upstream", "pcap")]), ("nginx.wsl.conf", [])])
def test_resolver_liveness_and_global_topology_are_unchanged(config: str, upstreams: list[tuple[str, ...]]) -> None:
    parsed = _parse_nginx((ROOT / "tls-proxy" / config).read_text(encoding="utf-8"))
    assert parsed.directives == []
    assert [child.header for child in parsed.children] == [("events",), ("http",)]
    events = _one(parsed, ("events",))
    assert events.directives == []
    assert events.children == []
    http = _one(parsed, ("http",))
    assert http.directives == [
        ("access_log", "/dev/stdout"),
        ("error_log", "/dev/stderr", "warn"),
        ("include", "/etc/nginx/mime.types"),
        ("resolver", "127.0.0.11", "valid=10s", "ipv6=off"),
    ]
    assert [child.header for child in http.children] == [
        ("map", "$http_upgrade", "$connection_upgrade"),
        *upstreams,
        ("server",),
        ("server",),
        ("server",),
        ("server",),
    ]
    upgrade = _one(http, ("map", "$http_upgrade", "$connection_upgrade"))
    assert upgrade.directives == [("default", "upgrade"), ("''", "close")]
    assert upgrade.children == []
    for header in upstreams:
        upstream = _one(http, header)
        assert upstream.directives == [("server", "host.docker.internal:9090")]
        assert upstream.children == []
    liveness = [child for child in http.children if ("listen", "127.0.0.1:8099") in child.directives]
    assert len(liveness) == 1
    assert liveness[0].raw == _LIVENESS
