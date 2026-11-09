"""Unit tests for :class:`AIConnectionService`.

The env service is a tiny in-memory fake; ``httpx.AsyncClient`` is mocked
at the boundary so no real network call is made. Covers key-presence
detection, transient state transitions, secret non-disclosure and the
SSRF guard in ``_validate_target``.
"""

from __future__ import annotations

import socket
import ssl
from typing import Any

import httpcore
import httpx
import pytest

from otalon_api.services.ai_connection_service import (
    AIConnectionService,
    PinnedTarget,
    _PinnedAddressTransport,
    _PinnedNetworkBackend,
)

pytestmark = pytest.mark.unit


class _CannedStream(httpcore.AsyncNetworkStream):
    """A fake network stream that serves one canned HTTP/1.1 response.

    Records the TLS ``server_hostname`` (SNI) it is asked to negotiate and
    the raw request bytes written to it, so a test can prove that the
    original hostname (not the pinned IP) drives SNI and the ``Host``
    header while the socket peer is the pinned address.
    """

    def __init__(self, response: bytes) -> None:
        self._response = response
        self._read = False
        self.server_hostname: str | None = None
        self.written = bytearray()

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        if self._read:
            return b""
        self._read = True
        return self._response

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        self.written.extend(buffer)

    async def aclose(self) -> None:
        return None

    async def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> "httpcore.AsyncNetworkStream":
        self.server_hostname = server_hostname
        return self

    def get_extra_info(self, info: str) -> Any:
        return None


class _RecordingBackend(httpcore.AsyncNetworkBackend):
    """A backend that records every dialed address and returns a canned stream."""

    def __init__(self, response: bytes) -> None:
        self._response = response
        self.dialed: list[tuple[str, int]] = []
        self.stream = _CannedStream(response)

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Any = None,
    ) -> httpcore.AsyncNetworkStream:
        self.dialed.append((host, port))
        return self.stream

    async def connect_unix_socket(
        self, path: str, timeout: float | None = None, socket_options: Any = None
    ) -> httpcore.AsyncNetworkStream:  # pragma: no cover - not used over https
        raise NotImplementedError

    async def sleep(self, seconds: float) -> None:  # pragma: no cover - no retries
        return None


class _Env:
    """Minimal env-service fake exposing ``load`` and ``to_dict``."""

    def __init__(self, values: dict[str, str]) -> None:
        self._values = values
        self.loads = 0

    def load(self) -> None:
        self.loads += 1

    def to_dict(self) -> dict[str, str]:
        return dict(self._values)


def _service(values: dict[str, str]) -> AIConnectionService:
    return AIConnectionService(_Env(values))  # type: ignore[arg-type]


class TestMetadata:
    def test_missing_key_is_not_configured(self) -> None:
        svc = _service({"LITELLM_BASE_URL": "https://x", "LITELLM_API_KEY": ""})
        meta = svc.metadata()
        assert meta["key_configured"] is False
        assert meta["state"] == "not-configured"

    def test_placeholder_key_is_not_configured(self) -> None:
        svc = _service({"LITELLM_BASE_URL": "https://x", "LITELLM_API_KEY": "sk-no-key"})
        assert svc.metadata()["key_configured"] is False

    def test_metadata_never_contains_key_value(self) -> None:
        svc = _service({"LITELLM_BASE_URL": "https://x", "LITELLM_API_KEY": "sk-real-secret"})
        meta = svc.metadata()
        assert "sk-real-secret" not in str(meta.values())
        assert "key" not in meta

    def test_metadata_reloads_env(self) -> None:
        env = _Env({"LITELLM_BASE_URL": "https://x", "LITELLM_API_KEY": "sk-real"})
        svc = AIConnectionService(env)  # type: ignore[arg-type]
        svc.metadata()
        assert env.loads == 1


class TestValidateTarget:
    """Spec api--ai-connection: blocked before private; https only for public.

    The classification matrix covers IPv4, IPv6, IPv4-mapped and mixed
    resolution. ``socket.getaddrinfo`` is patched so the target class is
    derived from exactly the addresses the test declares, without DNS.
    """

    @staticmethod
    def _patch_resolve(monkeypatch: pytest.MonkeyPatch, ips: list[str]) -> None:
        def _fake_getaddrinfo(host: str, port: int, **_kwargs: Any) -> list[Any]:
            return [(socket.AF_INET, None, None, None, (ip, port)) for ip in ips]

        monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)

    def test_rejects_http_public(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch_resolve(monkeypatch, ["93.184.216.34"])
        with pytest.raises(ValueError, match="must use https for public targets"):
            AIConnectionService._validate_target("http://llm.example.com/v1")

    def test_rejects_non_http_scheme(self) -> None:
        with pytest.raises(ValueError, match="must use http or https"):
            AIConnectionService._validate_target("ftp://llm.example.com/v1")

    def test_accepts_https_public(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch_resolve(monkeypatch, ["93.184.216.34"])
        target = AIConnectionService._validate_target("https://llm.example.com/v1")
        assert target == PinnedTarget(ip="93.184.216.34", target_class="public", scheme="https")

    def test_accepts_private_http_and_https(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch_resolve(monkeypatch, ["172.17.0.1"])
        http_target = AIConnectionService._validate_target("http://host.docker.internal:4000/v1")
        https_target = AIConnectionService._validate_target("https://host.docker.internal:4000/v1")
        assert http_target == PinnedTarget(ip="172.17.0.1", target_class="private", scheme="http")
        assert https_target == PinnedTarget(ip="172.17.0.1", target_class="private", scheme="https")

    def test_accepts_private_ipv6(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch_resolve(monkeypatch, ["fd00::10"])
        target = AIConnectionService._validate_target("https://llm.internal/v1")
        assert target.target_class == "private"
        assert target.scheme == "https"

    def test_link_local_blocked_even_over_https(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch_resolve(monkeypatch, ["169.254.169.254"])
        with pytest.raises(ValueError, match="AI endpoint target is blocked"):
            AIConnectionService._validate_target("https://169.254.169.254/v1")

    def test_loopback_blocked_over_http(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch_resolve(monkeypatch, ["127.0.0.1"])
        with pytest.raises(ValueError, match="AI endpoint target is blocked"):
            AIConnectionService._validate_target("http://127.0.0.1:4000/v1")

    def test_ipv6_loopback_blocked(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch_resolve(monkeypatch, ["::1"])
        with pytest.raises(ValueError, match="AI endpoint target is blocked"):
            AIConnectionService._validate_target("https://llm.example.com/v1")

    def test_blocked_checked_before_private(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A blocked class address reports 'blocked', never 'private'.

        169.254.169.254 is also is_private=True; the blocked check must win
        (design.md D1). This is the mutation-guard anchor: removing the
        blocked-before-private ordering makes this test fail.
        """
        self._patch_resolve(monkeypatch, ["169.254.169.254"])
        with pytest.raises(ValueError, match="AI endpoint target is blocked"):
            AIConnectionService._validate_target("https://llm.example.com/v1")

    def test_mixed_private_public_requires_https(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch_resolve(monkeypatch, ["10.0.0.5", "93.184.216.34"])
        with pytest.raises(ValueError, match="must use https for public targets"):
            AIConnectionService._validate_target("http://llm.example.com/v1")

    def test_mixed_private_public_pins_public_class(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch_resolve(monkeypatch, ["10.0.0.5", "93.184.216.34"])
        target = AIConnectionService._validate_target("https://llm.example.com/v1")
        assert target.target_class == "public"

    def test_mixed_with_blocked_is_blocked(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch_resolve(monkeypatch, ["10.0.0.5", "169.254.0.1"])
        with pytest.raises(ValueError, match="AI endpoint target is blocked"):
            AIConnectionService._validate_target("https://llm.example.com/v1")

    def test_ipv4_mapped_public_is_public(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch_resolve(monkeypatch, ["::ffff:93.184.216.34"])
        target = AIConnectionService._validate_target("https://llm.example.com/v1")
        assert target.target_class == "public"
        assert target.ip == "93.184.216.34"

    def test_ipv4_mapped_link_local_is_blocked(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch_resolve(monkeypatch, ["::ffff:169.254.169.254"])
        with pytest.raises(ValueError, match="AI endpoint target is blocked"):
            AIConnectionService._validate_target("https://llm.example.com/v1")

    def test_empty_resolution_is_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [])
        with pytest.raises(ValueError, match="cannot be resolved"):
            AIConnectionService._validate_target("https://llm.example.com/v1")


class TestConnectivityTest:
    @pytest.mark.asyncio
    async def test_missing_config_returns_not_configured(self) -> None:
        svc = _service({"LITELLM_BASE_URL": "", "LITELLM_API_KEY": ""})
        assert await svc.test() == {"success": False, "state": "not-configured"}

    @pytest.mark.asyncio
    async def test_success_sets_ready(self, monkeypatch: pytest.MonkeyPatch) -> None:
        svc = _service({"LITELLM_BASE_URL": "https://llm.example.com", "LITELLM_API_KEY": "sk-real"})
        monkeypatch.setattr(
            AIConnectionService,
            "_validate_target",
            staticmethod(lambda _e: PinnedTarget(ip="203.0.113.10", target_class="public", scheme="https")),
        )

        class _Resp:
            is_success = True

        class _Client:
            def __init__(self, *a: Any, **k: Any) -> None: ...
            async def __aenter__(self) -> "_Client":
                return self

            async def __aexit__(self, *a: Any) -> None: ...
            async def get(self, *a: Any, **k: Any) -> _Resp:
                return _Resp()

        monkeypatch.setattr(httpx, "AsyncClient", _Client)
        result = await svc.test()
        assert result == {"success": True, "state": "ready"}
        assert svc.metadata()["state"] == "ready"

    @pytest.mark.asyncio
    async def test_transport_error_sets_failed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        svc = _service({"LITELLM_BASE_URL": "https://llm.example.com", "LITELLM_API_KEY": "sk-real"})
        monkeypatch.setattr(
            AIConnectionService,
            "_validate_target",
            staticmethod(lambda _e: PinnedTarget(ip="203.0.113.10", target_class="public", scheme="https")),
        )

        class _Client:
            def __init__(self, *a: Any, **k: Any) -> None: ...
            async def __aenter__(self) -> "_Client":
                return self

            async def __aexit__(self, *a: Any) -> None: ...
            async def get(self, *a: Any, **k: Any) -> Any:
                raise httpx.ConnectError("boom")

        monkeypatch.setattr(httpx, "AsyncClient", _Client)
        assert await svc.test() == {"success": False, "state": "failed"}

    @pytest.mark.asyncio
    async def test_validation_address_is_pinned_for_fetch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A validated public address is passed into the request transport."""
        svc = _service({"LITELLM_BASE_URL": "https://llm.example.com", "LITELLM_API_KEY": "sk-real"})
        monkeypatch.setattr(
            AIConnectionService,
            "_validate_target",
            staticmethod(lambda _e: PinnedTarget(ip="203.0.113.10", target_class="public", scheme="https")),
        )
        transports: list[Any] = []

        class _Resp:
            is_success = True

        class _Client:
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                transports.append(kwargs["transport"])

            async def __aenter__(self) -> "_Client":
                return self

            async def __aexit__(self, *args: Any) -> None: ...

            async def get(self, *args: Any, **kwargs: Any) -> _Resp:
                return _Resp()

        monkeypatch.setattr(httpx, "AsyncClient", _Client)
        assert await svc.test() == {"success": True, "state": "ready"}
        assert isinstance(transports[0], _PinnedAddressTransport)


def _install_recorder(transport: _PinnedAddressTransport, response: bytes) -> _RecordingBackend:
    """Swap the AnyIO backend inside the production pinned backend for a recorder.

    This preserves the real ``_PinnedNetworkBackend`` so the recorder observes
    exactly the address the production pinning code decides to dial, without
    opening a real socket.
    """
    recorder = _RecordingBackend(response)
    pinned = transport._pool._network_backend
    assert isinstance(pinned, _PinnedNetworkBackend)
    pinned._backend = recorder
    return recorder


class TestPinnedTransport:
    """Backend-boundary tests proving the DNS-rebind/TOCTOU guard holds.

    These drive a real :class:`httpx.Request` through the production
    ``_PinnedAddressTransport``. The recorder is injected as the AnyIO
    backend *inside* the production ``_PinnedNetworkBackend`` so it observes
    the exact address the production pinning code dials, without opening a
    real socket. They prove that a request for the original hostname is
    dialed to the *validated* address even though normal DNS for that
    hostname would resolve to a private address, that the original hostname
    still drives TLS SNI + the ``Host`` header, and that redirects are not
    followed.
    """

    @staticmethod
    def _canned_ok() -> bytes:
        return b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"

    @pytest.mark.asyncio
    async def test_dials_validated_ip_not_rebound_private_address(self) -> None:
        """The socket peer is the pinned public IP, never a re-resolved private one."""
        validated_ip = "203.0.113.10"
        transport = _PinnedAddressTransport(validated_ip)
        recorder = _install_recorder(transport, self._canned_ok())
        async with httpx.AsyncClient(transport=transport) as client:
            response = await client.get("https://llm.example.com/models")
        assert response.status_code == 200
        # Exactly one dial, to the validated public IP — the hostname is what
        # httpcore hands the pinned backend, but the socket peer stays the
        # validated IP, so a rebind DNS answer of e.g. 10.0.0.5 for
        # llm.example.com can never take effect here.
        assert recorder.dialed == [(validated_ip, 443)]
        assert not any(host == "llm.example.com" for host, _ in recorder.dialed)

    @pytest.mark.asyncio
    async def test_preserves_hostname_for_sni_and_host_header(self) -> None:
        """The original hostname drives SNI and the Host header, not the pinned IP."""
        transport = _PinnedAddressTransport("203.0.113.10")
        recorder = _install_recorder(transport, self._canned_ok())
        async with httpx.AsyncClient(transport=transport) as client:
            await client.get("https://llm.example.com/models")
        assert recorder.stream.server_hostname == "llm.example.com"
        assert b"host: llm.example.com" in bytes(recorder.stream.written).lower()
        assert b"203.0.113.10" not in bytes(recorder.stream.written)

    @pytest.mark.asyncio
    async def test_pinned_transport_does_not_follow_redirect_to_internal(self) -> None:
        """A redirect to an internal host is returned, never transparently followed."""
        redirect = (
            b"HTTP/1.1 302 Found\r\n"
            b"Location: https://169.254.169.254/latest/meta-data\r\n"
            b"Content-Length: 0\r\n\r\n"
        )
        transport = _PinnedAddressTransport("203.0.113.10")
        recorder = _install_recorder(transport, redirect)
        async with httpx.AsyncClient(transport=transport, follow_redirects=False) as client:
            response = await client.get("https://llm.example.com/models")
        assert response.status_code == 302
        assert recorder.dialed == [("203.0.113.10", 443)]

    @pytest.mark.asyncio
    async def test_service_test_rejects_redirect_as_non_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The service treats a 3xx (redirect) reply as a non-success, not a hop."""
        svc = _service({"LITELLM_BASE_URL": "https://llm.example.com", "LITELLM_API_KEY": "sk-real"})
        monkeypatch.setattr(
            AIConnectionService,
            "_validate_target",
            staticmethod(lambda _e: PinnedTarget(ip="203.0.113.10", target_class="public", scheme="https")),
        )
        recorders: list[_RecordingBackend] = []
        redirect = b"HTTP/1.1 302 Found\r\nLocation: https://10.0.0.5/x\r\nContent-Length: 0\r\n\r\n"
        real_transport_cls = _PinnedAddressTransport

        def _pinned(address: str, verify: bool = True) -> _PinnedAddressTransport:
            transport = real_transport_cls(address, verify=verify)
            recorders.append(_install_recorder(transport, redirect))
            return transport

        monkeypatch.setattr("otalon_api.services.ai_connection_service._PinnedAddressTransport", _pinned)
        assert await svc.test() == {"success": False, "state": "failed"}
        assert recorders[0].dialed == [("203.0.113.10", 443)]

    def test_pinned_network_backend_stores_pinned_address(self) -> None:
        """The backend retains the validated address it will always dial."""
        backend = _PinnedNetworkBackend("203.0.113.10")
        assert backend._address == "203.0.113.10"
