"""Bounded, server-side AI connection metadata and connectivity checks.

The service reads the LiteLLM boot env managed by otalon-ai through
the shared :class:`EnvComposeService`. It never returns or logs the API
key value: callers only ever see ``key_configured`` and a transient
connection ``state``. The transient state (``testing``/``ready``/
``failed``) is held in-process, so the service MUST be constructed as a
singleton (see :func:`otalon_api.dependencies.get_ai_connection_service`).

Endpoint target validation classifies every resolved address into
``blocked``/``private``/``public``/``mixed`` (design.md D1 of OpenSpec
change ``ai-045-litellm-connection``): blocked addresses are rejected
for every scheme, public targets require https, private targets may
use http.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import urlparse

import httpcore
import httpx
from otalon_common.runtime import OTALON_AI_SERVICE

from otalon_api.services.env_compose_service import EnvComposeService

# Friendly field name -> ``.env.compose`` key. Canonical mapping reused by
# the operations-config router so the wire contract and the env layout stay
# in one place.
AI_FIELD_TO_ENV: dict[str, str] = {
    "provider": "AGENT_LLM_PROVIDER",
    "endpoint": "LITELLM_BASE_URL",
    "chat_model": "CHAT_LLM_MODEL",
    "job_model": "JOBS_LLM_MODEL",
}

# AI-045: runtime_config key per non-secret AI field (service otalon-ai). The API key
# is deliberately absent: it is a secret and never leaves .env.compose.
AI_FIELD_TO_RUNTIME_KEY: dict[str, str] = {
    "provider": "ai.provider",
    "endpoint": "ai.endpoint",
    "chat_model": "ai.chat_model",
    "job_model": "ai.job_model",
    "context_window": "ai.context_window",
}

# Placeholder values that mean "no real key configured".
_PLACEHOLDER_KEYS: frozenset[str] = frozenset({"sk-no-key", "not-required", ""})


def is_placeholder_key(key: str) -> bool:
    """Return whether a key value means "no real key configured"."""
    return key.strip() in _PLACEHOLDER_KEYS


_TEST_TIMEOUT_SECONDS: float = 5.0

_TargetClass = Literal["blocked", "private", "public", "mixed"]

_BLOCKED_MESSAGE: str = "AI endpoint target is blocked"
_PUBLIC_HTTP_MESSAGE: str = "AI endpoint must use https for public targets"


def _classify_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> _TargetClass:
    """Classify one resolved address into ``blocked``/``private``/``public``.

    Blocked is checked FIRST: ``is_private`` also covers 127/8, 169.254/16
    and 0.0.0.0, so a private-only test would silently accept loopback
    and link-local targets (design.md D1).
    """
    if (
        ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return "blocked"
    return "private" if ip.is_private else "public"


@dataclass(frozen=True)
class PinnedTarget:
    """Result of the endpoint-target validation.

    Attributes:
        ip: The first resolved address the transport pins every connect to
            (IPv4-mapped IPv6 is normalised to its IPv4 form).
        target_class: Strictest class across all resolved addresses;
            ``blocked`` whenever any address is blocked.
        scheme: The scheme the request for this target may use.
    """

    ip: str
    target_class: _TargetClass
    scheme: str


class _PinnedNetworkBackend(httpcore.AsyncNetworkBackend):
    """Pin the TCP peer to a pre-validated IP without re-resolving DNS.

    The connection layer still passes the request's original hostname as
    ``host``; this backend ignores it for the socket connection and dials
    the validated address instead. The hostname is preserved for TLS SNI,
    the ``Host`` header, and certificate validation because those are
    driven by the request origin further up the stack (``start_tls`` uses
    ``server_hostname``), not by the ``connect_tcp`` host argument. This
    closes the DNS-rebinding/TOCTOU window between validation and connect.
    """

    def __init__(self, address: str) -> None:
        """Store the validated address and delegate to the AnyIO backend.

        Args:
            address: The pre-validated public IP to dial for every connect.
        """
        self._address = address
        self._backend: httpcore.AsyncNetworkBackend = httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        """Dial the pinned validated address rather than re-resolving ``host``."""
        return await self._backend.connect_tcp(
            self._address,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )


class _PinnedAddressTransport(httpx.AsyncHTTPTransport):
    """HTTPS transport pinned to a validated IP via a public backend seam.

    Encapsulates the DNS-rebinding guard behind a proper
    :class:`httpx.AsyncBaseTransport` rather than mutating the base
    transport's private connection pool. The pool is built here from the
    documented public :class:`httpcore.AsyncConnectionPool` interface with a
    real TLS context (so certificate verification is preserved) and the
    pinned network backend. Only ``http1`` is negotiated; the original
    hostname is retained for SNI/Host/certificate validation.
    """

    def __init__(self, address: str, verify: bool = True) -> None:
        """Build a pinned-address pool, preserving scheme-dependent TLS.

        Args:
            address: The pre-validated IP to pin every connect to.
            verify: Whether to verify TLS certificates (default ``True``).
                Only meaningful for https requests; the pool is shared by
                both schemes and plain-http connects simply never call
                ``start_tls``.
        """
        super().__init__(verify=verify, http1=True, http2=False, retries=0)
        ssl_context = httpx.create_ssl_context(verify=verify)
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=ssl_context,
            http1=True,
            http2=False,
            retries=0,
            network_backend=_PinnedNetworkBackend(address),
        )


def _as_context_window(raw: str) -> int:
    """Return the saved context window in tokens; the previous default on any unusable value.

    AI-046: the stored value is text in runtime_config. A corrupt row must not break the
    settings page, so it degrades to the old hard-coded 128000 instead of raising.
    """
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        return 128000
    return value if 4096 <= value <= 1000000 else 128000


class AIConnectionService:
    """Read configured AI credentials and perform safe connectivity checks."""

    def __init__(
        self, env_service: EnvComposeService, runtime_repo: object | None = None
    ) -> None:
        """Store the env service and initialise the transient state.

        Args:
            env_service: Shared env-compose service (singleton).
        """
        self._env = env_service
        # AI-045: runtime_config holds the non-secret connection values; the file keeps
        # only the API key. None = legacy file-only read (kept for existing callers).
        self._runtime_repo = runtime_repo
        self._state: str = "not-configured"

    def _key_configured(self, key: str) -> bool:
        """Return whether a real (non-placeholder) key is present."""
        return not is_placeholder_key(key)

    def metadata(self) -> dict[str, str | bool]:
        """Return non-secret connection metadata and the transient state.

        Re-reads ``.env.compose`` so a value changed out-of-band (or by a
        sibling write) is reflected without an API restart. The API key is
        never included.
        """
        self._env.load()
        values = self._env.to_dict()
        configured = self._key_configured(values.get("LITELLM_API_KEY", ""))
        non_secret = self._read_non_secret(values)
        endpoint = non_secret["endpoint"]
        if not configured or not endpoint:
            state = "not-configured"
        else:
            state = self._state if self._state != "not-configured" else "ready"
        return {
            "provider": non_secret["provider"],
            "endpoint": endpoint,
            "chat_model": non_secret["chat_model"],
            "job_model": non_secret["job_model"],
            "context_window": _as_context_window(non_secret["context_window"]),
            "state": state,
            "key_configured": configured,
        }

    def _read_non_secret(self, file_values: dict[str, str]) -> dict[str, str]:
        """Return provider/endpoint/models from runtime_config, falling back to the file.

        The runtime_config row is authoritative once a value was saved there. The file
        is the fallback for installs where nothing has been saved yet (migration path).
        """
        fallback = {
            "provider": file_values.get("AGENT_LLM_PROVIDER", "litellm"),
            "endpoint": file_values.get("LITELLM_BASE_URL", ""),
            "chat_model": file_values.get("CHAT_LLM_MODEL", ""),
            "job_model": file_values.get("JOBS_LLM_MODEL", ""),
            # AI-046: no .env.compose variable exists; the fallback is the previous hard-coded value.
            "context_window": "128000",
        }
        if self._runtime_repo is None:
            return fallback
        result = dict(fallback)
        for field, runtime_key in AI_FIELD_TO_RUNTIME_KEY.items():
            row = self._runtime_repo.get(OTALON_AI_SERVICE, runtime_key)  # type: ignore[attr-defined]
            if row is not None and row.get("value") is not None:
                result[field] = str(row["value"])
        return result

    async def test(self) -> dict[str, str | bool]:
        """Test the configured endpoint/key without returning or persisting a secret.

        Returns a ``{"success": bool, "state": ConnectionState}`` payload.
        A missing endpoint/key yields ``not-configured``; a transport or
        non-2xx result yields ``failed``; only a 2xx response yields
        ``ready``.
        """
        self._env.load()
        values = self._env.to_dict()
        # AI-045: the endpoint is read from runtime_config (what the operator saved), the
        # key from .env.compose (secret, never in the database).
        endpoint = self._read_non_secret(values)["endpoint"].rstrip("/")
        key = values.get("LITELLM_API_KEY", "")
        if not endpoint or not self._key_configured(key):
            self._state = "not-configured"
            return {"success": False, "state": self._state}
        pinned = self._validate_target(endpoint)
        self._state = "testing"
        transport = _PinnedAddressTransport(pinned.ip)
        try:
            async with httpx.AsyncClient(
                timeout=_TEST_TIMEOUT_SECONDS,
                transport=transport,
                follow_redirects=False,
            ) as client:
                response = await client.get(
                    f"{endpoint}/models",
                    headers={"Authorization": f"Bearer {key}"},
                )
        except httpx.HTTPError:
            self._state = "failed"
            return {"success": False, "state": self._state}
        self._state = "ready" if response.is_success else "failed"
        return {"success": response.is_success, "state": self._state}

    @staticmethod
    def _validate_target(endpoint: str) -> PinnedTarget:
        """Classify the endpoint target and pin its first resolved address.

        Per design.md D1 the resolved addresses are classified with the
        blocked check (loopback, link-local, multicast, reserved,
        unspecified) running BEFORE the private check, and the scheme is
        validated against the strictest resulting class:

        * any blocked address → rejected for every scheme,
        * at least one public address → only ``https`` is allowed,
        * private-only targets allow ``http`` and ``https``,
        * mixed private/non-blocked resolution counts as public (strictest
          rule wins, so a partial DNS rebind to a private address cannot
          downgrade the scheme requirement).

        Args:
            endpoint: The configured LiteLLM base URL.

        Returns:
            A :class:`PinnedTarget` naming the pinned address, the target
            class and the scheme the request must use.

        Raises:
            ValueError: If the endpoint has no usable hostname, cannot be
                resolved, targets a blocked address, or uses an unsafe
                scheme for its target class. The message never echoes the
                endpoint or any resolved address.
        """
        parsed = urlparse(endpoint)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("AI endpoint must use http or https")
        try:
            addresses = socket.getaddrinfo(
                parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM
            )
        except OSError as exc:
            raise ValueError("AI endpoint cannot be resolved") from exc
        classified: list[
            tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, _TargetClass]
        ] = []
        for address in addresses:
            ip = ipaddress.ip_address(str(address[4][0]))
            classified.append((ip, _classify_ip(ip)))
        if not classified:
            raise ValueError("AI endpoint cannot be resolved")
        if any(target_class == "blocked" for _, target_class in classified):
            raise ValueError(_BLOCKED_MESSAGE)
        contains_public = any(
            target_class == "public" for _, target_class in classified
        )
        target_class: _TargetClass = "public" if contains_public else "private"
        if target_class == "public" and parsed.scheme != "https":
            raise ValueError(_PUBLIC_HTTP_MESSAGE)
        pinned_ip = classified[0][0]
        if (
            isinstance(pinned_ip, ipaddress.IPv6Address)
            and pinned_ip.ipv4_mapped is not None
        ):
            pinned_ip = pinned_ip.ipv4_mapped
        else:
            pinned_ip = pinned_ip
        return PinnedTarget(
            ip=str(pinned_ip), target_class=target_class, scheme=parsed.scheme
        )
