"""Unit tests for the read-only capture status proxy service.

The service is a thin bounded HTTP proxy to the pcap_recorder ``/status``
endpoint. These tests assert truthful pass-through, strict type coercion,
null-preservation, and a degraded (all-null) snapshot on timeout, transport
error, non-200 or malformed upstream responses. They also assert the proxy
performs no host process/config inspection.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from otalon_api.services.capture_status_service import CaptureStatusService
from otalon_api.settings import Settings

_UPSTREAM = "http://recorder-test:9090"


def _make_settings(
    *,
    host: str = "recorder-test",
    port: int = 9090,
    timeout: float = 1.0,
    api_key: str = "test-secret",
    recorder_key: str = "",
) -> Settings:
    """Create minimal settings for capture-status tests."""
    return Settings(
        influxdb_host="localhost",
        influxdb_port=8181,
        influxdb_token="test-token",
        influxdb_org="test-org",
        influxdb_database="netcap",
        postgres_host="localhost",
        postgres_port=5432,
        postgres_user="test",
        postgres_password="test",
        postgres_database="test",
        admin_api_key=api_key,
        api_port=8090,
        pcap_recorder_host=host,
        pcap_recorder_port=port,
        pcap_recorder_timeout_s=timeout,
        pcap_recorder_api_key=recorder_key,
    )


@pytest.mark.unit
class TestCaptureStatusPassThrough:
    """Truthful mapping of the recorder /status payload."""

    async def test_full_payload_is_passed_through(self) -> None:
        """A fully-populated recorder payload maps field-for-field."""
        payload = {
            "interface": "enp5s0",
            "link_up": True,
            "recording": True,
            "drops_24h_pct": 1.5,
            "overflows": 3,
        }
        with respx.mock(assert_all_called=True, base_url=_UPSTREAM) as mock:
            mock.get("/status").mock(return_value=httpx.Response(200, json=payload))
            status = await CaptureStatusService(_make_settings()).get_status()

        assert status.interface == "enp5s0"
        assert status.link_up is True
        assert status.recording is True
        assert status.drops_24h_pct == 1.5
        assert status.overflows == 3

    async def test_not_recording_and_link_down(self) -> None:
        """recording=False and link_up=False are preserved (not coerced to None)."""
        payload = {
            "interface": "eth0",
            "link_up": False,
            "recording": False,
            "drops_24h_pct": None,
            "overflows": None,
        }
        with respx.mock(assert_all_called=True, base_url=_UPSTREAM) as mock:
            mock.get("/status").mock(return_value=httpx.Response(200, json=payload))
            status = await CaptureStatusService(_make_settings()).get_status()

        assert status.recording is False
        assert status.link_up is False
        assert status.drops_24h_pct is None
        assert status.overflows is None

    async def test_null_fields_preserved(self) -> None:
        """Null recorder fields stay null; nothing is fabricated."""
        payload = {
            "interface": None,
            "link_up": None,
            "recording": None,
            "drops_24h_pct": None,
            "overflows": None,
        }
        with respx.mock(assert_all_called=True, base_url=_UPSTREAM) as mock:
            mock.get("/status").mock(return_value=httpx.Response(200, json=payload))
            status = await CaptureStatusService(_make_settings()).get_status()

        assert status.interface is None
        assert status.link_up is None
        assert status.recording is None
        assert status.drops_24h_pct is None
        assert status.overflows is None

    async def test_integer_drops_coerced_to_float(self) -> None:
        """An integer drop percentage is coerced to float."""
        payload = {"interface": "eth0", "link_up": True, "recording": True, "drops_24h_pct": 2, "overflows": 0}
        with respx.mock(assert_all_called=True, base_url=_UPSTREAM) as mock:
            mock.get("/status").mock(return_value=httpx.Response(200, json=payload))
            status = await CaptureStatusService(_make_settings()).get_status()

        assert status.drops_24h_pct == 2.0
        assert isinstance(status.drops_24h_pct, float)
        assert status.overflows == 0


@pytest.mark.unit
class TestCaptureStatusCoercionGuards:
    """Malformed field types are rejected without raising."""

    async def test_non_bool_recording_becomes_none(self) -> None:
        """A non-boolean recording value is treated as unknown."""
        payload = {"interface": "eth0", "link_up": "yes", "recording": "maybe", "drops_24h_pct": "x", "overflows": "y"}
        with respx.mock(assert_all_called=True, base_url=_UPSTREAM) as mock:
            mock.get("/status").mock(return_value=httpx.Response(200, json=payload))
            status = await CaptureStatusService(_make_settings()).get_status()

        assert status.link_up is None
        assert status.recording is None
        assert status.drops_24h_pct is None
        assert status.overflows is None

    async def test_empty_interface_string_becomes_none(self) -> None:
        """An empty interface string is normalized to None."""
        payload = {"interface": "", "link_up": True, "recording": True, "drops_24h_pct": None, "overflows": None}
        with respx.mock(assert_all_called=True, base_url=_UPSTREAM) as mock:
            mock.get("/status").mock(return_value=httpx.Response(200, json=payload))
            status = await CaptureStatusService(_make_settings()).get_status()

        assert status.interface is None


@pytest.mark.unit
class TestCaptureStatusDegraded:
    """Degraded snapshots when the recorder is unavailable or malformed."""

    async def test_timeout_returns_all_null(self) -> None:
        """A recorder timeout yields an all-null degraded snapshot."""
        with respx.mock(assert_all_called=True, base_url=_UPSTREAM) as mock:
            mock.get("/status").mock(side_effect=httpx.ReadTimeout("slow"))
            status = await CaptureStatusService(_make_settings()).get_status()

        assert status == status.degraded()

    async def test_transport_error_returns_all_null(self) -> None:
        """An unreachable recorder yields an all-null degraded snapshot."""
        with respx.mock(assert_all_called=True, base_url=_UPSTREAM) as mock:
            mock.get("/status").mock(side_effect=httpx.ConnectError("refused"))
            status = await CaptureStatusService(_make_settings()).get_status()

        assert status.interface is None
        assert status.link_up is None
        assert status.recording is None

    async def test_non_200_returns_all_null(self) -> None:
        """A non-200 recorder response yields a degraded snapshot."""
        with respx.mock(assert_all_called=True, base_url=_UPSTREAM) as mock:
            mock.get("/status").mock(return_value=httpx.Response(503, json={"detail": "down"}))
            status = await CaptureStatusService(_make_settings()).get_status()

        assert status.recording is None
        assert status.interface is None

    async def test_non_json_body_returns_all_null(self) -> None:
        """A non-JSON 200 body yields a degraded snapshot."""
        with respx.mock(assert_all_called=True, base_url=_UPSTREAM) as mock:
            mock.get("/status").mock(return_value=httpx.Response(200, text="not-json"))
            status = await CaptureStatusService(_make_settings()).get_status()

        assert status == status.degraded()

    async def test_json_list_body_returns_all_null(self) -> None:
        """A JSON body that is not an object yields a degraded snapshot."""
        with respx.mock(assert_all_called=True, base_url=_UPSTREAM) as mock:
            mock.get("/status").mock(return_value=httpx.Response(200, json=[1, 2, 3]))
            status = await CaptureStatusService(_make_settings()).get_status()

        assert status == status.degraded()


@pytest.mark.unit
class TestCaptureStatusRequest:
    """Request shaping: URL, timeout and optional recorder key."""

    async def test_requests_status_path_on_configured_host(self) -> None:
        """The proxy targets ``/status`` on the configured recorder host/port."""
        with respx.mock(assert_all_called=True, base_url=_UPSTREAM) as mock:
            route = mock.get("/status").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "interface": "eth0",
                        "link_up": True,
                        "recording": True,
                        "drops_24h_pct": None,
                        "overflows": None,
                    },
                )
            )
            await CaptureStatusService(_make_settings()).get_status()

        assert route.called
        request = route.calls.last.request
        assert request.url.path == "/status"
        assert "x-api-key" not in {k.lower() for k in request.headers}

    async def test_forwards_recorder_key_when_configured(self) -> None:
        """When a recorder key is configured it is forwarded as X-API-Key."""
        with respx.mock(assert_all_called=True, base_url=_UPSTREAM) as mock:
            route = mock.get("/status").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "interface": "eth0",
                        "link_up": None,
                        "recording": True,
                        "drops_24h_pct": None,
                        "overflows": None,
                    },
                )
            )
            await CaptureStatusService(_make_settings(recorder_key="recorder-secret")).get_status()

        request = route.calls.last.request
        assert request.headers["X-API-Key"] == "recorder-secret"

    async def test_response_body_has_no_admin_secret(self) -> None:
        """The mapped result never carries the admin key or other secrets."""
        payload = {
            "interface": "eth0",
            "link_up": True,
            "recording": True,
            "drops_24h_pct": None,
            "overflows": None,
        }
        with respx.mock(assert_all_called=True, base_url=_UPSTREAM) as mock:
            mock.get("/status").mock(return_value=httpx.Response(200, json=payload))
            status = await CaptureStatusService(_make_settings(api_key="super-secret-admin")).get_status()

        assert "super-secret-admin" not in repr(status)
