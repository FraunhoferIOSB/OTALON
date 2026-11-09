"""Tests for the read-only capture status surface.

Covers the ``CaptureStatusProvider`` and the ``GET /status`` route added in
UI-075 Wave C. The status surface is read-only: these tests assert that
querying it never starts, stops or reconfigures capture, that unknown
fields stay ``null`` rather than being fabricated, that interface names are
validated before being used in a sysfs path, and that no paths, commands or
secrets leak into the response body.
"""

from __future__ import annotations

from typing import Iterable, List, Optional

import pytest
from fastapi.testclient import TestClient
from pcap_recorder import api as api_module
from pcap_recorder.api import CaptureStatusProvider, PcapService, create_app


class _FakeRecorder:
    """Read-only recorder stand-in exposing only status members.

    Tracks whether any mutating attribute was touched so tests can assert
    the status path never calls control methods.
    """

    def __init__(self, *, interface: str, running: bool) -> None:
        self._interface = interface
        self._running = running
        self.mutated = False

    @property
    def interface(self) -> str:
        return self._interface

    @property
    def is_running(self) -> bool:
        return self._running

    def start(self) -> None:  # pragma: no cover - must never be called
        self.mutated = True
        raise AssertionError("status path must not start the recorder")

    def stop(self, timeout_s: float = 5.0) -> None:  # pragma: no cover
        self.mutated = True
        raise AssertionError("status path must not stop the recorder")


class _DummyIndex:
    """Minimal index stub so ``create_app`` can build a ``PcapService``."""

    def find_by_timerange(self, _start: object, _end: object, include_non_archive: bool = True) -> List[object]:
        return []

    def list_all(self) -> List[object]:
        return []

    def mark_anomaly(self, chunk_ids: Iterable[str], labels: Optional[dict] = None) -> List[object]:
        return []


class _DummyRingbuffer:
    """Minimal ringbuffer stub for ``PcapService``."""

    def archive_chunks(self, chunk_ids: Iterable[str]) -> dict:
        return {}


def _client(recorder: _FakeRecorder) -> TestClient:
    service = PcapService(index=_DummyIndex(), ringbuffer=_DummyRingbuffer())
    provider = CaptureStatusProvider(recorder)
    return TestClient(create_app(service, status_provider=provider))


class TestCaptureStatusProvider:
    """Unit tests for the provider's truthful field derivation."""

    def test_recording_true_when_process_alive(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A live subprocess yields recording=True."""
        monkeypatch.setattr(api_module, "_read_link_up", lambda _iface: None)
        provider = CaptureStatusProvider(_FakeRecorder(interface="eth0", running=True))
        status = provider.get_status()
        assert status.recording is True
        assert status.interface == "eth0"

    def test_recording_false_when_process_dead(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A dead subprocess yields recording=False (not None)."""
        monkeypatch.setattr(api_module, "_read_link_up", lambda _iface: None)
        provider = CaptureStatusProvider(_FakeRecorder(interface="eth0", running=False))
        status = provider.get_status()
        assert status.recording is False

    def test_link_up_true(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """operstate 'up' maps to link_up=True."""
        monkeypatch.setattr(api_module, "_read_link_up", lambda iface: iface == "eth0")
        status = CaptureStatusProvider(_FakeRecorder(interface="eth0", running=True)).get_status()
        assert status.link_up is True

    def test_link_down(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """operstate 'down' maps to link_up=False."""
        monkeypatch.setattr(api_module, "_read_link_up", lambda _iface: False)
        status = CaptureStatusProvider(_FakeRecorder(interface="eth0", running=True)).get_status()
        assert status.link_up is False

    def test_link_unknown_stays_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An unknown carrier state stays None rather than a fabricated bool."""
        monkeypatch.setattr(api_module, "_read_link_up", lambda _iface: None)
        status = CaptureStatusProvider(_FakeRecorder(interface="eth0", running=True)).get_status()
        assert status.link_up is None

    def test_drops_and_overflows_are_null(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The provider never invents drop/overflow counters."""
        monkeypatch.setattr(api_module, "_read_link_up", lambda _iface: True)
        status = CaptureStatusProvider(_FakeRecorder(interface="eth0", running=True)).get_status()
        assert status.drops_24h_pct is None
        assert status.overflows is None

    def test_empty_interface_yields_null(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A blank interface name is reported as null, not an empty string."""
        monkeypatch.setattr(api_module, "_read_link_up", lambda _iface: None)
        status = CaptureStatusProvider(_FakeRecorder(interface="", running=False)).get_status()
        assert status.interface is None
        assert status.link_up is None


class TestReadLinkUpValidation:
    """Interface-name validation for the sysfs operstate read."""

    @pytest.mark.parametrize(
        "bad_iface",
        [
            "../../etc/passwd",
            "eth0/../../root",
            "eth 0",
            "a" * 33,
            "et;rm",
            "/eth0",
            "..",
            ".",
        ],
    )
    def test_unsafe_interface_names_return_none(self, bad_iface: str) -> None:
        """Traversal/injection interface names never touch the filesystem."""
        assert api_module._read_link_up(bad_iface) is None

    @pytest.mark.parametrize("dot_iface", ["..", "."])
    def test_dot_traversal_cannot_escape_net_root(
        self, dot_iface: str, tmp_path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A ``.``/``..`` interface must not read outside the net root.

        Regression for the P3 sysfs guard: the allow-list admitted the pure-dot
        components ``.`` and ``..``, and because ``pathlib`` does not normalise,
        ``<root>/../operstate`` slipped past the structural parent check while
        resolving one level *above* the net root. A sentinel ``operstate`` file
        is planted at that escaped location; the read must still return ``None``.
        """
        net_root = tmp_path / "class" / "net"
        net_root.mkdir(parents=True)
        # Sentinel one level above the net root: <root>/../operstate.
        (net_root.parent / "operstate").write_text("up\n", encoding="ascii")
        # Sentinel at the net root itself: <root>/./operstate.
        (net_root / "operstate").write_text("up\n", encoding="ascii")
        monkeypatch.setattr(api_module, "_OPERSTATE_ROOT", net_root)
        assert api_module._read_link_up(dot_iface) is None

    def test_none_interface_returns_none(self) -> None:
        """A missing interface name returns None."""
        assert api_module._read_link_up(None) is None

    def test_operstate_read_up(self, tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A valid interface with operstate 'up' is read as True from sysfs."""
        iface = "eth0"
        (tmp_path / iface).mkdir()
        (tmp_path / iface / "operstate").write_text("up\n", encoding="ascii")
        monkeypatch.setattr(api_module, "_OPERSTATE_ROOT", tmp_path)
        assert api_module._read_link_up(iface) is True

    def test_operstate_read_down(self, tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A valid interface with operstate 'down' is read as False from sysfs."""
        iface = "eth0"
        (tmp_path / iface).mkdir()
        (tmp_path / iface / "operstate").write_text("down\n", encoding="ascii")
        monkeypatch.setattr(api_module, "_OPERSTATE_ROOT", tmp_path)
        assert api_module._read_link_up(iface) is False

    def test_operstate_unknown_value(self, tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A non-definitive operstate (e.g. 'unknown') maps to None."""
        iface = "eth0"
        (tmp_path / iface).mkdir()
        (tmp_path / iface / "operstate").write_text("unknown\n", encoding="ascii")
        monkeypatch.setattr(api_module, "_OPERSTATE_ROOT", tmp_path)
        assert api_module._read_link_up(iface) is None

    def test_operstate_missing_file(self, tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A missing operstate file yields None, not an exception."""
        monkeypatch.setattr(api_module, "_OPERSTATE_ROOT", tmp_path)
        assert api_module._read_link_up("eth0") is None

    def test_operstate_read_through_sysfs_style_symlink(self, tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Real sysfs interfaces are symlinks into /sys/devices; follow them.

        Regression: the traversal guard must validate the constructed
        ``<root>/<iface>`` structure, not the resolved symlink target, so a
        genuine physical NIC (whose ``operstate`` resolves out of the net
        root) is still read.
        """
        net_root = tmp_path / "net"
        net_root.mkdir()
        device_dir = tmp_path / "devices" / "pci0000:00" / "net" / "eth0"
        device_dir.mkdir(parents=True)
        (device_dir / "operstate").write_text("up\n", encoding="ascii")
        (net_root / "eth0").symlink_to(device_dir)
        monkeypatch.setattr(api_module, "_OPERSTATE_ROOT", net_root)
        assert api_module._read_link_up("eth0") is True


class TestStatusRoute:
    """Integration tests for the ``GET /status`` route."""

    def test_status_returns_recording_and_interface(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Route returns interface + link + recording for a running recorder."""
        monkeypatch.setattr(api_module, "_read_link_up", lambda _iface: True)
        recorder = _FakeRecorder(interface="eth0", running=True)
        response = _client(recorder).get("/status")
        assert response.status_code == 200
        body = response.json()
        assert body["interface"] == "eth0"
        assert body["link_up"] is True
        assert body["recording"] is True
        assert body["drops_24h_pct"] is None
        assert body["overflows"] is None

    def test_status_reports_not_recording(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A stopped recorder is reported as recording=False over HTTP."""
        monkeypatch.setattr(api_module, "_read_link_up", lambda _iface: False)
        recorder = _FakeRecorder(interface="eth0", running=False)
        body = _client(recorder).get("/status").json()
        assert body["recording"] is False
        assert body["link_up"] is False

    def test_status_does_not_mutate_recorder(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Calling /status must not touch any mutating recorder method."""
        monkeypatch.setattr(api_module, "_read_link_up", lambda _iface: None)
        recorder = _FakeRecorder(interface="eth0", running=True)
        client = _client(recorder)
        for _ in range(3):
            assert client.get("/status").status_code == 200
        assert recorder.mutated is False

    def test_status_body_has_no_paths_commands_or_secrets(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The status body exposes no filesystem paths, CLI or secret material."""
        monkeypatch.setattr(api_module, "_read_link_up", lambda _iface: True)
        recorder = _FakeRecorder(interface="eth0", running=True)
        body = _client(recorder).get("/status").text.lower()
        for leaked in ("tcpdump", "/sys/", "/workspace", "password", "token", "secret", "-w", "bpf"):
            assert leaked not in body

    def test_status_503_when_provider_absent(self) -> None:
        """Without a status provider the route fails closed with 503."""
        service = PcapService(index=_DummyIndex(), ringbuffer=_DummyRingbuffer())
        response = TestClient(create_app(service)).get("/status")
        assert response.status_code == 503
