"""Tests fuer die tshark-Argument-Allow-List und den Privilege-Drop (PCAP-008)."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Dict, List, Optional
from unittest.mock import patch

import pytest

from pcap_recorder.api import _build_privilege_dropper, _tshark_read
from pcap_recorder.tshark_args import (
    MAX_RAW_LENGTH,
    MAX_TOKENS,
    TsharkArgError,
    parse_tshark_args,
)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("", []),
        ("   ", []),
        ("-q", ["-q"]),
        ("-q -z io,phs", ["-q", "-z", "io,phs"]),
        ("-q -z conv,ip", ["-q", "-z", "conv,ip"]),
        ("-q -z endpoints,tcp", ["-q", "-z", "endpoints,tcp"]),
        ("-q -z io,stat,1", ["-q", "-z", "io,stat,1"]),
        ("-q -z io,stat,5,pn_rt", ["-q", "-z", "io,stat,5,pn_rt"]),
        ("-q -z plen,tree", ["-q", "-z", "plen,tree"]),
        ("-c 50", ["-c", "50"]),
        ("-V", ["-V"]),
        ("-n -x", ["-n", "-x"]),
        ("-t ad", ["-t", "ad"]),
        ("-Y pn_rt", ["-Y", "pn_rt"]),
        ("-Y eth.addr==aa:bb:cc:dd:ee:ff", ["-Y", "eth.addr==aa:bb:cc:dd:ee:ff"]),
        (
            '-Y "tcp.flags.syn==1 and tcp.flags.ack==0"',
            ["-Y", "tcp.flags.syn==1 and tcp.flags.ack==0"],
        ),
        (
            "-T fields -e ip.src -e ip.dst -e frame.protocols",
            ["-T", "fields", "-e", "ip.src", "-e", "ip.dst", "-e", "frame.protocols"],
        ),
        ("-T fields -e _ws.col.Info", ["-T", "fields", "-e", "_ws.col.Info"]),
    ],
)
def test_parse_tshark_args_accepts_allow_listed(raw: str, expected: List[str]) -> None:
    """Every argument string the MCP tools build survives validation."""

    assert parse_tshark_args(raw) == expected


@pytest.mark.unit
@pytest.mark.parametrize(
    "raw",
    [
        "-w /tmp/exfil.pcap",
        "-X lua_script:/tmp/evil.lua",
        '-o uat:user_dlts,"foo"',
        "-r /etc/shadow",
        "-G",
        "--help",
        "-z io,phs -w /tmp/out",
        "-z ../../etc/passwd",
        "-z io,stat,notanumber",
        "-z conv,bluetooth",
        "-T html",
        "-e ip.src;rm",
        "-c 50x",
        "-t ../",
        "-Y",
        "-e",
        "-z",
        "io,phs",
        'unquoted"',
    ],
)
def test_parse_tshark_args_rejects_everything_else(raw: str) -> None:
    """Anything outside the allow-list raises before a subprocess is built."""

    with pytest.raises(TsharkArgError):
        parse_tshark_args(raw)


@pytest.mark.unit
def test_parse_tshark_args_rejects_over_long_string() -> None:
    """A raw string beyond the length ceiling is rejected wholesale."""

    with pytest.raises(TsharkArgError):
        parse_tshark_args("-q " * MAX_RAW_LENGTH)


@pytest.mark.unit
def test_parse_tshark_args_rejects_too_many_tokens() -> None:
    """A token flood inside the length ceiling is still rejected."""

    raw = " ".join(["-n"] * (MAX_TOKENS + 1))
    assert len(raw) <= MAX_RAW_LENGTH
    with pytest.raises(TsharkArgError):
        parse_tshark_args(raw)


@pytest.mark.unit
def test_parse_tshark_args_rejects_option_shaped_value() -> None:
    """A value that is itself a flag never passes as a value."""

    with pytest.raises(TsharkArgError):
        parse_tshark_args("-Y -w")


class _FakeCompleted:
    """Minimal stand-in for ``subprocess.CompletedProcess``."""

    def __init__(self) -> None:
        self.returncode = 0
        self.stdout = "ok\n"
        self.stderr = ""


def _capture_preexec(recorder: Dict[str, Any]) -> Callable[..., _FakeCompleted]:
    """Return a ``subprocess.run`` replacement that records its arguments."""

    def _run(command: List[str], **kwargs: Any) -> _FakeCompleted:
        recorder["command"] = command
        recorder["preexec_fn"] = kwargs.get("preexec_fn")
        return _FakeCompleted()

    return _run


@pytest.mark.unit
def test_tshark_read_uses_no_preexec_when_not_root(tmp_path: Path) -> None:
    """PCAP-008 red case: as a non-root euid no privilege drop is attempted.

    Before the guard, ``os.initgroups`` and ``os.setgroups`` both raised
    ``PermissionError`` for an unprivileged process, which ``subprocess``
    reports as ``SubprocessError: Exception occurred in preexec_fn`` and
    FastAPI maps to 500 on every ``format=detail`` request.
    """

    pcap_path = tmp_path / "20260213_120000.pcap"
    pcap_path.write_bytes(b"demo")
    recorder: Dict[str, Any] = {}
    assert os.geteuid() != 0, "test must run unprivileged to be meaningful"

    with patch("subprocess.run", _capture_preexec(recorder)):
        output = _tshark_read(pcap_path)

    assert output == "ok\n"
    assert recorder["preexec_fn"] is None


@pytest.mark.unit
def test_build_privilege_dropper_returns_none_when_not_root() -> None:
    """The dropper is not even built for an already-unprivileged process."""

    assert os.geteuid() != 0
    assert _build_privilege_dropper() is None


@pytest.mark.unit
def test_build_privilege_dropper_drops_in_fixed_order() -> None:
    """As root the drop runs groups → setgid → setuid with ``pw_gid``."""

    fake_pw = SimpleNamespace(pw_uid=10006, pw_gid=10006)
    calls: List[str] = []

    with (
        patch("os.geteuid", return_value=0),
        patch("pcap_recorder.api.pwd.getpwnam", return_value=fake_pw),
    ):
        dropper = _build_privilege_dropper()
        assert dropper is not None
        with (
            patch("os.initgroups", side_effect=lambda *_: calls.append("initgroups")),
            patch("os.setgid", side_effect=lambda *_: calls.append("setgid")),
            patch("os.setuid", side_effect=lambda *_: calls.append("setuid")),
        ):
            dropper()

    assert calls == ["initgroups", "setgid", "setuid"]


@pytest.mark.unit
def test_build_privilege_dropper_raises_when_root_and_user_missing() -> None:
    """Running tshark as root because the account is absent is not an option."""

    with (
        patch("os.geteuid", return_value=0),
        patch("pcap_recorder.api.pwd.getpwnam", side_effect=KeyError("pcapuser")),
    ):
        with pytest.raises(RuntimeError, match="does not exist"):
            _build_privilege_dropper()


@pytest.mark.unit
def test_tshark_read_splices_extra_args_after_read_path(tmp_path: Path) -> None:
    """Validated argv lands after ``-r <path>``, never replacing it."""

    pcap_path = tmp_path / "20260213_120000.pcap"
    pcap_path.write_bytes(b"demo")
    recorder: Dict[str, Any] = {}

    with patch("subprocess.run", _capture_preexec(recorder)):
        _tshark_read(pcap_path, extra_args=["-q", "-z", "io,phs"])

    assert recorder["command"] == ["tshark", "-r", str(pcap_path), "-q", "-z", "io,phs"]


@pytest.mark.unit
def test_tshark_read_maps_preexec_failure_to_runtime_error(tmp_path: Path) -> None:
    """A start-up failure becomes a named ``RuntimeError``, not a raw traceback."""

    pcap_path = tmp_path / "20260213_120000.pcap"
    pcap_path.write_bytes(b"demo")

    def _boom(_command: List[str], **_kwargs: Optional[Any]) -> None:
        raise subprocess.SubprocessError("Exception occurred in preexec_fn.")

    with patch("subprocess.run", _boom):
        with pytest.raises(RuntimeError, match="tshark could not be started"):
            _tshark_read(pcap_path)
