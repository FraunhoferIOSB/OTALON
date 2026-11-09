"""Regression tests for the NET-005 recorder-side security fixes.

* CAP-01 — ``POST /anomalies/flag`` carried only the service dependency, so
  anyone able to reach the recorder could pin chunks against ringbuffer
  eviction and attach operator-visible labels.
* CAP-06 — the tshark privilege drop passed ``pw_uid`` to ``os.setgid`` and
  never replaced the parent's supplementary groups.

The existing API suite builds its client with a valid key already attached,
which is precisely why the missing dependency went unnoticed; these tests
drive the unauthenticated case explicitly.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Dict, Iterator, List, Optional

import pytest
from fastapi.testclient import TestClient

from pcap_recorder.api import PcapService, create_app
from pcap_recorder.index import PcapChunkMeta

API_KEY = "test-pcap-key"


class _Index:
    """Index double recording whether a flag actually reached the store."""

    def __init__(self, entries: List[PcapChunkMeta]) -> None:
        self._entries = entries
        self.marked: List[str] = []

    def find_by_timerange(
        self, start: datetime, end: datetime, include_non_archive: bool = True
    ) -> List[PcapChunkMeta]:
        return list(self._entries)

    def mark_anomaly(self, chunk_ids: Any, labels: Optional[Dict[str, str]] = None) -> List[PcapChunkMeta]:
        self.marked.extend(list(chunk_ids))
        return list(self._entries)

    def list_all(self) -> List[PcapChunkMeta]:
        return list(self._entries)


class _Ringbuffer:
    def archive_chunks(self, chunk_ids: Any) -> Dict[str, Any]:
        return {}


@pytest.fixture()
def chunk(tmp_path: Any) -> PcapChunkMeta:
    start = datetime(2026, 3, 6, 21, 8, 0)
    path = tmp_path / "pcap_20260306_210800.pcap"
    path.write_bytes(b"\xd4\xc3\xb2\xa1")
    return PcapChunkMeta(
        filename=path.name,
        path=path,
        start_ts=start,
        end_ts=start + timedelta(seconds=60),
        size_bytes=4,
    )


@pytest.fixture()
def index(chunk: PcapChunkMeta) -> _Index:
    return _Index([chunk])


@pytest.fixture()
def app_client(index: _Index, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    monkeypatch.setenv("ADMIN_API_KEY", API_KEY)
    service = PcapService(index=index, ringbuffer=_Ringbuffer())
    with TestClient(create_app(service)) as client:
        yield client


def _payload(chunk: PcapChunkMeta) -> Dict[str, str]:
    return {
        "start_ts": chunk.start_ts.isoformat(),
        "end_ts": chunk.end_ts.isoformat(),
    }


class TestFlagAnomalyRequiresOperatorKey:
    """CAP-01 — the flag route must reject unauthenticated callers."""

    def test_without_a_key_returns_401(self, app_client: TestClient, chunk: PcapChunkMeta) -> None:
        response = app_client.post("/anomalies/flag", json=_payload(chunk))
        assert response.status_code == 401

    def test_without_a_key_nothing_is_flagged(
        self, app_client: TestClient, chunk: PcapChunkMeta, index: _Index
    ) -> None:
        """The request must not reach the service at all."""
        app_client.post("/anomalies/flag", json=_payload(chunk))
        assert index.marked == []

    def test_with_a_wrong_key_returns_401(self, app_client: TestClient, chunk: PcapChunkMeta) -> None:
        response = app_client.post(
            "/anomalies/flag",
            json=_payload(chunk),
            headers={"X-API-Key": "not-the-key"},
        )
        assert response.status_code == 401

    def test_with_the_operator_key_succeeds(self, app_client: TestClient, chunk: PcapChunkMeta, index: _Index) -> None:
        response = app_client.post(
            "/anomalies/flag",
            json=_payload(chunk),
            headers={"X-API-Key": API_KEY},
        )
        assert response.status_code == 200
        assert index.marked, "an authenticated flag must reach the index"

    def test_validation_still_runs_for_authenticated_callers(
        self, app_client: TestClient, chunk: PcapChunkMeta
    ) -> None:
        """Auth must not mask the start/end ordering check."""
        response = app_client.post(
            "/anomalies/flag",
            json={
                "start_ts": chunk.end_ts.isoformat(),
                "end_ts": chunk.start_ts.isoformat(),
            },
            headers={"X-API-Key": API_KEY},
        )
        assert response.status_code == 400


class TestTsharkPrivilegeDrop:
    """CAP-06 — drop to the right group, and shed supplementary groups.

    Every case here stubs ``geteuid`` to 0: since PCAP-008 the drop only
    happens when the recorder actually is root, which is the only situation
    in which CAP-06's ordering requirements can matter. The unprivileged
    path is covered in ``test_tshark_args.py``.
    """

    def _capture_drop(self, monkeypatch: pytest.MonkeyPatch) -> Dict[str, Any]:
        """Run ``_tshark_read`` with syscalls stubbed, returning the calls made."""
        import pwd
        import subprocess

        from pcap_recorder import api as api_mod

        calls: Dict[str, Any] = {"order": []}

        class _Pw:
            pw_uid = 4242
            pw_gid = 7777

        monkeypatch.setattr(api_mod.os, "geteuid", lambda: 0)
        monkeypatch.setattr(pwd, "getpwnam", lambda _name: _Pw())
        monkeypatch.setattr(
            api_mod.os,
            "setgid",
            lambda gid: calls.__setitem__("setgid", gid) or calls["order"].append("setgid"),
        )
        monkeypatch.setattr(
            api_mod.os,
            "setuid",
            lambda uid: calls.__setitem__("setuid", uid) or calls["order"].append("setuid"),
        )
        monkeypatch.setattr(
            api_mod.os,
            "initgroups",
            lambda user, gid: calls.__setitem__("initgroups", (user, gid)) or calls["order"].append("initgroups"),
        )
        monkeypatch.setattr(
            api_mod.os,
            "setgroups",
            lambda groups: calls.__setitem__("setgroups", list(groups)) or calls["order"].append("setgroups"),
        )

        class _Result:
            returncode = 0
            stdout = "ok"
            stderr = ""

        def _run(command: Any, **kwargs: Any) -> Any:
            # Execute the preexec hook in-process so the calls are observable.
            kwargs["preexec_fn"]()
            return _Result()

        monkeypatch.setattr(subprocess, "run", _run)
        api_mod._tshark_read(api_mod.Path("/tmp/x.pcap"))
        return calls

    def test_setgid_uses_the_group_id(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """``pw_uid`` was passed to setgid, selecting an unrelated group."""
        calls = self._capture_drop(monkeypatch)
        assert calls["setgid"] == 7777

    def test_setuid_uses_the_user_id(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls = self._capture_drop(monkeypatch)
        assert calls["setuid"] == 4242

    def test_supplementary_groups_are_replaced(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Without this the child keeps root's groups regardless of setgid."""
        calls = self._capture_drop(monkeypatch)
        assert "initgroups" in calls or "setgroups" in calls

    def test_groups_are_set_before_setgid_and_setuid(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """After setuid the process may no longer change its groups."""
        order = self._capture_drop(monkeypatch)["order"]
        group_step = next(i for i, name in enumerate(order) if name in {"initgroups", "setgroups"})
        assert group_step < order.index("setgid") < order.index("setuid")

    def test_falls_back_to_setgroups_when_initgroups_is_denied(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A denied initgroups must still shed the inherited groups."""
        import pwd
        import subprocess

        from pcap_recorder import api as api_mod

        calls: Dict[str, Any] = {}

        class _Pw:
            pw_uid = 4242
            pw_gid = 7777

        def _denied(_user: str, _gid: int) -> None:
            raise PermissionError("not permitted")

        monkeypatch.setattr(api_mod.os, "geteuid", lambda: 0)
        monkeypatch.setattr(pwd, "getpwnam", lambda _name: _Pw())
        monkeypatch.setattr(api_mod.os, "initgroups", _denied)
        monkeypatch.setattr(api_mod.os, "setgroups", lambda g: calls.__setitem__("setgroups", list(g)))
        monkeypatch.setattr(api_mod.os, "setgid", lambda gid: calls.__setitem__("setgid", gid))
        monkeypatch.setattr(api_mod.os, "setuid", lambda uid: calls.__setitem__("setuid", uid))

        class _Result:
            returncode = 0
            stdout = "ok"
            stderr = ""

        monkeypatch.setattr(subprocess, "run", lambda command, **kwargs: (kwargs["preexec_fn"](), _Result())[1])
        api_mod._tshark_read(api_mod.Path("/tmp/x.pcap"))

        assert calls["setgroups"] == [7777]
        assert calls["setgid"] == 7777
