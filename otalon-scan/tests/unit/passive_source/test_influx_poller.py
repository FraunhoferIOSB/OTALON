"""Unit tests for ``otalon_scan.passive_source.influx_poller``.

Mocks at the boundary per AGENTS.md ("mock the HTTP/DB driver, not
your own functions"). The :class:`_FakeClient` below implements the
minimal ``_Queryable`` protocol the poller depends on; behaviour is
driven by a list of DataFrames (one per ``query()`` call) or a
``raise_exc`` to simulate transport-level failures.

Covers spec scenarios:

- ``Influx returns no points → no DB writes`` (poller side: empty
  result → ``macs={}`` , ``mac_to_ipv4={}``).
- ``Influx returns MACs → one upsert per filtered MAC`` (poller side:
  ``macs`` set populated).
- ``Influx returns HTTP 503 → cycle is skipped`` (poller side:
  :class:`InfluxUnreachableError` raised).
- ``Seeder never imports scapy or libpcap`` (asserted via import-set
  scan against the package's transitive imports).
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

from otalon_scan.passive_source.influx_poller import (
    InfluxPoller,
    InfluxUnreachableError,
    PollResult,
)

#: otalon-scan package root (``src/``); the import probe runs with this as
#: CWD so ``import otalon_scan.passive_source`` resolves in the child
#: interpreter.
_PROJECT_ROOT = Path(__file__).resolve().parents[3] / "src"


class _FakeClient:
    """Minimal Influx-client stub conforming to the ``_Queryable`` shape.

    Each ``query()`` call returns the next pre-loaded DataFrame; if
    ``raise_exc`` is set, every call raises it (simulating an Influx
    outage).
    """

    def __init__(
        self,
        results: list[pd.DataFrame] | None = None,
        raise_exc: Exception | None = None,
    ) -> None:
        self._results: list[pd.DataFrame] = list(results or [])
        self._raise_exc = raise_exc
        self.calls: list[str] = []

    def query(self, query: str, database: str, language: str = "sql") -> pd.DataFrame:
        self.calls.append(query)
        if self._raise_exc is not None:
            raise self._raise_exc
        if not self._results:
            return pd.DataFrame()
        return self._results.pop(0)


def _make_poller(client: _FakeClient) -> InfluxPoller:
    return InfluxPoller(client=client, database="netcap", lookback_window_s=300)


class TestPollOnce:
    """Cover the happy path, empty path, and outage path."""

    async def test_empty_influx_yields_empty_result(self) -> None:
        """SCENARIO (poller side): empty Influx → empty PollResult."""
        client = _FakeClient(results=[pd.DataFrame(), pd.DataFrame()])
        poller = _make_poller(client)

        result: PollResult = await poller.poll_once()

        assert result.macs == set()
        assert result.mac_to_ipv4 == {}
        assert result.uci_malformed == 0
        # Exactly 2 queries (mac_traffic + network_metrics).
        assert len(client.calls) == 2

    async def test_returns_distinct_macs(self) -> None:
        """SCENARIO (poller side): 5 MACs → set of 5 lowercased MACs."""
        mac_df = pd.DataFrame(
            {
                "mac_address": [
                    "aa:bb:cc:dd:ee:01",
                    "aa:bb:cc:dd:ee:02",
                    "AA:BB:CC:DD:EE:03",
                    "aa:bb:cc:dd:ee:04",
                    "aa:bb:cc:dd:ee:05",
                    # Duplicate to verify dedup.
                    "aa:bb:cc:dd:ee:01",
                ]
            }
        )
        uci_df = pd.DataFrame()
        client = _FakeClient(results=[mac_df, uci_df])
        poller = _make_poller(client)

        result = await poller.poll_once()

        assert result.macs == {
            "aa:bb:cc:dd:ee:01",
            "aa:bb:cc:dd:ee:02",
            "aa:bb:cc:dd:ee:03",
            "aa:bb:cc:dd:ee:04",
            "aa:bb:cc:dd:ee:05",
        }

    async def test_uci_splits_into_mac_and_ipv4(self) -> None:
        """A well-formed UCI yields one ``(mac, ipv4)`` pair."""
        uci = "aa:bb:cc:dd:ee:ff/11:22:33:44:55:66/0/6/10.0.0.1/10.0.0.2/1234/80/HTTP"
        client = _FakeClient(results=[pd.DataFrame(), pd.DataFrame({"uci": [uci]})])
        poller = _make_poller(client)

        result = await poller.poll_once()

        assert "aa:bb:cc:dd:ee:ff" in result.macs
        assert result.mac_to_ipv4 == {"aa:bb:cc:dd:ee:ff": "10.0.0.1"}
        assert result.uci_malformed == 0

    async def test_malformed_uci_counted_and_skipped(self) -> None:
        """A UCI with wrong slash-count SHALL be skipped + counted."""
        bad = "aa:bb:cc:dd:ee:ff/only/four/slashes"  # 4 components, not 9
        good = "aa:bb:cc:dd:ee:ff/11:22:33:44:55:66/0/6/10.0.0.1/10.0.0.2/1/2/X"
        client = _FakeClient(results=[pd.DataFrame(), pd.DataFrame({"uci": [bad, good]})])
        poller = _make_poller(client)

        result = await poller.poll_once()

        assert result.uci_malformed == 1
        assert "aa:bb:cc:dd:ee:ff" in result.macs
        assert result.mac_to_ipv4 == {"aa:bb:cc:dd:ee:ff": "10.0.0.1"}

    async def test_real_world_arp_uci_accepted(self) -> None:
        """Real netcap ARP UCI (no L3 fields) MUST be accepted.

        Bug-cluster 2026-05-21 regression fixture. Pure ARP frames
        carry only ``src_mac/dst_mac`` and an empty L3+L4 block. The
        passive seeder needs the MAC; the missing IPv4 is fine.
        """
        uci = "cc:82:7f:a1:8a:36/38:4b:24:fa:b6:34///////Ethernet:ARP"
        client = _FakeClient(results=[pd.DataFrame(), pd.DataFrame({"uci": [uci]})])
        poller = _make_poller(client)

        result = await poller.poll_once()

        assert result.uci_malformed == 0
        assert "cc:82:7f:a1:8a:36" in result.macs
        # No IPv4 was present in the tag — mac_to_ipv4 stays empty.
        assert result.mac_to_ipv4 == {}

    async def test_real_world_lldp_uci_accepted(self) -> None:
        """Real netcap LLDP UCI (no L3 fields) MUST be accepted."""
        uci = "30:b8:51:31:06:86/01:80:c2:00:00:0e///////Ethernet:LLDP"
        client = _FakeClient(results=[pd.DataFrame(), pd.DataFrame({"uci": [uci]})])
        poller = _make_poller(client)

        result = await poller.poll_once()

        assert result.uci_malformed == 0
        assert "30:b8:51:31:06:86" in result.macs
        assert result.mac_to_ipv4 == {}

    async def test_real_world_profinet_rt_uci_accepted(self) -> None:
        """Real netcap PROFINET_RT UCI (no L3 fields) MUST be accepted."""
        uci = "00:01:05:2b:ae:a2/30:b8:51:31:06:84///////Ethernet:PROFINET_RT:PROFINET_RT_IO"
        client = _FakeClient(results=[pd.DataFrame(), pd.DataFrame({"uci": [uci]})])
        poller = _make_poller(client)

        result = await poller.poll_once()

        assert result.uci_malformed == 0
        assert "00:01:05:2b:ae:a2" in result.macs
        assert result.mac_to_ipv4 == {}

    async def test_real_world_vlan_profinet_uci_accepted(self) -> None:
        """Real netcap VLAN+PROFINET_RT UCI (VLAN id, no L3) MUST be accepted."""
        uci = "00:01:05:2b:ae:a2/30:b8:51:31:06:84/0//////Ethernet:VLAN:PROFINET_RT:PROFINET_RT_IO"
        client = _FakeClient(results=[pd.DataFrame(), pd.DataFrame({"uci": [uci]})])
        poller = _make_poller(client)

        result = await poller.poll_once()

        assert result.uci_malformed == 0
        assert "00:01:05:2b:ae:a2" in result.macs
        assert result.mac_to_ipv4 == {}

    async def test_real_world_batch_zero_malformed(self) -> None:
        """All four real-world fixtures together produce ``uci_malformed=0``.

        Acceptance: live-cycle ``uci_malformed`` was ~18/24 before
        the fix; after the fix this batch (4 valid + 1 garbage)
        MUST count exactly the one synthetic garbage row.
        """
        fixtures = [
            "cc:82:7f:a1:8a:36/38:4b:24:fa:b6:34///////Ethernet:ARP",
            "30:b8:51:31:06:86/01:80:c2:00:00:0e///////Ethernet:LLDP",
            "00:01:05:2b:ae:a2/30:b8:51:31:06:84///////Ethernet:PROFINET_RT:PROFINET_RT_IO",
            "00:01:05:2b:ae:a2/30:b8:51:31:06:84/0//////Ethernet:VLAN:PROFINET_RT:PROFINET_RT_IO",
            # One synthetic negative case (5 fields) — parser must still reject.
            "aa:bb:cc:dd:ee:ff/11:22:33:44:55:66/0/1/x",
        ]
        client = _FakeClient(
            results=[pd.DataFrame(), pd.DataFrame({"uci": fixtures})],
        )
        poller = _make_poller(client)

        result = await poller.poll_once()

        assert result.uci_malformed == 1
        assert "cc:82:7f:a1:8a:36" in result.macs
        assert "30:b8:51:31:06:86" in result.macs
        assert "00:01:05:2b:ae:a2" in result.macs
        # No IPv4s present in any real fixture.
        assert result.mac_to_ipv4 == {}

    async def test_http_5xx_raises_typed_error(self) -> None:
        """SCENARIO: Influx returns HTTP 503 → cycle is skipped.

        At the poller layer, "skipped" means the typed
        :class:`InfluxUnreachableError` is raised and the caller
        applies the graceful-degradation behaviour.
        """
        client = _FakeClient(raise_exc=RuntimeError("HTTP 503: Service Unavailable"))
        poller = _make_poller(client)

        with pytest.raises(InfluxUnreachableError):
            await poller.poll_once()


class TestImportSet:
    """SCENARIO: Seeder never imports scapy or libpcap.

    Asserts that the ``otalon_scan.passive_source`` package's transitive imports
    contain no PCAP-parsing library.

    SCAN-029 hardened this from a namespace peek into a real transitive
    check: a fresh interpreter imports every seeder module and reports
    its resulting ``sys.modules`` set, so an indirect import three levels
    down is caught too. The old in-process variant could not see those
    because the pytest process itself had already imported the world.
    """

    def test_no_pcap_libs_in_import_graph(self) -> None:
        import json
        import subprocess
        import sys

        probe = (
            "import json, sys\n"
            "import otalon_scan.passive_source\n"
            "import otalon_scan.passive_source.entrypoint\n"
            "import otalon_scan.passive_source.influx_poller\n"
            "import otalon_scan.passive_source.mac_filters\n"
            "import otalon_scan.passive_source.settings\n"
            "print(json.dumps(sorted(sys.modules)))\n"
        )
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [sys.executable, "-c", probe],
            cwd=str(_PROJECT_ROOT),
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        assert completed.returncode == 0, f"seeder import probe failed:\n{completed.stderr}"

        imported = {name.split(".")[0] for name in json.loads(completed.stdout)}
        for forbidden in ("scapy", "pcapy", "pcap", "dpkt"):
            assert forbidden not in imported, f"otalon_scan.passive_source transitively imports forbidden {forbidden}"
