"""Unit tests for tools.pcap helper module.

All HTTP calls are mocked — no running pcap_recorder service is required.
"""

from unittest.mock import MagicMock, patch

import pytest

from otalon_mcp.tools import pcap as pcap_tools


@pytest.fixture(autouse=True)
def _init_pcap():
    """Initialize the pcap module with a fake base URL before every test."""
    pcap_tools.init(pcap_url="http://fake:9090", timeout=5)


def _mock_response(status_code: int = 200, json_data=None, text: str = ""):
    """Create a minimal mock requests.Response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data if json_data is not None else {}
    resp.text = text
    resp.raise_for_status = MagicMock()
    if status_code >= 400:
        resp.raise_for_status.side_effect = Exception(f"HTTP {status_code}")
    return resp


class TestHealth:
    """Tests for pcap.health()."""

    @patch("otalon_mcp.tools.pcap.requests.get")
    def test_health_ok(self, mock_get):
        mock_get.return_value = _mock_response(json_data={"status": "ok"})
        result = pcap_tools.health()
        assert result["ok"] is True
        assert result["status"] == "ok"
        mock_get.assert_called_once()

    @patch("otalon_mcp.tools.pcap.requests.get")
    def test_health_unreachable(self, mock_get):
        mock_get.side_effect = ConnectionError("Connection refused")
        result = pcap_tools.health()
        assert result["ok"] is False
        assert "error" in result


class TestListChunks:
    """Tests for pcap.list_chunks()."""

    @patch("otalon_mcp.tools.pcap.requests.get")
    def test_list_chunks_returns_metadata(self, mock_get):
        chunks = [
            {
                "chunk_id": "20260225_132357.pcap",
                "start_ts": "2026-02-25T13:23:57",
                "end_ts": "2026-02-25T13:24:57",
                "size_bytes": 405504,
                "is_anomaly": False,
            },
            {
                "chunk_id": "20260225_132427.pcap",
                "start_ts": "2026-02-25T13:24:27",
                "end_ts": "2026-02-25T13:25:27",
                "size_bytes": 102400,
                "is_anomaly": True,
            },
        ]
        mock_get.return_value = _mock_response(json_data=chunks)
        result = pcap_tools.list_chunks(start_ts="2026-02-25T13:00:00", end_ts="2026-02-25T14:00:00")
        assert result["ok"] is True
        assert result["count"] == 2
        assert len(result["chunks"]) == 2


class TestListAnomalyChunks:
    """Tests for pcap.list_anomaly_chunks()."""

    @patch("otalon_mcp.tools.pcap.requests.get")
    def test_list_anomaly_chunks_filters_client_side(self, mock_get):
        chunks = [
            {"chunk_id": "a.pcap", "is_anomaly": False},
            {"chunk_id": "b.pcap", "is_anomaly": True},
            {"chunk_id": "c.pcap", "is_anomaly": True},
        ]
        mock_get.return_value = _mock_response(json_data=chunks)
        result = pcap_tools.list_anomaly_chunks(start_ts="2026-02-25T13:00:00", end_ts="2026-02-25T14:00:00")
        assert result["ok"] is True
        assert result["count"] == 2
        ids = [c["chunk_id"] for c in result["chunks"]]
        assert "a.pcap" not in ids
        assert "b.pcap" in ids
        assert "c.pcap" in ids


class TestGetChunkMeta:
    """Tests for pcap.get_chunk_meta()."""

    @patch("otalon_mcp.tools.pcap.requests.get")
    def test_get_chunk_meta(self, mock_get):
        meta = {
            "chunk_id": "20260225_133027.pcap",
            "size_bytes": 2983959,
            "is_anomaly": True,
        }
        mock_get.return_value = _mock_response(json_data=meta)
        result = pcap_tools.get_chunk_meta(chunk_id="20260225_133027.pcap")
        assert result["ok"] is True
        assert result["chunk"]["chunk_id"] == "20260225_133027.pcap"


class TestReadChunkText:
    """Tests for pcap.read_chunk_text()."""

    @patch("otalon_mcp.tools.pcap.requests.get")
    def test_read_chunk_text_truncation(self, mock_get):
        long_text = "\n".join(f"line {i}" for i in range(200))
        mock_get.return_value = _mock_response(text=long_text)
        result = pcap_tools.read_chunk_text(chunk_id="20260225_133027.pcap", max_lines=10)
        assert result["ok"] is True
        assert result["truncated"] is True
        assert result["lines"] == 200
        assert result["text"].count("\n") == 9

    @patch("otalon_mcp.tools.pcap.requests.get")
    def test_read_chunk_text_no_truncation(self, mock_get):
        short_text = "line 1\nline 2\nline 3"
        mock_get.return_value = _mock_response(text=short_text)
        result = pcap_tools.read_chunk_text(chunk_id="20260225_133027.pcap", max_lines=50)
        assert result["ok"] is True
        assert result["truncated"] is False
        assert result["lines"] == 3


class TestAnalyzeChunk:
    """Tests for pcap.analyze_chunk()."""

    @patch("otalon_mcp.tools.pcap.requests.get")
    def test_analyze_chunk_with_tshark_args(self, mock_get):
        mock_get.return_value = _mock_response(text="Frame 1: 64 bytes\nFrame 2: 64 bytes")
        result = pcap_tools.analyze_chunk(chunk_id="20260225_133027.pcap", tshark_args="-Y pn_rt", max_lines=200)
        assert result["ok"] is True
        assert "Frame 1" in result["output"]
        call_args = mock_get.call_args
        params = call_args.kwargs.get("params") or call_args[1].get("params", {})
        assert params.get("tshark_args") == "-Y pn_rt"

    @patch("otalon_mcp.tools.pcap.requests.get")
    def test_analyze_chunk_default_args(self, mock_get):
        mock_get.return_value = _mock_response(text="verbose output")
        result = pcap_tools.analyze_chunk(chunk_id="20260225_133027.pcap")
        assert result["ok"] is True
        call_args = mock_get.call_args
        params = call_args.kwargs.get("params") or call_args[1].get("params", {})
        assert "tshark_args" not in params


class TestInspectTimewindow:
    """Tests for pcap.inspect_timewindow()."""

    @patch("otalon_mcp.tools.pcap.requests.get")
    def test_inspect_timewindow_builds_tshark_args(self, mock_get):
        mock_get.return_value = _mock_response(text="561\t...\n562\t...")
        result = pcap_tools.inspect_timewindow(
            chunk_id="20260225_133027.pcap", start_sec=29.0, end_sec=30.0, max_lines=100
        )
        assert result["ok"] is True
        call_args = mock_get.call_args
        params = call_args.kwargs.get("params") or call_args[1].get("params", {})
        tshark_args = params.get("tshark_args", "")
        assert "frame.time_relative>=29.0" in tshark_args
        assert "frame.time_relative<=30.0" in tshark_args
        assert "frame.number" in tshark_args
        assert "eth.src" in tshark_args
        assert "_ws.col.Info" in tshark_args


class TestProtocolStats:
    """Tests for pcap.protocol_stats()."""

    @patch("otalon_mcp.tools.pcap.requests.get")
    def test_protocol_stats(self, mock_get):
        stats_text = "eth  frames:37194 bytes:2385400\n  vlan  frames:37059"
        mock_get.return_value = _mock_response(text=stats_text)
        result = pcap_tools.protocol_stats(chunk_id="20260225_133027.pcap")
        assert result["ok"] is True
        assert "eth" in result["output"]
        assert "truncated" not in result
        call_args = mock_get.call_args
        params = call_args.kwargs.get("params") or call_args[1].get("params", {})
        assert params.get("tshark_args") == "-q -z io,phs"

    @patch("otalon_mcp.tools.pcap.requests.get")
    def test_protocol_stats_truncates_large_output(self, mock_get):
        big_text = "x" * (pcap_tools.MAX_OUTPUT_CHARS + 1000)
        mock_get.return_value = _mock_response(text=big_text)
        result = pcap_tools.protocol_stats(chunk_id="20260225_133027.pcap")
        assert result["ok"] is True
        assert result.get("truncated") is True
        assert result["original_length"] == len(big_text)
        assert "TRUNCATED" in result["output"]


class TestConversations:
    """Tests for pcap.conversations()."""

    @patch("otalon_mcp.tools.pcap.requests.get")
    def test_conversations_layer_param(self, mock_get):
        for layer in ("eth", "ip", "tcp"):
            mock_get.return_value = _mock_response(text=f"{layer} conversations")
            result = pcap_tools.conversations(chunk_id="20260225_133027.pcap", layer=layer)
            assert result["ok"] is True
            assert "truncated" not in result
            call_args = mock_get.call_args
            params = call_args.kwargs.get("params") or call_args[1].get("params", {})
            assert params.get("tshark_args") == f"-q -z conv,{layer}"

    @patch("otalon_mcp.tools.pcap.requests.get")
    def test_conversations_truncates_large_output(self, mock_get):
        big_text = ("eth conv\n" * 5) + ("y" * (pcap_tools.MAX_OUTPUT_CHARS + 1000))
        mock_get.return_value = _mock_response(text=big_text)
        result = pcap_tools.conversations(chunk_id="20260225_133027.pcap", layer="eth")
        assert result["ok"] is True
        assert result.get("truncated") is True
        assert "TRUNCATED" in result["output"]


class TestIoStats:
    """Tests for pcap.io_stats()."""

    @patch("otalon_mcp.tools.pcap.requests.get")
    def test_io_stats_default(self, mock_get):
        mock_get.return_value = _mock_response(text="IO Statistics\n...")
        result = pcap_tools.io_stats(chunk_id="20260225_133027.pcap")
        assert result["ok"] is True
        assert "truncated" not in result
        call_args = mock_get.call_args
        params = call_args.kwargs.get("params") or call_args[1].get("params", {})
        assert params.get("tshark_args") == "-q -z io,stat,1"

    @patch("otalon_mcp.tools.pcap.requests.get")
    def test_io_stats_with_filter(self, mock_get):
        mock_get.return_value = _mock_response(text="IO Statistics\n...")
        result = pcap_tools.io_stats(chunk_id="20260225_133027.pcap", interval_sec=5, filter="pn_rt")
        assert result["ok"] is True
        call_args = mock_get.call_args
        params = call_args.kwargs.get("params") or call_args[1].get("params", {})
        assert params.get("tshark_args") == "-q -z io,stat,5,pn_rt"

    @patch("otalon_mcp.tools.pcap.requests.get")
    def test_io_stats_clamps_interval_to_one(self, mock_get):
        mock_get.return_value = _mock_response(text="IO Statistics\n...")
        pcap_tools.io_stats(chunk_id="20260225_133027.pcap", interval_sec=0)
        call_args = mock_get.call_args
        params = call_args.kwargs.get("params") or call_args[1].get("params", {})
        assert params.get("tshark_args") == "-q -z io,stat,1"

    @patch("otalon_mcp.tools.pcap.requests.get")
    def test_io_stats_truncates_large_output(self, mock_get):
        big_text = "z" * (pcap_tools.MAX_OUTPUT_CHARS + 500)
        mock_get.return_value = _mock_response(text=big_text)
        result = pcap_tools.io_stats(chunk_id="20260225_133027.pcap")
        assert result["ok"] is True
        assert result.get("truncated") is True
        assert "TRUNCATED" in result["output"]


class TestFlagAnomaly:
    """Tests for pcap.flag_anomaly()."""

    @patch("otalon_mcp.tools.pcap.requests.post")
    def test_flag_anomaly(self, mock_post):
        mock_post.return_value = _mock_response(json_data={"chunk_ids": ["a.pcap", "b.pcap"]})
        result = pcap_tools.flag_anomaly(
            start_ts="2026-02-25T13:30:27",
            end_ts="2026-02-25T13:31:27",
            labels={"reason": "test"},
        )
        assert result["ok"] is True
        assert result["count"] == 2
        assert "a.pcap" in result["chunk_ids"]
        call_args = mock_post.call_args
        body = call_args.kwargs.get("json") or call_args[1].get("json", {})
        assert body["start_ts"] == "2026-02-25T13:30:27"
        assert body["labels"] == {"reason": "test"}


class TestTruncate:
    """Tests for the _truncate helper."""

    def test_truncate_below_limit(self):
        text = "a\nb\nc"
        result_text, total, truncated = pcap_tools._truncate(text, 10)
        assert result_text == text
        assert total == 3
        assert truncated is False

    def test_truncate_above_limit(self):
        text = "\n".join(f"line {i}" for i in range(100))
        result_text, total, truncated = pcap_tools._truncate(text, 5)
        assert total == 100
        assert truncated is True
        assert result_text.count("\n") == 4

    def test_truncate_exact_limit(self):
        text = "a\nb\nc"
        result_text, total, truncated = pcap_tools._truncate(text, 3)
        assert truncated is False
        assert total == 3


class TestResolveTimeWindow:
    """Tests for _resolve_time_window helper."""

    def test_explicit_timestamps_passthrough(self):
        start, end = pcap_tools._resolve_time_window(start_ts="2026-01-01T00:00:00", end_ts="2026-01-01T01:00:00")
        assert start == "2026-01-01T00:00:00"
        assert end == "2026-01-01T01:00:00"

    def test_last_minutes_overrides_explicit(self):
        start, end = pcap_tools._resolve_time_window(
            start_ts="2020-01-01T00:00:00",
            end_ts="2020-01-01T01:00:00",
            last_minutes=30,
        )
        assert start != "2020-01-01T00:00:00"
        from datetime import datetime

        parsed_end = datetime.fromisoformat(end)
        parsed_start = datetime.fromisoformat(start)
        delta = parsed_end - parsed_start
        assert 29 <= delta.total_seconds() / 60 <= 31

    def test_last_hours_converts_to_minutes(self):
        start, end = pcap_tools._resolve_time_window(last_hours=2)
        from datetime import datetime

        parsed_end = datetime.fromisoformat(end)
        parsed_start = datetime.fromisoformat(start)
        delta = parsed_end - parsed_start
        assert 119 <= delta.total_seconds() / 60 <= 121

    def test_last_hours_overrides_last_minutes(self):
        start, end = pcap_tools._resolve_time_window(last_minutes=10, last_hours=3)
        from datetime import datetime

        parsed_end = datetime.fromisoformat(end)
        parsed_start = datetime.fromisoformat(start)
        delta = parsed_end - parsed_start
        assert 179 <= delta.total_seconds() / 60 <= 181

    def test_no_params_raises_value_error(self):
        with pytest.raises(ValueError, match="Either"):
            pcap_tools._resolve_time_window()


class TestNewestChunks:
    """Tests for _newest_chunks helper."""

    def test_returns_n_newest(self):
        chunks = [
            {"chunk_id": "old.pcap", "start_ts": "2026-01-01T01:00:00"},
            {"chunk_id": "newest.pcap", "start_ts": "2026-01-01T03:00:00"},
            {"chunk_id": "mid.pcap", "start_ts": "2026-01-01T02:00:00"},
        ]
        result = pcap_tools._newest_chunks(chunks, 2)
        assert len(result) == 2
        assert result[0]["chunk_id"] == "newest.pcap"
        assert result[1]["chunk_id"] == "mid.pcap"

    def test_count_larger_than_list(self):
        chunks = [{"chunk_id": "a.pcap", "start_ts": "2026-01-01T01:00:00"}]
        result = pcap_tools._newest_chunks(chunks, 10)
        assert len(result) == 1

    def test_empty_list(self):
        result = pcap_tools._newest_chunks([], 5)
        assert result == []


class TestListChunksRelativeTime:
    """Tests for list_chunks with relative time parameters."""

    @patch("otalon_mcp.tools.pcap.requests.get")
    def test_list_chunks_last_hours(self, mock_get):
        chunks = [
            {"chunk_id": "a.pcap", "start_ts": "2026-02-26T18:00:00", "is_anomaly": False},
        ]
        mock_get.return_value = _mock_response(json_data=chunks)
        result = pcap_tools.list_chunks(last_hours=2)
        assert result["ok"] is True
        assert result["count"] == 1
        call_params = mock_get.call_args.kwargs.get("params") or mock_get.call_args[1].get("params", {})
        assert "start_ts" in call_params
        assert "end_ts" in call_params

    @patch("otalon_mcp.tools.pcap.requests.get")
    def test_list_chunks_last_minutes(self, mock_get):
        mock_get.return_value = _mock_response(json_data=[])
        result = pcap_tools.list_chunks(last_minutes=30)
        assert result["ok"] is True
        assert result["count"] == 0

    @patch("otalon_mcp.tools.pcap.requests.get")
    def test_list_chunks_last_chunks(self, mock_get):
        chunks = [
            {"chunk_id": "old.pcap", "start_ts": "2026-02-26T10:00:00"},
            {"chunk_id": "new.pcap", "start_ts": "2026-02-26T19:00:00"},
            {"chunk_id": "mid.pcap", "start_ts": "2026-02-26T15:00:00"},
        ]
        mock_get.return_value = _mock_response(json_data=chunks)
        result = pcap_tools.list_chunks(last_chunks=2)
        assert result["ok"] is True
        assert result["count"] == 2
        assert result["chunks"][0]["chunk_id"] == "new.pcap"

    def test_list_chunks_no_params_returns_error(self):
        result = pcap_tools.list_chunks()
        assert result["ok"] is False
        assert "error" in result


class TestGetChunksByAlarmId:
    """Tests for pcap.get_chunks_by_alarm_id()."""

    @patch("otalon_mcp.tools.pcap.requests.get")
    def test_matches_by_alarm_id(self, mock_get):
        alarm_uuid = "1088d146-d807-49d7-b10f-0dc7d7d918a9"
        chunks = [
            {
                "chunk_id": "a.pcap",
                "start_ts": "2026-02-26T11:34:56",
                "is_anomaly": True,
                "labels": {"alarm_id": alarm_uuid, "primary_type": "T0888/port_scan"},
            },
            {
                "chunk_id": "b.pcap",
                "start_ts": "2026-02-26T11:35:26",
                "is_anomaly": True,
                "labels": {"alarm_id": alarm_uuid, "primary_type": "T0888/port_scan"},
            },
            {
                "chunk_id": "c.pcap",
                "start_ts": "2026-02-26T12:00:00",
                "is_anomaly": True,
                "labels": {"alarm_id": "other-uuid"},
            },
            {
                "chunk_id": "d.pcap",
                "start_ts": "2026-02-26T12:30:00",
                "is_anomaly": False,
            },
        ]
        mock_get.return_value = _mock_response(json_data=chunks)
        result = pcap_tools.get_chunks_by_alarm_id(alarm_id=alarm_uuid)
        assert result["ok"] is True
        assert result["alarm_id"] == alarm_uuid
        assert result["count"] == 2
        ids = [c["chunk_id"] for c in result["chunks"]]
        assert "a.pcap" in ids
        assert "b.pcap" in ids
        assert "c.pcap" not in ids

    @patch("otalon_mcp.tools.pcap.requests.get")
    def test_no_matching_chunks(self, mock_get):
        chunks = [
            {"chunk_id": "x.pcap", "start_ts": "2026-02-26T10:00:00", "labels": {"alarm_id": "other"}},
        ]
        mock_get.return_value = _mock_response(json_data=chunks)
        result = pcap_tools.get_chunks_by_alarm_id(alarm_id="nonexistent-uuid")
        assert result["ok"] is True
        assert result["count"] == 0
        assert result["chunks"] == []

    @patch("otalon_mcp.tools.pcap.requests.get")
    def test_sorted_by_start_ts(self, mock_get):
        alarm_uuid = "test-sort-uuid"
        chunks = [
            {"chunk_id": "later.pcap", "start_ts": "2026-02-26T12:00:00", "labels": {"alarm_id": alarm_uuid}},
            {"chunk_id": "earlier.pcap", "start_ts": "2026-02-26T11:00:00", "labels": {"alarm_id": alarm_uuid}},
        ]
        mock_get.return_value = _mock_response(json_data=chunks)
        result = pcap_tools.get_chunks_by_alarm_id(alarm_id=alarm_uuid)
        assert result["ok"] is True
        assert result["chunks"][0]["chunk_id"] == "earlier.pcap"
        assert result["chunks"][1]["chunk_id"] == "later.pcap"

    @patch("otalon_mcp.tools.pcap.requests.get")
    def test_chunks_without_labels_ignored(self, mock_get):
        chunks = [
            {"chunk_id": "no_labels.pcap", "start_ts": "2026-02-26T10:00:00"},
            {"chunk_id": "empty_labels.pcap", "start_ts": "2026-02-26T10:00:00", "labels": {}},
        ]
        mock_get.return_value = _mock_response(json_data=chunks)
        result = pcap_tools.get_chunks_by_alarm_id(alarm_id="any-uuid")
        assert result["ok"] is True
        assert result["count"] == 0


class TestListAnomalyChunksRelativeTime:
    """Tests for list_anomaly_chunks with relative time and labels."""

    @patch("otalon_mcp.tools.pcap.requests.get")
    def test_anomaly_chunks_last_hours(self, mock_get):
        chunks = [
            {"chunk_id": "a.pcap", "is_anomaly": True, "start_ts": "2026-02-26T18:00:00"},
            {"chunk_id": "b.pcap", "is_anomaly": False, "start_ts": "2026-02-26T18:01:00"},
        ]
        mock_get.return_value = _mock_response(json_data=chunks)
        result = pcap_tools.list_anomaly_chunks(last_hours=1)
        assert result["ok"] is True
        assert result["count"] == 1
        assert result["chunks"][0]["chunk_id"] == "a.pcap"

    @patch("otalon_mcp.tools.pcap.requests.get")
    def test_anomaly_chunks_last_chunks(self, mock_get):
        chunks = [
            {"chunk_id": "a.pcap", "is_anomaly": True, "start_ts": "2026-02-26T10:00:00"},
            {"chunk_id": "b.pcap", "is_anomaly": True, "start_ts": "2026-02-26T19:00:00"},
            {"chunk_id": "c.pcap", "is_anomaly": True, "start_ts": "2026-02-26T15:00:00"},
            {"chunk_id": "d.pcap", "is_anomaly": False, "start_ts": "2026-02-26T20:00:00"},
        ]
        mock_get.return_value = _mock_response(json_data=chunks)
        result = pcap_tools.list_anomaly_chunks(last_chunks=2)
        assert result["ok"] is True
        assert result["count"] == 2
        assert result["chunks"][0]["chunk_id"] == "b.pcap"
        assert result["chunks"][1]["chunk_id"] == "c.pcap"

    @patch("otalon_mcp.tools.pcap.requests.get")
    def test_anomaly_chunks_include_labels(self, mock_get):
        chunks = [
            {
                "chunk_id": "flagged.pcap",
                "is_anomaly": True,
                "start_ts": "2026-02-26T18:00:00",
                "labels": {"reason": "dos_attack", "uci": "plc1"},
            },
        ]
        mock_get.return_value = _mock_response(json_data=chunks)
        result = pcap_tools.list_anomaly_chunks(start_ts="2026-02-26T17:00:00", end_ts="2026-02-26T19:00:00")
        assert result["ok"] is True
        assert result["chunks"][0]["labels"]["reason"] == "dos_attack"
