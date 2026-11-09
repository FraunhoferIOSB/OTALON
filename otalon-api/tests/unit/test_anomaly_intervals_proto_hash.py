"""Unit tests for API-013: proto interval matching via proto_series_hash.

The proto subpage sends the plaintext protocol stack (e.g.
``"Ethernet:ARP"``) as ``series_id``, but proto_traffic alarm groups
persist their ``series_ids`` as the stable hash of that stack. These
tests verify that ``get_anomaly_intervals`` matches the hashed key when
the proto route passes ``match_uci=proto_series_hash(series_id)``, while
the plaintext mac_traffic match remains unchanged.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from otalon_api.domain.netcap.models import proto_series_hash
from otalon_api.services.anomaly_service import AnomalyService
from otalon_api.settings import Settings


class TestApi013ProtoHashMatch:
    """API-013: proto plaintext uci matches hashed series_ids."""

    @pytest.mark.unit
    async def test_proto_plaintext_uci_matches_hashed_group(
        self,
        mock_postgres_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """Plaintext proto uci must match a group with the hashed series_id.

        Args:
            mock_postgres_repo: Mocked PostgresRepository.
            mock_settings: Test settings.
        """
        protocol = "Ethernet:ARP"
        hashed = proto_series_hash(protocol)
        mock_postgres_repo.query_anomaly_groups.return_value = [
            {
                "id": "group-proto-1",
                "series_ids": [hashed, "999999999"],
                "start_timestamp": "2026-01-01T00:00:00Z",
                "end_timestamp": "2026-01-01T01:00:00Z",
                "primary_type": "T0846/arp_scan",
            }
        ]
        service = AnomalyService(mock_postgres_repo, mock_settings)

        result = await service.get_anomaly_intervals(
            uci=protocol,
            module="proto_traffic",
            match_uci=hashed,
        )

        assert result["row_count"] >= 1
        interval = result["data"][0]
        assert interval["alarm_group_id"] == "group-proto-1"
        assert interval["anomaly_type"] == "T0846/arp_scan"
        assert result["parameters"]["uci"] == protocol

    @pytest.mark.unit
    async def test_proto_non_matching_protocol_returns_empty(
        self,
        mock_postgres_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """A protocol whose hash is absent from series_ids must yield 0 rows.

        Args:
            mock_postgres_repo: Mocked PostgresRepository.
            mock_settings: Test settings.
        """
        present_hash = proto_series_hash("Ethernet:ARP")
        absent_protocol = "Ethernet:IPv4:TCP"
        mock_postgres_repo.query_anomaly_groups.return_value = [
            {
                "id": "group-proto-2",
                "series_ids": [present_hash],
                "start_timestamp": "2026-01-01T00:00:00Z",
                "end_timestamp": "2026-01-01T01:00:00Z",
                "primary_type": "BoundViolation",
            }
        ]
        service = AnomalyService(mock_postgres_repo, mock_settings)

        result = await service.get_anomaly_intervals(
            uci=absent_protocol,
            module="proto_traffic",
            match_uci=proto_series_hash(absent_protocol),
        )

        assert result["row_count"] == 0
        assert result["data"] == []

    @pytest.mark.unit
    async def test_proto_plaintext_does_not_match_hashed_without_transform(
        self,
        mock_postgres_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """Without ``match_uci`` the raw plaintext must not match the hash.

        This pins the regression: the old code path that compared the
        plaintext stack against hashed series_ids never matched.

        Args:
            mock_postgres_repo: Mocked PostgresRepository.
            mock_settings: Test settings.
        """
        protocol = "Ethernet:ARP"
        mock_postgres_repo.query_anomaly_groups.return_value = [
            {
                "id": "group-proto-3",
                "series_ids": [proto_series_hash(protocol)],
                "start_timestamp": "2026-01-01T00:00:00Z",
                "end_timestamp": "2026-01-01T01:00:00Z",
                "primary_type": "T0846/arp_scan",
            }
        ]
        service = AnomalyService(mock_postgres_repo, mock_settings)

        result = await service.get_anomaly_intervals(
            uci=protocol,
            module="proto_traffic",
        )

        assert result["row_count"] == 0


class TestApi013MacRegression:
    """API-013: plaintext mac_traffic matching stays unchanged."""

    @pytest.mark.unit
    async def test_mac_plaintext_match_unchanged(
        self,
        mock_postgres_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """A plaintext MAC must still match a group's plaintext series_ids.

        The mac path passes no ``match_uci``, so ``uci`` is matched
        directly; this proves the proto fix left the mac path untouched.

        Args:
            mock_postgres_repo: Mocked PostgresRepository.
            mock_settings: Test settings.
        """
        mac = "aa:bb:cc:dd:ee:ff"
        mock_postgres_repo.query_anomaly_groups.return_value = [
            {
                "id": "group-mac-1",
                "series_ids": [mac, "11:22:33:44:55:66"],
                "start_timestamp": "2026-01-01T00:00:00Z",
                "end_timestamp": "2026-01-01T01:00:00Z",
                "primary_type": "BoundViolation",
            }
        ]
        service = AnomalyService(mock_postgres_repo, mock_settings)

        result = await service.get_anomaly_intervals(
            uci=mac,
            module="mac_traffic",
        )

        assert result["row_count"] == 1
        assert result["data"][0]["alarm_group_id"] == "group-mac-1"
