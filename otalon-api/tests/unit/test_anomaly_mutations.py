"""Mutation tests for anomaly alarm group PATCH operations.

Tests PATCH idempotency and error handling for update_group_confirmed.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from otalon_api.services.anomaly_service import AnomalyService
from otalon_api.settings import Settings


class TestPatchIdempotency:
    """PATCH idempotency tests for update_group_confirmed."""

    @pytest.mark.unit
    async def test_double_confirm_idempotent(
        self,
        mock_postgres_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """Calling update_group_confirmed(True) twice has the same effect.

        Args:
            mock_postgres_repo: Mocked PostgresRepository.
            mock_settings: Test settings.
        """
        group_data = {
            "id": "test-uuid-1234",
            "confirmed": False,
            "primary_type": "BoundViolation",
            "series_ids": [],
        }
        mock_postgres_repo.get_anomaly_group_by_id.return_value = group_data
        mock_postgres_repo.update_alarm_group_confirmed.return_value = True

        service = AnomalyService(mock_postgres_repo, mock_settings)

        result1 = await service.update_group_confirmed("test-uuid-1234", True)
        assert result1["parameters"]["confirmed"] is True

        group_data_after = dict(group_data)
        group_data_after["confirmed"] = True
        mock_postgres_repo.get_anomaly_group_by_id.return_value = group_data_after

        result2 = await service.update_group_confirmed("test-uuid-1234", True)
        assert result2["parameters"]["confirmed"] is True
        assert result2["data"]["confirmed"] is True

    @pytest.mark.unit
    async def test_confirm_then_unconfirm(
        self,
        mock_postgres_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """Confirm then unconfirm should change status back to False.

        Args:
            mock_postgres_repo: Mocked PostgresRepository.
            mock_settings: Test settings.
        """
        group_data = {
            "id": "test-uuid-5678",
            "confirmed": False,
            "primary_type": "BoundViolation",
            "series_ids": [],
        }
        mock_postgres_repo.get_anomaly_group_by_id.return_value = group_data
        mock_postgres_repo.update_alarm_group_confirmed.return_value = True

        service = AnomalyService(mock_postgres_repo, mock_settings)

        await service.update_group_confirmed("test-uuid-5678", True)

        group_after_confirm = dict(group_data)
        group_after_confirm["confirmed"] = True
        mock_postgres_repo.get_anomaly_group_by_id.return_value = group_after_confirm

        result = await service.update_group_confirmed("test-uuid-5678", False)

        assert result["parameters"]["confirmed"] is False

        group_after_unconfirm = dict(group_data)
        group_after_unconfirm["confirmed"] = False
        mock_postgres_repo.get_anomaly_group_by_id.return_value = group_after_unconfirm

        final_result = await service.update_group_confirmed("test-uuid-5678", False)
        assert final_result["parameters"]["confirmed"] is False


class TestPatchErrorCases:
    """Error handling tests for update_group_confirmed."""

    @pytest.mark.unit
    async def test_nonexistent_group_raises_value_error(
        self,
        mock_postgres_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """Updating a non-existent group should raise ValueError.

        Args:
            mock_postgres_repo: Mocked PostgresRepository.
            mock_settings: Test settings.
        """
        mock_postgres_repo.get_anomaly_group_by_id.return_value = None

        service = AnomalyService(mock_postgres_repo, mock_settings)

        with pytest.raises(ValueError, match="Alarm group not found"):
            await service.update_group_confirmed("nonexistent-uuid", True)

    @pytest.mark.unit
    async def test_failed_update_raises_value_error(
        self,
        mock_postgres_repo: MagicMock,
        mock_settings: Settings,
    ) -> None:
        """Failed database update should raise ValueError.

        Args:
            mock_postgres_repo: Mocked PostgresRepository.
            mock_settings: Test settings.
        """
        mock_postgres_repo.get_anomaly_group_by_id.return_value = {
            "id": "test-uuid-fail",
            "confirmed": False,
        }
        mock_postgres_repo.update_alarm_group_confirmed.return_value = False

        service = AnomalyService(mock_postgres_repo, mock_settings)

        with pytest.raises(ValueError, match="Failed to update alarm group"):
            await service.update_group_confirmed("test-uuid-fail", True)

    @pytest.mark.unit
    def test_api_endpoint_invalid_group_id_returns_404(self) -> None:
        """API endpoint with non-existent group_id should return 404.

        This test requires overriding the dependency to avoid real DB calls.

        Args:
            api_client: FastAPI test client fixture.
        """
        from fastapi.testclient import TestClient

        from otalon_api.dependencies import get_anomaly_service
        from otalon_api.main import app

        mock_repo = MagicMock()
        mock_repo.get_anomaly_group_by_id.return_value = None

        mock_service = AnomalyService(
            mock_repo,
            Settings(
                influxdb_host="localhost",
                influxdb_port=8181,
                influxdb_token="test",
                influxdb_org="test",
                influxdb_database="test",
                postgres_host="localhost",
                postgres_port=5432,
                postgres_user="test",
                postgres_password="test",
                postgres_database="test",
                admin_api_key="test-key",
                api_port=8090,
                netcap_measurement="network_metrics",
                netcap_id_tag="uci",
                netcap_sparse_port_threshold=10,
                utc_offset_hours=1,
                default_sample_max_points=500,
            ),
        )

        async def override_service():
            return mock_service

        app.dependency_overrides[get_anomaly_service] = override_service
        try:
            with patch(
                "otalon_api.middleware.auth.get_settings",
                return_value=Settings(admin_api_key="test-suite-key-do-not-use-in-prod"),
            ):
                client = TestClient(app, headers={"X-API-Key": "test-suite-key-do-not-use-in-prod"})
                response = client.patch(
                    "/api/v1/anomalies/groups/nonexistent-uuid",
                    json={"confirmed": True},
                )
                assert response.status_code == 404
        finally:
            app.dependency_overrides.clear()
