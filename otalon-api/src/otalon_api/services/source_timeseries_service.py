"""Source-parametrised time-series data service for MAC and Proto sources.

Provides the same query/downsample pipeline as :class:`TimeseriesService`
but is initialised with a specific InfluxDB measurement, tag key, and
feature catalog rather than reading them from global settings.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional, cast

import numpy as np
import pandas as pd
from loguru import logger

from otalon_api.domain.time import time_policy
from otalon_api.repositories.influx_repo import InfluxRepository
from otalon_api.settings import Settings


class SourceTimeseriesService:
    """Service for time-series data retrieval parametrised by source."""

    def __init__(
        self,
        influx_repo: InfluxRepository,
        settings: Settings,
        measurement: str,
        id_tag: str,
        features: list[str],
    ) -> None:
        """Initialize the service for a specific source.

        Args:
            influx_repo: InfluxDB repository for data access.
            settings: Application settings.
            measurement: InfluxDB measurement name (e.g. ``"mac_traffic"``).
            id_tag: Tag column used as series identifier
                (e.g. ``"mac_address"``).
            features: Authorised feature catalog for this source.
        """
        self._repo = influx_repo
        self._settings = settings
        self._measurement = measurement
        self._id_tag = id_tag
        self._features = features

    def get_between(
        self,
        series_id: str,
        start: datetime,
        stop: datetime,
        features: list[str],
        aggregate: str | None = None,
        sample_max_points: int | None = None,
        preserve_extrema: bool = True,
    ) -> tuple[pd.DataFrame, int | None]:
        """Query timeseries data and apply the downsampling pipeline.

        Args:
            series_id: Series identifier to query.
            start: Range start in local time.
            stop: Range end in local time.
            features: List of feature column names to retrieve.
            aggregate: Aggregation function name (e.g. ``"mean"``).
            sample_max_points: Maximum number of data points returned.
            preserve_extrema: When ``True`` and aggregation is active,
                request additional MIN/MAX columns per field.

        Returns:
            A tuple of (DataFrame, bucket_seconds).  *bucket_seconds* is
            ``None`` when no aggregation was applied.
        """
        effective_max = sample_max_points or self._settings.default_sample_max_points
        start_str, stop_str = time_policy.ui_to_influx_query_range(start, stop)

        logger.debug(
            "get_between source={} series_id={} start={} stop={} agg={} max_pts={}",
            self._measurement,
            series_id,
            start_str,
            stop_str,
            aggregate,
            effective_max,
        )

        df = self._repo.query_timeseries(
            measurement=self._measurement,
            id_tag=self._id_tag,
            fields=list(features),
            start=start_str,
            stop=stop_str,
            tags={self._id_tag: series_id},
            aggregate=aggregate,
            sample_max_points=effective_max if aggregate else None,
            preserve_extrema=preserve_extrema,
        )

        bucket_seconds: int | None = df.attrs.get("bucket_seconds")

        df = cast(pd.DataFrame, time_policy.normalize_time_for_ui(df, time_cols=["time"]))
        df = self._round_time_columns(df)
        df = self._decimate_dataframe(df, effective_max)

        logger.debug("get_between result: {} rows, bucket={}s", len(df), bucket_seconds)
        return df, bucket_seconds

    def list_ids(
        self,
        start: datetime,
        stop: datetime,
        nonzero: bool = False,
        fields: list[str] | None = None,
    ) -> list[str]:
        """List series identifiers available in a time range.

        Args:
            start: Range start in local time.
            stop: Range end in local time.
            nonzero: When ``True``, only return IDs with non-zero summed
                fields.
            fields: Field names for the nonzero filter check.

        Returns:
            A sorted list of distinct identifier strings.
        """
        start_str, stop_str = time_policy.ui_to_influx_query_range(start, stop)

        ids = self._repo.list_ids_between(
            measurement=self._measurement,
            id_tag=self._id_tag,
            start=start_str,
            stop=stop_str,
            nonzero=nonzero,
            fields=fields,
        )
        return sorted(ids)

    def get_plot_data(
        self,
        series_id: str,
        start: datetime,
        stop: datetime,
        features: list[str],
        sample_max_points: int = 500,
        preserve_extrema: bool = True,
    ) -> tuple[pd.DataFrame, int | None]:
        """Convenience wrapper: get_between with aggregate='mean'.

        Args:
            series_id: Series identifier to query.
            start: Range start in local time.
            stop: Range end in local time.
            features: List of feature column names to retrieve.
            sample_max_points: Maximum number of data points returned.
            preserve_extrema: When ``True``, request MIN/MAX columns.

        Returns:
            A tuple of (DataFrame, bucket_seconds).
        """
        return self.get_between(
            series_id=series_id,
            start=start,
            stop=stop,
            features=features,
            aggregate="mean",
            sample_max_points=sample_max_points,
            preserve_extrema=preserve_extrema,
        )

    @staticmethod
    def _round_time_columns(df: pd.DataFrame) -> pd.DataFrame:
        """Round all datetime columns to second precision.

        Args:
            df: Input DataFrame.

        Returns:
            DataFrame with datetime columns rounded to whole seconds.
        """
        if not isinstance(df, pd.DataFrame) or df.empty:
            return df

        result = df.copy()
        for col in result.columns:
            if pd.api.types.is_datetime64_any_dtype(result[col]):
                result[col] = result[col].dt.round("s")
        if isinstance(result.index, pd.DatetimeIndex):
            result.index = result.index.round("s")
        return result

    @staticmethod
    def _decimate_dataframe(df: pd.DataFrame, target_points: Optional[int]) -> pd.DataFrame:
        """Downsample by selecting evenly-spaced indices via np.linspace.

        Args:
            df: Input DataFrame.
            target_points: Desired maximum number of rows.  ``None`` or
                non-positive values disable decimation.

        Returns:
            The (possibly downsampled) DataFrame.
        """
        if not isinstance(df, pd.DataFrame) or df.empty:
            return df

        try:
            points = int(target_points) if target_points is not None else None
        except (TypeError, ValueError):
            points = None

        if points is None or points <= 0:
            return df
        if len(df) <= points:
            return df

        indices = np.linspace(0, len(df) - 1, points).astype(int)
        return df.iloc[indices].reset_index(drop=True)
