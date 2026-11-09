"""Sliding window preprocessor decorator for rolling feature aggregation.

Wraps a base preprocessor and applies a rolling time-window aggregation
after the base preprocessing step. For each feature column, computes
mean, std, min, and max over the configured window.
"""

from __future__ import annotations

import polars as pl
from otalon_clas.preprocessing.base import BasePreprocessor
from loguru import logger


class SlidingWindowPreprocessor(BasePreprocessor):
    """Decorator preprocessor that adds rolling window statistics.

    Wraps any ``BasePreprocessor`` and extends its output with rolling
    aggregations (mean, std, min, max) computed per feature column over
    a time-based sliding window grouped by the tag column.

    Args:
        base: The underlying preprocessor to delegate to first.
        window_seconds: Rolling window size in seconds.
    """

    def __init__(self, base: BasePreprocessor, window_seconds: int = 10) -> None:
        """Initialize the sliding window preprocessor.

        Args:
            base: Base preprocessor whose output is extended with rolling stats.
            window_seconds: Width of the rolling time window in seconds.
        """
        self._base = base
        self._window_seconds = window_seconds

    def preprocess_for_training(self, df: pl.DataFrame) -> pl.DataFrame:
        """Apply base preprocessing then rolling window aggregation for training.

        Args:
            df: Raw DataFrame from InfluxDB.

        Returns:
            DataFrame with original features plus rolling window statistics.
        """
        df = self._base.preprocess_for_training(df)
        return self._apply_rolling_window(df)

    def preprocess_for_prediction(self, df: pl.DataFrame) -> pl.DataFrame:
        """Apply base preprocessing then rolling window aggregation for prediction.

        Args:
            df: Raw DataFrame from InfluxDB.

        Returns:
            DataFrame with original features plus rolling window statistics.
        """
        df = self._base.preprocess_for_prediction(df)
        return self._apply_rolling_window(df)

    def get_tag_column(self) -> str:
        """Return the tag column name from the base preprocessor.

        Returns:
            Tag column name string.
        """
        return self._base.get_tag_column()

    def get_feature_columns(self) -> list[str]:
        """Return all feature columns including rolling window statistics.

        Returns:
            List containing original features plus ``{feature}_{stat}``
            columns for each rolling statistic (mean, std, min, max).
        """
        base_features = self._base.get_feature_columns()
        window_features = _build_window_feature_names(base_features)
        return base_features + window_features

    def get_window_seconds(self) -> int:
        """Return the rolling window size in seconds.

        Used by ``InfluxModule`` to calculate the required data buffer
        for live prediction mode.

        Returns:
            Window size in seconds.
        """
        return self._window_seconds

    def _apply_rolling_window(self, df: pl.DataFrame) -> pl.DataFrame:
        """Compute rolling window statistics per tag group.

        Groups the DataFrame by the tag column, sorts by time, and computes
        a rolling aggregation per feature.

        Args:
            df: Preprocessed DataFrame with ``time`` and feature columns.

        Returns:
            DataFrame with additional rolling statistic columns appended.
        """
        if df.is_empty() or "time" not in df.columns:
            logger.debug("SlidingWindowPreprocessor: skipping rolling window (empty or no time column)")
            return df

        tag_col = self._base.get_tag_column()
        base_features = self._base.get_feature_columns()
        available_features = [f for f in base_features if f in df.columns]
        window_duration = f"{self._window_seconds}s"

        logger.debug(
            "SlidingWindowPreprocessor: applying {}s window over {} features",
            self._window_seconds,
            len(available_features),
        )

        df = df.sort([tag_col, "time"])
        rolling_exprs = _build_rolling_expressions(available_features, window_duration)

        result = df.rolling(
            index_column="time",
            period=window_duration,
            group_by=tag_col,
        ).agg(rolling_exprs)

        return df.join(result, on=[tag_col, "time"], how="left")


def _build_window_feature_names(base_features: list[str]) -> list[str]:
    """Build the list of rolling window statistic column names.

    Args:
        base_features: Original feature column names.

    Returns:
        List of ``{feature}_{stat}`` names for mean, std, min, max.
    """
    suffixes = ("mean", "std", "min", "max")
    return [f"{feat}_{suffix}" for feat in base_features for suffix in suffixes]


def _build_rolling_expressions(features: list[str], window_duration: str) -> list[pl.Expr]:
    """Build Polars aggregation expressions for rolling window statistics.

    Args:
        features: Feature column names to aggregate.
        window_duration: Unused in expression building but documents intent.

    Returns:
        List of Polars expressions computing mean, std, min, max per feature.
    """
    exprs: list[pl.Expr] = []
    for feat in features:
        exprs.append(pl.col(feat).mean().alias(f"{feat}_mean"))
        exprs.append(pl.col(feat).std().alias(f"{feat}_std"))
        exprs.append(pl.col(feat).min().alias(f"{feat}_min"))
        exprs.append(pl.col(feat).max().alias(f"{feat}_max"))
    return exprs
