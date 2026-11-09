"""Abstract base class for data source preprocessors.

All preprocessor implementations must inherit from ``BasePreprocessor`` and
implement its four abstract methods. The preprocessing registry dispatches
to these implementations based on the ``preprocessor.type`` configured per
module.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

import polars as pl


class BasePreprocessor(ABC):
    """Abstract base class defining the preprocessor contract.

    Each data source module (connection, MAC traffic, protocol traffic) has
    a dedicated preprocessor that transforms raw InfluxDB data into a format
    suitable for boundary training, anomaly detection, and ML classification.
    """

    @abstractmethod
    def preprocess_for_training(self, df: pl.DataFrame) -> pl.DataFrame:
        """Transform raw data for boundary and ML model training.

        Args:
            df: Raw Polars DataFrame as fetched from InfluxDB.

        Returns:
            Preprocessed DataFrame ready for training pipelines.
        """

    @abstractmethod
    def preprocess_for_prediction(self, df: pl.DataFrame) -> pl.DataFrame:
        """Transform raw data for live or offline anomaly prediction.

        Args:
            df: Raw Polars DataFrame as fetched from InfluxDB.

        Returns:
            Preprocessed DataFrame ready for prediction pipelines.
        """

    @abstractmethod
    def get_tag_column(self) -> str:
        """Return the name of the tag column used to identify time series.

        Returns:
            Column name string (e.g., ``"uci"``, ``"mac_address"``).
        """

    @abstractmethod
    def get_feature_columns(self) -> list[str]:
        """Return the ordered list of feature column names.

        Returns:
            List of feature column name strings.
        """
