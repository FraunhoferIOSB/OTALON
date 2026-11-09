"""Abstract base class for post-processing pipeline stages."""

from __future__ import annotations

from abc import ABC, abstractmethod

import polars as pl


class PostProcessingStage(ABC):
    """Contract for all post-processing pipeline stages.

    Each stage receives a DataFrame of detected anomalies and returns a
    transformed DataFrame. Stages may filter, enrich, group, or reclassify
    anomalies.
    """

    @abstractmethod
    def process(self, anomalies: pl.DataFrame) -> pl.DataFrame:
        """Process the anomaly DataFrame and return the transformed result.

        Args:
            anomalies: Input anomaly DataFrame.

        Returns:
            Transformed anomaly DataFrame.
        """
        ...

    @abstractmethod
    def is_enabled(self) -> bool:
        """Return whether this stage is active and should be executed.

        Returns:
            True if the stage should participate in the pipeline.
        """
        ...
