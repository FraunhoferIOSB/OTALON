"""Pipeline builder: reads configuration and instantiates post-processing stages.

Supports ``ensemble_ml`` and ``rule_based`` stage types and skips disabled stages.
"""

from __future__ import annotations

import polars as pl
from otalon_clas.common.settings import (AnomalyGroupingConfig,
                                                PipelinePostProcessingConfig,
                                                StageConfig)
from otalon_clas.pipeline.base import PostProcessingStage
from otalon_clas.pipeline.ensemble import EnsembleMLStage
from otalon_clas.pipeline.rule_based import RuleBasedStage
from loguru import logger


class PipelineBuilder:
    """Builds and executes a post-processing pipeline from configuration.

    Reads the list of stage configurations, instantiates each stage in
    order, and skips disabled stages during execution.

    Args:
        config: Post-processing pipeline configuration.
        grouping_config: Anomaly grouping configuration for rule-based stages.
    """

    def __init__(
        self,
        config: PipelinePostProcessingConfig,
        grouping_config: AnomalyGroupingConfig | None = None,
    ) -> None:
        """Initialize the pipeline builder.

        Args:
            config: Pipeline post-processing configuration.
            grouping_config: Optional anomaly grouping config.
        """
        self._config = config
        self._grouping_config = grouping_config or AnomalyGroupingConfig()
        self._stages: list[PostProcessingStage] = []
        self._build()

    @property
    def stages(self) -> list[PostProcessingStage]:
        """Return the list of instantiated pipeline stages.

        Returns:
            Ordered list of post-processing stages.
        """
        return list(self._stages)

    @property
    def active_stages(self) -> list[PostProcessingStage]:
        """Return only the enabled pipeline stages.

        Returns:
            Filtered list of active stages.
        """
        return [s for s in self._stages if s.is_enabled()]

    def run(self, anomalies: pl.DataFrame) -> pl.DataFrame:
        """Execute all active stages sequentially on the anomaly DataFrame.

        Args:
            anomalies: Input anomaly DataFrame.

        Returns:
            Transformed anomaly DataFrame after all active stages.
        """
        result = anomalies
        for stage in self.active_stages:
            stage_name = type(stage).__name__
            logger.debug("Running post-processing stage: {}", stage_name)
            result = stage.process(result)
            logger.debug("Stage {} completed, {} rows", stage_name, len(result))
        return result

    def _build(self) -> None:
        """Instantiate stages from the configuration list."""
        for stage_config in self._config.stages:
            stage = self._create_stage(stage_config)
            if stage is not None:
                self._stages.append(stage)
                logger.debug(
                    "Registered stage: {} (enabled={})",
                    type(stage).__name__,
                    stage.is_enabled(),
                )

    def _create_stage(self, stage_config: StageConfig) -> PostProcessingStage | None:
        """Instantiate a single stage from its configuration.

        Args:
            stage_config: Stage configuration with type and parameters.

        Returns:
            PostProcessingStage instance or None if type is unknown.
        """
        stage_type = stage_config.type

        if stage_type == "rule_based":
            return self._create_rule_based(stage_config)
        if stage_type == "ensemble_ml":
            return self._create_ensemble_ml(stage_config)

        logger.warning("Unknown post-processing stage type: '{}'", stage_type)
        return None

    def _create_rule_based(self, stage_config: StageConfig) -> RuleBasedStage:
        """Create a rule-based stage from configuration.

        Args:
            stage_config: Stage configuration with optional ``config`` sub-dict.

        Returns:
            Configured RuleBasedStage instance.
        """
        inner = getattr(stage_config, "config", None)
        if inner is None:
            inner = {}
        elif hasattr(inner, "model_dump"):
            inner = inner.model_dump()
        elif not isinstance(inner, dict):
            inner = dict(inner) if hasattr(inner, "__iter__") else {}

        return RuleBasedStage(
            gap_tolerance_seconds=inner.get("gap_tolerance_seconds", 10),
            cross_module_correlation=inner.get("cross_module_correlation", True),
            module_weights=inner.get("module_weights"),
            grouping_config=self._grouping_config,
            enabled=stage_config.enabled,
        )

    def _create_ensemble_ml(self, stage_config: StageConfig) -> EnsembleMLStage:
        """Create an ensemble ML stage from configuration.

        Args:
            stage_config: Stage configuration with algorithm and params fields.

        Returns:
            Configured EnsembleMLStage instance.
        """
        algorithm = getattr(stage_config, "algorithm", "gradient_boosting")
        params = getattr(stage_config, "params", {})
        if hasattr(params, "model_dump"):
            params = params.model_dump()
        elif not isinstance(params, dict):
            params = {}

        return EnsembleMLStage(
            algorithm=str(algorithm),
            params=params,
            enabled=stage_config.enabled,
        )
