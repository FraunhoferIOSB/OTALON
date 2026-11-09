"""Persistence layer for the alarm-group classifier model.

Stores the trained estimator, scaler, feature-name list, and training
metadata as a single joblib bundle so that live inference can restore
the same column order and label mapping that was used during training.

The bundle is written with a write-time SHA-256 sidecar and verified
before deserialization (CLAS-048); see
:mod:`otalon_clas.common.artifact_integrity` for the format and the
fail-closed policy for artifacts deployed before that check existed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from loguru import logger
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

from otalon_clas.common.artifact_integrity import dump_sealed, load_verified


@dataclass(frozen=True, slots=True)
class StoredGroupModel:
    """Bundle of artifacts loaded from disk for live inference."""

    model: RandomForestClassifier
    scaler: StandardScaler
    feature_names: list[str]
    classes: list[str]
    metadata: dict[str, Any]


class GroupClassifierStore:
    """Save and load alarm-group-classifier artifacts.

    The bundle is stored as a single joblib file containing the model,
    scaler, feature-name list, and class label list. Metadata (CV
    metrics, training-window timestamps, feature-set name, etc.) is
    written alongside as a sibling JSON file for easy inspection, and the
    integrity sidecar as ``<bundle-name>.integrity.json``.

    Args:
        model_path: Path to the joblib bundle. The metadata file is
            derived as ``model_path.with_suffix('.meta.json')``.
    """

    def __init__(self, model_path: str | Path) -> None:
        """Initialize the store with the absolute model bundle path."""
        self._model_path = Path(model_path)
        self._meta_path = self._model_path.with_suffix(".meta.json")

    @property
    def model_path(self) -> Path:
        """Return the configured model bundle path."""
        return self._model_path

    @property
    def meta_path(self) -> Path:
        """Return the sibling metadata JSON path."""
        return self._meta_path

    def exists(self) -> bool:
        """Return ``True`` when the model bundle file exists on disk."""
        return self._model_path.exists()

    def save(
        self,
        model: RandomForestClassifier,
        scaler: StandardScaler,
        feature_names: list[str],
        classes: list[str],
        metadata: dict[str, Any],
    ) -> None:
        """Persist the trained classifier and metadata to disk.

        Args:
            model: Trained Random-Forest estimator.
            scaler: Fitted standard scaler.
            feature_names: Ordered feature column names (length matches
                the model's ``n_features_in_``).
            classes: Sorted list of class labels in the same order as
                ``model.classes_``.
            metadata: Free-form metadata to serialize as JSON.
        """
        self._model_path.parent.mkdir(parents=True, exist_ok=True)
        bundle = {
            "model": model,
            "scaler": scaler,
            "feature_names": list(feature_names),
            "classes": list(classes),
            "metadata": dict(metadata),
        }
        dump_sealed(bundle, self._model_path)
        logger.info("GroupClassifierStore: saved model bundle to {}", self._model_path)

        self._meta_path.write_text(json.dumps(metadata, indent=2, default=str))
        logger.info("GroupClassifierStore: saved metadata to {}", self._meta_path)

    def load(self) -> StoredGroupModel:
        """Load the trained classifier from disk.

        Returns:
            :class:`StoredGroupModel` instance.

        Raises:
            FileNotFoundError: When the model bundle file is missing.
            ArtifactIntegrityError: When the bundle carries no write-time
                integrity metadata or its bytes no longer match it.
        """
        if not self._model_path.exists():
            msg = f"Group-classifier model not found: {self._model_path}"
            raise FileNotFoundError(msg)

        bundle = load_verified(self._model_path)
        metadata = bundle.get("metadata", {})
        if self._meta_path.exists():
            try:
                metadata = json.loads(self._meta_path.read_text())
            except (OSError, json.JSONDecodeError) as exc:
                logger.warning(
                    "GroupClassifierStore: failed to read metadata file {}: {}",
                    self._meta_path,
                    exc,
                )

        return StoredGroupModel(
            model=bundle["model"],
            scaler=bundle["scaler"],
            feature_names=list(bundle.get("feature_names", [])),
            classes=list(bundle.get("classes", [])),
            metadata=metadata,
        )
