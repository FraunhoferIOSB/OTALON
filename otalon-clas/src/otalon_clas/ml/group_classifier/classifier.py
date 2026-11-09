"""Live alarm-group classifier inference and MITRE-label mapping.

Loads a model bundle from :class:`GroupClassifierStore`, extracts FS-C
features for an alarm at runtime, predicts the most likely
``technical_method``, and maps it back to a MITRE-attack-method label
of the form ``T<id>/<technique>`` so that the alarm's ``primary_type``
column stays consistent with the row-level Decision-Tree classifier.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

import numpy as np
import polars as pl
from otalon_clas.common.artifact_integrity import ArtifactIntegrityError
from otalon_clas.ml.group_classifier.features import \
    extract_alarm_features
from otalon_clas.ml.group_classifier.store import (GroupClassifierStore,
                                                          StoredGroupModel)
from loguru import logger

DEFAULT_TECHNICAL_METHOD_TO_MITRE: dict[str, str] = {
    "arp_scan": "arp_scan",
    "arp_spoofing": "arp_spoofing",
    "icmp_flood": "icmp_flood",
    "opcua_enumeration": "opcua_enumeration",
    "opcua_service_discovery": "opcua_service_discovery",
    "port_scan": "port_scan",
    "profinet_discovery": "profinet_discovery",
    "tcp_flood": "tcp_flood",
    "udp_flood": "udp_flood",
}
"""Identity mapping: write the raw ``technical_method`` label as the
``primary_type`` of an alarm.

The mapping is kept as a dictionary so that callers can override it
when they need MITRE-style labels (``T0814/hping3``) instead. By
default we expose the more specific ``technical_method`` directly so
that the three Denial-of-Service variants (icmp_flood, tcp_flood,
udp_flood) stay distinguishable in the UI.
"""


@dataclass(frozen=True, slots=True)
class GroupClassifierPrediction:
    """One prediction returned by :meth:`GroupClassifier.classify`."""

    technical_method: str
    mitre_label: str
    confidence: float
    classified_at: datetime


class GroupClassifier:
    """Run alarm-group classification with a persisted RF model.

    Args:
        store: The persistence layer pointing at the model bundle to load.
        confidence_threshold: Predictions whose confidence falls below
            this threshold are returned as ``None`` from :meth:`classify`.
        technical_method_to_mitre: Optional override of the default
            technical_method to MITRE-label mapping.
    """

    def __init__(
        self,
        store: GroupClassifierStore,
        confidence_threshold: float = 0.5,
        technical_method_to_mitre: dict[str, str] | None = None,
    ) -> None:
        """Initialize the classifier and load the model from disk."""
        self._store = store
        self._confidence_threshold = float(confidence_threshold)
        self._mitre_map = dict(
            technical_method_to_mitre or DEFAULT_TECHNICAL_METHOD_TO_MITRE
        )
        self._loaded: StoredGroupModel | None = None

    @property
    def is_active(self) -> bool:
        """Return whether the classifier was successfully loaded."""
        return self._loaded is not None

    @property
    def confidence_threshold(self) -> float:
        """Return the configured confidence threshold."""
        return self._confidence_threshold

    @property
    def metadata(self) -> dict[str, Any]:
        """Return the loaded model's training metadata (empty when unloaded)."""
        if self._loaded is None:
            return {}
        return self._loaded.metadata

    def load(self) -> bool:
        """Load the model bundle from disk.

        Returns:
            ``True`` on successful load; ``False`` when the model file
            is missing or cannot be loaded (the classifier stays inactive).
        """
        if not self._store.exists():
            logger.warning(
                "GroupClassifier: model not found at {}, classifier inactive",
                self._store.model_path,
            )
            return False
        try:
            self._loaded = self._store.load()
        except ArtifactIntegrityError as exc:
            # Named separately from a generic load failure: the bundle on
            # disk is not the one this suite wrote (CLAS-048).
            logger.error(
                "GroupClassifier: model bundle at {} REJECTED by integrity check, classifier inactive — {}",
                self._store.model_path,
                exc,
            )
            self._loaded = None
            return False
        except Exception:
            logger.exception(
                "GroupClassifier: failed to load model bundle from {}",
                self._store.model_path,
            )
            self._loaded = None
            return False

        logger.info(
            "GroupClassifier: loaded model with {} features and {} classes",
            len(self._loaded.feature_names),
            len(self._loaded.classes),
        )
        return True

    def classify(
        self,
        influx_rows: pl.DataFrame,
        series_ids_count: int,
        duration_seconds: float,
    ) -> GroupClassifierPrediction | None:
        """Classify a single alarm based on its underlying network rows.

        Args:
            influx_rows: Pre-filtered network metrics rows for the alarm
                (typically obtained via
                :func:`filter_rows_by_series_ids`).
            series_ids_count: Number of series_ids declared on the alarm.
            duration_seconds: Alarm duration in seconds.

        Returns:
            A :class:`GroupClassifierPrediction` or ``None`` if the
            classifier is inactive, the feature extraction failed, or
            the prediction confidence is below the configured threshold.
        """
        if self._loaded is None:
            return None
        if influx_rows.is_empty():
            return None

        feature_vector, _names = extract_alarm_features(
            influx_rows=influx_rows,
            series_ids_count=series_ids_count,
            duration_seconds=duration_seconds,
        )
        X = feature_vector.reshape(1, -1)

        if X.shape[1] != self._loaded.model.n_features_in_:
            logger.warning(
                "GroupClassifier: feature count mismatch (got {}, model expects {})",
                X.shape[1],
                self._loaded.model.n_features_in_,
            )
            return None

        X_scaled = self._loaded.scaler.transform(X)
        probabilities = self._loaded.model.predict_proba(X_scaled)[0]
        best_idx = int(np.argmax(probabilities))
        confidence = float(probabilities[best_idx])
        technical_method = str(self._loaded.model.classes_[best_idx])

        # Always log the top prediction so we can see what RF inferred
        # even when it falls under the configured threshold.
        top_three_idx = np.argsort(probabilities)[::-1][:3]
        top_three = [
            (str(self._loaded.model.classes_[i]), float(probabilities[i]))
            for i in top_three_idx
        ]
        logger.info(
            "GroupClassifier: top3={} (winner {:.3f})", top_three, confidence
        )

        if confidence < self._confidence_threshold:
            logger.info(
                "GroupClassifier: prediction '{}' below threshold ({:.3f} < {:.3f})",
                technical_method,
                confidence,
                self._confidence_threshold,
            )
            return None
        logger.debug(
            "GroupClassifier: predicted '{}' with confidence {:.3f}",
            technical_method,
            confidence,
        )

        mitre_label = self._mitre_map.get(technical_method, technical_method)
        return GroupClassifierPrediction(
            technical_method=technical_method,
            mitre_label=mitre_label,
            confidence=confidence,
            classified_at=datetime.utcnow(),
        )
