"""Pipeline-level guards for the CLAS-004 blocker chain.

CLAS-004 asks why a ``mac_traffic`` / ``proto_traffic`` anomaly carries
no MITRE technique. Three independent blockers sit between the raw frame
and a labelled anomaly. The encoder shipped with this ticket removes the
first one; the other two are pinned here so the follow-up ticket has an
executable definition of what is still broken.

Blocker 1 (fixed): the configured preprocessor destroyed the tag column
the labeler matches on.
Blocker 2 (open): no ``mac_traffic`` / ``proto_traffic`` classifier
artifact exists, so the ML gate closes and fusion falls through to
``BoundViolation``.
Blocker 3 (open): the prediction path demands ``uci`` / ``_bucket_epoch``
join keys that only the ``conn`` preprocessor produces.
"""

from __future__ import annotations

import polars as pl
import pytest
from otalon_common.types import AnomalyType, is_ml_type

from otalon_clas.common.config_validator import KNOWN_PREPROCESSOR_TYPES
from otalon_clas.detection.fusion import _resolve_single_row
from otalon_clas.preprocessing.registry import PREPROCESSOR_REGISTRY
from otalon_clas.preprocessing.tag_encoding import TagEncodingPreprocessor

pytestmark = pytest.mark.unit

ML_JOIN_KEYS: tuple[str, ...] = ("uci", "_bucket_epoch")
"""Join keys required by ``main.py::_run_ml_prediction`` (main.py:1255)."""


class TestFusionFallsBackToBoundViolation:
    """Without an ML type, fusion can only emit BoundViolation."""

    def test_bound_violation_without_ml_stays_unlabelled(self) -> None:
        """No ML type in, no MITRE technique out (fusion.py:313)."""
        result = _resolve_single_row(
            {
                "anomaly_type": AnomalyType.BOUND_VIOLATION,
                "is_anomaly": True,
                "confidence": 0.9,
                "ml_type": None,
                "ml_confidence": 0.0,
            }
        )
        assert result.anomaly_type == AnomalyType.BOUND_VIOLATION
        assert not is_ml_type(result.anomaly_type)

    def test_bound_violation_with_ml_adopts_the_technique(self) -> None:
        """With an ML type present the technique wins (fusion.py:283)."""
        result = _resolve_single_row(
            {
                "anomaly_type": AnomalyType.BOUND_VIOLATION,
                "is_anomaly": True,
                "confidence": 0.4,
                "ml_type": "T0842/arp_scan",
                "ml_confidence": 0.8,
            }
        )
        assert result.anomaly_type == "T0842/arp_scan"
        assert is_ml_type(result.anomaly_type)
        assert result.confidence == pytest.approx(0.8)

    def test_benign_ml_type_does_not_count_as_a_technique(self) -> None:
        """A single-class ``benign`` model cannot produce a label.

        This is the downstream consequence of the labeling blocker: even
        a successfully trained model whose only class is ``benign`` is
        rejected by :func:`is_ml_type`.
        """
        assert not is_ml_type("benign")


class TestOpenBlockers:
    """Executable record of what CLAS-004 does not yet fix."""

    def test_tag_encoding_frame_lacks_the_ml_join_keys(self) -> None:
        """Blocker 3: mac/proto frames carry neither join key.

        ``_run_ml_prediction`` raises ``MLPredictionError`` when neither
        ``uci`` nor ``_bucket_epoch`` is present (main.py:1255-1257), so
        even a trained mac/proto model would never score a row.
        """
        encoder = TagEncodingPreprocessor(
            "protocol",
            ["proto_conn_count"],
            {"encode_tags": {"protocol": "dictionary"}},
        )
        out = encoder.preprocess_for_prediction(
            pl.DataFrame(
                {
                    "time": ["2026-04-18T22:00:00Z"],
                    "protocol": ["ethernet:arp"],
                    "proto_conn_count": [3],
                }
            )
        )
        assert [k for k in ML_JOIN_KEYS if k in out.columns] == []

    def test_config_validator_whitelist_lags_the_registry(self) -> None:
        """Blocker 2b: a second hardcoded whitelist gates config.json.

        ``main.py:106-109`` calls ``sys.exit(1)`` on any validation
        error, so pointing a module at ``tag_encoding`` before
        ``KNOWN_PREPROCESSOR_TYPES`` learns the key would stop the
        service from booting. Fixing that list is outside the CLAS-004
        file scope; this test documents the coupling.
        """
        assert "tag_encoding" in PREPROCESSOR_REGISTRY
        assert "tag_encoding" not in KNOWN_PREPROCESSOR_TYPES
