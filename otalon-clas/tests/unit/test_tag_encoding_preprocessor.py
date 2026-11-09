"""Unit tests for :mod:`otalon_clas.preprocessing.tag_encoding` (CLAS-004).

Covers the three properties the ticket requires of the encoder:
determinism across independent instances and processes, explicit
handling of unseen tag values at inference time, and preservation of the
raw string tag column that the MITRE labelers and the bounds detector
key on.
"""

from __future__ import annotations

import subprocess
import sys

import pandas as pd
import polars as pl
import pytest

from otalon_clas.ml.labeling import MitreLabel, ProtoLabeler
from otalon_clas.preprocessing.base import BasePreprocessor
from otalon_clas.preprocessing.passthrough import PassthroughPreprocessor
from otalon_clas.preprocessing.registry import get_preprocessor
from otalon_clas.preprocessing.tag_encoding import UNKNOWN_CODE, TagEncodingPreprocessor, stable_hash

pytestmark = pytest.mark.unit

PROTO_FEATURES: list[str] = ["proto_conn_count", "proto_total_packets"]
MAC_FEATURES: list[str] = ["out_conn_count", "in_conn_count"]


def _proto_frame(protocols: list[str]) -> pl.DataFrame:
    """Build a minimal proto_traffic-shaped frame.

    Args:
        protocols: Protocol tag values, one per row.

    Returns:
        DataFrame with ``time``, ``protocol`` and the proto features.
    """
    n = len(protocols)
    return pl.DataFrame(
        {
            "time": [pd.Timestamp("2026-04-18T22:00:00Z")] * n,
            "protocol": protocols,
            "proto_conn_count": list(range(1, n + 1)),
            "proto_total_packets": list(range(10, 10 + n)),
        }
    )


def _mac_frame(macs: list[str]) -> pl.DataFrame:
    """Build a minimal mac_traffic-shaped frame.

    Args:
        macs: MAC tag values, one per row.

    Returns:
        DataFrame with ``time``, ``mac_address`` and the MAC features.
    """
    n = len(macs)
    return pl.DataFrame(
        {
            "time": [pd.Timestamp("2026-04-18T22:00:00Z")] * n,
            "mac_address": macs,
            "out_conn_count": list(range(1, n + 1)),
            "in_conn_count": list(range(5, 5 + n)),
        }
    )


def _proto_encoder(**params: object) -> TagEncodingPreprocessor:
    """Construct a proto_traffic tag encoder.

    Args:
        **params: Extra preprocessor params merged over the defaults.

    Returns:
        A configured :class:`TagEncodingPreprocessor`.
    """
    merged: dict[str, object] = {"encode_tags": {"protocol": "dictionary"}}
    merged.update(params)
    return TagEncodingPreprocessor("protocol", PROTO_FEATURES, merged)


class TestContract:
    """The preprocessor honours the BasePreprocessor contract."""

    def test_is_registered_under_tag_encoding(self) -> None:
        """The registry resolves the new key to the new class."""
        assert get_preprocessor("tag_encoding") is TagEncodingPreprocessor

    def test_subclasses_base_preprocessor(self) -> None:
        """The class implements the abstract preprocessor contract."""
        assert issubclass(TagEncodingPreprocessor, BasePreprocessor)

    def test_get_tag_column_returns_configured_key(self) -> None:
        """The tag column is reported unchanged."""
        assert _proto_encoder().get_tag_column() == "protocol"

    def test_feature_columns_append_code_after_metrics(self) -> None:
        """Encoded codes extend, but never reorder, the metric features."""
        cols = _proto_encoder().get_feature_columns()
        assert cols == [*PROTO_FEATURES, "protocol_code"]

    def test_empty_frame_passes_through(self) -> None:
        """An empty input frame is returned as-is, not raised on."""
        empty = _proto_frame([])
        assert _proto_encoder().preprocess_for_prediction(empty).is_empty()

    def test_rejects_unknown_encoding_name(self) -> None:
        """A typo in encode_tags fails loudly at construction."""
        with pytest.raises(ValueError, match="Unsupported tag encodings"):
            TagEncodingPreprocessor("protocol", PROTO_FEATURES, {"encode_tags": {"protocol": "onehot"}})

    def test_rejects_non_positive_hash_modulus(self) -> None:
        """A zero modulus would make every hash code collide on 0."""
        with pytest.raises(ValueError, match="hash_modulus must be positive"):
            TagEncodingPreprocessor("protocol", PROTO_FEATURES, {"hash_modulus": 0})


class TestOutputShape:
    """Encoding adds a numeric column without destroying the tag."""

    def test_raw_tag_column_survives_as_string(self) -> None:
        """The string tag column is preserved for labeling and bounds.

        This is the regression guard for CLAS-004: ``PassthroughPreprocessor``
        overwrote ``protocol`` in place with its hash code.
        """
        out = _proto_encoder().preprocess_for_training(_proto_frame(["ethernet:arp", "ethernet:ipv4:tcp"]))
        assert out["protocol"].dtype == pl.Utf8
        assert out["protocol"].to_list() == ["ethernet:arp", "ethernet:ipv4:tcp"]

    def test_code_column_is_int64(self) -> None:
        """The generated code column has the dtype the model expects."""
        out = _proto_encoder().preprocess_for_training(_proto_frame(["ethernet:arp"]))
        assert out["protocol_code"].dtype == pl.Int64

    def test_all_feature_columns_present_and_numeric(self) -> None:
        """Every declared feature column is present and numerically typed."""
        encoder = _proto_encoder()
        out = encoder.preprocess_for_training(_proto_frame(["a", "b", "c"]))
        for col in encoder.get_feature_columns():
            assert col in out.columns
            assert out[col].dtype.is_numeric()

    def test_feature_nulls_filled_with_zero(self) -> None:
        """Null metric values become zero rather than propagating."""
        frame = _proto_frame(["ethernet:arp"]).with_columns(pl.lit(None, dtype=pl.Int64).alias("proto_conn_count"))
        out = _proto_encoder().preprocess_for_training(frame)
        assert out["proto_conn_count"].to_list() == [0]

    def test_custom_code_suffix_is_honoured(self) -> None:
        """The encoded column name follows the configured suffix."""
        encoder = _proto_encoder(code_suffix="_enc")
        out = encoder.preprocess_for_training(_proto_frame(["ethernet:arp"]))
        assert "protocol_enc" in out.columns

    def test_missing_tag_column_yields_unknown_code(self) -> None:
        """A frame without the tag column does not crash the pipeline."""
        frame = _proto_frame(["ethernet:arp"]).drop("protocol")
        out = _proto_encoder().preprocess_for_training(frame)
        assert out["protocol_code"].to_list() == [UNKNOWN_CODE]


class TestDeterminism:
    """Encoding is stable across instances, orderings and processes."""

    def test_two_independent_instances_agree(self) -> None:
        """Two separately constructed encoders produce identical codes."""
        frame = _proto_frame(["ethernet:arp", "ethernet:ipv4:tcp", "ethernet:ipv4:udp"])
        first = _proto_encoder().preprocess_for_training(frame)
        second = _proto_encoder().preprocess_for_training(frame)
        assert first["protocol_code"].to_list() == second["protocol_code"].to_list()

    def test_row_order_does_not_change_codes(self) -> None:
        """Codes depend on the value set, not on arrival order.

        Arrival-order codes would differ between the training batch and a
        live batch that happens to see the same protocols in another
        order, silently shifting the feature under the model.
        """
        values = ["ethernet:arp", "ethernet:ipv4:tcp", "ethernet:ipv4:udp"]
        forward = _proto_encoder().preprocess_for_training(_proto_frame(values))
        reverse = _proto_encoder().preprocess_for_training(_proto_frame(list(reversed(values))))
        forward_map = dict(zip(forward["protocol"].to_list(), forward["protocol_code"].to_list()))
        reverse_map = dict(zip(reverse["protocol"].to_list(), reverse["protocol_code"].to_list()))
        assert forward_map == reverse_map

    def test_batch_split_matches_single_batch(self) -> None:
        """Processing in two batches yields the same map as one batch."""
        values = ["ethernet:arp", "ethernet:ipv4:tcp", "ethernet:ipv4:udp"]
        whole = _proto_encoder()
        whole.preprocess_for_training(_proto_frame(values))

        split = _proto_encoder()
        split.preprocess_for_training(_proto_frame(values[:2]))
        split.preprocess_for_training(_proto_frame(values[2:]))

        assert whole.protocol_map == split.protocol_map

    def test_hash_encoding_is_stable_across_processes(self) -> None:
        """SHA-256 hashing survives a fresh interpreter and PYTHONHASHSEED.

        Python's built-in ``hash`` of a string is salted per process, so
        an encoder built on it maps the same protocol to different codes
        after a restart.
        """
        expected = stable_hash("ethernet:arp")
        script = "from otalon_clas.preprocessing.tag_encoding import stable_hash;" "print(stable_hash('ethernet:arp'))"
        seen = {
            subprocess.run(
                [sys.executable, "-c", script],
                capture_output=True,
                text=True,
                check=True,
                env={"PYTHONHASHSEED": seed, "PATH": "/usr/bin:/bin"},
            ).stdout.strip()
            for seed in ("0", "1", "12345")
        }
        assert seen == {str(expected)}

    def test_hash_encoding_matches_between_instances(self) -> None:
        """Hash mode needs no shared state to agree across instances."""
        frame = _proto_frame(["ethernet:arp", "ethernet:ipv4:tcp"])
        params = {"encode_tags": {"protocol": "hash"}}
        first = TagEncodingPreprocessor("protocol", PROTO_FEATURES, params)
        second = TagEncodingPreprocessor("protocol", PROTO_FEATURES, params)
        assert (
            first.preprocess_for_training(frame)["protocol_code"].to_list()
            == second.preprocess_for_prediction(frame)["protocol_code"].to_list()
        )

    def test_code_map_roundtrips_through_persistence(self) -> None:
        """A restored map reproduces the training-time codes exactly.

        This is the mechanism that carries determinism across a restart:
        the map travels with the model artifact via ``protocol_map``.
        """
        frame = _proto_frame(["ethernet:arp", "ethernet:ipv4:tcp"])
        trained = _proto_encoder()
        expected = trained.preprocess_for_training(frame)["protocol_code"].to_list()

        restored = _proto_encoder()
        restored.load_protocol_map(trained.protocol_map, lock=True)
        assert restored.preprocess_for_prediction(frame)["protocol_code"].to_list() == expected


class TestUnseenValues:
    """Unknown tag values at inference are handled, never fatal."""

    def test_locked_map_encodes_unseen_value_as_unknown(self) -> None:
        """An unseen protocol gets the reserved code, not a fresh one."""
        trained = _proto_encoder()
        trained.preprocess_for_training(_proto_frame(["ethernet:arp"]))

        live = _proto_encoder()
        live.load_protocol_map(trained.protocol_map, lock=True)
        out = live.preprocess_for_prediction(_proto_frame(["ethernet:ipv4:sctp"]))
        assert out["protocol_code"].to_list() == [UNKNOWN_CODE]

    def test_locked_map_is_not_mutated_by_unseen_value(self) -> None:
        """Inference never extends a locked map behind the model's back."""
        trained = _proto_encoder()
        trained.preprocess_for_training(_proto_frame(["ethernet:arp"]))

        live = _proto_encoder()
        live.load_protocol_map(trained.protocol_map, lock=True)
        live.preprocess_for_prediction(_proto_frame(["ethernet:ipv4:sctp"]))
        assert live.protocol_map == trained.protocol_map

    def test_known_values_still_resolve_alongside_unseen_ones(self) -> None:
        """A mixed batch keeps known codes and flags only the unknown."""
        trained = _proto_encoder()
        trained.preprocess_for_training(_proto_frame(["ethernet:arp"]))
        known_code = trained.protocol_map["ethernet:arp"]

        live = _proto_encoder()
        live.load_protocol_map(trained.protocol_map, lock=True)
        out = live.preprocess_for_prediction(_proto_frame(["ethernet:arp", "ethernet:ipv4:sctp"]))
        assert out["protocol_code"].to_list() == [known_code, UNKNOWN_CODE]

    def test_null_tag_value_encodes_as_unknown(self) -> None:
        """A null tag never raises and never collides with a real code."""
        frame = _proto_frame(["ethernet:arp"]).with_columns(pl.lit(None, dtype=pl.Utf8).alias("protocol"))
        out = _proto_encoder().preprocess_for_training(frame)
        assert out["protocol_code"].to_list() == [UNKNOWN_CODE]

    def test_unlocked_map_grows_for_new_values(self) -> None:
        """Training mode still learns codes for newly observed values."""
        encoder = _proto_encoder()
        encoder.preprocess_for_training(_proto_frame(["ethernet:arp"]))
        encoder.preprocess_for_training(_proto_frame(["ethernet:ipv4:tcp"]))
        assert set(encoder.protocol_map) == {"ethernet:arp", "ethernet:ipv4:tcp"}

    def test_no_real_value_receives_the_unknown_code(self) -> None:
        """Codes start at 1 so ``0`` unambiguously means unknown."""
        encoder = _proto_encoder()
        encoder.preprocess_for_training(_proto_frame(["a", "b", "c"]))
        assert UNKNOWN_CODE not in encoder.protocol_map.values()


class TestMacModule:
    """The same encoder serves the mac_traffic module."""

    def test_mac_address_encoded_and_preserved(self) -> None:
        """The MAC tag keeps its string form and gains a code column."""
        encoder = TagEncodingPreprocessor("mac_address", MAC_FEATURES, {"encode_tags": {"mac_address": "dictionary"}})
        out = encoder.preprocess_for_training(_mac_frame(["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"]))
        assert out["mac_address"].dtype == pl.Utf8
        assert out["mac_address_code"].dtype == pl.Int64
        assert encoder.get_feature_columns() == [*MAC_FEATURES, "mac_address_code"]

    def test_defaults_to_encoding_the_tag_key(self) -> None:
        """Omitting encode_tags encodes the module's own tag key."""
        encoder = TagEncodingPreprocessor("mac_address", MAC_FEATURES)
        out = encoder.preprocess_for_training(_mac_frame(["aa:bb:cc:dd:ee:ff"]))
        assert "mac_address_code" in out.columns


class TestLabelingRegression:
    """The encoder keeps the MITRE labeler able to match (CLAS-004)."""

    @staticmethod
    def _arp_label() -> MitreLabel:
        """Return a ground-truth ARP-scan label covering the test window.

        Returns:
            A single :class:`MitreLabel` for protocol ``arp``.
        """
        return MitreLabel(
            module_name="T0842/arp_scan",
            technical_method="arp_scan",
            start_time=pd.Timestamp("2026-04-18T21:59:00Z"),
            end_time=pd.Timestamp("2026-04-18T22:01:00Z"),
            target_ip=[],
            target_mac=["aa:bb:cc:dd:ee:ff"],
            protocol="arp",
            source_ip="",
            source_mac="",
        )

    def test_passthrough_hash_destroys_the_label_match(self) -> None:
        """Red guard: the old config makes every training row benign.

        ``PassthroughPreprocessor`` replaces ``protocol`` with its hash,
        so ``ProtoLabeler`` compares ``"arp"`` against ``"1737447090"``
        and matches nothing. A single-class training set cannot yield a
        MITRE technique, which is why the anomaly stays a bare
        ``BoundViolation``.
        """
        legacy = PassthroughPreprocessor("protocol", PROTO_FEATURES, {"encode_tags": {"protocol": "hash"}})
        out = legacy.preprocess_for_training(_proto_frame(["ethernet:arp"]))
        labeled = ProtoLabeler([self._arp_label()], label_field="technical_method").apply_labels(out)
        assert labeled["label"].to_list() == ["benign"]

    def test_tag_encoding_preserves_the_label_match(self) -> None:
        """Green: the new encoder lets the labeler assign the technique."""
        out = _proto_encoder().preprocess_for_training(_proto_frame(["ethernet:arp"]))
        labeled = ProtoLabeler([self._arp_label()], label_field="technical_method").apply_labels(out)
        assert labeled["label"].to_list() == ["arp_scan"]

    def test_tag_encoding_yields_more_than_one_class(self) -> None:
        """A trainable label set needs both an attack and a benign class."""
        frame = _proto_frame(["ethernet:arp", "ethernet:ipv4:tcp"])
        out = _proto_encoder().preprocess_for_training(frame)
        labeled = ProtoLabeler([self._arp_label()], label_field="technical_method").apply_labels(out)
        assert set(labeled["label"].to_list()) == {"arp_scan", "benign"}
