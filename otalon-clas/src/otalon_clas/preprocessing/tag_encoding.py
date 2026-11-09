"""Tag-encoding preprocessor for categorical-tag data sources.

Turns the categorical tag columns of the MAC-traffic and
protocol-traffic feature frames into stable numeric features **without
destroying the original string tag column**.

This exists because :class:`~otalon_clas.preprocessing.passthrough.PassthroughPreprocessor`
encodes tags *in place* (``.alias(col_name)``), which overwrites the
series-identity column the bounds detector, the frequency monitor and
the MITRE labelers all key on. With ``encode_tags = {"protocol": "hash"}``
the ``protocol`` column reaching
:class:`~otalon_clas.ml.labeling.ProtoLabeler` is an ``Int64`` such as
``1408324714``, so ``_proto_partial_match("1408324714", "arp")`` is
always ``False``, every training row collapses to ``benign`` and the
resulting classifier has exactly one class — which
:func:`otalon_common.types.is_ml_type` rejects, leaving the anomaly as a
bare ``BoundViolation``.

The encoded value is therefore published as a **separate** column
(``<tag><suffix>``, default ``protocol_code``) that is appended to the
ML feature list only, exactly mirroring how
:class:`~otalon_clas.preprocessing.connection.ConnectionPreprocessor`
treats its categorical ``protocols`` column.
"""

from __future__ import annotations

import hashlib
from typing import Any

import polars as pl
from loguru import logger

from otalon_clas.preprocessing.base import BasePreprocessor

HASH_MODULUS: int = 2**31
"""Default modulus for deterministic hash encoding of string tag values."""

UNKNOWN_CODE: int = 0
"""Reserved code for null and unseen tag values in dictionary mode."""

DICTIONARY_ENCODING: str = "dictionary"
"""Encoding that assigns stable codes from a persisted lookup map."""

HASH_ENCODING: str = "hash"
"""Encoding that derives the code from a cryptographic digest."""

SUPPORTED_ENCODINGS: frozenset[str] = frozenset({DICTIONARY_ENCODING, HASH_ENCODING})
"""Encoding names accepted in the ``encode_tags`` parameter."""

DEFAULT_CODE_SUFFIX: str = "_code"
"""Suffix appended to a tag column name to form its encoded column."""


def stable_hash(value: str, modulus: int = HASH_MODULUS) -> int:
    """Deterministically map a string to a non-negative integer.

    Uses SHA-256 rather than the built-in :func:`hash`, whose string
    hashing is salted per interpreter run via ``PYTHONHASHSEED``. A
    salted hash makes the training-time and inference-time encoding of
    the same tag differ across process restarts, which silently feeds
    the classifier a feature it never saw during training.

    Args:
        value: String tag value to encode.
        modulus: Positive modulus bounding the returned code.

    Returns:
        Stable non-negative integer in ``[0, modulus)``.
    """
    digest = hashlib.sha256(value.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") % modulus


class TagEncodingPreprocessor(BasePreprocessor):
    """Preprocessor that adds deterministic numeric codes for tag columns.

    Feature columns are null-filled to zero; each configured tag column
    keeps its original string value and gains a sibling ``Int64`` column
    carrying its numeric code.

    Args:
        tag_key: Tag column name identifying a time series
            (``"mac_address"``, ``"protocol"``).
        features: Ordered list of numeric feature column names used by
            the bounds detector and the frequency monitor.
        params: Optional dict. Supported keys: ``encode_tags`` mapping a
            column name to ``"dictionary"`` or ``"hash"``,
            ``code_suffix`` (default ``"_code"``) and ``hash_modulus``
            (default ``2**31``).
    """

    def __init__(
        self,
        tag_key: str,
        features: list[str],
        params: dict[str, Any] | None = None,
    ) -> None:
        """Initialize the tag-encoding preprocessor.

        Args:
            tag_key: Tag column name for series identification.
            features: Numeric feature column names.
            params: Optional parameters dict (see class docstring).

        Raises:
            ValueError: If an unsupported encoding name is configured or
                ``hash_modulus`` is not a positive integer.
        """
        resolved = params if params is not None else {}
        self._tag_key = tag_key
        self._features = list(features)
        self._code_suffix = str(resolved.get("code_suffix", DEFAULT_CODE_SUFFIX))
        self._hash_modulus = int(resolved.get("hash_modulus", HASH_MODULUS))
        self._encode_tags: dict[str, str] = dict(resolved.get("encode_tags", {tag_key: DICTIONARY_ENCODING}))
        self._validate_config()
        self._code_map: dict[str, int] = {}
        self._code_map_locked: bool = False

    def _validate_config(self) -> None:
        """Reject unusable encoding parameters at construction time.

        Raises:
            ValueError: On an unknown encoding name or a non-positive
                ``hash_modulus``.
        """
        if self._hash_modulus <= 0:
            raise ValueError(f"hash_modulus must be positive, got {self._hash_modulus}")
        unknown = {name: enc for name, enc in self._encode_tags.items() if enc not in SUPPORTED_ENCODINGS}
        if unknown:
            supported = sorted(SUPPORTED_ENCODINGS)
            raise ValueError(f"Unsupported tag encodings {unknown}; supported: {supported}")

    def preprocess_for_training(self, df: pl.DataFrame) -> pl.DataFrame:
        """Preprocess data for boundary and ML training.

        In dictionary mode the code map grows as new tag values are
        observed, so training defines the mapping that is later
        persisted alongside the model artifact.

        Args:
            df: Raw DataFrame from InfluxDB.

        Returns:
            Preprocessed DataFrame with nulls filled and code columns added.
        """
        return self._apply_preprocessing(df, mode="training")

    def preprocess_for_prediction(self, df: pl.DataFrame) -> pl.DataFrame:
        """Preprocess data for live or offline prediction.

        Applies the identical transform to training. When the code map
        has been restored from a model artifact and locked, unseen tag
        values resolve to :data:`UNKNOWN_CODE` instead of extending the
        map, so inference can never invent a code the model was not
        trained on.

        Args:
            df: Raw DataFrame from InfluxDB.

        Returns:
            Preprocessed DataFrame with nulls filled and code columns added.
        """
        return self._apply_preprocessing(df, mode="prediction")

    def get_tag_column(self) -> str:
        """Return the tag column name.

        Returns:
            The configured tag key string.
        """
        return self._tag_key

    def get_feature_columns(self) -> list[str]:
        """Return the ordered feature column list used by the classifier.

        The numeric metric features come first, followed by the encoded
        tag code columns. The raw ``features`` list stays untouched so
        the bounds detector never sees a categorical code — a bound on a
        code value is meaningless.

        Returns:
            List of feature column name strings.
        """
        cols = list(self._features)
        for name in self._encoded_column_names():
            if name not in cols:
                cols.append(name)
        return cols

    def _encoded_column_names(self) -> list[str]:
        """Return the encoded column name for every configured tag.

        Returns:
            Ordered list of ``<tag><suffix>`` column names.
        """
        return [f"{name}{self._code_suffix}" for name in sorted(self._encode_tags)]

    @property
    def protocol_map(self) -> dict[str, int]:
        """Return a copy of the tag-value-to-code mapping.

        Named ``protocol_map`` to match the artifact key already read by
        the model store and the runtime model loader, so the mapping is
        persisted and restored with no change to those call sites.

        Returns:
            Dict mapping tag value strings to their integer codes.
        """
        return dict(self._code_map)

    def load_protocol_map(self, mapping: dict[str, int], lock: bool = True) -> None:
        """Restore a previously trained tag-code mapping for inference.

        Args:
            mapping: ``tag-value -> code`` dict to load.
            lock: When True (default) unseen tag values receive
                :data:`UNKNOWN_CODE` instead of being added to the map.
        """
        self._code_map = dict(mapping)
        self._code_map_locked = lock
        logger.debug(
            "TagEncodingPreprocessor[{}]: loaded code map with {} entries (locked={})",
            self._tag_key,
            len(self._code_map),
            lock,
        )

    def _apply_preprocessing(self, df: pl.DataFrame, mode: str) -> pl.DataFrame:
        """Shared preprocessing pipeline for training and prediction.

        Args:
            df: Raw input DataFrame.
            mode: Pipeline mode label, ``"training"`` or ``"prediction"``.

        Returns:
            Preprocessed DataFrame.
        """
        if df.is_empty():
            logger.debug(
                "TagEncodingPreprocessor[{}]: empty input for {}, returning as-is",
                self._tag_key,
                mode,
            )
            return df

        df = self._fill_nulls(df)
        return self._add_code_columns(df, mode)

    def _fill_nulls(self, df: pl.DataFrame) -> pl.DataFrame:
        """Replace null values with zero in all numeric feature columns.

        Args:
            df: DataFrame potentially containing nulls.

        Returns:
            DataFrame with feature nulls filled to zero.
        """
        fill_exprs = [pl.col(col).fill_null(0).alias(col) for col in self._features if col in df.columns]
        if fill_exprs:
            df = df.with_columns(fill_exprs)
        return df

    def _add_code_columns(self, df: pl.DataFrame, mode: str) -> pl.DataFrame:
        """Append one Int64 code column per configured tag column.

        Args:
            df: DataFrame carrying the tag columns.
            mode: Pipeline mode label, used to decide map growth.

        Returns:
            DataFrame with the encoded columns appended.
        """
        for col_name, encoding in sorted(self._encode_tags.items()):
            target = f"{col_name}{self._code_suffix}"
            if col_name not in df.columns:
                logger.warning(
                    "TagEncodingPreprocessor[{}]: tag column '{}' missing, " "filling '{}' with the unknown code",
                    self._tag_key,
                    col_name,
                    target,
                )
                df = df.with_columns(pl.lit(UNKNOWN_CODE, dtype=pl.Int64).alias(target))
                continue
            values = df[col_name].cast(pl.Utf8).to_list()
            codes = self._encode_values(values, encoding, mode)
            df = df.with_columns(pl.Series(target, codes, dtype=pl.Int64))
        return df

    def _encode_values(
        self,
        values: list[str | None],
        encoding: str,
        mode: str,
    ) -> list[int]:
        """Encode a list of raw tag values into integer codes.

        Args:
            values: Raw tag values, possibly containing ``None``.
            encoding: Either ``"dictionary"`` or ``"hash"``.
            mode: Pipeline mode label, used to decide map growth.

        Returns:
            List of integer codes aligned with *values*.
        """
        if encoding == HASH_ENCODING:
            return [UNKNOWN_CODE if v is None else stable_hash(v, self._hash_modulus) for v in values]
        return self._encode_dictionary(values, mode)

    def _encode_dictionary(self, values: list[str | None], mode: str) -> list[int]:
        """Encode values through the stable, order-independent code map.

        New values are assigned codes in sorted order rather than in
        arrival order, so two processes fed the same set of tag values
        derive an identical map regardless of row ordering or batch
        splitting. Codes start at 1; :data:`UNKNOWN_CODE` stays reserved
        for null and unseen values.

        Args:
            values: Raw tag values, possibly containing ``None``.
            mode: Pipeline mode label. Growth is suppressed once the map
                has been locked by :meth:`load_protocol_map`.

        Returns:
            List of integer codes aligned with *values*.
        """
        if not self._code_map_locked:
            self._extend_code_map(values)
        unseen = 0
        codes: list[int] = []
        for value in values:
            if value is None:
                codes.append(UNKNOWN_CODE)
                continue
            code = self._code_map.get(value, UNKNOWN_CODE)
            if code == UNKNOWN_CODE:
                unseen += 1
            codes.append(code)
        if unseen:
            logger.debug(
                "TagEncodingPreprocessor[{}]: {} of {} {} values unseen, " "encoded as the unknown code",
                self._tag_key,
                unseen,
                len(values),
                mode,
            )
        return codes

    def _extend_code_map(self, values: list[str | None]) -> None:
        """Add codes for previously unseen values in sorted order.

        Args:
            values: Raw tag values, possibly containing ``None``.
        """
        new_values = sorted({v for v in values if v is not None} - set(self._code_map))
        next_code = max(self._code_map.values(), default=UNKNOWN_CODE) + 1
        for offset, value in enumerate(new_values):
            self._code_map[value] = next_code + offset
