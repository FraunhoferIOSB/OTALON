"""Passthrough preprocessor with optional tag encoding.

Minimal preprocessing for data sources that do not require UCI expansion
or port collapsing (e.g., MAC traffic, protocol traffic). Supports
optional integer or hash encoding of categorical tag columns.
"""

from __future__ import annotations

import hashlib
from typing import Any

import polars as pl
from loguru import logger

from otalon_clas.preprocessing.base import BasePreprocessor

HASH_MODULUS: int = 2**31
"""Modulus for deterministic hash encoding of string tag values."""


def _stable_hash(value: str) -> int:
    """Deterministically hash a string into a non-negative integer.

    Uses SHA-1 instead of the built-in ``hash`` so the same string maps
    to the same integer across processes. Python's ``hash`` of strings is
    salted per interpreter run (``PYTHONHASHSEED``), which made trained
    bounds keyed by the encoded ``protocol`` value unreachable at
    detection time (every series resolved to ``NoBounds``).

    Args:
        value: String tag value to encode.

    Returns:
        Stable non-negative integer in ``[0, HASH_MODULUS)``.
    """
    digest = hashlib.sha1(value.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") % HASH_MODULUS


class PassthroughPreprocessor(BasePreprocessor):
    """Preprocessor that passes features through with null filling and optional tag encoding.

    For data sources like MAC traffic or protocol traffic where the raw
    InfluxDB data is already in the expected structure.

    Args:
        tag_key: Tag column name (e.g., ``"mac_address"``, ``"protocol"``).
        features: Ordered list of feature column names.
        params: Optional dict with key ``encode_tags`` mapping tag column
            names to encoding type (``"integer"`` or ``"hash"``).
    """

    def __init__(
        self,
        tag_key: str,
        features: list[str],
        params: dict[str, Any] | None = None,
    ) -> None:
        """Initialize the passthrough preprocessor.

        Args:
            tag_key: Tag column name for series identification.
            features: Feature column names.
            params: Optional parameters dict. Supported keys:
                ``encode_tags`` — dict mapping column names to encoding type.
        """
        self._tag_key = tag_key
        self._features = list(features)
        resolved_params = params if params is not None else {}
        self._encode_tags: dict[str, str] = resolved_params.get("encode_tags", {})

    def preprocess_for_training(self, df: pl.DataFrame) -> pl.DataFrame:
        """Preprocess data for training with null filling and tag encoding.

        Args:
            df: Raw DataFrame from InfluxDB.

        Returns:
            Preprocessed DataFrame with nulls filled and tags encoded.
        """
        return self._apply_preprocessing(df, mode="training")

    def preprocess_for_prediction(self, df: pl.DataFrame) -> pl.DataFrame:
        """Preprocess data for prediction with null filling and tag encoding.

        Applies the same pipeline as training.

        Args:
            df: Raw DataFrame from InfluxDB.

        Returns:
            Preprocessed DataFrame with nulls filled and tags encoded.
        """
        return self._apply_preprocessing(df, mode="prediction")

    def get_tag_column(self) -> str:
        """Return the tag column name.

        Returns:
            The configured tag key string.
        """
        return self._tag_key

    def get_feature_columns(self) -> list[str]:
        """Return the ordered feature column list.

        Returns:
            List of feature column name strings.
        """
        return list(self._features)

    def _apply_preprocessing(self, df: pl.DataFrame, mode: str) -> pl.DataFrame:
        """Shared preprocessing pipeline for training and prediction.

        Args:
            df: Raw input DataFrame.
            mode: Pipeline mode label for logging.

        Returns:
            Preprocessed DataFrame.
        """
        if df.is_empty():
            logger.debug(
                "PassthroughPreprocessor: empty input for {}, returning as-is", mode
            )
            return df

        logger.debug(
            "PassthroughPreprocessor: {} mode, {} rows, encode_tags={}",
            mode,
            len(df),
            list(self._encode_tags.keys()),
        )

        df = self._fill_nulls(df)
        df = self._encode_tag_columns(df)
        return df

    def _fill_nulls(self, df: pl.DataFrame) -> pl.DataFrame:
        """Replace null values with zero in all feature columns.

        Args:
            df: DataFrame potentially containing nulls in feature columns.

        Returns:
            DataFrame with nulls filled to zero.
        """
        fill_exprs = [
            pl.col(col).fill_null(0).alias(col)
            for col in self._features
            if col in df.columns
        ]
        if fill_exprs:
            df = df.with_columns(fill_exprs)
        return df

    def _encode_tag_columns(self, df: pl.DataFrame) -> pl.DataFrame:
        """Apply integer or hash encoding to configured tag columns.

        Args:
            df: DataFrame with tag columns to encode.

        Returns:
            DataFrame with encoded tag columns.
        """
        for col_name, encoding_type in self._encode_tags.items():
            if col_name not in df.columns:
                logger.warning(
                    "PassthroughPreprocessor: encode_tags column '{}' not found in DataFrame",
                    col_name,
                )
                continue

            if encoding_type == "integer":
                df = _apply_integer_encoding(df, col_name)
            elif encoding_type == "hash":
                df = _apply_hash_encoding(df, col_name)
            else:
                logger.warning(
                    "PassthroughPreprocessor: unknown encoding type '{}' for column '{}'",
                    encoding_type,
                    col_name,
                )
        return df


def _apply_integer_encoding(df: pl.DataFrame, col_name: str) -> pl.DataFrame:
    """Encode a string column as consecutive integers via a lookup dictionary.

    Creates a deterministic mapping from sorted unique string values to
    integer indices starting at 1. Unknown values (nulls) are mapped to 0.

    Args:
        df: DataFrame containing the column to encode.
        col_name: Name of the string column to encode.

    Returns:
        DataFrame with the column replaced by integer values.
    """
    unique_values = sorted(df[col_name].drop_nulls().unique().to_list())
    lookup: dict[str, int] = {val: idx + 1 for idx, val in enumerate(unique_values)}
    logger.debug(
        "PassthroughPreprocessor: integer encoding '{}' with {} unique values",
        col_name,
        len(lookup),
    )
    return df.with_columns(
        pl.col(col_name)
        .replace_strict(lookup, default=0)
        .cast(pl.Int64)
        .alias(col_name)
    )


def _apply_hash_encoding(df: pl.DataFrame, col_name: str) -> pl.DataFrame:
    """Encode a string column using a deterministic hash function.

    Applies a stable SHA-1-based hash modulo ``2**31`` to produce a
    non-negative integer that is identical across processes.

    Args:
        df: DataFrame containing the column to encode.
        col_name: Name of the string column to encode.

    Returns:
        DataFrame with the column replaced by hash-encoded integer values.
    """
    logger.debug("PassthroughPreprocessor: hash encoding column '{}'", col_name)
    return df.with_columns(
        pl.col(col_name)
        .map_elements(
            lambda s: _stable_hash(s) if s is not None else 0, return_dtype=pl.Int64
        )
        .alias(col_name)
    )
