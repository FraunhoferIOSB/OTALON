"""Preprocessing registry and implementations for data source transforms."""

from otalon_clas.preprocessing.base import BasePreprocessor
from otalon_clas.preprocessing.connection import ConnectionPreprocessor
from otalon_clas.preprocessing.passthrough import \
    PassthroughPreprocessor
from otalon_clas.preprocessing.registry import (PREPROCESSOR_REGISTRY,
                                                       get_preprocessor,
                                                       register_preprocessor)
from otalon_clas.preprocessing.sliding_window import \
    SlidingWindowPreprocessor
from otalon_clas.preprocessing.tag_encoding import \
    TagEncodingPreprocessor

__all__ = [
    "BasePreprocessor",
    "ConnectionPreprocessor",
    "PREPROCESSOR_REGISTRY",
    "PassthroughPreprocessor",
    "SlidingWindowPreprocessor",
    "TagEncodingPreprocessor",
    "get_preprocessor",
    "register_preprocessor",
]
