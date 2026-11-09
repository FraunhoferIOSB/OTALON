"""Capture-file domain helpers for the PCAP import path (UI-078, Wave B)."""

from __future__ import annotations

from otalon_api.domain.pcap_import.capture import (
    MAGIC_PREFIX_LENGTH,
    SUPPORTED_MAGICS,
    CaptureTimeRange,
    is_supported_magic,
    read_capture_time_range,
)

__all__ = [
    "MAGIC_PREFIX_LENGTH",
    "SUPPORTED_MAGICS",
    "CaptureTimeRange",
    "is_supported_magic",
    "read_capture_time_range",
]
