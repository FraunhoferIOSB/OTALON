"""Utility helpers used across otalon-scan modules and repositories.

Introduced by F-03 (``refactor-otalon-scan-device-network-ownership-v1``)
as the canonical home for cross-module pure helpers (MAC canonicalisation,
etc.). Helpers in this package SHALL be I/O-free, side-effect-free, and
suitable for ``mypy --strict``.
"""
