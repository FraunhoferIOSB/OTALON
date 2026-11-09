"""Shared test environment for protected otalon-ai surfaces."""

from __future__ import annotations

import os

os.environ.setdefault("OTALON_AI_ALLOWED_KEYS", "test:viewer:test-ai-key")
