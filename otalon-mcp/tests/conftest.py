"""Shared pytest compatibility fixtures for MCP tests."""

import asyncio

import pytest


@pytest.fixture(autouse=True)
def ensure_event_loop() -> None:
    """Provide event loop compatibility for synchronous legacy test calls."""
    try:
        asyncio.get_event_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())
