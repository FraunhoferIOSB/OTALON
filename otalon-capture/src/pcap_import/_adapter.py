"""Resolve the adapter package across this subproject's two import layouts.

``otalon_capture`` is importable under two different module paths depending on
where the interpreter is rooted:

* in the container the source root is on ``PYTHONPATH`` (``/app/src``), so the
  adapter is ``otalon_capture``;
* in the dev tree the workspace root wins, where ``otalon-capture`` is the
  subproject directory and the adapter is ``otalon-capture.src.otalon_capture``
  (the path the existing tests in this subproject already use).

The import worker reuses the adapter's pipeline, so it must reach it under
either layout. Resolving it here keeps that single concern in one place instead
of scattering conditional imports through the worker.
"""

from __future__ import annotations

from importlib import import_module
from types import ModuleType

_CANDIDATE_ROOTS = ("otalon_capture", "otalon-capture.src.otalon_capture")


def adapter_module(name: str) -> ModuleType:
    """Import ``name`` from the adapter package under whichever layout applies.

    Args:
        name: Module name relative to the adapter package, e.g. ``"pipeline"``.

    Returns:
        The imported module.

    Raises:
        ModuleNotFoundError: When the module is absent under every known layout.
    """

    last_error: ModuleNotFoundError | None = None
    for root in _CANDIDATE_ROOTS:
        try:
            return import_module(f"{root}.{name}")
        except ModuleNotFoundError as error:
            last_error = error
    raise ModuleNotFoundError(f"Adapter module '{name}' not found under any of {_CANDIDATE_ROOTS}.") from last_error


_pipeline = adapter_module("pipeline")
_settings = adapter_module("settings")

CapturePipeline = _pipeline.CapturePipeline
PipelineResult = _pipeline.PipelineResult
CaptureType = _settings.CaptureType
Settings = _settings.Settings

__all__ = [
    "CapturePipeline",
    "PipelineResult",
    "CaptureType",
    "Settings",
    "adapter_module",
]
