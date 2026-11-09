"""Configuration utilities for CyberScan-ICS.

Provides helpers to load JSON configuration files and merge runtime overrides
with default config files used by scanner modules.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

from loguru import logger


def load_json(file_path: str) -> Optional[Dict[str, Any]]:
    """Load a JSON file and return its dictionary content.

    Parameters
    ----------
    file_path:
        Path to a JSON file.

    Returns
    -------
    dict | None
        Parsed JSON as dictionary, or None if the file is missing/invalid.
    """
    if not file_path.endswith(".json"):
        logger.error("Invalid file type. Please provide a JSON file.")
        return None
    try:
        p = Path(file_path).expanduser()
        logger.debug("Loading JSON file: {p}", p=p)
        with p.open("r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                return data
            return None
    except FileNotFoundError:
        logger.error("The file '{file_path}' does not exist.", file_path=file_path)
    except json.JSONDecodeError:
        logger.error("Failed to decode JSON. Please check the file's content.")
    except Exception as exc:
        logger.exception("An error occurred reading JSON '{file_path}': {exc}", file_path=file_path, exc=exc)
    return None


def merge_configurations(partial_config: Dict[str, Any], path_full_config: str) -> Dict[str, Any]:
    """Merge a partial (override) config with a full config file.

    Values from partial_config take precedence over file values.

    Parameters
    ----------
    partial_config:
        Overrides provided at runtime (e.g., API payload).
    path_full_config:
        Path to a default JSON config file.

    Returns
    -------
    dict
        Merged configuration dictionary. Returns an empty dict on error.
    """
    try:
        base = load_json(path_full_config) or {}
        base.update(partial_config or {})
        return base
    except Exception as exc:
        logger.error("Failed to merge configurations: {exc}", exc=exc)
        return {}
