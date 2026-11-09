"""Two-step JSON parsing helpers ported from the paper experiment.

These functions extract the LLM's two-step classification from a free-form
response. Three response shapes are supported in priority order:

1. Two-step: ``{"step1_technical": {...}, "step2_classification": {"classifications": [...]}, "verdict": {...}}``
2. Flat: ``{"classifications": [{...}]}``
3. Legacy single-object: ``{"technique_id": "T0846", ...}``

`<think>...</think>` blocks (Nemotron, DeepSeek-R1) are stripped before
JSON extraction.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

TECHNIQUE_ID_RE = re.compile(r"^T\d{4}$")


def _strip_thinking_tags(text: str) -> str:
    """Remove ``<think>...</think>`` blocks from reasoning-model output."""
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
    text = text.replace("<think>", "").replace("</think>", "")
    return text.strip()


def _try_parse_json_blocks(source: str) -> List[dict[str, Any]]:
    """Try to parse JSON objects from fenced blocks first, then raw text."""
    results: List[dict[str, Any]] = []

    fenced = re.findall(r"```(?:json)?\s*(\{.*?\})\s*```", source, re.DOTALL)
    for block in fenced:
        try:
            obj = json.loads(block)
            if isinstance(obj, dict):
                results.append(obj)
        except json.JSONDecodeError:
            continue

    if not results:
        raw = re.findall(
            r"\{[^{}]*(?:\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}[^{}]*)*\}",
            source,
            re.DOTALL,
        )
        for block in raw:
            try:
                obj = json.loads(block)
                if isinstance(obj, dict):
                    results.append(obj)
            except json.JSONDecodeError:
                continue

    return results


def _validate_classifications(items: List[Any]) -> List[dict[str, Any]]:
    """Filter classification dicts to those with a valid technique_id, sort by confidence."""
    valid = [
        c
        for c in items
        if isinstance(c, dict) and "technique_id" in c and TECHNIQUE_ID_RE.match(str(c["technique_id"]))
    ]
    valid.sort(key=lambda c: float(c.get("confidence", 0)), reverse=True)
    return valid


def extract_two_step(text: str) -> Optional[Dict[str, Any]]:
    """Extract the two-step classification from the assistant's free-form response.

    Returns a dict with keys ``technical_method``, ``observed_activity``,
    ``evidence``, ``classifications`` — or ``None`` if no valid classification
    can be extracted.
    """
    text = _strip_thinking_tags(text)
    parsed_objects = _try_parse_json_blocks(text)

    # 1) Two-step format
    for obj in parsed_objects:
        step1 = obj.get("step1_technical")
        step2 = obj.get("step2_classification")
        if isinstance(step1, dict) and isinstance(step2, dict):
            cls_list = step2.get("classifications", [])
            if isinstance(cls_list, list):
                valid = _validate_classifications(cls_list)
                return {
                    "technical_method": step1.get("technical_method", ""),
                    "observed_activity": step1.get("observed_activity", ""),
                    "evidence": step1.get("evidence", []),
                    "classifications": valid,
                    "verdict": obj.get("verdict"),
                }

    # 2) Flat classifications
    for obj in parsed_objects:
        if "classifications" in obj and isinstance(obj["classifications"], list):
            valid = _validate_classifications(obj["classifications"])
            top = valid[0] if valid else {}
            return {
                "technical_method": top.get("variant", ""),
                "observed_activity": top.get("reasoning", ""),
                "evidence": [],
                "classifications": valid,
            }

    # 3) Legacy single-object
    for obj in parsed_objects:
        tid = obj.get("technique_id")
        if tid and TECHNIQUE_ID_RE.match(str(tid)):
            return {
                "technical_method": obj.get("variant", ""),
                "observed_activity": obj.get("reasoning", ""),
                "evidence": [],
                "classifications": [obj],
            }

    return None
