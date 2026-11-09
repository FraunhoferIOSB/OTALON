"""Unit tests for :func:`src.jobs.parsing.extract_two_step`."""

from __future__ import annotations

import pytest

from otalon_ai.jobs.parsing import extract_two_step


@pytest.mark.unit
def test_two_step_with_classifications() -> None:
    text = """```json
{
  "step1_technical": {
    "technical_method": "Modbus abuse",
    "observed_activity": "Write to coil",
    "evidence": ["pcap"]
  },
  "step2_classification": {
    "classifications": [
      {"technique_id": "T0846", "confidence": 0.92}
    ]
  }
}
```"""
    result = extract_two_step(text)
    assert result is not None
    assert result["technical_method"] == "Modbus abuse"
    assert len(result["classifications"]) == 1
    assert result["classifications"][0]["technique_id"] == "T0846"


@pytest.mark.unit
def test_two_step_empty_classifications_returns_dict() -> None:
    """A valid two-step JSON with empty classifications must NOT return None."""
    text = """```json
{
  "step1_technical": {
    "technical_method": "Bounds/jitter",
    "observed_activity": "Normal variance",
    "evidence": []
  },
  "step2_classification": {
    "classifications": []
  }
}
```"""
    result = extract_two_step(text)
    assert result is not None
    assert result["technical_method"] == "Bounds/jitter"
    assert result["classifications"] == []


@pytest.mark.unit
def test_flat_empty_classifications_returns_dict() -> None:
    """A flat JSON with empty classifications must NOT return None."""
    text = '{"classifications": []}'
    result = extract_two_step(text)
    assert result is not None
    assert result["classifications"] == []


@pytest.mark.unit
def test_unparseable_text_returns_none() -> None:
    """Text with no JSON at all must return None (genuine parse failure)."""
    result = extract_two_step("No JSON here at all.")
    assert result is None


@pytest.mark.unit
def test_invalid_json_shape_returns_none() -> None:
    """JSON present but missing required keys → None."""
    result = extract_two_step('{"foo": "bar"}')
    assert result is None


@pytest.mark.unit
def test_legacy_single_object() -> None:
    text = '{"technique_id": "T0846", "confidence": 0.8}'
    result = extract_two_step(text)
    assert result is not None
    assert len(result["classifications"]) == 1
    assert result["classifications"][0]["technique_id"] == "T0846"
