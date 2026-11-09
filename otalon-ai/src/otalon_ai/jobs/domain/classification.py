"""Classification result models matching the paper's two-step JSON shape."""

from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field


class Step1Technical(BaseModel):
    """Step-1 attack-method identification."""

    technical_method: str = ""
    observed_activity: str = ""
    evidence: List[str] = Field(default_factory=list)


class Classification(BaseModel):
    """One MITRE classification candidate produced by the LLM."""

    technique_id: str
    technique_name: Optional[str] = None
    confidence: float = 0.0
    reasoning: str = ""
    variant: Optional[str] = None


class Step2Classification(BaseModel):
    """Step-2 MITRE-mapping result."""

    classifications: List[Classification] = Field(default_factory=list)


class ClassificationResult(BaseModel):
    """Full two-step classification produced by ``extract_two_step``."""

    step1_technical: Step1Technical
    step2_classification: Step2Classification

    @property
    def top_technique(self) -> Optional[Classification]:
        """Return the classification with the highest confidence (sorted)."""
        if not self.step2_classification.classifications:
            return None
        return self.step2_classification.classifications[0]
