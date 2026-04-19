"""Pydantic request / response models for the FastAPI service."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    """POST /analyze — submit raw log lines for analysis."""

    log_text: str = Field(..., description="Raw log text, one line per event.")
    detectors: list[str] | None = Field(
        default=None,
        description="Which detectors to run (default: all).",
    )
    enable_rules: bool = Field(default=True, description="Evaluate Sigma rules alongside detectors.")
    enable_mitre: bool = Field(default=True, description="Tag events with ATT&CK techniques.")


class DetectionResponse(BaseModel):
    event: dict[str, Any]
    detector: str
    score: float
    threshold: float
    explanation: str
    mitre_techniques: list[str]
    sigma_rule_id: str | None


class AnalyzeResponse(BaseModel):
    events_parsed: int
    detectors_run: list[str]
    detections: list[DetectionResponse]
    mitre_coverage: dict[str, int] = Field(
        default_factory=dict,
        description="Technique ID → count of detections touching it.",
    )


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str
    detectors: list[str]
    rules_loaded: int


class RulesListResponse(BaseModel):
    rules: list[dict[str, Any]]


class MitreCoverageResponse(BaseModel):
    techniques: list[dict[str, Any]]
