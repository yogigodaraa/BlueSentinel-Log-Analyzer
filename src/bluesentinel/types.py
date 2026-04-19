"""Shared types used across parsers, detectors, enrichment, rules."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Event severity. Maps to typical SOC alert levels."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class LogEvent:
    """A single parsed log line after template extraction.

    Follows (a loose subset of) the Elastic Common Schema. We keep it
    intentionally small — detectors can query additional fields through
    `raw` if they need to — and serialisable so events round-trip through
    JSON / SQLite / Kafka without custom codecs.
    """

    # What happened
    timestamp: datetime
    message: str

    # Who / where
    host: str | None = None
    user: str | None = None
    source_ip: str | None = None

    # Process
    process_name: str | None = None
    process_pid: int | None = None

    # Template (filled in by the parser)
    template_id: int | None = None
    template: str | None = None
    template_params: list[str] = field(default_factory=list)

    # Severity (filled in post-parse by enrichment)
    severity: Severity = Severity.INFO

    # MITRE ATT&CK technique IDs (filled in by enrichment)
    mitre_techniques: list[str] = field(default_factory=list)

    # Everything else from the raw log line
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "message": self.message,
            "host": self.host,
            "user": self.user,
            "source_ip": self.source_ip,
            "process_name": self.process_name,
            "process_pid": self.process_pid,
            "template_id": self.template_id,
            "template": self.template,
            "template_params": self.template_params,
            "severity": self.severity.value,
            "mitre_techniques": self.mitre_techniques,
            "raw": self.raw,
        }


@dataclass
class Detection:
    """A single anomaly flagged by a detector."""

    event: LogEvent
    detector: str
    score: float
    """Higher = more anomalous. Units are detector-specific."""

    threshold: float
    """The threshold this score crossed."""

    explanation: str = ""
    """Why the detector flagged this — plain English."""

    mitre_techniques: list[str] = field(default_factory=list)
    sigma_rule_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "event": self.event.to_dict(),
            "detector": self.detector,
            "score": self.score,
            "threshold": self.threshold,
            "explanation": self.explanation,
            "mitre_techniques": self.mitre_techniques,
            "sigma_rule_id": self.sigma_rule_id,
        }


@dataclass
class BenchmarkResult:
    """Output of evaluating a detector against a labelled dataset."""

    detector: str
    dataset: str
    precision: float
    recall: float
    f1: float
    auc: float | None
    true_positives: int
    false_positives: int
    false_negatives: int
    runtime_seconds: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "detector": self.detector,
            "dataset": self.dataset,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "auc": round(self.auc, 4) if self.auc is not None else None,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "runtime_seconds": round(self.runtime_seconds, 2),
        }
