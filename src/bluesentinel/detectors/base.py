"""Detector interface. All detectors share the same fit / score / detect API
so a unified evaluation harness can compare them head-to-head.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence

import numpy as np

from bluesentinel.types import Detection, LogEvent


class BaseDetector(ABC):
    """Anomaly detector interface.

    Three methods every detector must implement:

    - ``fit(events)``      — learn normal behaviour from a training corpus.
    - ``score(events)``    — return a per-event anomaly score (higher = worse).
    - ``detect(events)``   — return a list of `Detection`s above threshold.

    Detectors should be **stateless in public methods** after fit: calling
    `score` or `detect` twice with the same input must return the same
    output. Any learned state lives on the instance.
    """

    name: str = "base"
    version: str = "0"

    #: Default anomaly-score threshold above which an event is flagged.
    #: Each detector subclasses override based on empirical distribution.
    default_threshold: float = 0.5

    # ─── Lifecycle ─────────────────────────────────────────────────────
    @abstractmethod
    def fit(self, events: Sequence[LogEvent]) -> "BaseDetector":
        """Learn normal patterns from a training corpus."""

    @abstractmethod
    def score(self, events: Sequence[LogEvent]) -> np.ndarray:
        """Return anomaly scores. Same length as `events`. Higher = more anomalous."""

    # ─── Convenience ───────────────────────────────────────────────────
    def detect(
        self,
        events: Sequence[LogEvent],
        *,
        threshold: float | None = None,
    ) -> list[Detection]:
        """Return all events whose score ≥ threshold as Detections."""
        threshold = threshold if threshold is not None else self.default_threshold
        scores = self.score(events)
        detections: list[Detection] = []
        for ev, s in zip(events, scores, strict=False):
            if s >= threshold:
                detections.append(
                    Detection(
                        event=ev,
                        detector=self.name,
                        score=float(s),
                        threshold=threshold,
                        explanation=self.explain(ev, float(s)),
                    )
                )
        return detections

    def explain(self, event: LogEvent, score: float) -> str:
        """Default explanation. Subclasses should override with model-specific logic."""
        return f"{self.name} scored event {score:.3f} (≥ {self.default_threshold:.3f})"

    # ─── Persistence ───────────────────────────────────────────────────
    def save(self, path: str) -> None:  # noqa: D401 — default is no-op
        """Persist the detector to disk. Subclasses override if they have state."""

    @classmethod
    def load(cls, path: str) -> "BaseDetector":
        raise NotImplementedError(f"{cls.__name__}.load not implemented")
