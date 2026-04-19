"""Classical Isolation Forest baseline.

Kept as a fast, dependency-light baseline to compare the neural detectors
against. It's the successor to the v1 `anomaly_detector.py` — same idea,
cleaner features, proper interface.
"""

from __future__ import annotations

from collections.abc import Sequence

import numpy as np
from sklearn.ensemble import IsolationForest as _IForest

from bluesentinel.detectors.base import BaseDetector
from bluesentinel.types import LogEvent


class IsolationForestDetector(BaseDetector):
    """Unsupervised Isolation Forest over hand-engineered message features.

    Features per event:

    - message length in characters
    - digit density (fraction of chars that are digits)
    - `failed` / `invalid` / `denied` / `error` keyword indicator
    - ALL-CAPS word count
    - unique template id (0 if unseen)

    Not a SOTA approach, but calibrated the same way DeepLog / LogBERT are,
    so comparison on the same datasets is apples-to-apples.
    """

    name = "isolation_forest"
    version = "2.0"
    default_threshold = 0.0  # score is the IF margin; anything > 0 is anomalous

    _BAD_KEYWORDS = ("failed", "invalid", "denied", "error", "unauthorized", "illegal")

    def __init__(self, *, contamination: float = 0.05, random_state: int = 42):
        self._model = _IForest(contamination=contamination, random_state=random_state)
        self._fitted = False

    # ─── Feature extraction ────────────────────────────────────────────
    def _features(self, events: Sequence[LogEvent]) -> np.ndarray:
        if not events:
            return np.empty((0, 5))
        X = np.zeros((len(events), 5), dtype=np.float32)
        for i, ev in enumerate(events):
            msg = ev.message or ""
            low = msg.lower()
            length = len(msg)
            X[i, 0] = length
            X[i, 1] = sum(c.isdigit() for c in msg) / max(length, 1)
            X[i, 2] = float(any(k in low for k in self._BAD_KEYWORDS))
            X[i, 3] = sum(1 for w in msg.split() if w.isupper() and len(w) > 1)
            X[i, 4] = ev.template_id or 0
        return X

    # ─── Lifecycle ─────────────────────────────────────────────────────
    def fit(self, events: Sequence[LogEvent]) -> "IsolationForestDetector":
        X = self._features(events)
        if len(X) > 0:
            self._model.fit(X)
            self._fitted = True
        return self

    def score(self, events: Sequence[LogEvent]) -> np.ndarray:
        if not self._fitted:
            # If never fitted, fit on the input set — legacy behaviour.
            self.fit(events)
        X = self._features(events)
        if len(X) == 0:
            return np.empty(0)
        # `decision_function` is higher for inliers. Flip so higher = anomalous.
        return -self._model.decision_function(X)

    def explain(self, event: LogEvent, score: float) -> str:
        msg = (event.message or "").lower()
        hits = [k for k in self._BAD_KEYWORDS if k in msg]
        if hits:
            return f"Isolation Forest flagged (score {score:.3f}); suspicious keyword(s): {', '.join(hits)}"
        return f"Isolation Forest flagged (score {score:.3f}); unusual message shape"
