"""Precision / recall / F1 / AUC computation for binary anomaly detection.

Standalone so the harness doesn't drag the whole sklearn API surface
into downstream code — and so unit tests can verify the calculation
against hand-rolled expected values.
"""

from __future__ import annotations

import numpy as np

from bluesentinel.types import BenchmarkResult


def compute_metrics(
    detector: str,
    dataset: str,
    y_true: np.ndarray,
    y_score: np.ndarray,
    threshold: float,
    runtime_seconds: float,
) -> BenchmarkResult:
    """Binary precision/recall/F1 at the given threshold, plus AUC over all thresholds."""
    y_true = np.asarray(y_true).astype(int)
    y_score = np.asarray(y_score).astype(float)
    y_pred = (y_score >= threshold).astype(int)

    tp = int(((y_pred == 1) & (y_true == 1)).sum())
    fp = int(((y_pred == 1) & (y_true == 0)).sum())
    fn = int(((y_pred == 0) & (y_true == 1)).sum())

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    auc = _roc_auc(y_true, y_score)

    return BenchmarkResult(
        detector=detector,
        dataset=dataset,
        precision=precision,
        recall=recall,
        f1=f1,
        auc=auc,
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        runtime_seconds=runtime_seconds,
    )


def _roc_auc(y_true: np.ndarray, y_score: np.ndarray) -> float | None:
    """ROC AUC without sklearn to keep the hot path tiny.

    Simplified Mann-Whitney U implementation: AUC = P(score(pos) > score(neg)).
    Ties count 0.5 each.
    """
    pos = y_score[y_true == 1]
    neg = y_score[y_true == 0]
    if len(pos) == 0 or len(neg) == 0:
        return None
    # Broadcast comparisons — O(P*N), fine for evaluation-scale datasets.
    gt = (pos[:, None] > neg[None, :]).sum()
    eq = (pos[:, None] == neg[None, :]).sum()
    return float((gt + 0.5 * eq) / (len(pos) * len(neg)))
