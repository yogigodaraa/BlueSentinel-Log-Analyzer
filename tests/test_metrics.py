"""Tests for the evaluation metrics."""

import numpy as np

from bluesentinel.evaluation.metrics import compute_metrics


def test_perfect_predictor():
    y_true = np.array([0, 0, 0, 1, 1])
    y_score = np.array([0.1, 0.2, 0.3, 0.9, 0.95])
    r = compute_metrics("x", "y", y_true, y_score, threshold=0.5, runtime_seconds=0.1)
    assert r.precision == 1.0
    assert r.recall == 1.0
    assert r.f1 == 1.0
    assert r.auc == 1.0


def test_random_predictor():
    y_true = np.array([0, 1, 0, 1, 0, 1, 0, 1])
    y_score = np.array([0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5])
    r = compute_metrics("x", "y", y_true, y_score, threshold=0.5, runtime_seconds=0.0)
    # All ties → AUC = 0.5
    assert r.auc == 0.5


def test_no_positives_returns_none_auc():
    y_true = np.array([0, 0, 0, 0])
    y_score = np.array([0.1, 0.2, 0.3, 0.4])
    r = compute_metrics("x", "y", y_true, y_score, threshold=0.5, runtime_seconds=0.0)
    assert r.auc is None
    assert r.precision == 0.0
    assert r.recall == 0.0


def test_threshold_behaviour():
    y_true = np.array([0, 0, 1, 1])
    y_score = np.array([0.1, 0.4, 0.6, 0.9])
    # threshold 0.5 → predict [0,0,1,1] → perfect
    r = compute_metrics("x", "y", y_true, y_score, threshold=0.5, runtime_seconds=0.0)
    assert r.f1 == 1.0
    # threshold 0.0 → predict all → precision ½
    r2 = compute_metrics("x", "y", y_true, y_score, threshold=0.0, runtime_seconds=0.0)
    assert r2.recall == 1.0
    assert r2.precision == 0.5
