"""Benchmark harness — precision/recall/F1/AUC across detectors & datasets."""

from bluesentinel.evaluation.datasets import (
    LoadedDataset,
    iter_loghub_raw,
    load_hdfs_csv,
    synthetic_dataset,
)
from bluesentinel.evaluation.harness import Benchmark
from bluesentinel.evaluation.metrics import compute_metrics

__all__ = [
    "Benchmark",
    "LoadedDataset",
    "compute_metrics",
    "iter_loghub_raw",
    "load_hdfs_csv",
    "synthetic_dataset",
]
