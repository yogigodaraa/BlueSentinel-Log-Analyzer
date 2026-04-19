"""Benchmark harness — run every detector on every dataset, report metrics.

Usage::

    from bluesentinel.evaluation.harness import Benchmark
    from bluesentinel.detectors import IsolationForestDetector, DeepLogDetector
    from bluesentinel.evaluation.datasets import synthetic_dataset

    bench = Benchmark([IsolationForestDetector(), DeepLogDetector()])
    bench.add_dataset(synthetic_dataset())
    results = bench.run()
    for r in results:
        print(r.to_dict())
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from bluesentinel.detectors.base import BaseDetector
from bluesentinel.evaluation.datasets import LoadedDataset
from bluesentinel.evaluation.metrics import compute_metrics
from bluesentinel.parsers.drain import DrainParser
from bluesentinel.types import BenchmarkResult


@dataclass
class Benchmark:
    detectors: list[BaseDetector]
    train_fraction: float = 0.6
    """Fraction of the normal-only subset used for training."""

    datasets: list[LoadedDataset] = field(default_factory=list)
    parse_templates: bool = True

    def add_dataset(self, dataset: LoadedDataset) -> None:
        self.datasets.append(dataset)

    def run(self) -> list[BenchmarkResult]:
        out: list[BenchmarkResult] = []
        for dataset in self.datasets:
            events = dataset.events
            labels = dataset.labels

            # Optionally extract templates via Drain3 so detectors can use them.
            if self.parse_templates:
                drain = DrainParser()
                for ev in events:
                    if ev.template_id is None:
                        res = drain.miner.add_log_message(ev.message)
                        ev.template_id = int(res["cluster_id"])
                        ev.template = res["template_mined"]

            # Train on the normal prefix (unsupervised / one-class setup)
            normal_mask = labels == 0
            cutoff = int(len(events) * self.train_fraction)
            train_events = [ev for ev, m in zip(events[:cutoff], normal_mask[:cutoff]) if m]

            for detector in self.detectors:
                t0 = time.perf_counter()
                detector.fit(train_events)
                scores = detector.score(events)
                runtime = time.perf_counter() - t0
                result = compute_metrics(
                    detector=detector.name,
                    dataset=dataset.name,
                    y_true=labels,
                    y_score=scores,
                    threshold=detector.default_threshold,
                    runtime_seconds=runtime,
                )
                out.append(result)
        return out
