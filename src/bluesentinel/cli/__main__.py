"""Command-line interface.

Three sub-commands:

    bluesentinel analyze   --logfile auth.log
    bluesentinel benchmark --dataset synthetic
    bluesentinel serve     [--host 0.0.0.0 --port 8000]
"""

from __future__ import annotations

import argparse
import json
import sys

from bluesentinel._version import __version__


def cmd_analyze(args: argparse.Namespace) -> None:
    from bluesentinel.detectors import IsolationForestDetector, LogBERTDetector
    from bluesentinel.enrichment import MitreEnricher
    from bluesentinel.parsers import DrainParser
    from bluesentinel.rules import SigmaEngine

    parser = DrainParser()
    events = parser.parse_to_list(args.logfile)
    print(f"parsed {len(events)} events, {parser.template_count()} distinct templates")

    enricher = MitreEnricher()
    enricher.enrich_all(events)

    rules = SigmaEngine()
    rules.load_builtin()

    detectors = {
        "isolation_forest": IsolationForestDetector(),
    }
    if not args.fast:
        detectors["logbert"] = LogBERTDetector()

    detections = []
    for det in detectors.values():
        det.fit(events)
        detections.extend(det.detect(events))
    detections.extend(rules.evaluate_all(events))

    output = {
        "events_parsed": len(events),
        "distinct_templates": parser.template_count(),
        "detections": [d.to_dict() for d in detections],
    }
    json.dump(output, sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")


def cmd_benchmark(args: argparse.Namespace) -> None:
    from bluesentinel.detectors import IsolationForestDetector, LogBERTDetector
    from bluesentinel.evaluation import Benchmark, synthetic_dataset

    bench = Benchmark([IsolationForestDetector(), LogBERTDetector()])
    if args.dataset == "synthetic":
        bench.add_dataset(synthetic_dataset())
    else:  # pragma: no cover
        raise SystemExit(f"Unknown dataset: {args.dataset}")

    results = bench.run()
    print(json.dumps([r.to_dict() for r in results], indent=2))


def cmd_serve(args: argparse.Namespace) -> None:
    import uvicorn

    uvicorn.run(
        "bluesentinel.api.app:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="bluesentinel", description="BlueSentinel CLI")
    parser.add_argument("--version", action="version", version=f"bluesentinel {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_analyze = sub.add_parser("analyze", help="Analyze a log file")
    p_analyze.add_argument("--logfile", required=True)
    p_analyze.add_argument("--fast", action="store_true", help="Skip heavy detectors (LogBERT)")
    p_analyze.set_defaults(func=cmd_analyze)

    p_bench = sub.add_parser("benchmark", help="Run the evaluation harness")
    p_bench.add_argument("--dataset", default="synthetic")
    p_bench.set_defaults(func=cmd_benchmark)

    p_serve = sub.add_parser("serve", help="Run the FastAPI service")
    p_serve.add_argument("--host", default="0.0.0.0")
    p_serve.add_argument("--port", type=int, default=8000)
    p_serve.add_argument("--reload", action="store_true")
    p_serve.set_defaults(func=cmd_serve)

    args = parser.parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
