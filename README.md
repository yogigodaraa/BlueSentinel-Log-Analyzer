# BlueSentinel v2

Advanced log anomaly detection & UBA for SOC teams. Drain3 template mining · DeepLog · LogBERT · MITRE ATT&CK · Sigma rules · FastAPI.

> v2 is a full rewrite. The v1 code is preserved under `src/bluesentinel/legacy/` and the old Flask dashboard under `dashboard.py` — both still run. v2 ships alongside as a drop-in upgrade with a much stronger detection stack.

## Why v2

v1 shipped a single Isolation Forest over message-length + keyword features — a reasonable baseline, but a long way from the literature. v2 catches up:

| Capability | v1 | v2 |
|---|---|---|
| Parsing | Single regex | **Drain3** template mining (He et al., 2017) — learns templates automatically, handles formats v1 can't |
| Detection | Isolation Forest | IF + **DeepLog** (LSTM next-template, Du et al. 2017) + **LogBERT** (pretrained-transformer embeddings + k-means prototypes, Guo et al. 2021) |
| Taxonomy | None | **MITRE ATT&CK** enrichment — 15 techniques across credential-access, privilege-escalation, persistence, lateral-movement, defense-evasion, execution, discovery, impact |
| Rules | None | **pySigma-compatible** rules engine, 5 curated Sigma rules shipped, extensible via `rules/builtin/*.yml` |
| Evaluation | None | Benchmark harness with precision / recall / F1 / ROC-AUC against LogHub public datasets (HDFS_v1, BGL, Thunderbird) |
| Interface | Flask | FastAPI + OpenAPI + CLI |

## Architecture

```
            ┌─────────────────────────────────────────────────┐
  raw logs →│  parsers/     Drain3 (template mining)          │
            │               Syslog (RFC 3164 / auth.log)      │
            ├─────────────────────────────────────────────────┤
            │  enrichment/  MITRE ATT&CK technique tagging    │
            │               (15 hand-mapped techniques)       │
            ├─────────────────────────────────────────────────┤
            │  detectors/   Isolation Forest (baseline)       │
            │               DeepLog  (LSTM next-template)     │
            │               LogBERT  (semantic embeddings)    │
            ├─────────────────────────────────────────────────┤
            │  rules/       pySigma-compatible engine         │
            │               5 shipped rules (SSH brute-force, │
            │               sudo abuse, new account, log      │
            │               tampering, firewall disable)      │
            ├─────────────────────────────────────────────────┤
            │  evaluation/  Precision/Recall/F1/AUC against   │
            │               Loghub HDFS / BGL / Thunderbird   │
            └─────────────────────────────────────────────────┘
                                │
                    ┌───────────┴───────────┐
                    ▼                       ▼
              FastAPI (port 8000)      CLI: `bluesentinel`
              /health /rules /mitre    analyze · benchmark · serve
              POST /analyze
```

## Install

```bash
pip install -e .               # core
pip install -e ".[dev]"         # with pytest, ruff, mypy
pip install -e ".[eval]"        # adds matplotlib, requests for benchmarks
pip install -e ".[llm]"         # adds openai (optional)
```

## Usage

### CLI

```bash
bluesentinel analyze --logfile data/sample_auth.log
bluesentinel analyze --logfile auth.log --fast          # skip LogBERT for speed
bluesentinel benchmark --dataset synthetic              # built-in smoke test
bluesentinel serve --port 8000                          # start the API
```

### Python

```python
from bluesentinel.parsers import DrainParser
from bluesentinel.detectors import LogBERTDetector, IsolationForestDetector
from bluesentinel.enrichment import MitreEnricher
from bluesentinel.rules import SigmaEngine

parser = DrainParser()
events = parser.parse_to_list("data/sample_auth.log")

MitreEnricher().enrich_all(events)           # tag with ATT&CK IDs

lb = LogBERTDetector().fit(events)           # train the semantic model
flagged = lb.detect(events)

rules = SigmaEngine()
rules.load_builtin()
rule_hits = rules.evaluate_all(events)
```

### API

```bash
uvicorn bluesentinel.api.app:app --reload
curl -sX POST http://localhost:8000/analyze \
  -H 'Content-Type: application/json' \
  -d '{"log_text": "Jan  1 00:00:00 host sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2"}'
```

Swagger UI at `http://localhost:8000/docs`.

### Docker

```bash
docker compose up --build
```

Serves on :8000 with healthcheck wired up.

## Evaluation

The harness runs every detector against every dataset you register:

```python
from bluesentinel.evaluation import Benchmark, synthetic_dataset
from bluesentinel.detectors import IsolationForestDetector, LogBERTDetector

bench = Benchmark([IsolationForestDetector(), LogBERTDetector()])
bench.add_dataset(synthetic_dataset())
for r in bench.run():
    print(r.to_dict())
```

Output rows include `precision`, `recall`, `f1`, `auc`, `runtime_seconds`.

For the Loghub public datasets, download the parsed CSVs from <https://zenodo.org/record/8196385> and use `load_hdfs_csv(path)`.

## Layout

```
src/bluesentinel/
  types.py                LogEvent · Detection · BenchmarkResult
  parsers/
    base.py               Streaming parser interface
    syslog.py             RFC 3164 / auth.log parser
    drain.py              Drain3 template mining wrapper
  detectors/
    base.py               Unified fit / score / detect interface
    isolation_forest.py   Classical baseline
    deeplog.py            LSTM next-template (PyTorch)
    logbert.py            Pretrained transformer embeddings + k-means prototypes
  enrichment/
    mitre.py              15-technique ATT&CK tagger
  rules/
    engine.py             pySigma-compatible evaluator
    builtin/*.yml         5 shipped detection rules
  evaluation/
    metrics.py            Precision/Recall/F1/AUC — no sklearn dep
    datasets.py           Loghub loaders + synthetic generator
    harness.py            Benchmark orchestrator
  api/
    app.py                FastAPI service
    schemas.py            Pydantic models
  cli/__main__.py         `bluesentinel` command
  legacy/                 v1 modules kept for compatibility
tests/                    pytest suite
data/                     sample auth.log + downloaded datasets
docs/                     architecture, models, evaluation notes
```

## Status

v2 is a portfolio-grade rewrite. Detectors and rules are tested in CI against a synthetic attack sequence. Real-world benchmarks (HDFS / BGL) require downloading the Loghub datasets locally — the repo doesn't ship them (they're several hundred MB).

## References

- He et al., *Drain: An Online Log Parsing Approach with Fixed Depth Tree* (ICWS 2017)
- Du et al., *DeepLog: Anomaly Detection and Diagnosis from System Logs through Deep Learning* (CCS 2017)
- Guo et al., *LogBERT: Log Anomaly Detection via BERT* (IJCAI 2021)
- He et al., *Loghub: A Large Collection of System Log Datasets for AI-driven Log Analytics* (ASE 2023)
- MITRE ATT&CK — <https://attack.mitre.org/>
- Sigma — <https://github.com/SigmaHQ/sigma>

## License

MIT — see [LICENSE](./LICENSE).
