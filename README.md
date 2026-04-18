# BlueSentinel Log Analyzer

AI-powered log anomaly detection for security operations. Parses system logs, detects suspicious behavior with an unsupervised ML model, and generates plain-language incident summaries.

## What it does

Five-step pipeline:

1. **Parse** — regex-based ingestion of Linux auth logs and firewall logs (`log_parser.py`)
2. **Detect** — Isolation Forest over message length + keyword features (`anomaly_detector.py`) — no labeled training data needed
3. **Classify** — rule-based severity (HIGH / MEDIUM / LOW) tied to events like failed logins and brute-force attempts; IP frequency analysis
4. **Summarize** — natural-language incident summaries via OpenAI (`summarizer.py`)
5. **Report** — console alerts + `alerts_report.txt` export

Optional Flask dashboard (`dashboard.py`) adds severity filtering and JSON export.

## Tech stack

- Python 3
- pandas, numpy
- scikit-learn (Isolation Forest)
- OpenAI API (summaries)
- Flask (optional dashboard)
- joblib (model persistence)
- loguru (logging)

## Getting started

```bash
pip install -r requirements.txt
python main.py path/to/auth.log
```

Optional dashboard:

```bash
python dashboard.py     # http://localhost:5000
```

Set `OPENAI_API_KEY` in your environment for natural-language summaries.

## Project structure

```
main.py                Entry; orchestrates the five-step pipeline
blue_sentinel/         Parser, detector, summarizer modules
dashboard.py           Flask UI (optional)
data/                  Sample logs
scripts/               CLI helpers
tests/                 Test suite
render.yaml            Render deployment config
alerts_report.txt      Output of latest run
```

## Status

Active WIP. Hand-crafted features + heuristic rules — suitable for learning / prototyping, not production-grade detection.
