# Copilot instructions for BlueSentinel

- **Stack:** Python ≥ 3.10 package in `src/bluesentinel/` (Drain3, scikit-learn, PyTorch/Transformers, pySigma, FastAPI). Next.js dashboard in `web/`.
- **Run:** `pip install -e ".[dev]"`, `pytest`, `ruff check .` (config in `pyproject.toml`). Web: `cd web && npm ci && npm run lint && npm run build`.
- **Layout:** `parsers/` → `enrichment/mitre.py` → `detectors/` → `rules/` (Sigma YAML in `rules/builtin/`) → `graph/` (attack-chain reconstruction) → `api/` and `cli/`. v1 lives in `src/bluesentinel/legacy/`, with a copy in `blue_sentinel/`. Don't add features there.
- **MITRE rules** are regexes in `enrichment/mitre.py`. Every change needs a positive and a negative case in `tests/test_mitre.py`. Watch out for `\b` next to non-word characters such as `-F`.
- **Data:** `data/sample_auth.log` is from the public LogHub Linux dataset. Never commit real logs from your own machines or employers.
- **When reviewing PRs:** check new detectors implement `detectors/base.py`, and that rule or regex changes come with tests.
- **email/** is the merged SOCShield email-security module: FastAPI backend in `email/backend/` (own `ruff.toml`, tests via `pytest`, Python 3.11, install `requirements-optimized.txt`) and Next.js frontend in `email/frontend/`. See `email/CLAUDE.md`.
