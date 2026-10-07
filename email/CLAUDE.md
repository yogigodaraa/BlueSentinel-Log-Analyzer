# CLAUDE.md

## What this is

SOCShield: FastAPI backend (`backend/`) + Next.js 15 dashboard (`frontend/`) for AI-assisted
phishing analysis: IOC extraction, LLM classification, threat-intel enrichment, header forensics,
BEC detection and MITRE ATT&CK mapping. Walkthrough: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
The README has an honest "implemented vs planned" table. Keep it accurate.

## Commands

```bash
# backend (Python 3.11)
cd backend
python3.11 -m venv venv && source venv/bin/activate
pip install -r requirements-optimized.txt   # what CI installs
uvicorn app.main:app --reload --port 8000
pytest                                      # config in pytest.ini (asyncio_mode=auto, coverage)
ruff check .                                # rules in ruff.toml

# frontend
cd frontend
npm ci && npm run dev
npm run type-check && npm run build         # CI runs these; ESLint isn't configured yet
```

## Layout

- `backend/app/services/`: security logic (start with `phishing_detector.py`)
- `backend/app/ai/`: provider interface + Gemini/OpenAI/Claude implementations, chosen by `AI_PROVIDER`
- `backend/app/api/v1/endpoints/`: thin FastAPI routers
- `backend/app/core/`: settings, DB, cache, middleware, logging
- `frontend/src/components/dashboard/`, `frontend/src/lib/api.ts`

## Conventions

- Settings come from `backend/.env` via `app/core/config.py`. Add new settings there with a safe default.
- Services are plain classes/functions and are tested directly in `backend/tests/`.
- Keep `requirements.txt` and `requirements-optimized.txt` in sync for shared packages.
- Optional infrastructure (Postgres, Redis) must keep failing soft.

## Do not

- Never commit real emails, inbox exports, or API keys. Test fixtures use synthetic addresses
  (`example.com`, `paypa1-secure.com`, …).
- Don't claim features in docs that are only config flags (quarantine, JWT, Slack/Splunk).
- Don't loosen `ruff.toml` or skip tests to get CI green. Fix the cause.
- `frontend/.env.production` is tracked in git. Never put secrets in it.
