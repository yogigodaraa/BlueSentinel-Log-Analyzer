# Copilot instructions for SOCShield

- **Backend:** Python 3.11, FastAPI, Pydantic v2, async SQLAlchemy, Redis (optional), Celery. Install `backend/requirements-optimized.txt`. Run `pytest` and `ruff check .` from `backend/`.
- **Frontend:** Next.js 15, TypeScript, Tailwind, axios (`frontend/src/lib/api.ts`). Run `npm run type-check` and `npm run build`. ESLint isn't configured yet.
- **Architecture:** `PhishingDetector.analyze_email` orchestrates regex IOC extraction → LLM analysis → threat intel → risk score. LLM vendors sit behind the interface in `backend/app/ai/base.py`. See `docs/ARCHITECTURE.md`.
- **Conventions:** settings live in `app/core/config.py` (read from `backend/.env`). Optional infra must fail soft. Tests use in-memory SQLite and synthetic email addresses.
- **Security:** never commit real emails or API keys. Don't log full email bodies at INFO level.
- **Don't touch:** `frontend/package-lock.json` by hand, `ruff.toml` rule selection (don't loosen it), or the README's implemented/planned table, unless you're changing what's actually implemented.
- **When reviewing PRs:** check new external calls go through `threat_intel.py` / `threat_feeds.py` with timeouts, and that new endpoints validate input with Pydantic models.
