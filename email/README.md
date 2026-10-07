# SOCShield

[![CI](https://github.com/yogigodaraa/SOCShield/actions/workflows/ci.yml/badge.svg)](https://github.com/yogigodaraa/SOCShield/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

AI-assisted phishing analysis for Security Operations Centers. Paste or upload an email and
SOCShield extracts indicators of compromise (IOCs), classifies the email with an LLM, checks
URLs and domains against threat-intelligence feeds, runs header forensics (SPF / DKIM / DMARC)
and business-email-compromise (BEC) checks, and maps what it finds to MITRE ATT&CK.

## What works today vs. what's planned

Read from the code (October 2026). Several features in older docs are only config placeholders.

| Feature | Status | Where |
|---|---|---|
| Email analysis API: regex + LLM IOC extraction, LLM classification, risk score | ✅ Implemented | `backend/app/services/phishing_detector.py`, `POST /api/v1/analysis/analyze` |
| IOC extraction (domains, URLs, IPs, emails) | ✅ Implemented | `services/ioc_extractor.py`, `POST /api/v1/analysis/extract-iocs` |
| Threat intel: VirusTotal, urlscan, PhishTank, URLhaus, AbuseIPDB, OpenPhish | ✅ Implemented (needs your API keys where applicable) | `services/threat_intel.py`, `services/threat_feeds.py` |
| Header forensics (SPF/DKIM/DMARC, Received chain) + BEC lookalike/homograph detection | ✅ Implemented | `services/header_forensics.py`, `services/bec_detector.py`, `POST /api/v1/forensics/analyze` |
| MITRE ATT&CK mapping (T1566 Phishing and sub-techniques) | ✅ Implemented | `services/mitre_mapping.py`, `GET /api/v1/forensics/mitre/coverage` |
| Switchable LLM provider: Gemini / OpenAI / Claude | ✅ Implemented, ⚠️ model ids are dated (see below) | `backend/app/ai/` |
| Dashboard (stats, threat feed, analysis panel) | ✅ Implemented. Falls back to mock data when Postgres is unavailable. | `frontend/` |
| Rate limiting, security headers, request tracking | ✅ Implemented | `core/middleware.py` |
| Live inbox monitoring (IMAP) | 🟡 Service written, **not wired** into the app | `services/email_monitor.py` |
| Background processing (Celery) | 🟡 Celery app configured, **no tasks defined** | `app/worker.py` |
| Auto-quarantine / auto-block | ⬜ Config flag + DB column only | `core/config.py` |
| JWT auth, Slack / Teams / Twilio alerts, Splunk | ⬜ Config placeholders only | `config/.env.example` |

> ⚠️ **Model ids:** the providers use `claude-3-5-sonnet-20241022`, `gpt-4-turbo-preview` and
> `gemini-2.0-flash-exp` with SDK versions pinned in 2023. Some of these have since been retired,
> so live LLM calls may fail until they're updated. See the roadmap.

## Screenshots / architecture

<!-- TODO: add a dashboard screenshot (using the sample emails, never real mail) -->
See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for a diagram and walkthrough.

## Tech stack

- **Backend** (`backend/`): Python 3.11, FastAPI, Pydantic v2, SQLAlchemy (async; PostgreSQL in production, SQLite in tests), Redis cache (with in-memory fallback), Celery, Anthropic / OpenAI / Google Generative AI SDKs
- **Frontend** (`frontend/`): Next.js 15, React, TypeScript, Tailwind CSS, axios
- **Infra**: Dockerfiles for both services, `config/docker-compose.yml`

## Quickstart

```bash
git clone https://github.com/yogigodaraa/SOCShield.git
cd SOCShield
```

**Backend**

```bash
cd backend
python3.11 -m venv venv && source venv/bin/activate
pip install -r requirements-optimized.txt   # lean set; requirements.txt adds unused ML libraries
cp ../config/.env.example .env               # settings are read from backend/.env
# set AI_PROVIDER and the matching *_API_KEY; Postgres/Redis are optional for local dev
uvicorn app.main:app --reload --port 8000    # API docs at http://localhost:8000/docs
```

**Frontend**

```bash
cd frontend
npm ci
cp .env.example .env.local                   # NEXT_PUBLIC_API_URL=http://localhost:8000
npm run dev                                  # http://localhost:3000
```

Or use `npm run dev:both` from the repo root (expects the backend venv at `backend/venv`).

### Tests and checks

```bash
cd backend && pytest            # see "Project status": part of the suite is currently failing
cd backend && ruff check .
cd frontend && npm run type-check && npm run build
```

## Usage example

```bash
curl -X POST http://localhost:8000/api/v1/forensics/analyze \
  -H "Content-Type: application/json" \
  -d '{"raw_email": "From: CEO <ceo@examp1e.com>\nSubject: Urgent wire\n\nPlease send $40k today.", "protected_domains": ["example.com"]}'
```

## Project status

**Active, but needs maintenance.** In CI: 51 backend tests pass, 7 fail, and 4 error (one test
module targets an API that no longer exists, and the API tests use async fixtures that need updating for
pytest 9). Tracked in the repo issues. The frontend type-checks and builds; ESLint isn't
configured yet.

## Roadmap

- [ ] Fix the failing backend tests and make CI green
- [ ] Update LLM model ids and SDK versions
- [ ] Configure ESLint for the frontend
- [ ] Wire `EmailMonitor` into a Celery task for live inbox polling
- [ ] Implement auto-quarantine (IMAP move) behind `ENABLE_AUTO_QUARANTINE`
- [ ] Consolidate the many status/summary markdown files into `docs/`

## Security

Report vulnerabilities privately. See [SECURITY.md](https://github.com/yogigodaraa/.github/blob/main/SECURITY.md).
Sample emails in tests are synthetic.

## License

MIT. See [LICENSE](LICENSE).
