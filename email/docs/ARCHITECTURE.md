# Architecture

A plain-language tour of SOCShield for someone new to the code. For the older, longer design notes,
see `docs/architecture/`. This page describes what the code does **today**.

## The big picture

```text
                ┌───────────────────────── backend/ (FastAPI, /api/v1) ──────────────────────────┐
 frontend/      │                                                                                │
 Next.js  ───▶  │  middleware: security headers → request tracking → rate limit → CORS           │
 dashboard      │                                                                                │
 (axios)        │  /analysis/analyze ──▶ PhishingDetector.analyze_email()                       │
                │                          1. IOCExtractor (regex)                               │
                │                          2. AI provider .analyze_email()   ──▶ Gemini/OpenAI/  │
                │                          3. AI provider .extract_iocs()    ──▶ Claude          │
                │                          4. ThreatIntel: URL reputation    ──▶ VirusTotal,     │
                │                          5. ThreatIntel: domain reputation      urlscan, …     │
                │                          6. _calculate_final_risk() → risk_level + factors     │
                │                                                                                │
                │  /forensics/analyze ──▶ header_forensics.analyze_message()  (SPF/DKIM/DMARC)   │
                │                         bec_detector.detect_bec()           (lookalikes)       │
                │                         mitre_mapping.map_signal_to_techniques()               │
                │                                                                                │
                │  /emails /threats /dashboard ──▶ SQLAlchemy (Postgres) or mock data           │
                └────────────────────────────────────────────────────────────────────────────────┘
                       │ cache: Redis, or in-memory if Redis is down
```

## Backend modules (`backend/app/`)

### `main.py` (app startup)

Creates the FastAPI app, adds middleware, mounts the router at `/api/v1`, and tries to connect to
the database on startup. **If Postgres isn't reachable it logs a warning and serves mock data**,
which is why the dashboard works with zero infrastructure.

**Concept: graceful degradation.** Optional dependencies (DB, Redis) fail soft so development and
demos don't need the full stack. The trade-off is that you might not notice production running on mock
data, so watch the startup logs.

### `core/` (cross-cutting plumbing)

| File | Role |
|---|---|
| `config.py` | `Settings` (pydantic-settings) read from `backend/.env`: provider choice, API keys, DB/Redis URLs, feature flags |
| `database.py` | Async SQLAlchemy engine/session; rewrites `postgresql://` to `postgresql+asyncpg://` |
| `cache.py` | Redis client with an in-memory fallback |
| `middleware.py` | `SecurityHeadersMiddleware`, `RequestTrackingMiddleware`, `RateLimitMiddleware` (100 req/60 s) |
| `metrics.py`, `logging.py`, `exceptions.py` | Structured JSON logging, counters, error types |

### `ai/` (LLM providers behind one interface)

`base.py` defines the provider interface (`analyze_email`, `extract_iocs`). `gemini_provider.py`,
`openai_provider.py` and `claude_provider.py` implement it, and `factory.py` picks one from
`settings.AI_PROVIDER`.

**Concept: strategy pattern.** The detector calls `self.ai_provider.analyze_email(...)` and doesn't
care which vendor answers. Switching providers is a config change, not a code change.

### `services/` (the security logic)

| File | What it does | Concept to learn |
|---|---|---|
| `ioc_extractor.py` | Regex extraction of URLs, domains, IPs, emails; uses `tldextract` for registrable domains | Why regex + LLM together: regex is precise and cheap, the LLM catches obfuscated IOCs |
| `phishing_detector.py` | Orchestrates the 6-step pipeline above and merges regex + AI IOCs | Pipeline/orchestrator pattern |
| `threat_intel.py` | VirusTotal / urlscan / PhishTank reputation (API keys required) | Threat-intel enrichment |
| `threat_feeds.py` | URLhaus, AbuseIPDB, OpenPhish (cached feed), plus `aggregate_verdicts()` | Combining multiple noisy signals |
| `header_forensics.py` | Parses `Authentication-Results` (SPF/DKIM/DMARC) and the `Received` hop chain | Email authentication |
| `bec_detector.py` | Lookalike domains (Levenshtein distance), IDN homographs, display-name spoofing against your `protected_domains` | Business Email Compromise |
| `mitre_mapping.py` | Tags each signal with ATT&CK techniques (T1566.x) and builds a coverage matrix | MITRE ATT&CK |
| `email_monitor.py` | IMAP fetch + parse. **Not called anywhere yet.** | — |

### `api/v1/endpoints/`

`analysis.py` (analyze, extract-iocs, analyze-url, health), `forensics.py` (raw-email forensics,
MITRE coverage), `emails.py`, `threats.py`, `dashboard.py` (read models for the UI), `config.py`.
Interactive docs: run the backend and open `/docs`.

### `models/models.py`

SQLAlchemy tables: `Email`, `Threat`, `IOC`, `Alert`, `EmailAccount`, `AuditLog`. They include a `status` enum (with `QUARANTINED`) and an
`auto_quarantined` flag. These are ready for the quarantine feature, which isn't implemented yet.

### `worker.py`

A configured Celery app with **no tasks yet**. The natural first task is polling `EmailMonitor`.

## Frontend (`frontend/`)

Next.js 15 App Router. `src/lib/api.ts` is an axios client pointed at
`${NEXT_PUBLIC_API_URL}/api/v1`. `src/components/dashboard/` holds `Dashboard`, `StatsCard`,
`ThreatFeed` and `AnalysisPanel` (paste/upload an email → call the analysis endpoint).

## Tests (`backend/tests/`)

pytest with an in-memory SQLite database (`conftest.py` overrides `get_db`). The detector, IOC,
BEC, header-forensics and config tests are the best examples of how each service behaves. See
the README's "Project status" for what's currently failing.

## Where to start reading

1. `backend/app/services/phishing_detector.py`, the `analyze_email` method.
2. `backend/app/services/bec_detector.py`: self-contained, well commented, and a good security lesson.
3. `backend/app/api/v1/endpoints/forensics.py`: how services are combined into one response.
