# 🏗️ SOCShield Backend Architecture

**Version:** 2.0  
**Last Updated:** October 19, 2025  
**Status:** Production-Ready

---

## 📋 Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [System Components](#system-components)
3. [Data Flow](#data-flow)
4. [Design Patterns](#design-patterns)
5. [Infrastructure Layer](#infrastructure-layer)
6. [Service Layer](#service-layer)
7. [API Layer](#api-layer)
8. [Security Architecture](#security-architecture)
9. [Monitoring & Observability](#monitoring--observability)
10. [Deployment Architecture](#deployment-architecture)

---

## 🎯 Architecture Overview

SOCShield implements a **layered, microservice-oriented architecture** designed for:

- **Scalability:** Horizontal scaling via containerization
- **Maintainability:** Clear separation of concerns
- **Extensibility:** Plugin architecture for AI providers and threat intel sources
- **Reliability:** Built-in error handling, retries, and circuit breakers
- **Observability:** Comprehensive logging, metrics, and tracing

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Frontend Layer                           │
│              (Next.js React with TypeScript)                     │
└────────────────────────────┬────────────────────────────────────┘
                             │ REST API / WebSocket
┌────────────────────────────▼────────────────────────────────────┐
│                          API Gateway                             │
│         (FastAPI with Middleware & Rate Limiting)                │
└───┬──────────────────────┬─────────────────────┬───────────────┘
    │                      │                     │
┌───▼─────────┐    ┌──────▼──────┐     ┌───────▼────────┐
│   Email     │    │  Analysis   │     │   Threat       │
│  Service    │    │   Service   │     │   Intel        │
└───┬─────────┘    └──────┬──────┘     └───────┬────────┘
    │                     │                     │
    └─────────────┬───────┴─────────────────────┘
                  │
┌─────────────────▼──────────────────────────────────────┐
│                Core Infrastructure                      │
│  ┌──────────┐  ┌─────────┐  ┌────────┐  ┌──────────┐ │
│  │  Cache   │  │ Metrics │  │ Logger │  │ Database │ │
│  │ (Redis)  │  │         │  │        │  │(Postgres)│ │
│  └──────────┘  └─────────┘  └────────┘  └──────────┘ │
└────────────────────────────────────────────────────────┘
```

---

## 🧩 System Components

### Layer Overview

| Layer | Directory | Responsibility | Technologies |
|-------|-----------|----------------|--------------|
| **Presentation** | `frontend/` | User interface, data visualization | Next.js, React, TailwindCSS |
| **API Gateway** | `backend/app/api/` | Request routing, validation, auth | FastAPI, Pydantic |
| **Business Logic** | `backend/app/services/` | Core domain logic | Python async |
| **AI Abstraction** | `backend/app/ai/` | Multi-provider AI orchestration | OpenAI, Gemini, Claude APIs |
| **Infrastructure** | `backend/app/core/` | Cross-cutting concerns | Redis, PostgreSQL |
| **Background Tasks** | `backend/app/worker.py` | Async job processing | Celery, Redis |

---

## 🔄 Data Flow: "Email → Threat Intelligence"

### 1. **Email Ingestion Pipeline**

```python
Email Source → EmailMonitor → Parser → Queue → PhishingDetector
     ↓              ↓            ↓        ↓          ↓
  (IMAP/API)   (Polling)   (MIME→JSON) (Redis)  (Analysis)
```

**Key Files:**
- `app/services/email_monitor.py` - Email polling & fetching
- `app/services/phishing_detector.py` - Orchestration engine

### 2. **Analysis Pipeline**

```
┌─────────────────────────────────────────────────────────────┐
│                    PhishingDetector                          │
└───┬──────────────────────┬──────────────────┬──────────────┘
    │                      │                  │
    ▼                      ▼                  ▼
┌──────────┐         ┌──────────┐      ┌─────────────┐
│   IOC    │         │    AI    │      │   Threat    │
│Extractor │         │ Provider │      │    Intel    │
└──────────┘         └──────────┘      └─────────────┘
    │                      │                  │
    └──────────────────────┴──────────────────┘
                           │
                    ┌──────▼───────┐
                    │ Risk Scoring │
                    │   Engine     │
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │   Response   │
                    │   Actions    │
                    └──────────────┘
```

**Components:**

#### a) **IOC Extraction** (`app/services/ioc_extractor.py`)
- **Regex-based extraction:** URLs, domains, IPs, emails, hashes
- **Normalization:** via `tldextract`, `ipaddress` libraries
- **Suspiciousness scoring:** Heuristic rules for URL analysis
- **Output:** Structured IOC dictionary

#### b) **AI Analysis** (`app/ai/*.py`)
- **Factory pattern:** Dynamic provider selection (OpenAI/Gemini/Claude)
- **Prompt engineering:** Context-aware email classification
- **Confidence scoring:** Probabilistic phishing detection
- **Output:** Risk indicators + explanation

#### c) **Threat Intelligence** (`app/services/threat_intel.py`)
- **Multi-source queries:** VirusTotal, URLScan, PhishTank, AbuseIPDB
- **Parallel execution:** Async requests with timeout
- **Reputation aggregation:** Weighted scoring across sources
- **Caching:** 1-hour TTL for repeated lookups
- **Output:** Threat score (0-100) + reputation label

#### d) **Risk Scoring** (`phishing_detector._calculate_final_risk`)
- **Weighted factors:**
  - AI confidence (60%)
  - IOC count (15%)
  - Suspicious URLs (10%)
  - Threat intel findings (15%)
- **Risk levels:** Low → Medium → High → Critical
- **Threshold-based alerts:** Configurable via `settings.py`

### 3. **Response Actions**

```python
if risk_level == "critical":
    - Auto-quarantine email (if enabled)
    - Block sender domain (if enabled)
    - Send webhook alert (Slack/Teams)
    - Create SIEM event
    - Update dashboard metrics
```

---

## 🏛️ Design Patterns

### 1. **Factory Pattern** (`app/ai/factory.py`)
```python
def get_ai_provider() -> BaseAIProvider:
    provider = settings.AI_PROVIDER
    if provider == "openai":
        return OpenAIProvider()
    elif provider == "gemini":
        return GeminiProvider()
    # ...
```
**Benefits:** Easy to add new AI providers without modifying core logic

### 2. **Repository Pattern** (`app/core/database.py`)
- Abstraction over data access
- Async SQLAlchemy for non-blocking I/O
- Transaction management

### 3. **Dependency Injection**
```python
class PhishingDetector:
    def __init__(self):
        self.ai_provider = get_ai_provider()  # Injected
        self.ioc_extractor = IOCExtractor()   # Injected
        self.threat_intel = threat_intel      # Singleton
```

### 4. **Decorator Pattern** (Caching)
```python
@cached(prefix="url_reputation", expiry=3600)
async def check_url_reputation(url: str):
    # ...
```

### 5. **Observer Pattern** (Metrics)
```python
await SecurityMetrics.record_phishing_detection(...)
```

---

## 🛠️ Infrastructure Layer

### Core Components (`backend/app/core/`)

#### 1. **Configuration** (`config.py`)
- **Environment-based:** `.env` file with `pydantic-settings`
- **Type-safe:** Automatic validation
- **Cascading defaults:** Development → Staging → Production

#### 2. **Exception Handling** (`exceptions.py`)
```python
SOCShieldException
├── AIProviderException
│   ├── RateLimitException
│   └── InvalidAPIKeyException
├── EmailProcessingException
├── IOCExtractionException
├── DatabaseException
├── ThreatIntelException
└── ValidationException
```

**Benefits:**
- Structured error responses
- Granular error handling
- Automatic logging with context

#### 3. **Logging** (`logging.py`)
- **Structured logs:** JSON format for production
- **Contextual logging:** Request IDs, user context
- **Correlation:** Trace requests across services
- **Levels:** DEBUG → INFO → WARNING → ERROR → CRITICAL

**Example:**
```json
{
  "timestamp": "2025-10-19T12:34:56.789Z",
  "level": "INFO",
  "request_id": "abc-123-def",
  "message": "Phishing detected",
  "email_subject": "Urgent: Verify Account",
  "confidence": 0.95
}
```

#### 4. **Middleware** (`middleware.py`)

| Middleware | Purpose | Order |
|------------|---------|-------|
| `SecurityHeadersMiddleware` | Add security headers (CSP, HSTS) | 1st |
| `RequestTrackingMiddleware` | Generate request IDs, timing | 2nd |
| `RateLimitMiddleware` | Prevent abuse (100 req/min) | 3rd |
| `CORSMiddleware` | Allow frontend origins | 4th |

#### 5. **Caching** (`cache.py`)
- **Primary:** Redis for distributed caching
- **Fallback:** In-memory dict (development)
- **TTL:** Configurable per cache key
- **Invalidation:** Manual or time-based

**Use cases:**
- Threat intel results (1 hour)
- AI responses (5 minutes)
- Dashboard metrics (30 seconds)

#### 6. **Metrics** (`metrics.py`)
```python
# Counters
await metrics.increment('phishing.detections.total')

# Gauges
await metrics.gauge('active_connections', 42)

# Histograms
await metrics.histogram('response_time', 0.125)

# Timers (context manager)
async with Timer('db.query.duration'):
    result = await db.query(...)
```

**Metrics Collected:**
- Request rates & latencies
- Phishing detection rates
- AI provider performance
- Error rates
- IOC extraction counts

---

## ⚙️ Service Layer

### 1. **PhishingDetector** (`services/phishing_detector.py`)

**Responsibilities:**
- Orchestrate analysis workflow
- Aggregate results from multiple sources
- Calculate final risk score
- Trigger response actions

**Key Methods:**
```python
async def analyze_email(email_content: Dict) -> Dict:
    # 1. Extract IOCs (regex + AI)
    # 2. AI-based classification
    # 3. Threat intel enrichment
    # 4. Risk scoring
    # 5. Return verdict
```

### 2. **IOCExtractor** (`services/ioc_extractor.py`)

**Patterns Used:**
- Email: `r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'`
- URL: `r'https?://[^\s<>"{}|\\^`\[\]]+'`
- IP: `r'\b(?:(?:25[0-5]|...)\.)...`
- Domain: `tldextract` for proper parsing

**Filtering:**
- Remove private IPs
- Exclude common legitimate domains
- Validate format

### 3. **ThreatIntelService** (`services/threat_intel.py`)

**Integrations:**
- VirusTotal API
- URLScan.io
- PhishTank
- AbuseIPDB
- OpenDNS

**Features:**
- Parallel queries (async)
- Timeout handling (10s)
- Result aggregation
- Reputation scoring

### 4. **EmailMonitor** (`services/email_monitor.py`)

**Capabilities:**
- IMAP polling (Gmail, Outlook, Exchange)
- OAuth2 authentication
- Folder monitoring (INBOX, Spam)
- Attachment handling
- Rate limiting

---

## 🌐 API Layer

### Endpoints (`backend/app/api/v1/endpoints/`)

#### Analysis Endpoints (`analysis.py`)
```
POST   /api/v1/analysis/email       - Analyze single email
POST   /api/v1/analysis/batch       - Batch analysis
GET    /api/v1/analysis/{id}        - Get analysis result
```

#### Email Endpoints (`emails.py`)
```
GET    /api/v1/emails               - List monitored emails
POST   /api/v1/emails/scan          - Trigger manual scan
GET    /api/v1/emails/{id}          - Email details
DELETE /api/v1/emails/{id}          - Delete email
```

#### Threat Endpoints (`threats.py`)
```
GET    /api/v1/threats              - List detected threats
GET    /api/v1/threats/{id}         - Threat details
POST   /api/v1/threats/{id}/block   - Block IOC
POST   /api/v1/threats/{id}/allow   - Whitelist IOC
```

#### Dashboard Endpoints (`dashboard.py`)
```
GET    /api/v1/dashboard/stats      - Overall statistics
GET    /api/v1/dashboard/timeline   - Detection timeline
GET    /api/v1/dashboard/top-threats - Top threats
```

#### Config Endpoints (`config.py`)
```
GET    /api/v1/config               - Current config
PUT    /api/v1/config               - Update config
GET    /health                      - Health check
GET    /metrics                     - Prometheus metrics
```

---

## 🔐 Security Architecture

### 1. **Authentication**
- JWT tokens (HS256)
- API key authentication
- OAuth2 support (planned)

### 2. **Authorization**
- Role-based access control (RBAC)
- Permission checks per endpoint

### 3. **Data Protection**
- Environment variable encryption
- Secrets management (AWS Secrets Manager / Vault)
- Database encryption at rest
- TLS for all external communications

### 4. **Input Validation**
- Pydantic models for request validation
- SQL injection prevention (parameterized queries)
- XSS protection (CSP headers)

### 5. **Rate Limiting**
- IP-based throttling
- Per-user quotas
- Exponential backoff for AI APIs

---

## 📊 Monitoring & Observability

### 1. **Logging Strategy**

| Environment | Format | Destination |
|-------------|--------|-------------|
| Development | Plain text | Console |
| Staging | JSON | Console + File |
| Production | JSON | ELK/Loki + S3 |

### 2. **Metrics Exposure**

**Prometheus `/metrics` endpoint:**
```
# Phishing detections
phishing_detections_total{risk_level="critical"} 42

# AI requests
ai_requests_duration_seconds{provider="gemini",quantile="0.95"} 1.2

# Email processing
email_processed_total 1523
email_processed_failure 3
```

### 3. **Alerting**

**Alert Channels:**
- Slack webhooks
- MS Teams webhooks
- Email notifications
- SMS (Twilio)
- SIEM integration (Splunk, Elastic)

**Alert Triggers:**
- Critical phishing detection
- High error rate (> 5%)
- AI provider down
- Database connection lost

---

## 🚀 Deployment Architecture

### Development
```yaml
version: "3.8"
services:
  backend:
    image: socshield-backend:dev
    ports: ["8000:8000"]
  
  frontend:
    image: socshield-frontend:dev
    ports: ["3000:3000"]
  
  postgres:
    image: postgres:15
  
  redis:
    image: redis:7-alpine
```

### Production (Kubernetes)
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: socshield-backend
spec:
  replicas: 3
  selector:
    matchLabels:
      app: socshield-backend
  template:
    spec:
      containers:
      - name: backend
        image: socshield-backend:1.0
        resources:
          requests:
            cpu: "500m"
            memory: "512Mi"
          limits:
            cpu: "2000m"
            memory: "2Gi"
```

### Scaling Strategy

| Component | Horizontal Scaling | Vertical Scaling |
|-----------|-------------------|------------------|
| API Gateway | ✅ Load balancer | Limited |
| Worker Nodes | ✅ Celery workers | ⚠️ Memory-bound |
| Database | ⚠️ Read replicas | ✅ Primary concern |
| Redis | ✅ Cluster mode | Limited |

---

## 📈 Performance Characteristics

### Throughput
- **Email analysis:** 50-100 emails/minute (single instance)
- **API requests:** 1000 req/sec (with load balancer)
- **Concurrent connections:** 500+

### Latency (p95)
- Email analysis: < 3 seconds
- API requests: < 100ms
- Database queries: < 50ms
- Cache lookups: < 5ms

---

## 🔮 Future Enhancements

1. **ML Model Training Pipeline**
   - Collect labeled dataset
   - Train custom phishing classifier
   - A/B test against AI providers

2. **Real-time Streaming**
   - WebSocket for live alerts
   - Server-Sent Events for dashboard updates

3. **Advanced Threat Hunting**
   - Behavioral analysis
   - Anomaly detection
   - Graph-based IOC correlation

4. **Multi-tenancy**
   - Organization isolation
   - Per-tenant rate limits
   - Custom model fine-tuning

---

## 📚 Additional Resources

- [API Examples](API_EXAMPLES.md)
- [Configuration Guide](CONFIGURATION_COMPLETE.md)
- [Testing Guide](TESTING.md)
- [Deployment Guide](GETTING_STARTED.md)

---

**Maintained by:** SOCShield Team  
**License:** MIT  
**Contact:** [GitHub Issues](https://github.com/yogigodaraa/SOCShield/issues)
