# SOCShield Architecture

## System Overview

SOCShield is built as a microservices-based architecture with the following components:

```
┌─────────────────────────────────────────────────────────────────┐
│                         Frontend (Next.js)                       │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │  Dashboard   │  │   Analysis   │  │   Threats    │         │
│  │   Component  │  │    Panel     │  │   Manager    │         │
│  └──────────────┘  └──────────────┘  └──────────────┘         │
└─────────────────────────────────────────────────────────────────┘
                              │
                        REST API / WebSocket
                              │
┌─────────────────────────────────────────────────────────────────┐
│                    Backend API (FastAPI)                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │   Analysis   │  │    Threat    │  │  Dashboard   │         │
│  │   Endpoints  │  │   Endpoints  │  │   Endpoints  │         │
│  └──────────────┘  └──────────────┘  └──────────────┘         │
└─────────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              │               │               │
┌─────────────▼──────┐ ┌─────▼──────┐ ┌─────▼──────────┐
│   AI Provider      │ │   Email    │ │  IOC Extractor │
│   Factory          │ │  Monitor   │ │                │
│ ┌────────────────┐ │ │            │ │                │
│ │ Gemini 2.5     │ │ │ IMAP/SMTP  │ │  Regex/NLP     │
│ │ OpenAI GPT-4   │ │ │  Parser    │ │  URL Analysis  │
│ │ Claude 3.5     │ │ │            │ │                │
│ └────────────────┘ │ └────────────┘ └────────────────┘
└────────────────────┘
              │
┌─────────────▼──────────────────────────────────────────────────┐
│              Background Workers (Celery)                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐        │
│  │   Email      │  │   Threat     │  │   Alert      │        │
│  │  Scanning    │  │  Detection   │  │  Dispatch    │        │
│  └──────────────┘  └──────────────┘  └──────────────┘        │
└────────────────────────────────────────────────────────────────┘
              │
┌─────────────▼──────────────────────────────────────────────────┐
│                       Data Layer                                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐        │
│  │  PostgreSQL  │  │    Redis     │  │   Vector DB  │        │
│  │   (Primary)  │  │   (Cache)    │  │  (pgvector)  │        │
│  └──────────────┘  └──────────────┘  └──────────────┘        │
└────────────────────────────────────────────────────────────────┘
```

---

## Component Details

### Frontend (Next.js)

**Technology Stack:**
- Next.js 14 with App Router
- TypeScript
- Tailwind CSS
- React Query (TanStack Query)
- Recharts for visualizations

**Key Components:**

1. **Dashboard Component**
   - Real-time statistics display
   - Threat timeline visualization
   - System health monitoring
   - Quick action buttons

2. **Analysis Panel**
   - Email input form
   - Real-time analysis results
   - IOC visualization
   - Risk assessment display

3. **Threat Feed**
   - Recent threats list
   - Severity indicators
   - Quick triage actions
   - Time-based filtering

4. **Configuration Panel**
   - Email account management
   - AI provider selection
   - Alert configuration
   - SIEM integration settings

**File Structure:**
```
frontend/
├── src/
│   ├── app/
│   │   ├── layout.tsx          # Root layout
│   │   ├── page.tsx            # Home page
│   │   └── globals.css         # Global styles
│   ├── components/
│   │   ├── dashboard/
│   │   │   ├── Dashboard.tsx   # Main dashboard
│   │   │   ├── StatsCard.tsx   # Statistics cards
│   │   │   ├── ThreatFeed.tsx  # Threat list
│   │   │   └── AnalysisPanel.tsx # Analysis interface
│   │   └── providers.tsx       # Context providers
│   └── lib/
│       └── api.ts              # API client
├── package.json
└── next.config.mjs
```

---

### Backend API (FastAPI)

**Technology Stack:**
- FastAPI (Python 3.11+)
- SQLAlchemy (ORM)
- Pydantic (validation)
- asyncio (async operations)

**Architecture Layers:**

1. **API Layer** (`app/api/v1/`)
   - RESTful endpoints
   - Request validation
   - Response formatting
   - Error handling

2. **Service Layer** (`app/services/`)
   - Business logic
   - Email monitoring
   - Phishing detection
   - IOC extraction

3. **AI Layer** (`app/ai/`)
   - Provider abstraction
   - Multi-model support
   - Prompt engineering
   - Response parsing

4. **Data Layer** (`app/models/`)
   - Database models
   - Relationships
   - Migrations

**File Structure:**
```
backend/
├── app/
│   ├── main.py                 # FastAPI application
│   ├── core/
│   │   ├── config.py           # Configuration
│   │   └── database.py         # DB setup
│   ├── api/
│   │   └── v1/
│   │       ├── router.py       # Main router
│   │       └── endpoints/
│   │           ├── analysis.py # Analysis endpoints
│   │           ├── threats.py  # Threat management
│   │           └── dashboard.py# Dashboard stats
│   ├── ai/
│   │   ├── base.py             # Base provider
│   │   ├── gemini_provider.py  # Google Gemini
│   │   ├── openai_provider.py  # OpenAI GPT
│   │   ├── claude_provider.py  # Anthropic Claude
│   │   └── factory.py          # Provider factory
│   ├── services/
│   │   ├── email_monitor.py    # Email fetching
│   │   ├── ioc_extractor.py    # IOC extraction
│   │   └── phishing_detector.py# Main detector
│   ├── models/
│   │   └── models.py           # Database models
│   └── worker.py               # Celery worker
├── requirements.txt
└── Dockerfile
```

---

## Data Flow

### Email Analysis Flow

```
1. User Input / Email Monitor
   │
   ├─→ Email Parser
   │    ├─ Extract subject, sender, body
   │    ├─ Parse headers
   │    └─ Extract links & attachments
   │
   ├─→ IOC Extractor (Parallel)
   │    ├─ Regex pattern matching
   │    ├─ Domain extraction
   │    ├─ URL parsing
   │    └─ IP address detection
   │
   ├─→ AI Provider (Parallel)
   │    ├─ Content analysis
   │    ├─ Phishing detection
   │    └─ AI-based IOC extraction
   │
   └─→ Phishing Detector (Orchestrator)
        ├─ Merge results
        ├─ Calculate risk score
        ├─ URL suspiciousness analysis
        ├─ Final classification
        │
        ├─→ Store in Database
        │    ├─ Email record
        │    ├─ IOCs
        │    ├─ Analysis results
        │    └─ Threat record
        │
        └─→ Trigger Actions
             ├─ Send alerts
             ├─ Quarantine (if configured)
             ├─ Block sender (if configured)
             └─ Create SIEM ticket
```

---

## Database Schema

### Core Tables

**emails**
```sql
- id (PK)
- message_id (unique)
- subject
- sender
- recipient
- body_text
- body_html
- headers (JSON)
- received_date
- processed_date
- is_phishing
- confidence
- risk_level
- status
- ai_analysis (JSON)
- indicators (JSON)
- analysis_duration
- ai_provider
```

**threats**
```sql
- id (PK)
- email_id (FK)
- title
- description
- severity
- auto_quarantined
- auto_blocked
- manual_review_required
- assigned_to
- status
- detected_at
- resolved_at
```

**iocs**
```sql
- id (PK)
- email_id (FK)
- ioc_type (domain, url, ip, email, hash)
- value
- is_malicious
- threat_score
- first_seen
- last_seen
- occurrence_count
- virustotal_score
- threat_intel_sources (JSON)
```

**alerts**
```sql
- id (PK)
- threat_id (FK)
- alert_type (email, slack, teams, sms)
- recipient
- message
- sent
- sent_at
- error_message
```

---

## AI Provider Integration

### Abstraction Layer

```python
class BaseAIProvider(ABC):
    @abstractmethod
    async def analyze_email(self, email_content):
        """Analyze email for phishing"""
        pass
    
    @abstractmethod
    async def extract_iocs(self, email_content):
        """Extract IOCs"""
        pass
```

### Provider Implementations

1. **Google Gemini**
   - Model: gemini-2.0-flash-exp
   - Features: Fast, cost-effective
   - Best for: High-volume scanning

2. **OpenAI GPT-4**
   - Model: gpt-4-turbo-preview
   - Features: High accuracy, structured output
   - Best for: Complex analysis

3. **Anthropic Claude**
   - Model: claude-3-5-sonnet-20241022
   - Features: Detailed explanations
   - Best for: Investigation support

### Switching Providers

```python
# In .env
AI_PROVIDER=gemini  # or openai or claude

# Runtime switching (future feature)
ai_provider = AIService.get_provider()
result = await ai_provider.analyze_email(email_data)
```

---

## Security Considerations

### API Security

1. **Authentication**
   - JWT tokens for API access
   - API key validation
   - Rate limiting per client

2. **Data Protection**
   - HTTPS only in production
   - Encrypted API keys
   - Encrypted email passwords
   - Database encryption at rest

3. **Input Validation**
   - Pydantic models for all inputs
   - SQL injection prevention (ORM)
   - XSS prevention (sanitization)

### Email Security

1. **IMAP/SMTP**
   - TLS/SSL connections
   - App-specific passwords
   - OAuth2 support (future)

2. **Email Storage**
   - Configurable retention
   - PII redaction options
   - GDPR compliance features

---

## Performance Optimization

### Caching Strategy

1. **Redis Cache**
   - Analysis results (1 hour TTL)
   - Dashboard stats (5 minutes TTL)
   - Threat intelligence (24 hours TTL)

2. **Database Indexing**
   - Email sender, subject
   - Threat severity, status
   - IOC values, types
   - Timestamps

### Async Processing

1. **FastAPI Async**
   - Non-blocking I/O
   - Concurrent request handling
   - Async database operations

2. **Celery Tasks**
   - Email scanning (scheduled)
   - Batch analysis
   - Alert dispatching
   - Report generation

---

## Scalability

### Horizontal Scaling

```yaml
# Docker Compose example
services:
  backend:
    replicas: 3
    deploy:
      resources:
        limits:
          cpus: '1'
          memory: 2G
  
  celery-worker:
    replicas: 5
```

### Load Balancing

- NGINX reverse proxy
- Round-robin distribution
- Health check endpoints
- Session affinity for WebSocket

---

## Monitoring & Observability

### Metrics Collection

1. **Application Metrics**
   - Request rate
   - Response time
   - Error rate
   - AI provider latency

2. **Business Metrics**
   - Emails scanned per hour
   - Threats detected
   - Detection accuracy
   - False positive rate

### Logging Strategy

```python
# Structured logging
logger.info("Email analyzed", extra={
    "email_id": email.id,
    "sender": email.sender,
    "is_phishing": result.is_phishing,
    "confidence": result.confidence,
    "duration": analysis_duration
})
```

---

## Future Enhancements

1. **Machine Learning**
   - Custom ML models
   - Transfer learning
   - Model ensemble
   - Continuous training

2. **Advanced Features**
   - Email sandboxing
   - Attachment analysis
   - Header analysis
   - Sender reputation scoring

3. **Integrations**
   - Microsoft 365
   - Google Workspace
   - More SIEM platforms
   - Threat intelligence feeds

4. **UI/UX**
   - Mobile app
   - Real-time dashboard
   - Advanced visualizations
   - Playbook automation

---

## Development Workflow

```bash
# 1. Create feature branch
git checkout -b feature/new-detector

# 2. Make changes
# backend/app/services/new_detector.py

# 3. Test locally
pytest tests/test_new_detector.py

# 4. Run full test suite
pytest

# 5. Code formatting
black app/
flake8 app/

# 6. Commit and push
git commit -m "Add new detector"
git push origin feature/new-detector

# 7. Create pull request
# Review → Approve → Merge
```

---

For detailed API documentation, see [API_EXAMPLES.md](API_EXAMPLES.md)
For setup instructions, see [SETUP.md](SETUP.md)
