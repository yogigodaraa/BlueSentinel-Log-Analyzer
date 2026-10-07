# 🚀 Quick Reference: New Backend Features

## 🎯 Overview
Quick guide to using the new infrastructure components in SOCShield backend.

---

## 📝 Structured Logging

### Basic Usage
```python
from app.core.logging import get_logger

logger = get_logger(__name__)

logger.debug("Debugging info")
logger.info("Something happened")
logger.warning("Warning message")
logger.error("Error occurred")
logger.exception("Exception with traceback")  # Auto-includes stack trace
```

### With Context
```python
# Add context that persists across log calls
log = logger.with_context(
    email_id="abc-123",
    user="admin@example.com",
    operation="phishing_analysis"
)

log.info("Starting analysis")  # Context automatically included
log.error("Analysis failed")   # Context still included
```

### Request ID Tracking
```python
from app.core.logging import set_request_id, get_request_id

# Set for current request (done automatically by middleware)
set_request_id("req-123-abc")

# Get current request ID
request_id = get_request_id()  # Returns: "req-123-abc"
```

---

## 🚨 Exception Handling

### Using Custom Exceptions
```python
from app.core.exceptions import (
    EmailProcessingException,
    AIProviderException,
    ThreatIntelException,
    ValidationException
)

# Raise with context
raise EmailProcessingException(
    message="Failed to parse email",
    email_id="email-123"
)

# AI provider errors
raise AIProviderException(
    message="API rate limit exceeded",
    provider="openai",
    details={"retry_after": 60}
)

# Threat intel errors
raise ThreatIntelException(
    message="VirusTotal API unavailable",
    service="virustotal"
)
```

### Exception in API Endpoints
```python
from fastapi import HTTPException
from app.core.exceptions import ValidationException

@router.post("/analyze")
async def analyze_email(email: EmailSchema):
    try:
        result = await detector.analyze_email(email.dict())
        return result
    except ValidationException as e:
        # Automatically returns 400 with structured error
        raise
    except Exception as e:
        # Automatically returns 500 in non-DEBUG mode
        raise
```

---

## 💾 Caching

### Using Cache Decorator
```python
from app.core.cache import cached

# Cache for 5 minutes (300 seconds)
@cached(prefix="user_profile", expiry=300)
async def get_user_profile(user_id: int):
    # Expensive operation
    return await db.query_user(user_id)

# Cache threat intel results for 1 hour
@cached(prefix="url_reputation", expiry=3600)
async def check_url(url: str):
    return await threat_intel.check_url_reputation(url)
```

### Manual Cache Operations
```python
from app.core.cache import cache_manager

# Set value
await cache_manager.set("my_key", {"data": "value"}, expiry=600)

# Get value
value = await cache_manager.get("my_key")  # Returns dict or None

# Delete value
await cache_manager.delete("my_key")

# Clear all cache
await cache_manager.clear()

# Generate cache key
key = cache_manager.generate_key("prefix", arg1, arg2, kwarg1="value")
```

### Custom Key Builder
```python
def build_email_cache_key(email_id: str, **kwargs) -> str:
    return f"email_analysis:{email_id}"

@cached(prefix="email", expiry=300, key_builder=build_email_cache_key)
async def analyze_email(email_id: str, deep_scan: bool = False):
    # ...
```

---

## 📊 Metrics Collection

### Basic Metrics
```python
from app.core.metrics import metrics

# Increment counter
await metrics.increment('api.requests.total')
await metrics.increment('emails.processed', value=5)

# Set gauge (current value)
await metrics.gauge('active_connections', 42)
await metrics.gauge('queue.size', len(queue))

# Record histogram value
await metrics.histogram('response.time_ms', 125.5)
await metrics.histogram('email.size_kb', 45.2)
```

### With Tags
```python
# Tag by endpoint
await metrics.increment(
    'api.requests',
    tags={'endpoint': '/analyze', 'method': 'POST'}
)

# Tag by status
await metrics.increment(
    'api.responses',
    tags={'status_code': '200'}
)

# Tag by provider
await metrics.histogram(
    'ai.latency',
    2.3,
    tags={'provider': 'gemini'}
)
```

### Timing Operations
```python
from app.core.metrics import Timer

# Context manager
async with Timer('database.query.duration'):
    result = await db.complex_query()
    
# With tags
async with Timer('ai.analysis', tags={'provider': 'openai'}):
    result = await ai_provider.analyze(email)
```

### Security-Specific Metrics
```python
from app.core.metrics import SecurityMetrics

# Record phishing detection
await SecurityMetrics.record_phishing_detection(
    is_phishing=True,
    confidence=0.95,
    risk_level="critical"
)

# Record IOC extraction
await SecurityMetrics.record_ioc_extraction(
    ioc_type="urls",
    count=5
)

# Record AI request
await SecurityMetrics.record_ai_request(
    provider="gemini",
    success=True,
    duration=1.2
)

# Record email processing
await SecurityMetrics.record_email_processed(success=True)

# Record threat detection
await SecurityMetrics.record_threat_detected(
    threat_type="phishing",
    severity="high"
)
```

### View Metrics
```python
# Get snapshot
snapshot = await metrics.get_snapshot()

# Returns:
{
    'counters': {'metric.name': 42, ...},
    'gauges': {'metric.name': 3.14, ...},
    'histograms': {
        'metric.name': {
            'count': 100,
            'avg': 1.5,
            'min': 0.1,
            'max': 5.0
        }
    },
    'timestamp': '2025-10-19T12:34:56.789Z'
}
```

---

## 🔍 Threat Intelligence

### Check URL Reputation
```python
from app.services.threat_intel import threat_intel

reputation = await threat_intel.check_url_reputation("https://evil.com")

# Returns:
{
    'indicator': 'https://evil.com',
    'reputation': 'malicious',  # or 'suspicious', 'clean', 'unknown'
    'threat_score': 85,          # 0-100
    'sources_checked': 3,
    'malicious_sources': 2,
    'suspicious_sources': 1,
    'clean_sources': 0,
    'details': [...],
    'checked_at': '2025-10-19T12:34:56.789Z'
}
```

### Check Domain Reputation
```python
reputation = await threat_intel.check_domain_reputation("evil.com")

# Same structure as URL reputation
```

### Check IP Reputation
```python
reputation = await threat_intel.check_ip_reputation("1.2.3.4")

# Same structure
```

### In Analysis Pipeline
```python
# Automatically integrated in PhishingDetector
detector = PhishingDetector()
result = await detector.analyze_email(email_content)

# Result includes:
{
    'url_analysis': [
        {
            'url': 'https://example.com',
            'is_suspicious': True,
            'suspiciousness_score': 45,
            'threat_intel': {
                'reputation': 'suspicious',
                'threat_score': 60
            }
        }
    ],
    'domain_reputation': [...]
}
```

---

## 🛡️ Middleware

### Request Tracking
```python
# Automatically adds to every response:
# - X-Request-ID: Unique identifier
# - X-Response-Time: Duration in seconds

# Access in endpoint
from fastapi import Request

@router.get("/example")
async def example(request: Request):
    request_id = request.state.request_id
    return {"request_id": request_id}
```

### Rate Limiting
```python
# Configured in main.py
# Default: 100 requests per 60 seconds per IP

# Headers added to response:
# - X-RateLimit-Limit: 100
# - X-RateLimit-Remaining: 95
# - Retry-After: 60 (if rate limited)

# Returns 429 Too Many Requests if exceeded
```

### Security Headers
```python
# Automatically added to all responses:
# - X-Content-Type-Options: nosniff
# - X-Frame-Options: DENY
# - X-XSS-Protection: 1; mode=block
# - Strict-Transport-Security: max-age=31536000
```

---

## 🔧 Configuration

### Environment Variables
```env
# Logging
LOG_LEVEL=INFO              # DEBUG, INFO, WARNING, ERROR, CRITICAL
JSON_LOGS=true              # Use JSON format for logs

# Caching
REDIS_URL=redis://localhost:6379/0
ENABLE_CACHING=true

# Threat Intelligence
ENABLE_THREAT_INTEL=true
VIRUSTOTAL_API_KEY=your_key
ABUSEIPDB_API_KEY=your_key

# Rate Limiting
ENABLE_RATE_LIMITING=true
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=60

# Metrics
ENABLE_METRICS=true
```

### Runtime Configuration
```python
from app.core.config import settings

# Access settings
if settings.ENABLE_THREAT_INTEL:
    await threat_intel.check_url(url)

# Check debug mode
if settings.DEBUG:
    logger.debug("Debug info")
```

---

## 🎨 Best Practices

### 1. Always Use Structured Logging
```python
# ❌ Bad
print(f"Processing email {email_id}")

# ✅ Good
logger.info(f"Processing email {email_id}")

# ✅ Better
logger.with_context(email_id=email_id).info("Processing email")
```

### 2. Use Custom Exceptions
```python
# ❌ Bad
raise Exception("Something went wrong")

# ✅ Good
raise EmailProcessingException(
    message="Failed to parse headers",
    email_id=email_id
)
```

### 3. Cache Expensive Operations
```python
# ❌ Bad - No caching
async def get_user(user_id: int):
    return await db.query(user_id)

# ✅ Good - With caching
@cached(prefix="user", expiry=300)
async def get_user(user_id: int):
    return await db.query(user_id)
```

### 4. Record Metrics for Important Operations
```python
# ❌ Bad - No metrics
async def process_email(email):
    result = await analyze(email)
    return result

# ✅ Good - With metrics
async def process_email(email):
    async with Timer('email.processing'):
        result = await analyze(email)
        await metrics.increment('email.processed')
        return result
```

### 5. Use Context Managers for Cleanup
```python
# ✅ Good
async with Timer('operation'):
    async with database.transaction():
        await do_work()
        # Auto-commit or rollback
```

---

## 📍 Common Patterns

### API Endpoint Pattern
```python
from fastapi import APIRouter, HTTPException
from app.core.logging import get_logger
from app.core.metrics import metrics, Timer
from app.core.exceptions import ValidationException

router = APIRouter()
logger = get_logger(__name__)

@router.post("/analyze")
async def analyze_email(email: EmailSchema):
    """Analyze email for phishing"""
    
    log = logger.with_context(
        email_id=email.id,
        sender=email.sender
    )
    
    try:
        # Timing
        async with Timer('email.analysis.duration'):
            # Process
            result = await detector.analyze_email(email.dict())
            
            # Metrics
            await metrics.increment('api.analyze.success')
            
            # Log
            log.info(f"Analysis complete: {result['risk_level']}")
            
            return result
            
    except ValidationException as e:
        await metrics.increment('api.analyze.validation_error')
        log.warning(f"Validation error: {e.message}")
        raise
        
    except Exception as e:
        await metrics.increment('api.analyze.error')
        log.exception("Analysis failed")
        raise HTTPException(status_code=500, detail="Analysis failed")
```

### Service Pattern
```python
from app.core.logging import get_logger
from app.core.cache import cached
from app.core.metrics import SecurityMetrics
from app.core.exceptions import EmailProcessingException

class EmailService:
    def __init__(self):
        self.logger = get_logger(__name__)
    
    @cached(prefix="email_analysis", expiry=300)
    async def analyze(self, email_id: str):
        log = self.logger.with_context(email_id=email_id)
        
        try:
            log.info("Starting analysis")
            
            # Your logic here
            result = await self._do_analysis(email_id)
            
            # Record metrics
            await SecurityMetrics.record_email_processed(success=True)
            
            log.info("Analysis complete")
            return result
            
        except Exception as e:
            await SecurityMetrics.record_email_processed(success=False)
            log.exception("Analysis failed")
            raise EmailProcessingException(
                message=str(e),
                email_id=email_id
            )
```

---

## 🔍 Debugging Tips

### 1. Find All Logs for a Request
```bash
# Search logs by request ID
grep "request_id.*abc-123" /var/log/socshield/app.log
```

### 2. Check Metrics
```bash
# View current metrics
curl http://localhost:8000/metrics

# Filter specific metric
curl http://localhost:8000/metrics | grep "phishing.detections"
```

### 3. View Cache Status
```python
from app.core.cache import cache_manager

# Get specific key
value = await cache_manager.get("my_key")

# Clear cache for debugging
await cache_manager.clear()
```

### 4. Test Exception Handling
```python
# Trigger custom exception
raise EmailProcessingException("Test error", email_id="test-123")

# Check response format at /api/v1/endpoint
```

---

## 📚 Additional Resources

- [Full Architecture Documentation](BACKEND_ARCHITECTURE.md)
- [Improvements Summary](BACKEND_IMPROVEMENTS_SUMMARY.md)
- [API Documentation](http://localhost:8000/docs)
- [Metrics Endpoint](http://localhost:8000/metrics)
- [Health Check](http://localhost:8000/health)

---

**Need Help?**
- Check logs: `/var/log/socshield/app.log`
- View metrics: `http://localhost:8000/metrics`
- API docs: `http://localhost:8000/docs`
- GitHub Issues: Create an issue with logs and context

