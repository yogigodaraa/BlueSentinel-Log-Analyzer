# SOCShield API Examples

## Table of Contents

1. [Email Analysis](#email-analysis)
2. [IOC Extraction](#ioc-extraction)
3. [URL Analysis](#url-analysis)
4. [Dashboard Stats](#dashboard-stats)
5. [Threat Management](#threat-management)

---

## Email Analysis

### Analyze Email for Phishing

**Endpoint**: `POST /api/v1/analysis/analyze`

**Request**:
```bash
curl -X POST "http://localhost:8000/api/v1/analysis/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "Urgent: Your Account Has Been Suspended",
    "sender": "security@paypa1-support.com",
    "recipient": "user@company.com",
    "body": "Dear Customer,\n\nYour account has been temporarily suspended due to unusual activity. Click the link below to verify your identity:\n\nhttps://secure-paypal-verify.tk/login\n\nFailure to verify within 24 hours will result in permanent account closure.\n\nBest regards,\nPayPal Security Team",
    "links": [
      "https://secure-paypal-verify.tk/login"
    ]
  }'
```

**Response**:
```json
{
  "is_phishing": true,
  "confidence": 0.92,
  "risk_level": "critical",
  "indicators": [
    "Suspicious domain (paypa1-support.com instead of paypal.com)",
    "Urgency language and threats",
    "Suspicious TLD (.tk is commonly used in phishing)",
    "Link mismatch (claims to be PayPal but goes to different domain)",
    "Requests immediate action"
  ],
  "explanation": "This email exhibits multiple strong phishing indicators including a spoofed sender domain, urgent threatening language, and a malicious link to a suspicious .tk domain. The email impersonates PayPal to steal credentials.",
  "iocs": {
    "domains": [
      "paypa1-support.com",
      "secure-paypal-verify.tk"
    ],
    "urls": [
      "https://secure-paypal-verify.tk/login"
    ],
    "ip_addresses": [],
    "email_addresses": [
      "security@paypa1-support.com"
    ],
    "file_hashes": []
  },
  "url_analysis": [
    {
      "url": "https://secure-paypal-verify.tk/login",
      "domain": "secure-paypal-verify.tk",
      "suspiciousness_score": 65,
      "indicators": [
        "Suspicious TLD: .tk",
        "Suspicious keywords in path"
      ],
      "is_suspicious": true
    }
  ],
  "analysis_duration": 2.34,
  "analyzed_at": "2025-10-15T10:30:00Z",
  "ai_provider": "gemini"
}
```

---

## IOC Extraction

### Extract IOCs from Email

**Endpoint**: `POST /api/v1/analysis/extract-iocs`

**Request**:
```bash
curl -X POST "http://localhost:8000/api/v1/analysis/extract-iocs" \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "Invoice #12345",
    "sender": "billing@suspicious-company.xyz",
    "body": "Please review the attached invoice. Contact us at support@suspicious-company.xyz or call 192.168.1.100",
    "links": [
      "https://download-invoice.xyz/file.exe",
      "http://192.168.1.100/invoice.pdf"
    ]
  }'
```

**Response**:
```json
{
  "iocs": {
    "domains": [
      "suspicious-company.xyz",
      "download-invoice.xyz"
    ],
    "urls": [
      "https://download-invoice.xyz/file.exe",
      "http://192.168.1.100/invoice.pdf"
    ],
    "ip_addresses": [
      "192.168.1.100"
    ],
    "email_addresses": [
      "billing@suspicious-company.xyz",
      "support@suspicious-company.xyz"
    ],
    "file_hashes": []
  },
  "total_count": 7
}
```

---

## URL Analysis

### Analyze Single URL

**Endpoint**: `POST /api/v1/analysis/analyze-url`

**Request**:
```bash
curl -X POST "http://localhost:8000/api/v1/analysis/analyze-url?url=https://fake-microsoft-login.tk/office365/signin" \
  -H "Content-Type: application/json"
```

**Response**:
```json
{
  "url": "https://fake-microsoft-login.tk/office365/signin",
  "domain": "fake-microsoft-login.tk",
  "suspiciousness_score": 75,
  "indicators": [
    "Suspicious TLD: .tk",
    "Suspicious keywords in path",
    "Domain impersonates legitimate service (Microsoft)"
  ],
  "is_suspicious": true
}
```

---

## Dashboard Stats

### Get Dashboard Statistics

**Endpoint**: `GET /api/v1/dashboard/stats`

**Request**:
```bash
curl "http://localhost:8000/api/v1/dashboard/stats"
```

**Response**:
```json
{
  "total_emails": 1250,
  "threats_detected": 47,
  "emails_today": 156,
  "detection_rate": 0.95,
  "average_detection_time": 19.2,
  "risk_distribution": {
    "critical": 8,
    "high": 15,
    "medium": 18,
    "low": 6
  },
  "trending_threats": [
    {
      "type": "credential_phishing",
      "count": 23,
      "change": "+15%"
    },
    {
      "type": "invoice_scam",
      "count": 12,
      "change": "+8%"
    },
    {
      "type": "malware_attachment",
      "count": 12,
      "change": "-5%"
    }
  ]
}
```

---

## Threat Management

### List Threats

**Endpoint**: `GET /api/v1/threats`

**Request**:
```bash
curl "http://localhost:8000/api/v1/threats?status=open&severity=high"
```

**Response**:
```json
{
  "threats": [
    {
      "id": 1,
      "email_id": 42,
      "title": "PayPal Phishing Campaign",
      "description": "Sophisticated phishing email impersonating PayPal",
      "severity": "critical",
      "status": "open",
      "detected_at": "2025-10-15T09:15:00Z",
      "email": {
        "subject": "Urgent: Account Suspended",
        "sender": "security@paypa1.com",
        "is_phishing": true,
        "confidence": 0.92
      }
    },
    {
      "id": 2,
      "email_id": 38,
      "title": "Microsoft Login Phishing",
      "description": "Fake Microsoft login page",
      "severity": "high",
      "status": "investigating",
      "detected_at": "2025-10-15T08:45:00Z"
    }
  ],
  "total": 2,
  "page": 1,
  "per_page": 20
}
```

### Get Threat Details

**Endpoint**: `GET /api/v1/threats/{threat_id}`

**Request**:
```bash
curl "http://localhost:8000/api/v1/threats/1"
```

**Response**:
```json
{
  "id": 1,
  "email_id": 42,
  "title": "PayPal Phishing Campaign",
  "description": "Sophisticated phishing email impersonating PayPal with fake login page",
  "severity": "critical",
  "status": "open",
  "auto_quarantined": true,
  "auto_blocked": false,
  "manual_review_required": true,
  "assigned_to": null,
  "detected_at": "2025-10-15T09:15:00Z",
  "resolved_at": null,
  "email": {
    "id": 42,
    "message_id": "<abc123@mail.example.com>",
    "subject": "Urgent: Your Account Has Been Suspended",
    "sender": "security@paypa1.com",
    "recipient": "user@company.com",
    "body_text": "Dear Customer...",
    "received_date": "2025-10-15T09:14:30Z",
    "is_phishing": true,
    "confidence": 0.92,
    "risk_level": "critical"
  },
  "iocs": [
    {
      "type": "domain",
      "value": "paypa1.com",
      "is_malicious": true,
      "threat_score": 0.95
    },
    {
      "type": "url",
      "value": "https://secure-paypal-verify.tk/login",
      "is_malicious": true,
      "threat_score": 0.88
    }
  ]
}
```

---

## Python Client Example

```python
import requests

class SOCShieldClient:
    def __init__(self, base_url="http://localhost:8000"):
        self.base_url = base_url
        self.api_url = f"{base_url}/api/v1"
    
    def analyze_email(self, subject, sender, body, links=None):
        """Analyze an email for phishing"""
        data = {
            "subject": subject,
            "sender": sender,
            "body": body,
            "links": links or []
        }
        
        response = requests.post(
            f"{self.api_url}/analysis/analyze",
            json=data
        )
        response.raise_for_status()
        return response.json()
    
    def get_dashboard_stats(self):
        """Get dashboard statistics"""
        response = requests.get(f"{self.api_url}/dashboard/stats")
        response.raise_for_status()
        return response.json()
    
    def list_threats(self, status=None, severity=None):
        """List threats with optional filters"""
        params = {}
        if status:
            params['status'] = status
        if severity:
            params['severity'] = severity
        
        response = requests.get(
            f"{self.api_url}/threats",
            params=params
        )
        response.raise_for_status()
        return response.json()

# Usage
client = SOCShieldClient()

# Analyze email
result = client.analyze_email(
    subject="Urgent: Verify your account",
    sender="security@fake-bank.com",
    body="Click here to verify...",
    links=["https://fake-site.tk/verify"]
)

print(f"Is Phishing: {result['is_phishing']}")
print(f"Confidence: {result['confidence']:.2%}")
print(f"Risk Level: {result['risk_level']}")

# Get stats
stats = client.get_dashboard_stats()
print(f"Total Threats: {stats['threats_detected']}")
```

---

## JavaScript/TypeScript Client Example

```typescript
class SOCShieldClient {
  constructor(private baseUrl = 'http://localhost:8000') {}

  async analyzeEmail(data: {
    subject: string;
    sender: string;
    body: string;
    links?: string[];
  }) {
    const response = await fetch(`${this.baseUrl}/api/v1/analysis/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    
    if (!response.ok) {
      throw new Error(`API error: ${response.statusText}`);
    }
    
    return response.json();
  }

  async getDashboardStats() {
    const response = await fetch(`${this.baseUrl}/api/v1/dashboard/stats`);
    return response.json();
  }

  async listThreats(filters?: { status?: string; severity?: string }) {
    const params = new URLSearchParams(filters);
    const response = await fetch(
      `${this.baseUrl}/api/v1/threats?${params}`
    );
    return response.json();
  }
}

// Usage
const client = new SOCShieldClient();

// Analyze email
const result = await client.analyzeEmail({
  subject: 'Urgent: Verify your account',
  sender: 'security@fake-bank.com',
  body: 'Click here to verify...',
  links: ['https://fake-site.tk/verify'],
});

console.log(`Is Phishing: ${result.is_phishing}`);
console.log(`Confidence: ${(result.confidence * 100).toFixed(1)}%`);
console.log(`Risk Level: ${result.risk_level}`);
```

---

## cURL Examples for Testing

### Quick Health Check
```bash
curl http://localhost:8000/health
```

### Test Benign Email
```bash
curl -X POST "http://localhost:8000/api/v1/analysis/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "Team Meeting Tomorrow",
    "sender": "colleague@company.com",
    "body": "Hi team, reminder about our meeting tomorrow at 2pm in Conference Room A."
  }'
```

### Test Phishing Email
```bash
curl -X POST "http://localhost:8000/api/v1/analysis/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "URGENT: Account Suspended - Action Required",
    "sender": "security@bankofamerica-secure.tk",
    "body": "Your account has been suspended. Click here immediately: https://verify-boa.tk/login or your account will be closed permanently.",
    "links": ["https://verify-boa.tk/login"]
  }'
```

---

For more information, visit the API documentation at: http://localhost:8000/docs
