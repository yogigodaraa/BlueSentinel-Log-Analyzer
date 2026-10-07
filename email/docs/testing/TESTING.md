# 🧪 SOCShield Testing Guide

## Quick Test Scenarios

### 1. Test Phishing Email Detection

Use these real-world-inspired phishing examples to test SOCShield:

#### Example 1: PayPal Phishing
```json
{
  "subject": "Urgent: Your PayPal Account Has Been Limited",
  "sender": "security@paypa1-secure.com",
  "body": "Dear Valued Customer,\n\nYour PayPal account has been temporarily limited due to unusual activity. To restore full access, please verify your identity immediately by clicking the link below:\n\nhttps://secure-paypal-verify.tk/account/login\n\nFailure to complete verification within 24 hours will result in permanent account suspension.\n\nSincerely,\nPayPal Security Team",
  "links": ["https://secure-paypal-verify.tk/account/login"]
}
```

**Expected Result:**
- `is_phishing`: true
- `confidence`: 0.85-0.95
- `risk_level`: "critical" or "high"
- Indicators: Spoofed domain, urgency, suspicious TLD

---

#### Example 2: Microsoft Office 365 Phishing
```json
{
  "subject": "Action Required: Verify Your Microsoft Account",
  "sender": "no-reply@microsoft-security.xyz",
  "body": "Your Microsoft 365 account requires immediate verification. Click below to confirm your identity:\n\nhttps://login-microsoftonline.tk/signin\n\nIf you don't verify within 2 hours, your account will be suspended.",
  "links": ["https://login-microsoftonline.tk/signin"]
}
```

**Expected Result:**
- `is_phishing`: true
- `confidence`: 0.80-0.90
- `risk_level`: "high"
- Indicators: Suspicious domain, impersonation, urgency

---

#### Example 3: Invoice Scam
```json
{
  "subject": "Invoice #INV-2024-10-12345 - Payment Overdue",
  "sender": "billing@accounting-services.xyz",
  "body": "Your invoice payment is overdue. Download the attached invoice and make payment immediately to avoid service interruption.\n\nClick here to download: http://192.168.1.100/invoice.exe",
  "links": ["http://192.168.1.100/invoice.exe"]
}
```

**Expected Result:**
- `is_phishing`: true
- `confidence`: 0.75-0.90
- `risk_level`: "high" or "medium"
- Indicators: Suspicious file extension (.exe), IP address in URL

---

#### Example 4: Benign Email (Should NOT be flagged)
```json
{
  "subject": "Team Meeting - Q4 Planning",
  "sender": "manager@yourcompany.com",
  "body": "Hi team,\n\nLet's schedule our Q4 planning meeting for next Tuesday at 2 PM. Please review the agenda document before the meeting.\n\nBest regards,\nJohn"
}
```

**Expected Result:**
- `is_phishing`: false
- `confidence`: 0.10-0.30
- `risk_level`: "low"
- Indicators: Few or none

---

### 2. Testing via Dashboard

1. **Access the Dashboard**
   ```
   http://localhost:3000
   ```

2. **Navigate to Analysis Tab**
   - Click "analysis" in the top navigation

3. **Enter Test Data**
   - Copy one of the examples above
   - Paste into the form fields
   - Click "Analyze Email"

4. **Review Results**
   - Check the risk assessment
   - Review phishing indicators
   - Examine IOC extraction
   - Note the confidence score

---

### 3. Testing via API

#### Using cURL

```bash
# Test 1: Phishing Email
curl -X POST "http://localhost:8000/api/v1/analysis/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "Urgent: Your Account Has Been Suspended",
    "sender": "security@fake-bank.tk",
    "body": "Click here to verify: https://verify-account.tk/login",
    "links": ["https://verify-account.tk/login"]
  }'

# Test 2: Benign Email
curl -X POST "http://localhost:8000/api/v1/analysis/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "Project Update",
    "sender": "colleague@company.com",
    "body": "Here is the status update for our project."
  }'
```

#### Using Python

```python
import requests

def test_email_analysis():
    url = "http://localhost:8000/api/v1/analysis/analyze"
    
    # Test phishing email
    phishing_email = {
        "subject": "Urgent: Account Suspended",
        "sender": "security@fake-paypal.tk",
        "body": "Verify immediately: https://verify-paypal.tk",
        "links": ["https://verify-paypal.tk"]
    }
    
    response = requests.post(url, json=phishing_email)
    result = response.json()
    
    print(f"Is Phishing: {result['is_phishing']}")
    print(f"Confidence: {result['confidence']:.2%}")
    print(f"Risk Level: {result['risk_level']}")
    print(f"Indicators: {result['indicators']}")
    
    # Assertions for testing
    assert result['is_phishing'] == True
    assert result['confidence'] > 0.7
    assert result['risk_level'] in ['high', 'critical']
    print("\n✅ Phishing detection test passed!")

if __name__ == "__main__":
    test_email_analysis()
```

#### Using JavaScript/Node.js

```javascript
async function testEmailAnalysis() {
  const response = await fetch('http://localhost:8000/api/v1/analysis/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      subject: 'Urgent: Account Suspended',
      sender: 'security@fake-bank.tk',
      body: 'Click to verify: https://verify.tk',
      links: ['https://verify.tk']
    })
  });
  
  const result = await response.json();
  
  console.log('Is Phishing:', result.is_phishing);
  console.log('Confidence:', (result.confidence * 100).toFixed(1) + '%');
  console.log('Risk Level:', result.risk_level);
  
  // Assertions
  if (result.is_phishing && result.confidence > 0.7) {
    console.log('✅ Test passed!');
  } else {
    console.log('❌ Test failed!');
  }
}

testEmailAnalysis();
```

---

### 4. IOC Extraction Testing

Test the IOC extractor with various email contents:

```bash
# Test IOC extraction
curl -X POST "http://localhost:8000/api/v1/analysis/extract-iocs" \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "Important Document",
    "sender": "sender@suspicious-domain.xyz",
    "body": "Visit http://192.168.1.100 or contact admin@phishing-site.tk for more info. Download from https://malware-site.com/payload.exe",
    "links": [
      "http://192.168.1.100",
      "https://malware-site.com/payload.exe"
    ]
  }'
```

**Expected IOCs:**
- Domains: suspicious-domain.xyz, phishing-site.tk, malware-site.com
- URLs: http://192.168.1.100, https://malware-site.com/payload.exe
- IP Addresses: 192.168.1.100
- Email Addresses: sender@suspicious-domain.xyz, admin@phishing-site.tk

---

### 5. URL Analysis Testing

Test individual URL suspiciousness scoring:

```bash
# Test suspicious URL
curl -X POST "http://localhost:8000/api/v1/analysis/analyze-url?url=https://fake-microsoft-login.tk/office365/signin"

# Test legitimate URL
curl -X POST "http://localhost:8000/api/v1/analysis/analyze-url?url=https://www.microsoft.com/login"
```

---

### 6. Performance Testing

#### Measure Detection Speed

```python
import requests
import time

def benchmark_analysis():
    url = "http://localhost:8000/api/v1/analysis/analyze"
    
    test_email = {
        "subject": "Test Email",
        "sender": "test@test.com",
        "body": "This is a test email for performance benchmarking.",
        "links": ["https://example.com"]
    }
    
    times = []
    for i in range(10):
        start = time.time()
        response = requests.post(url, json=test_email)
        elapsed = time.time() - start
        times.append(elapsed)
        print(f"Request {i+1}: {elapsed:.2f}s")
    
    avg_time = sum(times) / len(times)
    print(f"\n📊 Average analysis time: {avg_time:.2f}s")
    print(f"Min: {min(times):.2f}s, Max: {max(times):.2f}s")

benchmark_analysis()
```

---

### 7. Load Testing

Use Apache Bench for load testing:

```bash
# Install Apache Bench (if not installed)
# macOS: brew install httpd
# Linux: sudo apt-get install apache2-utils

# Create test payload file
cat > test_payload.json << 'EOF'
{
  "subject": "Test Subject",
  "sender": "test@test.com",
  "body": "Test body"
}
EOF

# Run load test (100 requests, 10 concurrent)
ab -n 100 -c 10 -p test_payload.json -T application/json \
  http://localhost:8000/api/v1/analysis/analyze
```

---

### 8. Integration Testing

#### Test Full Workflow

```python
import requests
import time

def test_full_workflow():
    base_url = "http://localhost:8000/api/v1"
    
    print("1. Health Check...")
    health = requests.get("http://localhost:8000/health")
    assert health.status_code == 200
    print("   ✅ Backend is healthy")
    
    print("\n2. Analyzing phishing email...")
    analysis = requests.post(f"{base_url}/analysis/analyze", json={
        "subject": "Urgent: Verify Account",
        "sender": "security@fake-bank.tk",
        "body": "Click here: https://phishing-site.tk",
        "links": ["https://phishing-site.tk"]
    })
    result = analysis.json()
    assert result['is_phishing'] == True
    print(f"   ✅ Phishing detected (confidence: {result['confidence']:.2%})")
    
    print("\n3. Extracting IOCs...")
    iocs = requests.post(f"{base_url}/analysis/extract-iocs", json={
        "subject": "Test",
        "sender": "test@suspicious.tk",
        "body": "Visit https://malware.tk",
        "links": ["https://malware.tk"]
    })
    ioc_result = iocs.json()
    assert len(ioc_result['iocs']['domains']) > 0
    print(f"   ✅ IOCs extracted: {ioc_result['total_count']} items")
    
    print("\n4. Getting dashboard stats...")
    stats = requests.get(f"{base_url}/dashboard/stats")
    assert stats.status_code == 200
    print("   ✅ Dashboard stats retrieved")
    
    print("\n🎉 All integration tests passed!")

if __name__ == "__main__":
    test_full_workflow()
```

---

### 9. AI Provider Testing

Test each AI provider separately:

```bash
# Test with Gemini
curl -X POST "http://localhost:8000/api/v1/analysis/analyze" \
  -H "Content-Type: application/json" \
  -d '{"subject":"Test","sender":"test@test.com","body":"Test email"}'

# Check which provider was used in response
# "ai_provider": "gemini"
```

To test different providers:

1. Stop the backend
2. Edit `.env` and change `AI_PROVIDER=openai` (or claude)
3. Restart the backend
4. Run the same test
5. Verify the `ai_provider` field in response

---

### 10. Error Handling Testing

Test various error scenarios:

```bash
# Test missing required fields
curl -X POST "http://localhost:8000/api/v1/analysis/analyze" \
  -H "Content-Type: application/json" \
  -d '{"subject":"Test"}'
# Expected: 422 Unprocessable Entity

# Test invalid email format
curl -X POST "http://localhost:8000/api/v1/analysis/analyze" \
  -H "Content-Type: application/json" \
  -d '{"subject":"Test","sender":"invalid-email","body":"Test"}'
# Expected: 422 Unprocessable Entity

# Test invalid endpoint
curl "http://localhost:8000/api/v1/nonexistent"
# Expected: 404 Not Found
```

---

### 11. Real-World Testing

For the most realistic testing, use actual phishing emails:

#### Sources of Test Emails:
1. **PhishTank**: https://www.phishtank.com/
   - Download recent phishing emails
   - Parse and feed into SOCShield

2. **Spam Assassin Public Corpus**: https://spamassassin.apache.org/
   - Large collection of spam and ham emails

3. **Your Own Spam Folder**
   - Use real emails from your spam folder
   - Redact sensitive information

#### Example Process:
```python
import requests

def test_phishtank_email():
    # Example from PhishTank (sanitized)
    phishing_email = {
        "subject": "Your Amazon Prime membership is expiring",
        "sender": "no-reply@amazon-prime-renewal.tk",
        "body": """Dear Customer,
        
Your Amazon Prime membership is about to expire. 
Renew now to continue enjoying free shipping: 
https://amazon-renewal.tk/renew

If you don't renew within 24 hours, you will lose your benefits.

Amazon Prime Team""",
        "links": ["https://amazon-renewal.tk/renew"]
    }
    
    response = requests.post(
        "http://localhost:8000/api/v1/analysis/analyze",
        json=phishing_email
    )
    
    result = response.json()
    print(f"Detection: {result['is_phishing']}")
    print(f"Confidence: {result['confidence']:.2%}")
    print(f"Risk: {result['risk_level']}")

test_phishtank_email()
```

---

## Test Results Template

Use this template to document your test results:

```markdown
## Test Results - [Date]

### System Info
- Version: 1.0.0
- AI Provider: Gemini
- Database: PostgreSQL 15
- Python: 3.11
- Node.js: 18

### Test Scenarios

#### 1. PayPal Phishing
- **Status**: ✅ Pass / ❌ Fail
- **Expected**: Phishing detected
- **Actual**: is_phishing=true, confidence=0.92
- **Notes**: Correctly identified all indicators

#### 2. Microsoft Phishing
- **Status**: ✅ Pass
- **Expected**: Phishing detected
- **Actual**: is_phishing=true, confidence=0.88
- **Notes**: Slight delay in response (3.2s)

#### 3. Benign Email
- **Status**: ✅ Pass
- **Expected**: Safe email
- **Actual**: is_phishing=false, confidence=0.15
- **Notes**: Correctly classified as safe

### Performance
- Average detection time: 2.1s
- API response time: <100ms
- IOC extraction: 10ms

### Issues Found
- None

### Recommendations
- Consider adjusting confidence threshold
- Add more test cases for edge scenarios
```

---

## Automated Testing Script

Save this as `test_socshield.sh`:

```bash
#!/bin/bash

echo "🧪 SOCShield Testing Suite"
echo "=========================="

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

API_URL="http://localhost:8000"

# Test 1: Health Check
echo -e "\n1. Health Check..."
HEALTH=$(curl -s "${API_URL}/health")
if [[ $HEALTH == *"healthy"* ]]; then
    echo -e "${GREEN}✅ Health check passed${NC}"
else
    echo -e "${RED}❌ Health check failed${NC}"
    exit 1
fi

# Test 2: Phishing Detection
echo -e "\n2. Phishing Detection..."
PHISHING=$(curl -s -X POST "${API_URL}/api/v1/analysis/analyze" \
  -H "Content-Type: application/json" \
  -d '{"subject":"Urgent Account","sender":"security@fake.tk","body":"Click here","links":["https://phish.tk"]}')

if [[ $PHISHING == *"\"is_phishing\":true"* ]]; then
    echo -e "${GREEN}✅ Phishing detected correctly${NC}"
else
    echo -e "${RED}❌ Phishing detection failed${NC}"
fi

# Test 3: IOC Extraction
echo -e "\n3. IOC Extraction..."
IOC=$(curl -s -X POST "${API_URL}/api/v1/analysis/extract-iocs" \
  -H "Content-Type: application/json" \
  -d '{"subject":"Test","sender":"test@bad.tk","body":"Visit https://malware.tk"}')

if [[ $IOC == *"\"domains\""* ]]; then
    echo -e "${GREEN}✅ IOC extraction working${NC}"
else
    echo -e "${RED}❌ IOC extraction failed${NC}"
fi

echo -e "\n=========================="
echo -e "${GREEN}✅ All tests completed!${NC}"
```

Make it executable and run:
```bash
chmod +x test_socshield.sh
./test_socshield.sh
```

---

## Continuous Testing

Add these tests to your CI/CD pipeline:

```yaml
# .github/workflows/test.yml
name: SOCShield Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Start services
        run: docker-compose up -d
      
      - name: Wait for services
        run: sleep 30
      
      - name: Run tests
        run: ./test_socshield.sh
      
      - name: Stop services
        run: docker-compose down
```

---

**Happy Testing! 🧪**

Remember: The more you test, the better SOCShield becomes!
