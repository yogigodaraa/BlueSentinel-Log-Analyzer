# 🔑 Quick API Keys Setup Guide for SOCShield

## You Need ONE of These API Keys

Choose the AI provider you want to use. You only need ONE, not all three!

---

## Option 1: Google Gemini (Recommended for Testing)

### ✅ Pros:
- 🆓 **Free tier:** 60 requests/minute
- ⚡ Fast responses (200-500ms)
- 🎯 Good accuracy (90-95%)
- 💰 Cheapest option

### 📝 How to Get API Key:

1. **Visit:** https://makersuite.google.com/app/apikey
2. **Sign in** with Google account
3. Click **"Create API Key"**
4. **Copy** the key (starts with `AIza...`)

### ⚙️ Configure:

```bash
cd /Users/yogigodara/Downloads/Projects/SOCShield
cp .env.example .env
```

Edit `.env`:
```bash
AI_PROVIDER=gemini
GOOGLE_API_KEY=AIzaSyD...your_key_here...
```

### 💰 Pricing:
- **Free tier:** 60 requests/minute, 1,500/day
- **Paid:** $0.00025 per request (~$0.25 per 1,000 emails)

---

## Option 2: OpenAI GPT-4 (Best Accuracy)

### ✅ Pros:
- 🎯 **Best accuracy** (92-97%)
- 📚 Most advanced reasoning
- 🔍 Excellent at subtle phishing detection

### ⚠️ Cons:
- 💰 More expensive ($0.01-0.03 per email)
- 🐢 Slower responses (1-2 seconds)
- 💳 Requires payment method

### 📝 How to Get API Key:

1. **Visit:** https://platform.openai.com/api-keys
2. **Sign up** (or sign in)
3. Add payment method (credit card)
4. **Add credits:** Minimum $5
5. Click **"Create new secret key"**
6. **Copy** key (starts with `sk-...`)
7. ⚠️ **Save it!** You can't see it again

### ⚙️ Configure:

Edit `.env`:
```bash
AI_PROVIDER=openai
OPENAI_API_KEY=sk-...your_key_here...
```

### 💰 Pricing:
- **New accounts:** $5 free credit
- **GPT-4:** $0.01-0.03 per 1k tokens (~$0.01 per email)
- **Budget tip:** Use `gpt-3.5-turbo` for $0.001 per email

### 🎛️ Optional: Switch to GPT-3.5 (Cheaper)

Edit `backend/app/ai/openai_provider.py`:
```python
self.model = "gpt-3.5-turbo"  # Instead of "gpt-4-turbo-preview"
```

---

## Option 3: Anthropic Claude (Balanced)

### ✅ Pros:
- 🎯 Good accuracy (90-95%)
- 🛡️ Strong safety features
- 📝 Excellent at explanations

### 📝 How to Get API Key:

1. **Visit:** https://console.anthropic.com/
2. **Sign up** for account
3. **Verify email**
4. Navigate to **"API Keys"**
5. Click **"Create Key"**
6. **Copy** key (starts with `sk-ant-...`)

### ⚙️ Configure:

Edit `.env`:
```bash
AI_PROVIDER=claude
ANTHROPIC_API_KEY=sk-ant-...your_key_here...
```

### 💰 Pricing:
- **Free tier:** Limited
- **Claude 3.5 Sonnet:** $3 per million input tokens
- **~$0.003 per email** (cheaper than GPT-4, pricier than Gemini)

---

## 🚀 Quick Setup (5 Minutes)

### Step 1: Choose Provider & Get Key (3 mins)
Pick one from above ☝️

### Step 2: Configure Environment (1 min)

```bash
cd /Users/yogigodara/Downloads/Projects/SOCShield

# Copy example config
cp .env.example .env

# Edit with your key
nano .env  # or use any text editor
```

### Step 3: Set Your API Key (1 min)

Add ONE of these to `.env`:

```bash
# Option 1: Gemini (Recommended)
AI_PROVIDER=gemini
GOOGLE_API_KEY=AIza...your_key...

# Option 2: OpenAI
# AI_PROVIDER=openai
# OPENAI_API_KEY=sk-...your_key...

# Option 3: Claude
# AI_PROVIDER=claude
# ANTHROPIC_API_KEY=sk-ant-...your_key...
```

### Step 4: Test It! (30 seconds)

```bash
cd backend
source venv/bin/activate
python -c "
from app.core.config import settings
from app.ai.factory import get_ai_provider

print(f'✓ Provider: {settings.AI_PROVIDER}')
print(f'✓ API Key: {settings.GOOGLE_API_KEY[:20] if settings.GOOGLE_API_KEY else \"Not set\"}...')

provider = get_ai_provider()
print('✓ AI Provider initialized successfully!')
"
```

---

## 🔍 Verify Setup

### Test with Sample Email:

```bash
cd backend
source venv/bin/activate
python << 'EOF'
import asyncio
from app.services.phishing_detector import PhishingDetector

async def test():
    detector = PhishingDetector()
    
    email = {
        'subject': 'URGENT: Verify your account',
        'sender': 'noreply@suspicious-bank.com',
        'body': 'Click here immediately: http://phishing-site.tk/verify',
        'links': ['http://phishing-site.tk/verify']
    }
    
    print("🔍 Analyzing email...")
    result = await detector.analyze_email(email)
    
    print(f"\n✅ Analysis Complete!")
    print(f"   - Is Phishing: {result['is_phishing']}")
    print(f"   - Confidence: {result['confidence']:.2f}")
    print(f"   - Risk Level: {result['risk_level']}")
    print(f"   - Provider: {result['ai_provider']}")

asyncio.run(test())
EOF
```

**Expected Output:**
```
🔍 Analyzing email...

✅ Analysis Complete!
   - Is Phishing: True
   - Confidence: 0.95
   - Risk Level: high
   - Provider: gemini
```

---

## 💰 Cost Comparison (Per 1,000 Emails)

| Provider | Cost | Speed | Accuracy | Free Tier |
|----------|------|-------|----------|-----------|
| **Gemini** | $0.25 | Fast (300ms) | 90-95% | ✅ 1,500/day |
| **GPT-3.5** | $1.00 | Fast (500ms) | 85-92% | ✅ $5 credit |
| **GPT-4** | $10-30 | Slow (1-2s) | 92-97% | ✅ $5 credit |
| **Claude 3.5** | $3.00 | Medium (800ms) | 90-95% | ⚠️ Limited |

### 💡 Recommendation:

**For Development/Testing:**
- Use **Gemini** (free tier is generous)

**For Production (<10k emails/day):**
- Use **Gemini** (cheapest, good quality)

**For Production (>10k emails/day):**
- Use **GPT-4** if accuracy critical
- Use **Gemini** if cost-sensitive

**For High Security Environments:**
- Use **GPT-4** or **Claude 3.5**

---

## 🛠️ Troubleshooting

### Error: "Invalid API key"

**Problem:** Key is wrong or expired

**Solution:**
1. Double-check key in `.env`
2. Make sure no extra spaces
3. Regenerate key from provider dashboard

### Error: "Module not found: google.generativeai"

**Problem:** Dependencies not installed

**Solution:**
```bash
cd backend
source venv/bin/activate
pip install -r requirements.txt
```

### Error: "Rate limit exceeded"

**Problem:** Too many requests (free tier limit)

**Solutions:**
1. **Wait:** Limits reset after 1 minute/1 day
2. **Upgrade:** Add payment method
3. **Switch provider:** Try different AI provider

### Error: "Could not connect to API"

**Problem:** Network/firewall issues

**Solutions:**
1. Check internet connection
2. Check firewall settings
3. Try different provider
4. Check API status page

---

## 🎓 Provider Comparison Summary

### When to Use Gemini:
- ✅ Testing/development
- ✅ Cost-sensitive deployment
- ✅ High volume with budget constraints
- ✅ Fast response time needed

### When to Use GPT-4:
- ✅ Highest accuracy required
- ✅ Complex phishing detection
- ✅ Low-medium volume (<10k/day)
- ✅ Budget available

### When to Use Claude:
- ✅ Balanced accuracy/cost
- ✅ Need detailed explanations
- ✅ Trust/safety critical

### When to Use GPT-3.5:
- ✅ High volume on budget
- ✅ Simple phishing detection
- ✅ Fast responses needed

---

## 📊 My Recommendation

**Start Here:** 🎯

1. **Day 1:** Use **Gemini** (free, fast setup)
2. **Week 1:** Test with real emails, measure accuracy
3. **Month 1:** Evaluate costs and accuracy needs
4. **Optimize:** Switch to GPT-4 if need better accuracy, or stay with Gemini if it's working well

**Most Common Setup:**
```bash
AI_PROVIDER=gemini
GOOGLE_API_KEY=your_key_here
```

**Cost for 1,000 emails/day:**
- Gemini: $0.25/day = $7.50/month ✅
- GPT-3.5: $1/day = $30/month
- GPT-4: $10-30/day = $300-900/month
- Claude: $3/day = $90/month

---

## ✅ Next Steps

1. ✅ **Get API key** (3 minutes) ← Do this first!
2. ✅ **Configure .env** (1 minute)
3. ✅ **Test setup** (30 seconds)
4. ✅ **Start backend** (see GETTING_STARTED.md)
5. ✅ **Test with real emails** (30 minutes)

---

**Questions?** Check the main documentation or test different providers - switching is easy!
