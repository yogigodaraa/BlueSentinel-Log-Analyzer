# SOCShield - Getting Started in 5 Minutes

## What is SOCShield?

SOCShield is an AI-powered phishing detection system that automatically analyzes emails and identifies threats in seconds. It's like having a 24/7 security analyst that never gets tired!

---

## What You Get

✅ **3 AI Models to Choose From**
- Google Gemini (fast & free)
- OpenAI GPT-4 (most accurate)
- Anthropic Claude (detailed analysis)

✅ **Beautiful Dashboard**
- Real-time threat detection
- Interactive email analysis
- Live statistics

✅ **Complete Backend**
- REST API for integration
- Email monitoring (IMAP)
- Threat intelligence

✅ **Production Ready**
- Docker deployment
- PostgreSQL database
- Redis caching
- Scalable architecture

---

## Quick Start (Literally 5 Minutes!)

### Step 1: Get an AI API Key (2 minutes)

Pick ONE:

**Option A: Google Gemini** (Recommended - Free!)
1. Go to: https://makersuite.google.com/app/apikey
2. Click "Create API Key"
3. Copy the key

**Option B: OpenAI**
1. Go to: https://platform.openai.com/api-keys
2. Create new key
3. Copy the key

**Option C: Anthropic Claude**
1. Go to: https://console.anthropic.com/
2. Create API key
3. Copy the key

### Step 2: Configure & Start (3 minutes)

```bash
# 1. Navigate to project
cd SOCShield

# 2. Copy environment file
cp .env.example .env

# 3. Edit .env (add your API key)
# On Mac:
nano .env
# Or use any text editor

# Add this (replace with your actual key):
AI_PROVIDER=gemini
GOOGLE_API_KEY=your_actual_api_key_here

# 4. Start everything with Docker
docker-compose up -d

# 5. Open your browser
open http://localhost:3000
```

**That's it! You're running SOCShield!** 🎉

---

## Your First Test

1. **Open Dashboard**: http://localhost:3000

2. **Click "Analysis" tab**

3. **Copy this test phishing email**:
   - Subject: `Urgent: Your Account Has Been Suspended`
   - Sender: `security@paypa1-secure.com`
   - Body: `Your PayPal account has been suspended. Click here to verify: https://fake-paypal.tk/login`
   - Links: `https://fake-paypal.tk/login`

4. **Click "Analyze Email"**

5. **Watch the magic happen!** 🪄
   - AI analyzes the email
   - Extracts suspicious indicators
   - Calculates risk score
   - Shows you detailed results

---

## What Can You Do?

### 1. Analyze Any Email
Paste suspicious emails and get instant analysis

### 2. See Real-Time Threats
Watch the threat feed update with new detections

### 3. Check Statistics
View detection rates, processed emails, and more

### 4. Use the API
Integrate with your existing tools

---

## Common Questions

### "Do I need to install Python/Node.js?"
Nope! Docker handles everything.

### "Can I switch AI providers?"
Yes! Just change `AI_PROVIDER` in `.env` and restart:
```bash
docker-compose restart
```

### "How much does this cost?"
- Google Gemini: FREE (generous free tier)
- OpenAI: ~$0.01 per analysis
- Claude: ~$0.015 per analysis

### "Can I monitor my email inbox?"
Yes! Add your Gmail credentials to `.env`:
```env
IMAP_SERVER=imap.gmail.com
IMAP_PORT=993
IMAP_USERNAME=your_email@gmail.com
IMAP_PASSWORD=your_app_password
```

### "Is my data secure?"
Yes! Everything runs locally on your machine. No data leaves unless you configure external services.

### "Can I use this in production?"
Absolutely! It's production-ready with:
- Database persistence
- Horizontal scaling
- API authentication (coming soon)
- Docker deployment

---

## Next Steps

### Learn More
- 📖 Read [README.md](README.md) for full features
- 🏗️ Check [ARCHITECTURE.md](ARCHITECTURE.md) to understand how it works
- 🔧 See [API_EXAMPLES.md](API_EXAMPLES.md) for integration examples

### Customize It
- Change detection thresholds
- Add custom rules
- Connect to Slack/Teams
- Integrate with your SIEM

### Get Help
- Check the docs in this folder
- API documentation: http://localhost:8000/docs
- Open an issue on GitHub

---

## Troubleshooting

### "docker-compose command not found"
Install Docker Desktop: https://www.docker.com/products/docker-desktop

### "Port 8000 already in use"
Stop the conflicting service:
```bash
lsof -ti:8000 | xargs kill -9
```

### "AI provider error"
Check your API key is correct in `.env`

### "Can't connect to database"
Make sure Docker is running:
```bash
docker-compose ps
```

---

## Visual Guide

### Dashboard Overview
```
┌─────────────────────────────────────────┐
│           SOCShield Dashboard            │
├─────────────────────────────────────────┤
│  📊 Stats  │  🔍 Analysis  │  ⚠️ Threats │
├─────────────────────────────────────────┤
│                                          │
│  [Emails Scanned: 1,247]  ↑ +12.5%     │
│  [Threats Detected: 47]   ↑ +8.2%      │
│  [Detection Rate: 95.4%]  ↑ +2.1%      │
│  [Avg Time: 19s]          ↓ -15.3%     │
│                                          │
│  Recent Threats:                         │
│  ⚠️ PayPal phishing - 5 min ago         │
│  ⚠️ Microsoft scam - 15 min ago         │
│  ⚠️ Invoice fraud - 32 min ago          │
│                                          │
└─────────────────────────────────────────┘
```

### Analysis Flow
```
1. Paste Email
   ↓
2. Click "Analyze"
   ↓
3. AI Processes (19 seconds)
   ↓
4. Get Results:
   - Is it phishing? ✅/❌
   - Confidence score: 92%
   - Risk level: Critical
   - Suspicious indicators
   - Extracted IOCs
```

---

## Tips & Tricks

💡 **Use Keyboard Shortcuts**
- Ctrl+K: Quick search (coming soon)
- Ctrl+N: New analysis

💡 **Test Different AI Models**
Each has strengths:
- Gemini: Fast, great for bulk
- GPT-4: Most accurate
- Claude: Best explanations

💡 **Save Common Tests**
Create a file with test cases:
```bash
curl -X POST http://localhost:8000/api/v1/analysis/analyze \
  -H "Content-Type: application/json" \
  -d @test_case.json
```

💡 **Monitor Performance**
```bash
docker-compose logs -f backend
```

---

## Success Checklist

After 5 minutes, you should have:
- [x] Docker running
- [x] Services started
- [x] Dashboard accessible
- [x] Test email analyzed
- [x] Results displayed

---

## What's Next?

### Today
- Test more phishing emails
- Explore the API docs
- Try different AI providers

### This Week
- Connect your email inbox
- Set up Slack alerts
- Customize the dashboard

### This Month
- Integrate with your SIEM
- Train your team
- Deploy to production

---

## Support

Need help?
- 📖 Read the docs in this folder
- 🌐 Check http://localhost:8000/docs
- 💬 Open a GitHub issue
- 📧 Email: support@socshield.io

---

**You're All Set! 🚀**

You now have a fully functional AI-powered phishing detection system running on your machine!

Start analyzing those suspicious emails and keep your organization safe! 🛡️

---

*Made with ❤️ for Security Operations Centers worldwide*
