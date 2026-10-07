# SOCShield - Quick Reference

## 🚀 One-Minute Start

```bash
cp .env.example .env
# Add your AI API key to .env
docker-compose up -d
open http://localhost:3000
```

---

## 🔑 Essential Commands

### Start Services
```bash
# With Docker
docker-compose up -d

# Manual
cd backend && uvicorn app.main:app --reload
cd frontend && npm run dev
```

### Stop Services
```bash
docker-compose down
```

### View Logs
```bash
docker-compose logs -f
```

### Access Points
- Frontend: http://localhost:3000
- API Docs: http://localhost:8000/docs
- Health Check: http://localhost:8000/health

---

## 🔧 Configuration Quick Tips

### Minimum Required (.env)
```bash
AI_PROVIDER=gemini
GOOGLE_API_KEY=your_key_here
DATABASE_URL=postgresql://socshield:password@localhost:5432/socshield
```

### Switch AI Provider
```bash
# In .env, change to:
AI_PROVIDER=openai
OPENAI_API_KEY=your_openai_key

# Or:
AI_PROVIDER=claude
ANTHROPIC_API_KEY=your_claude_key
```

---

## 📡 API Quick Reference

### Analyze Email
```bash
curl -X POST http://localhost:8000/api/v1/analysis/analyze \
  -H "Content-Type: application/json" \
  -d '{"subject":"Test","sender":"test@test.com","body":"Test email"}'
```

### Health Check
```bash
curl http://localhost:8000/health
```

### Get Stats
```bash
curl http://localhost:8000/api/v1/dashboard/stats
```

---

## 🐛 Quick Troubleshooting

| Problem | Solution |
|---------|----------|
| Port 8000 in use | `lsof -ti:8000 \| xargs kill -9` |
| Port 3000 in use | `lsof -ti:3000 \| xargs kill -9` |
| Database error | Check PostgreSQL running: `pg_isctl status` |
| Module not found | `pip install -r requirements.txt` |
| npm errors | `rm -rf node_modules && npm install` |

---

## 📂 Important Files

| File | Purpose |
|------|---------|
| `.env` | Configuration |
| `docker-compose.yml` | Service orchestration |
| `backend/app/main.py` | API entry point |
| `frontend/src/app/page.tsx` | Frontend entry |

---

## 🎯 Common Tasks

### Test Email Analysis
1. Go to http://localhost:3000
2. Click "Analysis" tab
3. Fill form with suspicious email
4. Click "Analyze Email"

### View Threats
1. Go to http://localhost:3000
2. Check "Recent Threats" panel
3. Click threat for details

### Check API Documentation
1. Go to http://localhost:8000/docs
2. Try interactive API examples

---

## 💡 Pro Tips

- Use Gemini for cost-effective scanning
- Use GPT-4 for highest accuracy
- Monitor logs with `docker-compose logs -f`
- Test with real phishing emails from PhishTank
- Adjust thresholds in `.env` for your needs

---

## 📞 Need Help?

- Read: [SETUP.md](SETUP.md) - Detailed setup
- Read: [API_EXAMPLES.md](API_EXAMPLES.md) - API usage
- Read: [ARCHITECTURE.md](ARCHITECTURE.md) - Technical details
- Check: http://localhost:8000/docs - Interactive API docs

---

## 🎓 Learning Path

1. Start services → Visit dashboard
2. Try email analysis → See results
3. Check API docs → Try endpoints
4. Read architecture → Understand flow
5. Customize code → Make it yours

---

## ⚡ Performance Tips

- Use Redis for caching (included in Docker Compose)
- Enable Celery workers for background tasks
- Scale with `docker-compose up --scale backend=3`
- Monitor with Prometheus/Grafana

---

## 🔒 Security Checklist

- [ ] Change default passwords
- [ ] Set strong JWT_SECRET
- [ ] Enable HTTPS in production
- [ ] Rotate API keys regularly
- [ ] Enable rate limiting
- [ ] Set up monitoring

---

Keep this file handy for quick reference! 📋
