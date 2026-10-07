# SOCShield Setup Guide

## Quick Start Guide

Follow these steps to get SOCShield running on your local machine.

### Prerequisites

Ensure you have the following installed:

- **Python 3.11+** - [Download](https://www.python.org/downloads/)
- **Node.js 18+** - [Download](https://nodejs.org/)
- **PostgreSQL 15+** - [Download](https://www.postgresql.org/download/)
- **Redis 7+** - [Download](https://redis.io/download)
- **Git** - [Download](https://git-scm.com/downloads)

### 1. Clone the Repository

```bash
git clone <your-repo-url>
cd SOCShield
```

### 2. Backend Setup

#### a. Create Python Virtual Environment

```bash
cd backend
python3 -m venv venv

# On macOS/Linux:
source venv/bin/activate

# On Windows:
# venv\Scripts\activate
```

#### b. Install Python Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

#### c. Download spaCy Model

```bash
python -m spacy download en_core_web_sm
```

#### d. Configure Environment Variables

```bash
cp ../.env.example .env
```

Edit `.env` and configure at minimum:

```env
# Database
DATABASE_URL=postgresql://socshield:your_password@localhost:5432/socshield

# AI Provider (choose one)
AI_PROVIDER=gemini
GOOGLE_API_KEY=your_gemini_api_key_here

# OR
# AI_PROVIDER=openai
# OPENAI_API_KEY=your_openai_api_key_here

# OR
# AI_PROVIDER=claude
# ANTHROPIC_API_KEY=your_claude_api_key_here

# Email Configuration
IMAP_SERVER=imap.gmail.com
IMAP_PORT=993
IMAP_USERNAME=your_email@gmail.com
IMAP_PASSWORD=your_app_password
```

### 3. Database Setup

#### a. Create PostgreSQL Database

```bash
# Connect to PostgreSQL
psql -U postgres

# Create database and user
CREATE DATABASE socshield;
CREATE USER socshield WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE socshield TO socshield;
\q
```

#### b. Run Migrations

```bash
# Still in backend directory
alembic upgrade head
```

### 4. Frontend Setup

```bash
# From project root
cd frontend

# Install dependencies
npm install

# Configure environment
cp .env.example .env.local
```

Edit `.env.local`:

```env
NEXT_PUBLIC_API_URL=http://localhost:8000
NEXT_PUBLIC_WS_URL=ws://localhost:8000/ws
```

### 5. Start Services

You'll need **4 terminal windows**:

#### Terminal 1: Backend API

```bash
cd backend
source venv/bin/activate  # On Windows: venv\Scripts\activate
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

#### Terminal 2: Celery Worker (Optional, for background tasks)

```bash
cd backend
source venv/bin/activate
celery -A app.worker worker --loglevel=info
```

#### Terminal 3: Celery Beat (Optional, for scheduled tasks)

```bash
cd backend
source venv/bin/activate
celery -A app.worker beat --loglevel=info
```

#### Terminal 4: Frontend

```bash
cd frontend
npm run dev
```

### 6. Access SOCShield

- **Frontend Dashboard**: http://localhost:3000
- **Backend API Docs**: http://localhost:8000/docs
- **Backend Health**: http://localhost:8000/health

---

## Using Docker Compose (Recommended for Production)

### 1. Configure Environment

```bash
cp .env.example .env
# Edit .env with your configuration
```

### 2. Start All Services

```bash
docker-compose up -d
```

### 3. Access Services

- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8000/docs
- **PostgreSQL**: localhost:5432
- **Redis**: localhost:6379

### 4. View Logs

```bash
docker-compose logs -f
```

### 5. Stop Services

```bash
docker-compose down
```

---

## Getting AI API Keys

### Google Gemini

1. Go to [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Click "Create API Key"
3. Copy the key and add to `.env`: `GOOGLE_API_KEY=your_key`

### OpenAI

1. Go to [OpenAI Platform](https://platform.openai.com/api-keys)
2. Create a new API key
3. Copy the key and add to `.env`: `OPENAI_API_KEY=your_key`

### Anthropic Claude

1. Go to [Anthropic Console](https://console.anthropic.com/)
2. Navigate to API Keys
3. Create a new key
4. Copy the key and add to `.env`: `ANTHROPIC_API_KEY=your_key`

---

## Gmail Configuration (for Email Monitoring)

### 1. Enable IMAP in Gmail

1. Go to Gmail Settings → See all settings
2. Click "Forwarding and POP/IMAP"
3. Enable IMAP
4. Save changes

### 2. Create App Password

1. Go to [Google Account Security](https://myaccount.google.com/security)
2. Enable 2-Step Verification (if not already enabled)
3. Go to App Passwords
4. Select "Mail" and "Other"
5. Generate password
6. Use this password in `.env` as `IMAP_PASSWORD`

---

## Testing the System

### 1. Test Backend API

```bash
curl http://localhost:8000/health
```

Expected response:
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "ai_provider": "gemini"
}
```

### 2. Test Email Analysis

#### Using the Dashboard

1. Open http://localhost:3000
2. Click "Analysis" tab
3. Fill in the form with test email data:
   - Subject: "Urgent: Verify your account"
   - Sender: suspicious@example.com
   - Body: "Click here to verify your account or it will be suspended"
   - Links: https://fake-bank-site.tk/verify
4. Click "Analyze Email"

#### Using API Directly

```bash
curl -X POST "http://localhost:8000/api/v1/analysis/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "Urgent: Verify your account",
    "sender": "suspicious@example.com",
    "body": "Click here to verify your account or it will be suspended",
    "links": ["https://fake-bank-site.tk/verify"]
  }'
```

---

## Troubleshooting

### Backend won't start

**Problem**: Import errors or module not found

**Solution**:
```bash
cd backend
source venv/bin/activate
pip install -r requirements.txt
python -m spacy download en_core_web_sm
```

### Database connection error

**Problem**: Can't connect to PostgreSQL

**Solution**:
1. Ensure PostgreSQL is running: `sudo systemctl status postgresql`
2. Check DATABASE_URL in `.env`
3. Verify database exists: `psql -U postgres -l`

### Frontend build errors

**Problem**: Module not found or dependency errors

**Solution**:
```bash
cd frontend
rm -rf node_modules package-lock.json
npm install
```

### AI Provider errors

**Problem**: API key invalid or quota exceeded

**Solution**:
1. Verify your API key is correct in `.env`
2. Check your API quota/billing
3. Try switching to a different provider

### Email monitoring not working

**Problem**: Can't fetch emails via IMAP

**Solution**:
1. Verify IMAP is enabled in Gmail
2. Use App Password, not regular password
3. Check IMAP server and port in `.env`

---

## Development Tips

### Hot Reloading

Both backend and frontend support hot reloading:
- Backend: Automatically reloads on code changes
- Frontend: Automatically refreshes on code changes

### Database Migrations

When you modify database models:

```bash
cd backend
alembic revision --autogenerate -m "Description of changes"
alembic upgrade head
```

### Running Tests

```bash
# Backend tests
cd backend
pytest

# Frontend tests
cd frontend
npm test
```

### Code Formatting

```bash
# Backend (Python)
cd backend
black app/
flake8 app/

# Frontend (TypeScript)
cd frontend
npm run lint
```

---

## Next Steps

1. **Configure Email Monitoring**: Set up email accounts to monitor
2. **Set Up Alerts**: Configure Slack/Teams webhooks for notifications
3. **SIEM Integration**: Connect to your SIEM platform
4. **Customize Detection**: Adjust confidence thresholds
5. **Add Users**: Implement authentication and user management
6. **Production Deploy**: Deploy to cloud infrastructure

---

## Support

For issues and questions:
- Check the [README.md](../README.md)
- Open an issue on GitHub
- Check logs: `docker-compose logs` or terminal output

---

## Security Notes

- Never commit `.env` files to version control
- Rotate API keys regularly
- Use strong database passwords
- Enable HTTPS in production
- Implement rate limiting
- Regular security audits

---

Happy phishing detection! 🛡️
