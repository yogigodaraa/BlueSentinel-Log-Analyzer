# SOCShield Backend-Frontend Integration Guide

## Overview
This guide explains how the backend and frontend are integrated and how to properly run both services.

## Architecture

### Backend (FastAPI)
- **URL**: `http://localhost:8000`
- **API Base**: `http://localhost:8000/api/v1`
- **Documentation**: `http://localhost:8000/docs`

### Frontend (Next.js)
- **URL**: `http://localhost:3000`
- **Framework**: Next.js 14 with App Router
- **API Client**: Axios

## API Endpoints

### Dashboard
- `GET /api/v1/dashboard/stats` - Get dashboard statistics
- `GET /api/v1/dashboard/recent-activity` - Get recent analysis activity

### Analysis
- `POST /api/v1/analysis/analyze` - Analyze an email for phishing
- `POST /api/v1/analysis/extract-iocs` - Extract IOCs from email
- `POST /api/v1/analysis/analyze-url` - Analyze URL suspiciousness

### Emails
- `GET /api/v1/emails` - List all emails
- `GET /api/v1/emails/{id}` - Get specific email details

### Threats
- `GET /api/v1/threats` - List all detected threats
- `GET /api/v1/threats/{id}` - Get specific threat details

### Config
- `GET /health` - Health check endpoint
- `GET /metrics` - Application metrics

## Frontend Pages

### Home Page (`/`)
- Landing page with feature overview
- Links to dashboard and GitHub

### Dashboard Page (`/dashboard`)
- Real-time statistics
- Email analysis panel
- Threat feed
- Settings

## Setup Instructions

### 1. Backend Setup

```bash
cd backend

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Edit .env and add your API keys

# Run the backend
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Required environment variables:
```env
# AI Provider (choose one)
AI_PROVIDER=gemini
GOOGLE_API_KEY=your_gemini_api_key

# OR
AI_PROVIDER=openai
OPENAI_API_KEY=your_openai_api_key

# OR
AI_PROVIDER=claude
ANTHROPIC_API_KEY=your_claude_api_key

# Database (optional - uses mock data if not configured)
DATABASE_URL=postgresql://socshield:changeme@localhost:5432/socshield

# Redis (optional)
REDIS_URL=redis://localhost:6379/0
```

### 2. Frontend Setup

```bash
cd frontend

# Install dependencies
npm install

# Set up environment variables
echo "NEXT_PUBLIC_API_URL=http://localhost:8000" > .env.local

# Run the frontend
npm run dev
```

### 3. Access the Application

1. **Frontend**: http://localhost:3000
2. **Backend API Docs**: http://localhost:8000/docs
3. **Health Check**: http://localhost:8000/health

## Testing the Integration

### 1. Test Backend
```bash
curl http://localhost:8000/health
```

Expected response:
```json
{
  "status": "healthy",
  "version": "1.0.0",
  ...
}
```

### 2. Test Dashboard Stats
```bash
curl http://localhost:8000/api/v1/dashboard/stats
```

### 3. Test Email Analysis
```bash
curl -X POST http://localhost:8000/api/v1/analysis/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "Urgent: Verify Your Account",
    "sender": "noreply@paypal-secure.tk",
    "body": "Click here to verify your account: http://suspicious-link.com"
  }'
```

### 4. Test Frontend
1. Navigate to http://localhost:3000
2. Click "Launch Dashboard" button
3. Go to "Analysis" tab
4. Submit an email for analysis

## CORS Configuration

The backend is configured to allow requests from:
- `http://localhost:3000` (default frontend)
- `http://localhost:3001` (alternative port)

To add more origins, update `CORS_ORIGINS` in `backend/app/core/config.py`.

## Database Setup (Optional)

If you want to use a real database instead of mock data:

### Using Docker
```bash
cd backend
docker-compose up -d postgres redis
```

### Manual Setup
1. Install PostgreSQL and Redis
2. Create database: `createdb socshield`
3. Update `DATABASE_URL` in `.env`
4. The backend will automatically create tables on startup

## Common Issues & Solutions

### Issue: Frontend can't connect to backend
**Solution**: 
- Verify backend is running: `curl http://localhost:8000/health`
- Check CORS configuration in `backend/app/core/config.py`
- Verify `.env.local` has correct `NEXT_PUBLIC_API_URL`

### Issue: "AI Provider not configured" error
**Solution**: 
- Set `AI_PROVIDER` in backend `.env`
- Add corresponding API key (`GOOGLE_API_KEY`, `OPENAI_API_KEY`, or `ANTHROPIC_API_KEY`)

### Issue: Dashboard shows "..." or no data
**Solution**:
- Check browser console for API errors
- Verify backend is running and accessible
- Check CORS errors in browser console

### Issue: Analysis fails
**Solution**:
- Verify AI provider API key is valid
- Check backend logs for detailed error messages
- Ensure email format is correct (valid email address for sender)

## Development Tips

### Hot Reload
Both services support hot reload:
- **Backend**: Uses `--reload` flag
- **Frontend**: Next.js dev server auto-reloads

### API Testing
Use the interactive API documentation:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

### Debugging
- **Backend logs**: Check terminal running uvicorn
- **Frontend logs**: Check browser console and Next.js terminal
- **Network requests**: Use browser DevTools Network tab

## Production Deployment

### Backend (Vercel/Docker)
```bash
# Using Docker
docker build -t socshield-backend ./backend
docker run -p 8000:8000 socshield-backend

# Or use docker-compose
docker-compose up
```

### Frontend (Vercel)
```bash
# Deploy to Vercel
vercel deploy

# Or build and serve
npm run build
npm start
```

Update `NEXT_PUBLIC_API_URL` to your production backend URL.

## Next Steps

1. ✅ Backend and frontend are properly integrated
2. ✅ Dashboard page created at `/dashboard`
3. ✅ API endpoints return real data from database
4. ✅ Email analysis panel fully functional
5. ✅ CORS properly configured

To start using SOCShield:
1. Start the backend: `cd backend && python -m uvicorn app.main:app --reload`
2. Start the frontend: `cd frontend && npm run dev`
3. Open http://localhost:3000
4. Click "Launch Dashboard"
5. Go to "Analysis" tab and test email analysis

## Support

For issues or questions:
- Check backend logs for API errors
- Check browser console for frontend errors
- Review this integration guide
- Check the API documentation at http://localhost:8000/docs
