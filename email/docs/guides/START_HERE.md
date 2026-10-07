# 🚀 How to Start SOCShield

## Quick Start Instructions

### ⚠️ Important: The backend is Python, the frontend is Node.js

You need **TWO separate terminals** - one for backend, one for frontend.

---

## Terminal 1: Start Backend (Python/FastAPI)

```bash
# Navigate to backend directory
cd /Users/yogigodara/Downloads/Projects/SOCShield/backend

# Install dependencies (first time only)
pip3 install -r requirements.txt

# Create .env file (first time only)
cat > .env << 'EOF'
AI_PROVIDER=gemini
GOOGLE_API_KEY=your_api_key_here
DEBUG=true
DATABASE_URL=sqlite:///./socshield.db
REDIS_URL=redis://localhost:6379/0
EOF

# Start the backend server
python3 -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

**Backend will run on:** http://localhost:8000

---

## Terminal 2: Start Frontend (Next.js)

```bash
# Navigate to frontend directory
cd /Users/yogigodara/Downloads/Projects/SOCShield/frontend

# Install dependencies (first time only)
npm install

# Start the frontend
npm run dev
```

**Frontend will run on:** http://localhost:3000

---

## Access the Application

1. **Home Page:** http://localhost:3000
2. **Dashboard:** http://localhost:3000/dashboard
3. **API Documentation:** http://localhost:8000/docs
4. **Health Check:** http://localhost:8000/health

---

## Common Errors & Solutions

### Error: "npm run dev" fails in backend directory
**Problem:** You're trying to run npm in the backend (Python) directory  
**Solution:** Use `python3 -m uvicorn app.main:app --reload` for backend

### Error: Module not found
**Backend:** Run `pip3 install -r requirements.txt` in backend directory  
**Frontend:** Run `npm install` in frontend directory

### Error: Can't connect to backend
**Solution:** Make sure backend is running on port 8000 first

---

## Environment Variables

### Backend (.env in backend/ directory)
```env
AI_PROVIDER=gemini
GOOGLE_API_KEY=your_gemini_api_key
DEBUG=true
```

### Frontend (.env.local in frontend/ directory)
```env
NEXT_PUBLIC_API_URL=http://localhost:8000
```

---

## Project Structure

```
SOCShield/
├── backend/          ← Python/FastAPI (port 8000)
│   ├── app/
│   ├── requirements.txt
│   └── .env
├── frontend/         ← Next.js/React (port 3000)
│   ├── src/
│   ├── package.json
│   └── .env.local
└── START_HERE.md    ← This file
```

---

## Step-by-Step First Time Setup

### 1. Setup Backend
```bash
cd backend
pip3 install -r requirements.txt
echo 'AI_PROVIDER=gemini\nGOOGLE_API_KEY=your_key\nDEBUG=true' > .env
python3 -m uvicorn app.main:app --reload
```

### 2. Setup Frontend (in new terminal)
```bash
cd frontend
npm install
echo 'NEXT_PUBLIC_API_URL=http://localhost:8000' > .env.local
npm run dev
```

### 3. Open Browser
Go to: http://localhost:3000

---

**That's it! Both services should now be running. 🎉**
