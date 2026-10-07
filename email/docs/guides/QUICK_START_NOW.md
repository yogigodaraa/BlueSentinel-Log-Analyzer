# 🚀 Quick Start Guide - SOCShield

## ⚡ The Easiest Way to Start

You're now in the **root directory** of SOCShield. Everything is properly integrated!

### Option 1: Using the Root Directory (Recommended)

```bash
# From the root directory (/Users/yogigodara/Downloads/Projects/SOCShield)

# Start frontend only
npm run dev

# Start backend only (in a new terminal)
cd backend
source venv/bin/activate
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Or use the startup script
./start-services.sh
```

### Option 2: Manual Start (Two Terminals)

**Terminal 1 - Backend:**
```bash
cd backend
source venv/bin/activate
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

**Terminal 2 - Frontend:**
```bash
cd frontend
npm run dev
```

### Option 3: Install concurrently and run both together

```bash
# From root directory
npm install
npm run dev:both
```

## 📍 Where You Are Now

```
SOCShield/                        ← YOU ARE HERE
├── backend/                      ← Python FastAPI backend
│   ├── app/
│   ├── venv/
│   └── requirements.txt
├── frontend/                     ← Next.js frontend
│   ├── src/
│   ├── package.json
│   └── node_modules/
├── package.json                  ← Root package.json (NEW!)
├── start-services.sh             ← Automated startup script
└── QUICK_START_NOW.md           ← This file
```

## 🎯 What to Run from Where

| Command | Directory | What It Does |
|---------|-----------|--------------|
| `npm run dev` | **Root** | Starts frontend only |
| `npm run dev:both` | **Root** | Starts both (needs concurrently) |
| `npm run dev` | `frontend/` | Starts frontend |
| `python -m uvicorn...` | `backend/` | Starts backend |
| `./start-services.sh` | **Root** | Automated start script |

## ✅ Current Setup Status

- ✅ Backend and frontend are properly integrated
- ✅ Dashboard page created at `/dashboard`
- ✅ API endpoints configured
- ✅ CORS settings correct
- ✅ Environment variables configured

## 🌐 Access URLs

Once both services are running:

- **Frontend**: http://localhost:3000
- **Dashboard**: http://localhost:3000/dashboard
- **Backend API**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/health

## 📝 Step-by-Step Instructions

### 1️⃣ First Time Setup

```bash
# Make sure you're in the root directory
cd /Users/yogigodara/Downloads/Projects/SOCShield

# Install frontend dependencies
cd frontend
npm install
cd ..

# Install backend dependencies (if not done)
cd backend
source venv/bin/activate
pip install -r requirements.txt
cd ..
```

### 2️⃣ Configure API Keys

Edit `backend/.env`:
```env
AI_PROVIDER=gemini
GOOGLE_API_KEY=your_actual_api_key_here
```

### 3️⃣ Start Services

**Easy Way:**
```bash
./start-services.sh
```

**Manual Way:**

Open **Terminal 1**:
```bash
cd /Users/yogigodara/Downloads/Projects/SOCShield/backend
source venv/bin/activate
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Open **Terminal 2**:
```bash
cd /Users/yogigodara/Downloads/Projects/SOCShield/frontend
npm run dev
```

### 4️⃣ Open Browser

Go to: **http://localhost:3000**

## 🐛 Common Errors Fixed

### ❌ "npm error code ENOENT"
**Problem**: You ran `npm run dev` from the backend directory
**Solution**: Run it from the root or frontend directory

### ❌ "Cannot find package.json"
**Problem**: Wrong directory
**Solution**: 
```bash
cd /Users/yogigodara/Downloads/Projects/SOCShield  # Root directory
npm run dev                                          # This will work now!
```

### ❌ "Frontend can't connect to backend"
**Problem**: Backend not running
**Solution**: Start backend first (see step 3)

## 💡 Pro Tips

1. **Always check which directory you're in**:
   ```bash
   pwd
   ```

2. **Root directory commands**:
   - `npm run dev` → Starts frontend
   - `./start-services.sh` → Starts both

3. **Backend directory commands**:
   - Must activate venv first: `source venv/bin/activate`
   - Then: `python -m uvicorn app.main:app --reload`

4. **Frontend directory commands**:
   - `npm run dev` → Starts dev server
   - `npm run build` → Production build

## 🎉 You're Ready!

Now you can:
1. Run `npm run dev` from the root directory to start frontend
2. Open another terminal and start the backend
3. Access http://localhost:3000
4. Click "Launch Dashboard"
5. Start analyzing emails!

## 📚 More Info

- Full Integration Guide: `INTEGRATION_GUIDE.md`
- Integration Complete: `INTEGRATION_COMPLETE.md`
- API Examples: `API_EXAMPLES.md`

---

**Current Status**: ✅ Everything is properly integrated!

Just choose your preferred startup method above and go! 🚀
