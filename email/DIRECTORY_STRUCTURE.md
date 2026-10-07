# 📁 SOCShield Project Structure

## 🎯 Overview

This document describes the organized directory structure of the SOCShield project. All files have been reorganized for better maintainability and clarity.

## 📂 Root Directory Structure

```
SOCShield/
├── 📄 README.md                    # Main project README
├── 📄 package.json                 # Root package.json for unified commands
├── 📄 docker-compose.yml           # Docker services configuration
├── 📄 .gitignore                   # Git ignore rules
├── 📄 .env                         # Root environment variables
├── 📄 .env.example                 # Environment template
│
├── 📁 backend/                     # Python FastAPI Backend
│   ├── app/                        # Application code
│   │   ├── main.py                 # FastAPI app entry point
│   │   ├── api/v1/                 # API routes
│   │   ├── core/                   # Core utilities
│   │   ├── models/                 # Database models
│   │   └── services/               # Business logic
│   ├── tests/                      # Backend tests
│   ├── requirements.txt            # Python dependencies
│   ├── .env                        # Backend config
│   └── Dockerfile                  # Backend container
│
├── 📁 frontend/                    # Next.js Frontend
│   ├── src/                        # Source code
│   │   ├── app/                    # Next.js 14 App Router
│   │   │   ├── page.tsx            # Home page
│   │   │   └── dashboard/          # Dashboard route
│   │   │       └── page.tsx        # Dashboard page
│   │   ├── components/             # React components
│   │   │   └── dashboard/          # Dashboard components
│   │   └── lib/                    # Utilities
│   │       └── api.ts              # API client
│   ├── package.json                # Frontend dependencies
│   ├── .env.local                  # Frontend config
│   └── Dockerfile                  # Frontend container
│
├── 📁 docs/                        # 📚 Documentation (NEW!)
│   ├── architecture/               # Architecture documentation
│   │   ├── ARCHITECTURE.md
│   │   ├── BACKEND_ARCHITECTURE.md
│   │   └── PROJECT_SUMMARY.md
│   │
│   ├── guides/                     # User guides
│   │   ├── GETTING_STARTED.md
│   │   ├── SETUP.md
│   │   ├── QUICK_REFERENCE.md
│   │   ├── INTEGRATION_GUIDE.md
│   │   ├── INTEGRATION_COMPLETE.md
│   │   ├── QUICK_START_NOW.md
│   │   ├── START_HERE.md
│   │   └── API_KEYS_SETUP_GUIDE.md
│   │
│   ├── api/                        # API documentation
│   │   ├── API_EXAMPLES.md
│   │   └── BACKEND_FEATURES_QUICK_REFERENCE.md
│   │
│   ├── testing/                    # Testing documentation
│   │   ├── TESTING.md
│   │   ├── BACKEND_TESTS_COMPLETE.md
│   │   └── BACKEND_VERIFICATION_REPORT.md
│   │
│   ├── deployment/                 # Deployment guides
│   │   ├── VERCEL_DEPLOYMENT.md
│   │   └── ROADMAP.md
│   │
│   └── 📝 Other docs               # Changelogs & summaries
│       ├── BACKEND_CHANGES_COMPLETE.md
│       ├── BACKEND_IMPROVEMENTS_SUMMARY.md
│       ├── CHANGELOG_BACKEND_V2.md
│       ├── CONFIGURATION_COMPLETE.md
│       ├── ML_MODELS_GUIDE.md
│       ├── MODEL_TRAINING_SUMMARY.md
│       ├── SERVER_RUNNING.md
│       └── SESSION_SUMMARY.md
│
├── 📁 scripts/                     # 🔧 Utility Scripts (NEW!)
│   ├── start-services.sh           # Start both services
│   ├── stop-services.sh            # Stop all services
│   ├── test-integration.sh         # Test integration
│   ├── quick-start.sh              # Quick start script
│   ├── quick-start-now.sh          # Alternative quick start
│   ├── setup-and-start.sh          # Setup and start
│   └── start-both.sh               # Start both (concurrently)
│
├── 📁 config/                      # ⚙️ Configuration (NEW!)
│   └── vercel.json                 # Vercel deployment config
│
└── 📁 tests/                       # 🧪 Integration Tests (NEW!)
    └── .archived/                  # Archived test files
```

## 🚀 Quick Start Commands

### From Root Directory

```bash
# Start frontend only
npm run dev

# Start backend (in another terminal)
cd backend
source venv/bin/activate
python -m uvicorn app.main:app --reload

# Or use the automated script
./scripts/start-services.sh

# Test the integration
./scripts/test-integration.sh
```

## 📝 Documentation Index

### 🏗️ Architecture
- **[ARCHITECTURE.md](docs/architecture/ARCHITECTURE.md)** - System architecture overview
- **[BACKEND_ARCHITECTURE.md](docs/architecture/BACKEND_ARCHITECTURE.md)** - Backend detailed design
- **[PROJECT_SUMMARY.md](docs/architecture/PROJECT_SUMMARY.md)** - Project overview

### 📖 Guides
- **[START_HERE.md](docs/guides/START_HERE.md)** - ⭐ **Start here!**
- **[GETTING_STARTED.md](docs/guides/GETTING_STARTED.md)** - Getting started guide
- **[SETUP.md](docs/guides/SETUP.md)** - Detailed setup instructions
- **[INTEGRATION_COMPLETE.md](docs/guides/INTEGRATION_COMPLETE.md)** - Integration guide
- **[API_KEYS_SETUP_GUIDE.md](docs/guides/API_KEYS_SETUP_GUIDE.md)** - API keys configuration

### 🔌 API
- **[API_EXAMPLES.md](docs/api/API_EXAMPLES.md)** - API usage examples
- **[BACKEND_FEATURES_QUICK_REFERENCE.md](docs/api/BACKEND_FEATURES_QUICK_REFERENCE.md)** - Quick API reference

### 🧪 Testing
- **[TESTING.md](docs/testing/TESTING.md)** - Testing guide
- **[BACKEND_TESTS_COMPLETE.md](docs/testing/BACKEND_TESTS_COMPLETE.md)** - Test completion report

### 🚀 Deployment
- **[VERCEL_DEPLOYMENT.md](docs/deployment/VERCEL_DEPLOYMENT.md)** - Vercel deployment
- **[ROADMAP.md](docs/deployment/ROADMAP.md)** - Project roadmap

## 🔧 Scripts Reference

| Script | Description | Usage |
|--------|-------------|-------|
| `start-services.sh` | Start both backend and frontend | `./scripts/start-services.sh` |
| `stop-services.sh` | Stop all services | `./scripts/stop-services.sh` |
| `test-integration.sh` | Test API integration | `./scripts/test-integration.sh` |
| `quick-start.sh` | Quick setup and start | `./scripts/quick-start.sh` |

## 📂 Directory Purpose

### `/backend`
Python FastAPI backend with AI-powered phishing detection.

**Key Files:**
- `app/main.py` - Application entry point
- `app/api/v1/endpoints/` - API routes
- `app/services/` - Business logic
- `requirements.txt` - Dependencies

### `/frontend`
Next.js 14 frontend with React components.

**Key Files:**
- `src/app/page.tsx` - Home page
- `src/app/dashboard/page.tsx` - Dashboard
- `src/components/dashboard/` - Dashboard components
- `src/lib/api.ts` - API client

### `/docs`
All project documentation organized by category.

**Subdirectories:**
- `architecture/` - Design and architecture docs
- `guides/` - User and setup guides
- `api/` - API documentation
- `testing/` - Testing guides
- `deployment/` - Deployment instructions

### `/scripts`
Utility scripts for development and deployment.

**Purpose:**
- Automate common tasks
- Start/stop services
- Run tests
- Deploy application

### `/config`
Configuration files for various tools.

**Contents:**
- `vercel.json` - Vercel deployment config
- (More configs can be added here)

## 🎯 Benefits of New Structure

1. **📚 Clear Organization** - Easy to find documentation
2. **🔧 Centralized Scripts** - All utilities in one place
3. **⚙️ Config Management** - Separate config directory
4. **🧪 Test Isolation** - Dedicated test directory
5. **📖 Better Navigation** - Logical grouping of files

## 🔄 Migration Notes

### What Changed?

1. **Documentation** moved to `/docs/` with subcategories
2. **Scripts** moved to `/scripts/` directory
3. **Config files** moved to `/config/` directory
4. **Root directory** cleaned up - only essential files remain

### What Stayed?

1. `README.md` - Main project README
2. `package.json` - Root package configuration
3. `docker-compose.yml` - Docker services
4. `.env` and `.env.example` - Environment files
5. `.gitignore` - Git configuration

## 📍 Common Tasks

### View Documentation
```bash
# Architecture docs
open docs/architecture/ARCHITECTURE.md

# Getting started
open docs/guides/START_HERE.md

# API examples
open docs/api/API_EXAMPLES.md
```

### Run Scripts
```bash
# Make executable (if needed)
chmod +x scripts/*.sh

# Start services
./scripts/start-services.sh

# Test integration
./scripts/test-integration.sh
```

### Development
```bash
# Frontend
cd frontend && npm run dev

# Backend
cd backend && source venv/bin/activate
python -m uvicorn app.main:app --reload
```

## 🆘 Need Help?

1. **Getting Started**: See [docs/guides/START_HERE.md](docs/guides/START_HERE.md)
2. **API Documentation**: See [docs/api/](docs/api/)
3. **Integration Issues**: See [docs/guides/INTEGRATION_COMPLETE.md](docs/guides/INTEGRATION_COMPLETE.md)
4. **Testing**: See [docs/testing/TESTING.md](docs/testing/TESTING.md)

## 📝 Contributing

When adding new files:
- **Documentation** → `/docs/` (appropriate subdirectory)
- **Scripts** → `/scripts/`
- **Config** → `/config/`
- **Tests** → `/tests/`

---

**Last Updated**: October 20, 2025  
**Version**: 2.0  
**Status**: ✅ Fully Organized
