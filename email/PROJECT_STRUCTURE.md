# 📁 SOCShield - Project Structure

## Root Directory
```
SOCShield/
├── README.md                    # Main project README
├── package.json                 # Root package.json for unified commands
├── .gitignore                   # Git ignore file
├── .env                         # Root environment variables
│
├── backend/                     # Python FastAPI Backend
│   ├── app/                     # Application code
│   │   ├── main.py             # FastAPI application entry
│   │   ├── api/                # API endpoints
│   │   ├── core/               # Core functionality
│   │   ├── models/             # Database models
│   │   ├── services/           # Business logic
│   │   └── ai/                 # AI provider integrations
│   ├── tests/                  # Backend tests
│   ├── requirements.txt        # Python dependencies
│   ├── Dockerfile              # Backend container
│   ├── .env                    # Backend environment variables
│   └── pytest.ini              # Test configuration
│
├── frontend/                    # Next.js Frontend
│   ├── src/                    # Source code
│   │   ├── app/                # Next.js app router
│   │   │   ├── page.tsx        # Home page
│   │   │   └── dashboard/      # Dashboard route
│   │   ├── components/         # React components
│   │   │   └── dashboard/      # Dashboard components
│   │   └── lib/                # Utilities
│   │       └── api.ts          # API client
│   ├── public/                 # Static files
│   ├── package.json            # Frontend dependencies
│   ├── next.config.mjs         # Next.js configuration
│   ├── tailwind.config.js      # Tailwind CSS config
│   ├── tsconfig.json           # TypeScript config
│   └── .env.local              # Frontend environment variables
│
├── scripts/                     # Automation scripts
│   ├── start-services.sh       # Start both backend & frontend
│   ├── stop-services.sh        # Stop all services
│   ├── test-integration.sh     # Integration tests
│   ├── quick-start.sh          # Quick start script
│   └── setup-and-start.sh      # Setup and start
│
├── config/                      # Configuration files
│   ├── docker-compose.yml      # Docker compose config
│   └── .env.example            # Environment variables template
│
├── docs/                        # Documentation
│   ├── architecture/           # Architecture documentation
│   │   ├── ARCHITECTURE.md
│   │   ├── BACKEND_ARCHITECTURE.md
│   │   ├── PROJECT_SUMMARY.md
│   │   ├── BACKEND_CHANGES_COMPLETE.md
│   │   └── BACKEND_IMPROVEMENTS_SUMMARY.md
│   │
│   ├── guides/                 # User guides
│   │   ├── GETTING_STARTED.md
│   │   ├── SETUP.md
│   │   ├── QUICK_START_NOW.md
│   │   ├── INTEGRATION_COMPLETE.md
│   │   ├── INTEGRATION_GUIDE.md
│   │   ├── QUICK_REFERENCE.md
│   │   ├── API_KEYS_SETUP_GUIDE.md
│   │   ├── CONFIGURATION_COMPLETE.md
│   │   ├── ML_MODELS_GUIDE.md
│   │   ├── MODEL_TRAINING_SUMMARY.md
│   │   └── SERVER_RUNNING.md
│   │
│   ├── api/                    # API documentation
│   │   ├── API_EXAMPLES.md
│   │   └── BACKEND_FEATURES_QUICK_REFERENCE.md
│   │
│   ├── testing/                # Testing documentation
│   │   ├── TESTING.md
│   │   ├── BACKEND_TESTS_COMPLETE.md
│   │   └── BACKEND_VERIFICATION_REPORT.md
│   │
│   ├── deployment/             # Deployment guides
│   │   ├── VERCEL_DEPLOYMENT.md
│   │   └── ROADMAP.md
│   │
│   ├── CHANGELOG_BACKEND_V2.md # Changelog
│   └── SESSION_SUMMARY.md      # Session summaries
│
└── tests/                       # Integration tests (future)
    └── .archived/              # Archived test files
```

## Directory Purposes

### `/backend`
Python FastAPI backend application with:
- RESTful API endpoints
- AI-powered phishing detection
- IOC extraction and threat intelligence
- Database models and services

### `/frontend`
Next.js React frontend with:
- Modern UI with Tailwind CSS
- Dashboard for monitoring
- Email analysis interface
- Real-time statistics

### `/scripts`
Automation and utility scripts:
- Service startup/shutdown scripts
- Testing scripts
- Setup automation

### `/config`
Configuration files:
- Docker compose for containerization
- Environment variable templates
- Deployment configurations

### `/docs`
Comprehensive documentation organized by category:
- **architecture/**: System design and architecture
- **guides/**: User and developer guides
- **api/**: API reference and examples
- **testing/**: Testing documentation
- **deployment/**: Deployment guides

## Quick Commands

### From Root Directory

```bash
# Start frontend only
npm run dev

# Start both services
./scripts/start-services.sh

# Stop all services
./scripts/stop-services.sh

# Test integration
./scripts/test-integration.sh
```

### From Backend Directory

```bash
cd backend
source venv/bin/activate
python -m uvicorn app.main:app --reload
```

### From Frontend Directory

```bash
cd frontend
npm run dev
```

## Environment Files

- **Root**: `.env` - Shared environment variables
- **Backend**: `backend/.env` - Backend-specific config (API keys, database)
- **Frontend**: `frontend/.env.local` - Frontend config (API URL)
- **Config**: `config/.env.example` - Template for all variables

## Documentation Access

All documentation is now organized in `/docs`:

- Getting Started: `docs/guides/GETTING_STARTED.md`
- Architecture: `docs/architecture/ARCHITECTURE.md`
- API Examples: `docs/api/API_EXAMPLES.md`
- Testing: `docs/testing/TESTING.md`
- Deployment: `docs/deployment/VERCEL_DEPLOYMENT.md`

## Clean Structure Benefits

✅ **Organized**: All files in logical directories
✅ **Scalable**: Easy to add new docs/scripts
✅ **Clear**: Purpose of each directory is obvious
✅ **Professional**: Industry-standard structure
✅ **Maintainable**: Easy to find and update files

---

**Last Updated**: October 20, 2025
