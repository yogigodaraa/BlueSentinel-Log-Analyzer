#!/bin/bash

echo "🚀 SOCShield - Complete Setup & Start Guide"
echo "============================================"
echo ""

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Step 1: Backend Setup
echo -e "${BLUE}Step 1: Setting up Backend${NC}"
echo "----------------------------"

cd backend

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo -e "${YELLOW}Creating Python virtual environment...${NC}"
    python3 -m venv venv
    echo -e "${GREEN}✅ Virtual environment created${NC}"
fi

# Activate virtual environment
echo -e "${YELLOW}Activating virtual environment...${NC}"
source venv/bin/activate

# Install dependencies
echo -e "${YELLOW}Installing backend dependencies...${NC}"
pip install -q --upgrade pip
pip install -q -r requirements.txt
echo -e "${GREEN}✅ Backend dependencies installed${NC}"

cd ..

# Step 2: Frontend Setup
echo ""
echo -e "${BLUE}Step 2: Setting up Frontend${NC}"
echo "----------------------------"

cd frontend

# Install dependencies
if [ ! -d "node_modules" ]; then
    echo -e "${YELLOW}Installing frontend dependencies...${NC}"
    npm install
    echo -e "${GREEN}✅ Frontend dependencies installed${NC}"
else
    echo -e "${GREEN}✅ Frontend dependencies already installed${NC}"
fi

cd ..

# Step 3: Configuration
echo ""
echo -e "${BLUE}Step 3: Configuration${NC}"
echo "----------------------"

if [ ! -f "backend/.env" ]; then
    echo -e "${YELLOW}Creating backend/.env...${NC}"
    cat > backend/.env << 'EOF'
# AI Provider Configuration
AI_PROVIDER=gemini
GOOGLE_API_KEY=your_google_api_key_here

# Database (optional - will use mock data if not set)
DATABASE_URL=postgresql://socshield:changeme@localhost:5432/socshield

# Redis (optional)
REDIS_URL=redis://localhost:6379/0

# CORS
CORS_ORIGINS=http://localhost:3000,http://localhost:3001

# Features
ENABLE_AUTO_QUARANTINE=true
ENABLE_AUTO_BLOCK=false
ENABLE_THREAT_INTEL=true

DEBUG=true
EOF
    echo -e "${GREEN}✅ Created backend/.env${NC}"
    echo -e "${RED}⚠️  IMPORTANT: Edit backend/.env and add your API key!${NC}"
else
    echo -e "${GREEN}✅ backend/.env already exists${NC}"
fi

if [ ! -f "frontend/.env.local" ]; then
    echo -e "${YELLOW}Creating frontend/.env.local...${NC}"
    echo "NEXT_PUBLIC_API_URL=http://localhost:8000" > frontend/.env.local
    echo -e "${GREEN}✅ Created frontend/.env.local${NC}"
else
    echo -e "${GREEN}✅ frontend/.env.local already exists${NC}"
fi

# Step 4: Ready to Start
echo ""
echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}✨ Setup Complete! Ready to start SOCShield${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${YELLOW}BEFORE STARTING:${NC}"
echo "1. Edit backend/.env and add your AI provider API key"
echo "   - For Gemini: GOOGLE_API_KEY"
echo "   - For OpenAI: OPENAI_API_KEY"
echo "   - For Claude: ANTHROPIC_API_KEY"
echo ""
echo -e "${BLUE}TO START THE APPLICATION:${NC}"
echo ""
echo -e "${YELLOW}Terminal 1 - Backend:${NC}"
echo "  cd backend"
echo "  source venv/bin/activate"
echo "  python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000"
echo ""
echo -e "${YELLOW}Terminal 2 - Frontend:${NC}"
echo "  cd frontend"
echo "  npm run dev"
echo ""
echo -e "${BLUE}QUICK START (after adding API key):${NC}"
echo "  ./start-both.sh"
echo ""
echo -e "${BLUE}ACCESS POINTS:${NC}"
echo "  Frontend:  http://localhost:3000"
echo "  Dashboard: http://localhost:3000/dashboard"
echo "  Backend:   http://localhost:8000"
echo "  API Docs:  http://localhost:8000/docs"
echo ""
