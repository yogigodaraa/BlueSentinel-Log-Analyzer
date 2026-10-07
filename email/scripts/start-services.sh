#!/bin/bash

# SOCShield - Start Both Backend and Frontend Services

echo "🚀 Starting SOCShield..."
echo ""

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check if backend dependencies are installed
if [ ! -d "backend/venv" ] && [ ! -f "backend/.venv/bin/activate" ]; then
    echo -e "${YELLOW}⚠️  Backend virtual environment not found${NC}"
    echo "Creating virtual environment..."
    cd backend
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    cd ..
    echo -e "${GREEN}✅ Backend dependencies installed${NC}"
fi

# Check if frontend dependencies are installed
if [ ! -d "frontend/node_modules" ]; then
    echo -e "${YELLOW}⚠️  Frontend dependencies not found${NC}"
    echo "Installing frontend dependencies..."
    cd frontend
    npm install
    cd ..
    echo -e "${GREEN}✅ Frontend dependencies installed${NC}"
fi

# Check for .env files
if [ ! -f "backend/.env" ]; then
    echo -e "${YELLOW}⚠️  Backend .env file not found${NC}"
    echo "Please create backend/.env with your configuration"
    echo "You can copy from backend/.env.example"
    exit 1
fi

if [ ! -f "frontend/.env.local" ]; then
    echo -e "${YELLOW}📝 Creating frontend/.env.local${NC}"
    echo "NEXT_PUBLIC_API_URL=http://localhost:8000" > frontend/.env.local
fi

echo ""
echo -e "${BLUE}═══════════════════════════════════════${NC}"
echo -e "${GREEN}    Starting Backend (Port 8000)${NC}"
echo -e "${BLUE}═══════════════════════════════════════${NC}"
echo ""

# Start backend in background
cd backend
if [ -d "venv" ]; then
    source venv/bin/activate
elif [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
fi
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000 > ../backend.log 2>&1 &
BACKEND_PID=$!
cd ..

# Wait for backend to start
echo "Waiting for backend to start..."
sleep 5

# Check if backend is running
if curl -s http://localhost:8000/health > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Backend is running at http://localhost:8000${NC}"
    echo -e "${GREEN}📚 API Documentation: http://localhost:8000/docs${NC}"
else
    echo -e "${RED}❌ Backend failed to start. Check backend.log for details${NC}"
    kill $BACKEND_PID 2>/dev/null
    exit 1
fi

echo ""
echo -e "${BLUE}═══════════════════════════════════════${NC}"
echo -e "${GREEN}    Starting Frontend (Port 3000)${NC}"
echo -e "${BLUE}═══════════════════════════════════════${NC}"
echo ""

# Start frontend in background
cd frontend
npm run dev > ../frontend.log 2>&1 &
FRONTEND_PID=$!
cd ..

# Wait for frontend to start
echo "Waiting for frontend to start..."
sleep 8

# Check if frontend is running
if curl -s http://localhost:3000 > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Frontend is running at http://localhost:3000${NC}"
else
    echo -e "${YELLOW}⚠️  Frontend may still be starting. Check frontend.log for details${NC}"
fi

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}✨ SOCShield is ready!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${BLUE}🌐 Frontend:${NC}       http://localhost:3000"
echo -e "${BLUE}🔧 Backend API:${NC}    http://localhost:8000"
echo -e "${BLUE}📚 API Docs:${NC}       http://localhost:8000/docs"
echo -e "${BLUE}❤️  Health Check:${NC}  http://localhost:8000/health"
echo ""
echo -e "${YELLOW}📝 Logs:${NC}"
echo "   Backend:  tail -f backend.log"
echo "   Frontend: tail -f frontend.log"
echo ""
echo -e "${YELLOW}🛑 To stop services:${NC}"
echo "   kill $BACKEND_PID $FRONTEND_PID"
echo "   or run: ./stop-services.sh"
echo ""

# Save PIDs for cleanup script
echo $BACKEND_PID > .backend.pid
echo $FRONTEND_PID > .frontend.pid

# Keep script running
echo -e "${GREEN}Press Ctrl+C to stop all services${NC}"
echo ""

# Trap Ctrl+C
trap "echo ''; echo 'Stopping services...'; kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; rm -f .backend.pid .frontend.pid; echo 'Services stopped.'; exit 0" INT

# Wait for processes
wait $BACKEND_PID $FRONTEND_PID
