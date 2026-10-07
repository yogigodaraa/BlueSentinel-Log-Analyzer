#!/bin/bash

# Quick start script - starts both backend and frontend

echo "🚀 Starting SOCShield Backend and Frontend..."
echo ""

# Start backend in background
echo "Starting backend on port 8000..."
cd backend
source venv/bin/activate 2>/dev/null || echo "Note: Run ./setup-and-start.sh first if this fails"
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000 &
BACKEND_PID=$!
cd ..

echo "✅ Backend starting... (PID: $BACKEND_PID)"
sleep 3

# Start frontend in new terminal or background
echo "Starting frontend on port 3000..."
cd frontend
npm run dev &
FRONTEND_PID=$!
cd ..

echo "✅ Frontend starting... (PID: $FRONTEND_PID)"
echo ""
echo "Services are starting up..."
echo ""
echo "📍 Access at:"
echo "   Frontend:  http://localhost:3000"
echo "   Dashboard: http://localhost:3000/dashboard"
echo "   Backend:   http://localhost:8000/docs"
echo ""
echo "To stop: kill $BACKEND_PID $FRONTEND_PID"
echo "Or run: ./stop-services.sh"

# Save PIDs
echo $BACKEND_PID > .backend.pid
echo $FRONTEND_PID > .frontend.pid

wait
