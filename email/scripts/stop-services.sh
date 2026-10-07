#!/bin/bash

# SOCShield - Stop All Services

echo "🛑 Stopping SOCShield services..."

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

# Stop by PID files if they exist
if [ -f .backend.pid ]; then
    BACKEND_PID=$(cat .backend.pid)
    if ps -p $BACKEND_PID > /dev/null 2>&1; then
        kill $BACKEND_PID
        echo -e "${GREEN}✅ Backend stopped (PID: $BACKEND_PID)${NC}"
    fi
    rm -f .backend.pid
fi

if [ -f .frontend.pid ]; then
    FRONTEND_PID=$(cat .frontend.pid)
    if ps -p $FRONTEND_PID > /dev/null 2>&1; then
        kill $FRONTEND_PID
        echo -e "${GREEN}✅ Frontend stopped (PID: $FRONTEND_PID)${NC}"
    fi
    rm -f .frontend.pid
fi

# Also kill by port (fallback)
lsof -ti:8000 | xargs kill -9 2>/dev/null
lsof -ti:3000 | xargs kill -9 2>/dev/null

echo -e "${GREEN}✅ All services stopped${NC}"
