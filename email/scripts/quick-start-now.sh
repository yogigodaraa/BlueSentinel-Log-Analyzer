#!/bin/bash

echo "🚀 Starting SOCShield Services..."
echo ""

# Check for backend .env
if [ ! -f "backend/.env" ]; then
    echo "📝 Creating backend/.env with minimal config..."
    cat > backend/.env << 'ENVEOF'
# AI Provider - Add your API key below
AI_PROVIDER=gemini
GOOGLE_API_KEY=your_google_api_key_here

# Database (optional - will use mock data if not configured)
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
ENVEOF
    echo "✅ Created backend/.env"
    echo "⚠️  Please edit backend/.env and add your Google API key (or other AI provider key)"
    echo ""
fi

# Check for frontend .env.local
if [ ! -f "frontend/.env.local" ]; then
    echo "📝 Creating frontend/.env.local..."
    echo "NEXT_PUBLIC_API_URL=http://localhost:8000" > frontend/.env.local
    echo "✅ Created frontend/.env.local"
    echo ""
fi

echo "Starting backend on port 8000..."
echo "Starting frontend on port 3000..."
echo ""
echo "📍 Services will be available at:"
echo "   Frontend:  http://localhost:3000"
echo "   Dashboard: http://localhost:3000/dashboard"
echo "   Backend:   http://localhost:8000"
echo "   API Docs:  http://localhost:8000/docs"
echo ""
echo "Press Ctrl+C in each terminal to stop"
echo ""
