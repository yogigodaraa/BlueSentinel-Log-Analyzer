#!/bin/bash

echo "🚀 Starting SOCShield Backend (Development Mode)"
echo ""

cd "$(dirname "$0")"

# Activate virtual environment
echo "📦 Activating virtual environment..."
source venv/bin/activate

# Set environment variables for SQLite (no PostgreSQL needed)
export DATABASE_URL="sqlite+aiosqlite:///./socshield.db"
export AI_PROVIDER="openai"
export OPENAI_API_KEY="your-openai-api-key-here"
export CORS_ORIGINS='["http://localhost:3000","http://localhost:3001","http://localhost:8000"]'

echo "✅ Environment configured"
echo "   Database: SQLite (no PostgreSQL needed)"
echo "   AI Provider: OpenAI GPT-4"
echo ""
echo "🌐 Starting server on http://localhost:8000"
echo "📖 API Docs will be at: http://localhost:8000/docs"
echo ""
echo "Press Ctrl+C to stop"
echo ""

# Start the server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
