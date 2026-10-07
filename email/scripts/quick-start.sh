#!/bin/bash

# SOCShield Quick Start Script
# This script helps you start the SOCShield backend quickly

set -e  # Exit on error

echo "╔════════════════════════════════════════════════════════════════════════╗"
echo "║                                                                        ║"
echo "║                  🛡️  SOCShield Quick Start  🛡️                       ║"
echo "║                                                                        ║"
echo "╚════════════════════════════════════════════════════════════════════════╝"
echo ""

# Check if we're in the right directory
if [ ! -f "docker-compose.yml" ]; then
    echo "❌ Error: Please run this script from the SOCShield root directory"
    exit 1
fi

# Check if .env file exists
if [ ! -f ".env" ]; then
    echo "⚠️  No .env file found!"
    echo "📝 Creating .env from .env.example..."
    cp .env.example .env
    echo "⚠️  Please edit .env and add your API keys before starting!"
    exit 1
fi

# Check if OpenAI key is set
if grep -q "your_openai_api_key_here" .env 2>/dev/null; then
    echo "⚠️  OpenAI API key not configured in .env file"
    echo "📝 Please edit .env and add your OpenAI API key"
    exit 1
fi

echo "✅ Configuration file found"
echo ""

# Menu
echo "Choose how to start SOCShield:"
echo ""
echo "1) 🐳 Docker Compose (Recommended - Full stack)"
echo "2) 💻 Backend Only (For testing)"
echo "3) 🧪 Run Tests"
echo "4) 📊 Check Status"
echo "5) 🛑 Stop All Services"
echo ""
read -p "Enter your choice (1-5): " choice

case $choice in
    1)
        echo ""
        echo "🐳 Starting SOCShield with Docker Compose..."
        echo ""
        
        # Check if Docker is installed
        if ! command -v docker &> /dev/null; then
            echo "❌ Docker is not installed!"
            echo "📥 Please install Docker Desktop: https://www.docker.com/products/docker-desktop"
            exit 1
        fi
        
        echo "📦 Building and starting services..."
        docker-compose up -d
        
        echo ""
        echo "✅ Services started successfully!"
        echo ""
        echo "🌐 Services available at:"
        echo "   • Backend API: http://localhost:8000"
        echo "   • API Docs: http://localhost:8000/docs"
        echo "   • Frontend: http://localhost:3000 (if built)"
        echo "   • PostgreSQL: localhost:5432"
        echo "   • Redis: localhost:6379"
        echo ""
        echo "📝 View logs with: docker-compose logs -f"
        echo "🛑 Stop with: docker-compose down"
        ;;
        
    2)
        echo ""
        echo "💻 Starting Backend Only..."
        echo ""
        
        cd backend
        
        # Check if venv exists
        if [ ! -d "venv" ]; then
            echo "📦 Creating virtual environment..."
            python3 -m venv venv
        fi
        
        echo "🔄 Activating virtual environment..."
        source venv/bin/activate
        
        echo "📦 Installing dependencies..."
        pip install -q uvicorn fastapi python-dotenv pydantic pydantic-settings openai
        
        echo ""
        echo "🚀 Starting FastAPI backend..."
        echo ""
        echo "✅ Backend will start at: http://localhost:8000"
        echo "📖 API Docs at: http://localhost:8000/docs"
        echo ""
        echo "Press Ctrl+C to stop"
        echo ""
        
        uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
        ;;
        
    3)
        echo ""
        echo "🧪 Running Tests..."
        echo ""
        
        cd backend
        
        if [ ! -d "venv" ]; then
            echo "❌ Virtual environment not found. Please run option 2 first."
            exit 1
        fi
        
        source venv/bin/activate
        
        echo "📦 Installing test dependencies..."
        pip install -q pytest pytest-asyncio pytest-cov
        
        echo ""
        echo "Running test suite..."
        python -m pytest tests/ -v
        ;;
        
    4)
        echo ""
        echo "📊 Checking Service Status..."
        echo ""
        
        if command -v docker &> /dev/null; then
            echo "🐳 Docker Services:"
            docker-compose ps
        else
            echo "⚠️  Docker not installed"
        fi
        
        echo ""
        echo "🌐 Checking Ports:"
        echo ""
        
        if lsof -Pi :8000 -sTCP:LISTEN -t >/dev/null 2>&1; then
            echo "   ✅ Port 8000 (Backend): ACTIVE"
        else
            echo "   ❌ Port 8000 (Backend): Not running"
        fi
        
        if lsof -Pi :3000 -sTCP:LISTEN -t >/dev/null 2>&1; then
            echo "   ✅ Port 3000 (Frontend): ACTIVE"
        else
            echo "   ❌ Port 3000 (Frontend): Not running"
        fi
        
        if lsof -Pi :5432 -sTCP:LISTEN -t >/dev/null 2>&1; then
            echo "   ✅ Port 5432 (PostgreSQL): ACTIVE"
        else
            echo "   ❌ Port 5432 (PostgreSQL): Not running"
        fi
        
        if lsof -Pi :6379 -sTCP:LISTEN -t >/dev/null 2>&1; then
            echo "   ✅ Port 6379 (Redis): ACTIVE"
        else
            echo "   ❌ Port 6379 (Redis): Not running"
        fi
        
        echo ""
        echo "📁 Configuration:"
        if [ -f ".env" ]; then
            echo "   ✅ .env file: EXISTS"
            if grep -q "OPENAI_API_KEY=sk-" .env 2>/dev/null; then
                echo "   ✅ OpenAI API Key: CONFIGURED"
            else
                echo "   ⚠️  OpenAI API Key: NOT CONFIGURED"
            fi
        else
            echo "   ❌ .env file: MISSING"
        fi
        ;;
        
    5)
        echo ""
        echo "🛑 Stopping All Services..."
        echo ""
        
        if command -v docker &> /dev/null; then
            echo "🐳 Stopping Docker services..."
            docker-compose down
        fi
        
        echo "🛑 Stopping any running backend processes..."
        pkill -f "uvicorn app.main:app" 2>/dev/null || true
        
        echo ""
        echo "✅ All services stopped"
        ;;
        
    *)
        echo "❌ Invalid choice. Please run the script again."
        exit 1
        ;;
esac

echo ""
echo "════════════════════════════════════════════════════════════════════════"
