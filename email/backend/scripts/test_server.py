#!/usr/bin/env python3
"""
Simple FastAPI server without database - just for testing OpenAI integration
"""
import os
import sys
from pathlib import Path

# Add backend to path
backend_path = Path(__file__).parent
sys.path.insert(0, str(backend_path))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv

# Load environment
load_dotenv('../.env')

print("=" * 60)
print("🚀 SOCShield - Simple Test Server")
print("=" * 60)
print(f"✅ OpenAI Key: {os.getenv('OPENAI_API_KEY', 'NOT SET')[:20]}...")
print(f"✅ AI Provider: {os.getenv('AI_PROVIDER', 'NOT SET')}")
print("=" * 60)

app = FastAPI(
    title="SOCShield Test API",
    description="Simplified API for testing OpenAI integration",
    version="1.0.0"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:3001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class EmailAnalysisRequest(BaseModel):
    subject: str
    sender: str
    body: str
    links: list = []

@app.get("/")
async def root():
    return {
        "message": "SOCShield Test API",
        "status": "running",
        "ai_provider": os.getenv('AI_PROVIDER', 'not configured')
    }

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "ai_provider": os.getenv('AI_PROVIDER', 'not configured'),
        "openai_configured": bool(os.getenv('OPENAI_API_KEY'))
    }

@app.get("/api/v1/dashboard/stats")
async def get_dashboard_stats():
    """Get dashboard statistics (mock data for testing)"""
    return {
        "total_emails": 0,
        "threats_detected": 0,
        "detection_rate": 0.0,
        "avg_detection_time": 0.0,
        "recent_threats": []
    }

@app.get("/api/v1/threats/recent")
async def get_recent_threats():
    """Get recent threats (mock data for testing)"""
    return []

@app.post("/api/v1/analysis/analyze")
async def analyze_email(request: EmailAnalysisRequest):
    """Analyze email for phishing using OpenAI"""
    try:
        # Import here to avoid startup issues
        from app.ai.openai_provider import OpenAIProvider
        
        api_key = os.getenv('OPENAI_API_KEY')
        if not api_key:
            return {"error": "OpenAI API key not configured"}
        
        provider = OpenAIProvider(api_key)
        
        email_content = {
            'subject': request.subject,
            'sender': request.sender,
            'body': request.body,
            'links': request.links
        }
        
        result = await provider.analyze_email(email_content)
        
        # Format response to match frontend expectations
        return {
            "is_phishing": result.get("is_phishing", False),
            "confidence": result.get("confidence", 0.0),
            "risk_level": result.get("risk_level", "low"),
            "indicators": result.get("indicators", []),
            "explanation": result.get("explanation", ""),
            "iocs": result.get("iocs", {
                "domains": [],
                "urls": [],
                "ip_addresses": [],
                "email_addresses": [],
                "file_hashes": []
            }),
            "url_analysis": result.get("url_analysis", []),
            "analysis_duration": result.get("analysis_duration", 0.0),
            "analyzed_at": result.get("analyzed_at", ""),
            "ai_provider": "openai"
        }
        
    except Exception as e:
        import traceback
        return {
            "success": False,
            "error": str(e),
            "traceback": traceback.format_exc()
        }

if __name__ == "__main__":
    import uvicorn
    print("\n🌐 Starting server on http://localhost:8000")
    print("📖 API Docs: http://localhost:8000/docs")
    print("\nPress Ctrl+C to stop\n")
    
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=False)
