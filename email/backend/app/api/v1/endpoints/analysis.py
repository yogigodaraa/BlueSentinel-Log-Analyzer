"""
Analysis Endpoint
Real-time email analysis API
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, EmailStr
from typing import List, Optional, Dict, Any
from datetime import datetime

from app.services.phishing_detector import analyze_email_for_phishing
from app.services.ioc_extractor import IOCExtractor

router = APIRouter()


class EmailAnalysisRequest(BaseModel):
    """Request model for email analysis"""
    subject: str
    sender: EmailStr
    recipient: Optional[EmailStr] = None
    body: str
    body_html: Optional[str] = None
    links: List[str] = []
    attachments: List[Dict[str, Any]] = []


class AnalysisResponse(BaseModel):
    """Response model for analysis results"""
    is_phishing: bool
    confidence: float
    risk_level: str
    indicators: List[str]
    explanation: str
    iocs: Dict[str, List[str]]
    url_analysis: List[Dict[str, Any]]
    analysis_duration: float
    analyzed_at: str
    ai_provider: str


@router.post("/analyze", response_model=AnalysisResponse)
async def analyze_email(request: EmailAnalysisRequest):
    """
    Analyze an email for phishing indicators
    
    This endpoint performs comprehensive phishing analysis including:
    - AI-powered content analysis
    - IOC extraction (domains, URLs, IPs)
    - URL suspiciousness scoring
    - Risk level assessment
    """
    try:
        # Convert request to dict
        email_content = {
            'subject': request.subject,
            'sender': request.sender,
            'recipient': request.recipient,
            'body': request.body,
            'body_html': request.body_html,
            'body_text': request.body,
            'links': request.links,
            'attachments': request.attachments
        }
        
        # Perform analysis
        result = await analyze_email_for_phishing(email_content)
        
        return result
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/extract-iocs")
async def extract_iocs(request: EmailAnalysisRequest):
    """
    Extract Indicators of Compromise from email
    
    Extracts:
    - Domains
    - URLs
    - IP addresses
    - Email addresses
    - File hashes
    """
    try:
        email_content = {
            'subject': request.subject,
            'body': request.body,
            'body_text': request.body,
            'sender': request.sender,
            'links': request.links
        }
        
        extractor = IOCExtractor()
        iocs = extractor.extract_all(email_content)
        
        return {
            'iocs': iocs,
            'total_count': sum(len(v) for v in iocs.values())
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze-url")
async def analyze_url(url: str):
    """
    Analyze a single URL for suspiciousness
    """
    try:
        extractor = IOCExtractor()
        analysis = extractor.analyze_url_suspiciousness(url)
        return analysis
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/health")
async def health_check():
    """Health check for analysis service"""
    return {
        "status": "healthy",
        "service": "analysis",
        "timestamp": datetime.utcnow().isoformat()
    }
