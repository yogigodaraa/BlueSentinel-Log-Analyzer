"""Email management endpoints"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from typing import Optional

from app.core.database import get_db
from app.models.models import Email

router = APIRouter()

@router.get("/")
async def list_emails(
    limit: int = 50,
    offset: int = 0,
    is_phishing: Optional[bool] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    List emails with optional filtering
    """
    try:
        query = select(Email).order_by(desc(Email.received_at)).limit(limit).offset(offset)
        
        if is_phishing is not None:
            query = query.where(Email.is_phishing == is_phishing)
        
        result = await db.execute(query)
        emails = result.scalars().all()
        
        return {
            "emails": [
                {
                    "id": email.id,
                    "subject": email.subject,
                    "sender": email.sender,
                    "recipient": email.recipient,
                    "is_phishing": email.is_phishing,
                    "risk_score": email.risk_score,
                    "risk_level": email.risk_level,
                    "received_at": email.received_at.isoformat() if email.received_at else None,
                    "analyzed_at": email.analyzed_at.isoformat() if email.analyzed_at else None
                }
                for email in emails
            ],
            "total": len(emails),
            "limit": limit,
            "offset": offset
        }
    except Exception as e:
        # Return empty list if database is not set up yet
        return {
            "emails": [],
            "total": 0,
            "limit": limit,
            "offset": offset
        }

@router.get("/{email_id}")
async def get_email(email_id: int, db: AsyncSession = Depends(get_db)):
    """
    Get detailed information about a specific email
    """
    try:
        query = select(Email).where(Email.id == email_id)
        result = await db.execute(query)
        email = result.scalar_one_or_none()
        
        if not email:
            raise HTTPException(status_code=404, detail="Email not found")
        
        return {
            "id": email.id,
            "subject": email.subject,
            "sender": email.sender,
            "recipient": email.recipient,
            "body": email.body,
            "body_html": email.body_html,
            "is_phishing": email.is_phishing,
            "risk_score": email.risk_score,
            "risk_level": email.risk_level,
            "phishing_indicators": email.phishing_indicators,
            "iocs": email.iocs,
            "ai_analysis": email.ai_analysis,
            "received_at": email.received_at.isoformat() if email.received_at else None,
            "analyzed_at": email.analyzed_at.isoformat() if email.analyzed_at else None
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
