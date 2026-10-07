"""Threat management endpoints"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from typing import Optional

from app.core.database import get_db
from app.models.models import Threat

router = APIRouter()

@router.get("/")
async def list_threats(
    limit: int = 50,
    offset: int = 0,
    severity: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    List detected threats with optional filtering
    """
    try:
        query = select(Threat).order_by(desc(Threat.detected_at)).limit(limit).offset(offset)
        
        if severity:
            query = query.where(Threat.severity == severity)
        
        result = await db.execute(query)
        threats = result.scalars().all()
        
        return {
            "threats": [
                {
                    "id": threat.id,
                    "threat_type": threat.threat_type,
                    "severity": threat.severity,
                    "ioc_value": threat.ioc_value,
                    "ioc_type": threat.ioc_type,
                    "description": threat.description,
                    "detected_at": threat.detected_at.isoformat() if threat.detected_at else None,
                    "email_id": threat.email_id
                }
                for threat in threats
            ],
            "total": len(threats),
            "limit": limit,
            "offset": offset
        }
    except Exception as e:
        # Return empty list if database is not set up yet
        return {
            "threats": [],
            "total": 0,
            "limit": limit,
            "offset": offset
        }

@router.get("/{threat_id}")
async def get_threat(threat_id: int, db: AsyncSession = Depends(get_db)):
    """
    Get detailed information about a specific threat
    """
    try:
        query = select(Threat).where(Threat.id == threat_id)
        result = await db.execute(query)
        threat = result.scalar_one_or_none()
        
        if not threat:
            raise HTTPException(status_code=404, detail="Threat not found")
        
        return {
            "id": threat.id,
            "threat_type": threat.threat_type,
            "severity": threat.severity,
            "ioc_value": threat.ioc_value,
            "ioc_type": threat.ioc_type,
            "description": threat.description,
            "threat_intel_data": threat.threat_intel_data,
            "detected_at": threat.detected_at.isoformat() if threat.detected_at else None,
            "email_id": threat.email_id,
            "response_action": threat.response_action,
            "is_blocked": threat.is_blocked
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
