"""Configuration endpoints - placeholder"""
from fastapi import APIRouter

router = APIRouter()

@router.get("/")
async def get_config():
    return {"message": "Get configuration"}
