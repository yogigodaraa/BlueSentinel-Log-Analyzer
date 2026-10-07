"""
FastAPI Main Application
Handles API routing, middleware, and application lifecycle
"""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager

from app.core.config import settings
from app.core.logging import setup_logging, get_logger
from app.core.middleware import (
    RequestTrackingMiddleware,
    SecurityHeadersMiddleware,
    RateLimitMiddleware
)
from app.core.cache import init_cache
from app.core.exceptions import SOCShieldException
from app.api.v1.router import api_router
from app.core.database import engine, Base

# Setup structured logging
setup_logging(
    level="DEBUG" if settings.DEBUG else "INFO",
    json_logs=not settings.DEBUG
)
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events"""
    # Startup
    logger.info("🚀 Starting SOCShield application...")
    
    # Initialize cache
    logger.info("Initializing cache system...")
    await init_cache()
    
        # Create database tables (if database is available)
    logger.info("Creating database tables...")
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("✅ Database tables created")
    except Exception as e:
        logger.warning(f"⚠️  Database unavailable, using mock data: {str(e)}")
        logger.info("✅ Running in mock data mode")
    
    logger.info(f"🤖 AI Provider: {settings.AI_PROVIDER}")
    logger.info(f"🔒 Security features enabled: Auto-quarantine={settings.ENABLE_AUTO_QUARANTINE}")
    logger.info("✨ SOCShield is ready!")
    
    yield
    
    # Shutdown
    logger.info("⏹️  Shutting down SOCShield application...")
    logger.info("👋 Goodbye!")


# Create FastAPI application
app = FastAPI(
    title="SOCShield API",
    description="AI-Driven Phishing Detection & Response System",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_tags=[
        {
            "name": "emails",
            "description": "Email monitoring and processing operations"
        },
        {
            "name": "analysis",
            "description": "Phishing detection and threat analysis"
        },
        {
            "name": "threats",
            "description": "Threat intelligence and IOC management"
        },
        {
            "name": "dashboard",
            "description": "Dashboard metrics and statistics"
        },
        {
            "name": "config",
            "description": "System configuration and health checks"
        }
    ]
)

# Add custom middleware (order matters!)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestTrackingMiddleware)
if not settings.DEBUG:  # Rate limiting in production only
    app.add_middleware(RateLimitMiddleware, max_requests=100, window=60)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID", "X-Response-Time"]
)


# Exception handlers
@app.exception_handler(SOCShieldException)
async def socshield_exception_handler(request: Request, exc: SOCShieldException):
    """Handle custom SOCShield exceptions"""
    logger.error(
        f"SOCShield exception: {exc.message}",
        exc_info=True,
        extra={'error_code': exc.error_code, 'details': exc.details}
    )
    return JSONResponse(
        status_code=400,
        content={
            "error": exc.error_code,
            "message": exc.message,
            "details": exc.details if settings.DEBUG else {}
        }
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Handle all other exceptions"""
    logger.exception(f"Unhandled exception: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={
            "error": "INTERNAL_SERVER_ERROR",
            "message": "Internal server error",
            "details": str(exc) if settings.DEBUG else {}
        }
    )


# Health check endpoint
@app.get("/health", tags=["config"])
async def health_check():
    """
    Health check endpoint
    Returns system health status and configuration
    """
    from app.core.metrics import metrics
    
    metrics_snapshot = await metrics.get_snapshot()
    
    return {
        "status": "healthy",
        "version": settings.VERSION,
        "timestamp": metrics_snapshot['timestamp'],
        "configuration": {
            "ai_provider": settings.AI_PROVIDER,
            "debug_mode": settings.DEBUG,
            "features": {
                "auto_quarantine": settings.ENABLE_AUTO_QUARANTINE,
                "auto_block": settings.ENABLE_AUTO_BLOCK,
                "threat_intel": settings.ENABLE_THREAT_INTEL
            }
        },
        "metrics": {
            "emails_processed": metrics_snapshot['counters'].get('email.processed.total', 0),
            "phishing_detected": metrics_snapshot['counters'].get('phishing.detections.positive', 0),
            "threats_detected": metrics_snapshot['counters'].get('threat.detected.total', 0)
        }
    }


# Metrics endpoint
@app.get("/metrics", tags=["config"])
async def get_metrics():
    """
    Get application metrics
    Returns detailed performance and security metrics
    """
    from app.core.metrics import metrics
    
    return await metrics.get_snapshot()


# Root endpoint
@app.get("/", tags=["config"])
async def root():
    """
    Root endpoint
    Returns API information and available endpoints
    """
    return {
        "name": "SOCShield API",
        "description": "AI-Driven Phishing Detection & Response System",
        "version": settings.VERSION,
        "documentation": {
            "swagger": "/docs",
            "redoc": "/redoc"
        },
        "endpoints": {
            "health": "/health",
            "metrics": "/metrics",
            "api": "/api/v1"
        },
        "features": [
            "Real-time phishing detection",
            "Multi-provider AI analysis",
            "IOC extraction and enrichment",
            "Threat intelligence integration",
            "Automated response actions"
        ]
    }


# Include API router
app.include_router(api_router, prefix="/api/v1")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG
    )
