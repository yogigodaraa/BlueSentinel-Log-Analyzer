"""
Custom Middleware
Request tracking, rate limiting, and monitoring
"""

import time
import uuid
from typing import Callable
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from app.core.logging import get_logger, set_request_id

logger = get_logger(__name__)


class RequestTrackingMiddleware(BaseHTTPMiddleware):
    """Track requests with unique IDs and timing"""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Generate unique request ID
        request_id = str(uuid.uuid4())
        set_request_id(request_id)
        
        # Add to request state
        request.state.request_id = request_id
        
        # Start timer
        start_time = time.time()
        
        # Log request
        logger.with_context(
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            client_ip=request.client.host if request.client else None
        ).info(f"Request started: {request.method} {request.url.path}")
        
        try:
            # Process request
            response = await call_next(request)
            
            # Calculate duration
            duration = time.time() - start_time
            
            # Log response
            logger.with_context(
                request_id=request_id,
                status_code=response.status_code,
                duration=f"{duration:.3f}s"
            ).info(f"Request completed: {response.status_code} in {duration:.3f}s")
            
            # Add headers
            response.headers["X-Request-ID"] = request_id
            response.headers["X-Response-Time"] = f"{duration:.3f}"
            
            return response
            
        except Exception as e:
            duration = time.time() - start_time
            logger.with_context(
                request_id=request_id,
                duration=f"{duration:.3f}s"
            ).exception(f"Request failed: {str(e)}")
            raise


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Simple in-memory rate limiting (use Redis for production)"""
    
    def __init__(self, app: ASGIApp, max_requests: int = 100, window: int = 60):
        super().__init__(app)
        self.max_requests = max_requests
        self.window = window
        self.request_counts = {}
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Get client identifier
        client_id = request.client.host if request.client else "unknown"
        
        # Clean old entries
        current_time = time.time()
        self.request_counts = {
            k: v for k, v in self.request_counts.items()
            if current_time - v['timestamp'] < self.window
        }
        
        # Check rate limit
        if client_id in self.request_counts:
            count = self.request_counts[client_id]['count']
            if count >= self.max_requests:
                logger.warning(f"Rate limit exceeded for {client_id}")
                return Response(
                    content="Rate limit exceeded",
                    status_code=429,
                    headers={
                        "X-RateLimit-Limit": str(self.max_requests),
                        "X-RateLimit-Remaining": "0",
                        "Retry-After": str(self.window)
                    }
                )
            self.request_counts[client_id]['count'] += 1
        else:
            self.request_counts[client_id] = {
                'count': 1,
                'timestamp': current_time
            }
        
        # Add rate limit headers
        response = await call_next(request)
        remaining = self.max_requests - self.request_counts[client_id]['count']
        response.headers["X-RateLimit-Limit"] = str(self.max_requests)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to responses"""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        
        # Add security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        
        return response
