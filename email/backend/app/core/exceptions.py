"""
Custom Exception Classes
Centralized exception handling for better error management
"""

from typing import Optional, Dict, Any


class SOCShieldException(Exception):
    """Base exception for all SOCShield errors"""
    
    def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        self.message = message
        self.error_code = error_code or "SOCSHIELD_ERROR"
        self.details = details or {}
        super().__init__(self.message)


class AIProviderException(SOCShieldException):
    """AI provider related errors"""
    
    def __init__(self, message: str, provider: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            error_code="AI_PROVIDER_ERROR",
            details={**(details or {}), "provider": provider}
        )


class RateLimitException(AIProviderException):
    """Rate limit exceeded"""
    
    def __init__(self, provider: str, retry_after: Optional[int] = None):
        details = {"retry_after": retry_after} if retry_after else {}
        super().__init__(
            message=f"{provider} rate limit exceeded",
            provider=provider,
            details=details
        )


class InvalidAPIKeyException(AIProviderException):
    """Invalid API key"""
    
    def __init__(self, provider: str):
        super().__init__(
            message=f"Invalid API key for {provider}",
            provider=provider
        )


class EmailProcessingException(SOCShieldException):
    """Email processing errors"""
    
    def __init__(self, message: str, email_id: Optional[str] = None):
        super().__init__(
            message=message,
            error_code="EMAIL_PROCESSING_ERROR",
            details={"email_id": email_id} if email_id else {}
        )


class IOCExtractionException(SOCShieldException):
    """IOC extraction errors"""
    
    def __init__(self, message: str, ioc_type: Optional[str] = None):
        super().__init__(
            message=message,
            error_code="IOC_EXTRACTION_ERROR",
            details={"ioc_type": ioc_type} if ioc_type else {}
        )


class DatabaseException(SOCShieldException):
    """Database operation errors"""
    
    def __init__(self, message: str, operation: Optional[str] = None):
        super().__init__(
            message=message,
            error_code="DATABASE_ERROR",
            details={"operation": operation} if operation else {}
        )


class ThreatIntelException(SOCShieldException):
    """Threat intelligence service errors"""
    
    def __init__(self, message: str, service: Optional[str] = None):
        super().__init__(
            message=message,
            error_code="THREAT_INTEL_ERROR",
            details={"service": service} if service else {}
        )


class ConfigurationException(SOCShieldException):
    """Configuration errors"""
    
    def __init__(self, message: str, config_key: Optional[str] = None):
        super().__init__(
            message=message,
            error_code="CONFIGURATION_ERROR",
            details={"config_key": config_key} if config_key else {}
        )


class ValidationException(SOCShieldException):
    """Input validation errors"""
    
    def __init__(self, message: str, field: Optional[str] = None):
        super().__init__(
            message=message,
            error_code="VALIDATION_ERROR",
            details={"field": field} if field else {}
        )


class AuthenticationException(SOCShieldException):
    """Authentication errors"""
    
    def __init__(self, message: str = "Authentication failed"):
        super().__init__(
            message=message,
            error_code="AUTHENTICATION_ERROR"
        )


class AuthorizationException(SOCShieldException):
    """Authorization errors"""
    
    def __init__(self, message: str = "Permission denied"):
        super().__init__(
            message=message,
            error_code="AUTHORIZATION_ERROR"
        )
