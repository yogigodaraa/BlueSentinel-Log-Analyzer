"""
Application Configuration
Loads settings from environment variables
"""

from pydantic_settings import BaseSettings
from typing import List, Optional
from functools import lru_cache


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""
    
    # Application
    APP_NAME: str = "SOCShield"
    DEBUG: bool = False
    VERSION: str = "1.0.0"
    
    # Database
    DATABASE_URL: str = "postgresql://socshield:changeme@localhost:5432/socshield"
    
    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"
    
    # AI Provider Configuration
    AI_PROVIDER: str = "gemini"  # Options: gemini, openai, claude
    GOOGLE_API_KEY: Optional[str] = None
    OPENAI_API_KEY: Optional[str] = None
    ANTHROPIC_API_KEY: Optional[str] = None
    
    # Email Configuration
    IMAP_SERVER: str = "imap.gmail.com"
    IMAP_PORT: int = 993
    IMAP_USERNAME: Optional[str] = None
    IMAP_PASSWORD: Optional[str] = None
    MONITORED_FOLDERS: str = "INBOX,Spam"
    
    # SMTP Configuration
    SMTP_SERVER: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USERNAME: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    ALERT_EMAIL_FROM: str = "alerts@socshield.io"
    
    # Security
    JWT_SECRET: str = "change-this-secret-key-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRATION: int = 3600  # 1 hour
    API_KEY: Optional[str] = None
    
    # CORS
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:3001"]
    
    # Alerting
    SLACK_WEBHOOK_URL: Optional[str] = None
    TEAMS_WEBHOOK_URL: Optional[str] = None
    ENABLE_SMS_ALERTS: bool = False
    TWILIO_ACCOUNT_SID: Optional[str] = None
    TWILIO_AUTH_TOKEN: Optional[str] = None
    TWILIO_PHONE_NUMBER: Optional[str] = None
    
    # SIEM Integration
    SPLUNK_HOST: Optional[str] = None
    SPLUNK_PORT: int = 8089
    SPLUNK_TOKEN: Optional[str] = None
    
    # Feature Flags
    ENABLE_AUTO_QUARANTINE: bool = True
    ENABLE_AUTO_BLOCK: bool = False
    ENABLE_THREAT_INTEL: bool = True
    
    # Celery Configuration
    CELERY_BROKER_URL: Optional[str] = None
    CELERY_RESULT_BACKEND: Optional[str] = None
    
    # Email Processing
    EMAIL_SCAN_INTERVAL: int = 60  # seconds
    MAX_EMAILS_PER_SCAN: int = 100
    
    # Detection Thresholds
    PHISHING_CONFIDENCE_THRESHOLD: float = 0.7
    HIGH_RISK_THRESHOLD: float = 0.9
    
    class Config:
        env_file = ".env"
        case_sensitive = True
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Set Celery URLs from Redis if not specified
        if not self.CELERY_BROKER_URL:
            self.CELERY_BROKER_URL = self.REDIS_URL
        if not self.CELERY_RESULT_BACKEND:
            self.CELERY_RESULT_BACKEND = self.REDIS_URL
    
    @property
    def monitored_folders_list(self) -> List[str]:
        """Convert comma-separated folders to list"""
        return [f.strip() for f in self.MONITORED_FOLDERS.split(",")]


@lru_cache()
def get_settings() -> Settings:
    """Cached settings instance"""
    return Settings()


settings = get_settings()
