"""
Tests for configuration
"""
from app.core.config import Settings


class TestSettings:
    """Test application settings"""
    
    def test_default_settings(self):
        """Test default settings are loaded"""
        settings = Settings()
        
        assert settings.APP_NAME == "SOCShield"
        assert settings.VERSION == "1.0.0"
        assert settings.AI_PROVIDER in ["gemini", "openai", "claude"]
    
    def test_database_url(self):
        """Test database URL configuration"""
        settings = Settings()
        
        assert settings.DATABASE_URL is not None
        assert "postgresql" in settings.DATABASE_URL or "sqlite" in settings.DATABASE_URL
    
    def test_redis_url(self):
        """Test Redis URL configuration"""
        settings = Settings()
        
        assert settings.REDIS_URL is not None
        assert "redis://" in settings.REDIS_URL
    
    def test_celery_configuration(self):
        """Test Celery configuration"""
        settings = Settings()
        
        # Celery URLs should be set from Redis if not provided
        assert settings.CELERY_BROKER_URL is not None
        assert settings.CELERY_RESULT_BACKEND is not None
    
    def test_monitored_folders_list(self):
        """Test monitored folders parsing"""
        settings = Settings()
        
        folders = settings.monitored_folders_list
        
        assert isinstance(folders, list)
        assert len(folders) > 0
        assert "INBOX" in folders or "Spam" in folders
    
    def test_cors_origins(self):
        """Test CORS origins configuration"""
        settings = Settings()
        
        assert isinstance(settings.CORS_ORIGINS, list)
        assert len(settings.CORS_ORIGINS) > 0
    
    def test_detection_thresholds(self):
        """Test detection threshold values"""
        settings = Settings()
        
        assert 0.0 <= settings.PHISHING_CONFIDENCE_THRESHOLD <= 1.0
        assert 0.0 <= settings.HIGH_RISK_THRESHOLD <= 1.0
        assert settings.HIGH_RISK_THRESHOLD >= settings.PHISHING_CONFIDENCE_THRESHOLD
    
    def test_email_scan_settings(self):
        """Test email scanning settings"""
        settings = Settings()
        
        assert settings.EMAIL_SCAN_INTERVAL > 0
        assert settings.MAX_EMAILS_PER_SCAN > 0
    
    def test_feature_flags(self):
        """Test feature flags"""
        settings = Settings()
        
        assert isinstance(settings.ENABLE_AUTO_QUARANTINE, bool)
        assert isinstance(settings.ENABLE_AUTO_BLOCK, bool)
        assert isinstance(settings.ENABLE_THREAT_INTEL, bool)


class TestConfigValidation:
    """Test configuration validation"""
    
    def test_ai_provider_validation(self):
        """Test AI provider must be valid"""
        settings = Settings()
        
        assert settings.AI_PROVIDER in ["gemini", "openai", "claude"]
    
    def test_jwt_secret_set(self):
        """Test JWT secret is configured"""
        settings = Settings()
        
        assert settings.JWT_SECRET is not None
        assert len(settings.JWT_SECRET) > 0
    
    def test_smtp_configuration(self):
        """Test SMTP configuration"""
        settings = Settings()
        
        assert settings.SMTP_SERVER is not None
        assert settings.SMTP_PORT > 0
        assert settings.SMTP_PORT < 65536
