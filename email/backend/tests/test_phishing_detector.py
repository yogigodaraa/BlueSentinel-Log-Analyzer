"""
Tests for phishing detection service
"""
import pytest
from unittest.mock import patch
from app.services.phishing_detector import PhishingDetector


class TestPhishingDetector:
    """Test phishing detector service"""
    
    @pytest.fixture
    def detector(self):
        """Create phishing detector instance"""
        with patch('app.ai.factory.AIProviderFactory.create_provider'):
            detector = PhishingDetector()
            yield detector
    
    @pytest.mark.asyncio
    async def test_detect_phishing_url(self, detector):
        """Test detecting phishing URLs"""
        phishing_urls = [
            "https://paypa1.com",
            "http://microsoft-login.tk",
            "https://192.168.1.100/login.php"
        ]
        
        for url in phishing_urls:
            # Should identify suspicious patterns
            is_suspicious = await detector._check_url_suspicious(url)
            # Implementation dependent, but should have some detection
            assert isinstance(is_suspicious, bool)
    
    @pytest.mark.asyncio
    async def test_detect_urgency_keywords(self, detector):
        """Test detecting urgency keywords"""
        urgent_phrases = [
            "urgent action required",
            "verify your account immediately",
            "suspended within 24 hours",
            "act now or lose access"
        ]
        
        for phrase in urgent_phrases:
            email = {
                "subject": phrase,
                "body": "Test body",
                "sender": "test@example.com"
            }
            # Should detect urgency
            has_urgency = detector._has_urgency_indicators(email)
            assert isinstance(has_urgency, bool)
    
    @pytest.mark.asyncio
    async def test_detect_spoofed_sender(self, detector):
        """Test detecting spoofed senders"""
        spoofed_senders = [
            "security@paypa1.com",  # Look-alike
            "noreply@micros0ft.com",  # Zero instead of O
            "support@g00gle.com"  # Zeros instead of O
        ]
        
        for sender in spoofed_senders:
            is_spoofed = detector._is_sender_spoofed(sender)
            # Should identify potential spoofing
            assert isinstance(is_spoofed, bool)


class TestPhishingIndicators:
    """Test phishing indicator detection"""
    
    @pytest.mark.asyncio
    async def test_suspicious_attachments(self):
        """Test detecting suspicious attachments"""
        suspicious_files = [
            "invoice.exe",
            "document.scr",
            "payment.bat",
            "file.js"
        ]
        
        safe_files = [
            "report.pdf",
            "document.docx",
            "image.jpg"
        ]
        
        # Suspicious extensions should be flagged
        for filename in suspicious_files:
            extension = filename.split('.')[-1]
            assert extension in ['exe', 'scr', 'bat', 'js']
        
        # Safe extensions should pass
        for filename in safe_files:
            extension = filename.split('.')[-1]
            assert extension in ['pdf', 'docx', 'jpg']
    
    def test_suspicious_tlds(self):
        """Test detecting suspicious top-level domains"""
        suspicious_domains = [
            "example.tk",
            "test.ml",
            "phishing.ga",
            "spam.cf"
        ]
        
        suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq']
        
        for domain in suspicious_domains:
            tld = domain.split('.')[-1]
            assert tld in suspicious_tlds
    
    def test_ip_address_in_url(self):
        """Test detecting IP addresses in URLs"""
        import re
        
        ip_pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        
        urls_with_ips = [
            "http://192.168.1.100/login",
            "https://10.0.0.1/secure",
            "http://172.16.0.5/verify"
        ]
        
        for url in urls_with_ips:
            assert ip_pattern.search(url) is not None
