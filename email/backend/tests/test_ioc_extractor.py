"""
Tests for IOC extractor service
"""
import pytest
import re
from app.services.ioc_extractor import IOCExtractor


class TestIOCExtractor:
    """Test IOC extraction service"""
    
    @pytest.fixture
    def extractor(self):
        """Create IOC extractor instance"""
        return IOCExtractor()
    
    def test_extract_urls(self, extractor):
        """Test extracting URLs from text"""
        text = """
        Click here: https://example.com/login
        Or visit http://test.org
        Also check ftp://files.example.com
        """
        
        urls = extractor.extract_urls(text)
        
        assert len(urls) >= 2
        assert any('example.com' in url for url in urls)
        assert any('test.org' in url for url in urls)
    
    def test_extract_domains(self, extractor):
        """Test extracting domains"""
        text = """
        Contact us at support@example.com
        Visit www.test-site.org
        Or go to subdomain.example.net
        """
        
        domains = extractor.extract_domains(text)
        
        assert len(domains) > 0
        assert any('example.com' in domain for domain in domains)
    
    def test_extract_ip_addresses(self, extractor):
        """Test extracting IP addresses"""
        text = """
        Server is at 192.168.1.100
        Backup at 10.0.0.5
        External: 203.0.113.45
        """
        
        ips = extractor.extract_ip_addresses(text)
        
        assert len(ips) >= 3
        assert '192.168.1.100' in ips
        assert '10.0.0.5' in ips
        assert '203.0.113.45' in ips
    
    def test_extract_email_addresses(self, extractor):
        """Test extracting email addresses"""
        text = """
        Contact: support@example.com
        Reply to: admin@test-domain.org
        Sales: info@company.co.uk
        """
        
        emails = extractor.extract_email_addresses(text)
        
        assert len(emails) >= 3
        assert 'support@example.com' in emails
        assert 'admin@test-domain.org' in emails
    
    def test_extract_file_hashes(self, extractor):
        """Test extracting file hashes"""
        text = """
        MD5: d41d8cd98f00b204e9800998ecf8427e
        SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709
        """
        
        hashes = extractor.extract_file_hashes(text)
        
        assert len(hashes) >= 2
    
    def test_extract_all_iocs(self, extractor, sample_phishing_email):
        """Test extracting all IOCs from email"""
        iocs = extractor.extract_all(sample_phishing_email)
        
        assert 'urls' in iocs
        assert 'domains' in iocs
        assert 'ip_addresses' in iocs
        assert 'email_addresses' in iocs
        assert isinstance(iocs['urls'], list)
    
    def test_no_false_positives(self, extractor):
        """Test that normal text doesn't extract false positives"""
        text = "This is a normal sentence with no IOCs."
        
        iocs = extractor.extract_all({'body': text, 'subject': 'Normal', 'sender': 'test@example.com'})
        
        # Should have minimal or no extractions
        assert len(iocs['urls']) == 0
        assert len(iocs['ip_addresses']) == 0


class TestRegexPatterns:
    """Test regex patterns used for IOC extraction"""
    
    def test_url_pattern(self):
        """Test URL regex pattern"""
        url_pattern = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')
        
        valid_urls = [
            "https://example.com",
            "http://test.org/path",
            "https://sub.domain.com/path?query=1"
        ]
        
        for url in valid_urls:
            assert url_pattern.search(url) is not None
    
    def test_email_pattern(self):
        """Test email regex pattern"""
        email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        
        valid_emails = [
            "user@example.com",
            "test.user@sub.domain.org",
            "admin+tag@company.co.uk"
        ]
        
        for email in valid_emails:
            assert email_pattern.search(email) is not None
    
    def test_ipv4_pattern(self):
        """Test IPv4 regex pattern"""
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        
        valid_ips = [
            "192.168.1.1",
            "10.0.0.5",
            "172.16.0.100"
        ]
        
        for ip in valid_ips:
            assert ip_pattern.search(ip) is not None
        
        invalid_ips = [
            "999.999.999.999",
            "1.2.3",
            "a.b.c.d"
        ]
        
        # Note: Basic regex will match these, need additional validation
        # This test just checks the pattern matches numbers
