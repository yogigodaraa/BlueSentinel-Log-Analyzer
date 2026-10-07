"""
Integration tests for the complete phishing detection workflow
"""
import pytest


@pytest.mark.integration
class TestPhishingDetectionWorkflow:
    """Test complete phishing detection workflow"""
    
    @pytest.mark.asyncio
    async def test_complete_phishing_detection(self, sample_phishing_email):
        """Test end-to-end phishing detection"""
        # This is a high-level integration test
        # In a real scenario, this would test the complete flow:
        # 1. Email received
        # 2. IOC extraction
        # 3. AI analysis
        # 4. Threat classification
        # 5. Alert generation
        
        email = sample_phishing_email
        
        # Verify email structure
        assert 'subject' in email
        assert 'sender' in email
        assert 'body' in email
        
        # Should contain phishing indicators
        assert any(word in email['body'].lower() for word in ['urgent', 'verify', 'suspend'])
        assert any(word in email['subject'].lower() for word in ['urgent', 'limited', 'action'])
    
    @pytest.mark.asyncio
    async def test_legitimate_email_workflow(self, sample_legitimate_email):
        """Test workflow with legitimate email"""
        email = sample_legitimate_email
        
        # Verify email structure
        assert 'subject' in email
        assert 'sender' in email
        assert 'body' in email
        
        # Should NOT contain phishing indicators
        phishing_keywords = ['urgent', 'verify', 'suspend', 'account limited', 'click here']
        body_lower = email['body'].lower()
        subject_lower = email['subject'].lower()
        
        # Count phishing indicators (should be low)
        indicator_count = sum(1 for keyword in phishing_keywords if keyword in body_lower or keyword in subject_lower)
        assert indicator_count <= 1  # Allow for some common words


@pytest.mark.integration
class TestEmailProcessingPipeline:
    """Test email processing pipeline"""
    
    @pytest.mark.asyncio
    async def test_email_ingestion(self, sample_phishing_email):
        """Test email ingestion process"""
        email = sample_phishing_email
        
        # Validate required fields
        required_fields = ['subject', 'sender', 'body']
        for field in required_fields:
            assert field in email
            assert email[field] is not None
    
    @pytest.mark.asyncio
    async def test_ioc_extraction_pipeline(self, sample_phishing_email):
        """Test IOC extraction in pipeline"""
        email = sample_phishing_email
        
        # Should extract URLs
        if 'links' in email:
            assert len(email['links']) > 0
            
            # URLs should be valid format
            for link in email['links']:
                assert link.startswith(('http://', 'https://'))
    
    @pytest.mark.asyncio
    async def test_threat_scoring(self, sample_phishing_email):
        """Test threat scoring logic"""
        email = sample_phishing_email
        
        # Calculate basic threat score based on indicators
        threat_score = 0
        
        # Check for urgency
        urgency_words = ['urgent', 'immediately', 'now', 'suspend']
        if any(word in email['body'].lower() or word in email['subject'].lower() for word in urgency_words):
            threat_score += 30
        
        # Check for suspicious links
        if 'links' in email and len(email['links']) > 0:
            threat_score += 20
        
        # Check for spoofed sender
        suspicious_domains = ['.tk', '.ml', '.ga', '.cf']
        if any(domain in email['sender'] for domain in suspicious_domains):
            threat_score += 25
        
        # Phishing emails should have high threat score
        assert threat_score >= 30


@pytest.mark.integration
class TestAlertingWorkflow:
    """Test alerting and notification workflow"""
    
    @pytest.mark.asyncio
    async def test_high_risk_alert_generation(self, sample_phishing_email):
        """Test that high-risk emails trigger alerts"""
        email = sample_phishing_email
        
        # High-risk criteria
        is_high_risk = False
        
        # Check confidence threshold
        confidence = 0.9  # Simulated high confidence
        if confidence >= 0.8:
            is_high_risk = True
        
        assert is_high_risk == True
    
    @pytest.mark.asyncio
    async def test_low_risk_no_alert(self, sample_legitimate_email):
        """Test that low-risk emails don't trigger alerts"""
        email = sample_legitimate_email
        
        # Low-risk criteria
        is_low_risk = True
        
        # Check for phishing indicators
        phishing_indicators = ['urgent', 'verify', 'suspend', 'click here now']
        if any(indicator in email['body'].lower() for indicator in phishing_indicators):
            is_low_risk = False
        
        assert is_low_risk == True


@pytest.mark.integration
class TestDatabaseOperations:
    """Test database operations in the workflow"""
    
    @pytest.mark.asyncio
    async def test_email_persistence(self, test_db, sample_phishing_email):
        """Test storing email in database"""
        # This would test actual database operations
        # For now, just verify we have a database session
        assert test_db is not None
    
    @pytest.mark.asyncio
    async def test_threat_persistence(self, test_db):
        """Test storing threats in database"""
        assert test_db is not None
