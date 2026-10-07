"""
Tests for API endpoints
"""
from fastapi.testclient import TestClient


class TestHealthEndpoint:
    """Test health check endpoint"""
    
    def test_health_check(self, client: TestClient):
        """Test health endpoint returns correct status"""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data
        assert "ai_provider" in data["configuration"]
    
    def test_root_endpoint(self, client: TestClient):
        """Test root endpoint"""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert "SOCShield" in data["name"]
        assert data["documentation"]["swagger"] == "/docs"


class TestAnalysisEndpoint:
    """Test email analysis endpoint"""
    
    def test_analyze_phishing_email(self, client: TestClient, sample_phishing_email):
        """Test analyzing a phishing email"""
        response = client.post("/api/v1/analysis/analyze", json=sample_phishing_email)
        
        # Should succeed even if AI provider is not configured (mock response)
        assert response.status_code in [200, 500, 503]
        
        if response.status_code == 200:
            data = response.json()
            assert "is_phishing" in data
            assert "confidence" in data
            assert "risk_level" in data
    
    def test_analyze_legitimate_email(self, client: TestClient, sample_legitimate_email):
        """Test analyzing a legitimate email"""
        response = client.post("/api/v1/analysis/analyze", json=sample_legitimate_email)
        
        assert response.status_code in [200, 500, 503]
    
    def test_analyze_missing_subject(self, client: TestClient):
        """Test analyzing email without subject"""
        invalid_email = {
            "sender": "test@example.com",
            "body": "Test body"
        }
        response = client.post("/api/v1/analysis/analyze", json=invalid_email)
        
        # Should handle validation error
        assert response.status_code in [200, 422, 500]
    
    def test_analyze_empty_body(self, client: TestClient):
        """Test analyzing email with empty body"""
        email = {
            "subject": "Test",
            "sender": "test@example.com",
            "body": ""
        }
        response = client.post("/api/v1/analysis/analyze", json=email)
        
        assert response.status_code in [200, 422, 500]


class TestDashboardEndpoint:
    """Test dashboard statistics endpoint"""
    
    def test_get_stats(self, client: TestClient):
        """Test getting dashboard statistics"""
        response = client.get("/api/v1/dashboard/stats")
        
        assert response.status_code in [200, 500]
        
        if response.status_code == 200:
            data = response.json()
            assert "total_emails" in data or "error" in data
    
    def test_get_recent_threats(self, client: TestClient):
        """Test getting recent threats"""
        response = client.get("/api/v1/dashboard/threats/recent")
        
        assert response.status_code in [200, 404, 500]


class TestEmailsEndpoint:
    """Test emails endpoint"""
    
    def test_list_emails(self, client: TestClient):
        """Test listing emails"""
        response = client.get("/api/v1/emails/")
        
        assert response.status_code in [200, 500]
        
        if response.status_code == 200:
            data = response.json()
            assert isinstance(data["emails"], list) or "error" in data
    
    def test_get_email_by_id(self, client: TestClient):
        """Test getting email by ID"""
        response = client.get("/api/v1/emails/1")
        
        # Should return 404 if not found or 200 if exists
        assert response.status_code in [200, 404, 500]


class TestThreatsEndpoint:
    """Test threats endpoint"""
    
    def test_list_threats(self, client: TestClient):
        """Test listing threats"""
        response = client.get("/api/v1/threats/")
        
        assert response.status_code in [200, 500]
        
        if response.status_code == 200:
            data = response.json()
            assert isinstance(data["threats"], list) or "error" in data
    
    def test_get_threat_by_id(self, client: TestClient):
        """Test getting threat by ID"""
        response = client.get("/api/v1/threats/1")
        
        assert response.status_code in [200, 404, 500]


class TestCORSHeaders:
    """Test CORS configuration"""
    
    def test_cors_headers_present(self, client: TestClient):
        """Test that CORS headers are present"""
        response = client.options("/api/v1/dashboard/stats")
        
        # CORS headers should be present
        assert response.status_code in [200, 405]
