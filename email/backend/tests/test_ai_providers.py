"""
Tests for AI providers
"""
import pytest
from unittest.mock import Mock, patch, AsyncMock
from app.ai.factory import AIService
from app.core.config import settings
from app.ai.gemini_provider import GeminiProvider
from app.ai.openai_provider import OpenAIProvider
from app.ai.claude_provider import ClaudeProvider


class TestAIProviderFactory:
    """AIService picks the provider from settings.AI_PROVIDER and needs the matching key."""

    @pytest.fixture(autouse=True)
    def _reset_singleton(self):
        AIService.reset()
        yield
        AIService.reset()

    def test_create_gemini_provider(self, monkeypatch, mock_ai_api_key):
        monkeypatch.setattr(settings, "AI_PROVIDER", "gemini")
        monkeypatch.setattr(settings, "GOOGLE_API_KEY", mock_ai_api_key)
        with patch("google.generativeai.configure"), patch("google.generativeai.GenerativeModel"):
            assert isinstance(AIService.get_provider(), GeminiProvider)

    def test_create_openai_provider(self, monkeypatch, mock_ai_api_key):
        monkeypatch.setattr(settings, "AI_PROVIDER", "openai")
        monkeypatch.setattr(settings, "OPENAI_API_KEY", mock_ai_api_key)
        assert isinstance(AIService.get_provider(), OpenAIProvider)

    def test_create_claude_provider(self, monkeypatch, mock_ai_api_key):
        monkeypatch.setattr(settings, "AI_PROVIDER", "claude")
        monkeypatch.setattr(settings, "ANTHROPIC_API_KEY", mock_ai_api_key)
        assert isinstance(AIService.get_provider(), ClaudeProvider)

    def test_invalid_provider(self, monkeypatch):
        monkeypatch.setattr(settings, "AI_PROVIDER", "invalid")
        with pytest.raises(ValueError):
            AIService.get_provider()

    def test_missing_api_key(self, monkeypatch):
        monkeypatch.setattr(settings, "AI_PROVIDER", "gemini")
        monkeypatch.setattr(settings, "GOOGLE_API_KEY", "")
        with pytest.raises(ValueError):
            AIService.get_provider()

    def test_provider_is_a_singleton(self, monkeypatch, mock_ai_api_key):
        monkeypatch.setattr(settings, "AI_PROVIDER", "claude")
        monkeypatch.setattr(settings, "ANTHROPIC_API_KEY", mock_ai_api_key)
        assert AIService.get_provider() is AIService.get_provider()


class TestGeminiProvider:
    """Test Gemini AI provider"""
    
    @pytest.fixture
    def gemini_provider(self, mock_ai_api_key):
        """Create a Gemini provider instance"""
        with patch('google.generativeai.configure'):
            with patch('google.generativeai.GenerativeModel') as mock_model:
                mock_instance = Mock()
                mock_model.return_value = mock_instance
                provider = GeminiProvider(mock_ai_api_key)
                yield provider
    
    @pytest.mark.asyncio
    async def test_analyze_phishing_email(self, gemini_provider, sample_phishing_email):
        """Test analyzing phishing email"""
        # Mock response
        mock_response = Mock()
        mock_response.text = '''```json
{
    "is_phishing": true,
    "confidence": 0.92,
    "risk_level": "high",
    "indicators": ["Spoofed domain", "Urgency tactics", "Suspicious link"],
    "explanation": "This email shows multiple phishing indicators"
}
```'''
        
        gemini_provider.model.generate_content = Mock(return_value=mock_response)
        
        result = await gemini_provider.analyze_email(sample_phishing_email)
        
        assert result["is_phishing"]
        assert result["confidence"] > 0.7
        assert result["risk_level"] in ["high", "critical", "medium"]
        assert len(result["indicators"]) > 0
    
    @pytest.mark.asyncio
    async def test_analyze_legitimate_email(self, gemini_provider, sample_legitimate_email):
        """Test analyzing legitimate email"""
        mock_response = Mock()
        mock_response.text = '''```json
{
    "is_phishing": false,
    "confidence": 0.15,
    "risk_level": "low",
    "indicators": [],
    "explanation": "This appears to be a legitimate business email"
}
```'''
        
        gemini_provider.model.generate_content = Mock(return_value=mock_response)
        
        result = await gemini_provider.analyze_email(sample_legitimate_email)
        
        assert not result["is_phishing"]
        assert result["risk_level"] == "low"
    
    @pytest.mark.asyncio
    async def test_extract_iocs(self, gemini_provider, sample_phishing_email):
        """Test IOC extraction"""
        mock_response = Mock()
        mock_response.text = '''```json
{
    "domains": ["paypa1-secure.com", "secure-paypal-verify.tk"],
    "urls": ["https://secure-paypal-verify.tk/account/login"],
    "ip_addresses": [],
    "email_addresses": ["security@paypa1-secure.com"],
    "file_hashes": []
}
```'''
        
        gemini_provider.model.generate_content = Mock(return_value=mock_response)
        
        result = await gemini_provider.extract_iocs(sample_phishing_email)
        
        assert "domains" in result
        assert "urls" in result
        assert len(result["domains"]) > 0
    
    @pytest.mark.asyncio
    async def test_fallback_on_json_error(self, gemini_provider, sample_phishing_email):
        """Test fallback response on JSON parsing error"""
        mock_response = Mock()
        mock_response.text = "Invalid JSON response"
        
        gemini_provider.model.generate_content = Mock(return_value=mock_response)
        
        result = await gemini_provider.analyze_email(sample_phishing_email)
        
        assert result["risk_level"] == "unknown"
        assert "failed" in result["explanation"].lower() or "manual review" in result["explanation"].lower()


class TestOpenAIProvider:
    """Test OpenAI provider"""
    
    @pytest.fixture
    def openai_provider(self, mock_ai_api_key):
        """Create an OpenAI provider instance"""
        with patch('openai.AsyncOpenAI'):
            provider = OpenAIProvider(mock_ai_api_key)
            yield provider
    
    @pytest.mark.asyncio
    async def test_analyze_email(self, openai_provider, sample_phishing_email):
        """Test OpenAI email analysis"""
        # Mock OpenAI response
        mock_response = Mock()
        mock_choice = Mock()
        mock_message = Mock()
        mock_message.content = '''```json
{
    "is_phishing": true,
    "confidence": 0.88,
    "risk_level": "high",
    "indicators": ["Spoofed domain"],
    "explanation": "Phishing detected"
}
```'''
        mock_choice.message = mock_message
        mock_response.choices = [mock_choice]
        
        openai_provider.client.chat.completions.create = AsyncMock(return_value=mock_response)
        
        result = await openai_provider.analyze_email(sample_phishing_email)
        
        assert "is_phishing" in result
        assert "confidence" in result


class TestClaudeProvider:
    """Test Claude provider"""
    
    @pytest.fixture
    def claude_provider(self, mock_ai_api_key):
        """Create a Claude provider instance"""
        with patch('anthropic.AsyncAnthropic'):
            provider = ClaudeProvider(mock_ai_api_key)
            yield provider
    
    @pytest.mark.asyncio
    async def test_analyze_email(self, claude_provider, sample_phishing_email):
        """Test Claude email analysis"""
        # Mock Claude response
        mock_response = Mock()
        mock_content = Mock()
        mock_content.text = '''```json
{
    "is_phishing": true,
    "confidence": 0.90,
    "risk_level": "critical",
    "indicators": ["Spoofed sender"],
    "explanation": "High confidence phishing"
}
```'''
        mock_content.type = "text"
        thinking = Mock(type="thinking")  # current models may lead with a thinking block
        mock_response.content = [thinking, mock_content]
        mock_response.stop_reason = "end_turn"

        claude_provider.client.beta.messages.create = AsyncMock(return_value=mock_response)

        result = await claude_provider.analyze_email(sample_phishing_email)

        assert result["is_phishing"] is True
        assert result["risk_level"] == "critical"
        kwargs = claude_provider.client.beta.messages.create.call_args.kwargs
        assert "temperature" not in kwargs
        assert kwargs["fallbacks"] == "default"

    @pytest.mark.asyncio
    async def test_refusal_returns_manual_review(self, claude_provider, sample_phishing_email):
        """A declined request degrades to 'manual review' instead of crashing."""
        refused = Mock(stop_reason="refusal", stop_details=Mock(category="cyber"), content=[])
        claude_provider.client.beta.messages.create = AsyncMock(return_value=refused)

        result = await claude_provider.analyze_email(sample_phishing_email)

        assert result["risk_level"] == "unknown"
