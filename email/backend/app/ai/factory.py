"""
AI Service Factory
Manages AI provider initialization and selection
"""

from typing import Optional
from app.ai.base import BaseAIProvider, AIProvider
from app.ai.gemini_provider import GeminiProvider
from app.ai.openai_provider import OpenAIProvider
from app.ai.claude_provider import ClaudeProvider
from app.core.config import settings
import logging

logger = logging.getLogger(__name__)


class AIService:
    """Factory for creating and managing AI providers"""
    
    _instance: Optional[BaseAIProvider] = None
    
    @classmethod
    def get_provider(cls) -> BaseAIProvider:
        """Get the configured AI provider (singleton)"""
        if cls._instance is None:
            cls._instance = cls._create_provider()
        return cls._instance
    
    @classmethod
    def _create_provider(cls) -> BaseAIProvider:
        """Create AI provider based on configuration"""
        provider_type = settings.AI_PROVIDER.lower()
        
        logger.info(f"Initializing AI provider: {provider_type}")
        
        if provider_type == AIProvider.GEMINI:
            if not settings.GOOGLE_API_KEY:
                raise ValueError("GOOGLE_API_KEY not configured")
            return GeminiProvider(settings.GOOGLE_API_KEY)
        
        elif provider_type == AIProvider.OPENAI:
            if not settings.OPENAI_API_KEY:
                raise ValueError("OPENAI_API_KEY not configured")
            return OpenAIProvider(settings.OPENAI_API_KEY)
        
        elif provider_type == AIProvider.CLAUDE:
            if not settings.ANTHROPIC_API_KEY:
                raise ValueError("ANTHROPIC_API_KEY not configured")
            return ClaudeProvider(settings.ANTHROPIC_API_KEY)
        
        else:
            raise ValueError(f"Unsupported AI provider: {provider_type}")
    
    @classmethod
    def reset(cls):
        """Reset the provider instance (useful for testing)"""
        cls._instance = None


# Convenience function
def get_ai_provider() -> BaseAIProvider:
    """Get the AI provider instance"""
    return AIService.get_provider()
