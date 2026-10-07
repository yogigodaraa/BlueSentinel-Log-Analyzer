"""
AI Provider Factory
Manages multiple AI providers (Gemini, OpenAI, Claude)
"""

from abc import ABC, abstractmethod
from typing import Dict, Any
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class AIProvider(str, Enum):
    """Supported AI providers"""
    GEMINI = "gemini"
    OPENAI = "openai"
    CLAUDE = "claude"


class BaseAIProvider(ABC):
    """Base class for AI providers"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.logger = logging.getLogger(self.__class__.__name__)
    
    @abstractmethod
    async def analyze_email(self, email_content: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze email for phishing indicators
        
        Args:
            email_content: Dictionary containing email data
                - subject: Email subject
                - body: Email body (text/html)
                - sender: Sender email address
                - links: List of URLs found in email
                - attachments: List of attachment info
        
        Returns:
            Dictionary containing:
                - is_phishing: Boolean indicating if email is phishing
                - confidence: Float between 0-1
                - risk_level: "low", "medium", "high", "critical"
                - indicators: List of phishing indicators found
                - explanation: Detailed explanation
        """
        pass
    
    @abstractmethod
    async def extract_iocs(self, email_content: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract Indicators of Compromise from email
        
        Returns:
            Dictionary containing:
                - domains: List of suspicious domains
                - urls: List of malicious URLs
                - ip_addresses: List of suspicious IPs
                - email_addresses: List of suspicious email addresses
                - file_hashes: List of attachment hashes
        """
        pass
    
    def _create_analysis_prompt(self, email_content: Dict[str, Any]) -> str:
        """Create prompt for phishing analysis"""
        prompt = f"""Analyze the following email for phishing indicators:

Subject: {email_content.get('subject', 'N/A')}
Sender: {email_content.get('sender', 'N/A')}
Body:
{email_content.get('body', 'N/A')[:2000]}

URLs found: {', '.join(email_content.get('links', [])[:10])}

Analyze this email and respond in JSON format with:
1. is_phishing: boolean (true if phishing, false if benign)
2. confidence: float 0-1 (how confident you are)
3. risk_level: string (low/medium/high/critical)
4. indicators: array of specific phishing indicators found
5. explanation: detailed reasoning

Consider:
- Urgency language and social engineering tactics
- Sender authenticity and domain reputation
- URL legitimacy and link manipulation
- Spelling/grammar errors
- Requests for sensitive information
- Attachment types and names
- Email headers and routing
"""
        return prompt
    
    def _create_ioc_extraction_prompt(self, email_content: Dict[str, Any]) -> str:
        """Create prompt for IOC extraction"""
        prompt = f"""Extract Indicators of Compromise (IOCs) from this email:

Subject: {email_content.get('subject', 'N/A')}
Body: {email_content.get('body', 'N/A')[:2000]}
Links: {', '.join(email_content.get('links', []))}

Extract and respond in JSON format with:
1. domains: array of suspicious/malicious domains
2. urls: array of full malicious URLs
3. ip_addresses: array of suspicious IP addresses
4. email_addresses: array of suspicious email addresses
5. file_hashes: array of any file hashes mentioned

Only include IOCs that appear malicious or suspicious.
"""
        return prompt
