"""
Anthropic Claude Provider
"""

import json
from typing import Dict, Any
from anthropic import AsyncAnthropic
from app.ai.base import BaseAIProvider


class ClaudeProvider(BaseAIProvider):
    """Anthropic Claude provider for phishing detection"""
    
    def __init__(self, api_key: str):
        super().__init__(api_key)
        self.client = AsyncAnthropic(api_key=api_key)
        self.model = "claude-3-5-sonnet-20241022"
        self.logger.info("Initialized Claude provider")
    
    async def analyze_email(self, email_content: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze email using Claude"""
        try:
            prompt = self._create_analysis_prompt(email_content)
            
            response = await self.client.messages.create(
                model=self.model,
                max_tokens=1024,
                temperature=0.1,
                system="You are a cybersecurity expert specializing in phishing detection. Analyze emails and respond only with valid JSON.",
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            )
            
            result_text = response.content[0].text.strip()
            
            # Extract JSON from markdown code blocks if present
            if '```json' in result_text:
                result_text = result_text.split('```json')[1].split('```')[0].strip()
            elif '```' in result_text:
                result_text = result_text.split('```')[1].split('```')[0].strip()
            
            result = json.loads(result_text)
            
            self.logger.info(f"Claude analysis: {result.get('risk_level', 'unknown')} risk")
            return result
            
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse Claude response: {e}")
            return self._fallback_response(email_content)
        except Exception as e:
            self.logger.error(f"Claude analysis error: {e}")
            raise
    
    async def extract_iocs(self, email_content: Dict[str, Any]) -> Dict[str, Any]:
        """Extract IOCs using Claude"""
        try:
            prompt = self._create_ioc_extraction_prompt(email_content)
            
            response = await self.client.messages.create(
                model=self.model,
                max_tokens=1024,
                temperature=0.1,
                system="You are a cybersecurity analyst. Extract Indicators of Compromise from emails. Respond only with valid JSON.",
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            )
            
            result_text = response.content[0].text.strip()
            
            # Extract JSON from markdown code blocks if present
            if '```json' in result_text:
                result_text = result_text.split('```json')[1].split('```')[0].strip()
            elif '```' in result_text:
                result_text = result_text.split('```')[1].split('```')[0].strip()
            
            result = json.loads(result_text)
            
            self.logger.info(f"Extracted IOCs: {len(result.get('domains', []))} domains")
            return result
            
        except Exception as e:
            self.logger.error(f"Claude IOC extraction error: {e}")
            return {
                'domains': [],
                'urls': [],
                'ip_addresses': [],
                'email_addresses': [],
                'file_hashes': []
            }
    
    def _fallback_response(self, email_content: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback response if parsing fails"""
        return {
            'is_phishing': False,
            'confidence': 0.0,
            'risk_level': 'unknown',
            'indicators': ['Analysis failed - manual review required'],
            'explanation': 'Failed to parse AI response'
        }
