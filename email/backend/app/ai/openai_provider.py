"""
OpenAI GPT Provider
"""

import json
from typing import Dict, Any
from openai import AsyncOpenAI
from app.ai.base import BaseAIProvider


class OpenAIProvider(BaseAIProvider):
    """OpenAI GPT provider for phishing detection"""
    
    def __init__(self, api_key: str):
        super().__init__(api_key)
        self.client = AsyncOpenAI(api_key=api_key)
        self.model = "gpt-4-turbo-preview"
        self.logger.info("Initialized OpenAI provider")
    
    async def analyze_email(self, email_content: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze email using OpenAI GPT"""
        try:
            prompt = self._create_analysis_prompt(email_content)
            
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a cybersecurity expert specializing in phishing detection. Analyze emails and respond only with valid JSON."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.1,
                max_tokens=1024,
                response_format={"type": "json_object"}
            )
            
            result_text = response.choices[0].message.content.strip()
            result = json.loads(result_text)
            
            self.logger.info(f"OpenAI analysis: {result.get('risk_level', 'unknown')} risk")
            return result
            
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse OpenAI response: {e}")
            return self._fallback_response(email_content)
        except Exception as e:
            self.logger.error(f"OpenAI analysis error: {e}")
            raise
    
    async def extract_iocs(self, email_content: Dict[str, Any]) -> Dict[str, Any]:
        """Extract IOCs using OpenAI GPT"""
        try:
            prompt = self._create_ioc_extraction_prompt(email_content)
            
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a cybersecurity analyst. Extract Indicators of Compromise from emails. Respond only with valid JSON."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.1,
                max_tokens=1024,
                response_format={"type": "json_object"}
            )
            
            result_text = response.choices[0].message.content.strip()
            result = json.loads(result_text)
            
            self.logger.info(f"Extracted IOCs: {len(result.get('domains', []))} domains")
            return result
            
        except Exception as e:
            self.logger.error(f"OpenAI IOC extraction error: {e}")
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
