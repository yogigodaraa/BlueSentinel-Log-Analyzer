"""
Google Gemini AI Provider
"""

import json
from typing import Dict, Any
import google.generativeai as genai
from app.ai.base import BaseAIProvider


class GeminiProvider(BaseAIProvider):
    """Google Gemini AI provider for phishing detection"""
    
    def __init__(self, api_key: str):
        super().__init__(api_key)
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel('gemini-2.0-flash-exp')
        self.logger.info("Initialized Gemini provider")
    
    async def analyze_email(self, email_content: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze email using Gemini"""
        try:
            prompt = self._create_analysis_prompt(email_content)
            
            response = self.model.generate_content(
                prompt,
                generation_config={
                    'temperature': 0.1,
                    'top_p': 0.95,
                    'max_output_tokens': 1024,
                }
            )
            
            # Parse JSON response
            result_text = response.text.strip()
            
            # Extract JSON from markdown code blocks if present
            if '```json' in result_text:
                result_text = result_text.split('```json')[1].split('```')[0].strip()
            elif '```' in result_text:
                result_text = result_text.split('```')[1].split('```')[0].strip()
            
            result = json.loads(result_text)
            
            self.logger.info(f"Gemini analysis: {result.get('risk_level', 'unknown')} risk")
            return result
            
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse Gemini response: {e}")
            return self._fallback_response(email_content)
        except Exception as e:
            self.logger.error(f"Gemini analysis error: {e}")
            raise
    
    async def extract_iocs(self, email_content: Dict[str, Any]) -> Dict[str, Any]:
        """Extract IOCs using Gemini"""
        try:
            prompt = self._create_ioc_extraction_prompt(email_content)
            
            response = self.model.generate_content(
                prompt,
                generation_config={
                    'temperature': 0.1,
                    'max_output_tokens': 1024,
                }
            )
            
            result_text = response.text.strip()
            
            # Extract JSON from markdown code blocks if present
            if '```json' in result_text:
                result_text = result_text.split('```json')[1].split('```')[0].strip()
            elif '```' in result_text:
                result_text = result_text.split('```')[1].split('```')[0].strip()
            
            result = json.loads(result_text)
            
            self.logger.info(f"Extracted IOCs: {len(result.get('domains', []))} domains")
            return result
            
        except Exception as e:
            self.logger.error(f"Gemini IOC extraction error: {e}")
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
