"""
Anthropic Claude Provider
"""

import json
from typing import Any, Dict, Optional

from anthropic import AsyncAnthropic

from app.ai.base import BaseAIProvider
from app.core.config import settings

# Phishing analysis is security content, so a safety classifier can occasionally
# decline it. "default" server-side fallbacks re-run a declined request on a
# suitable model inside the same call instead of failing.
_FALLBACK_BETA = "server-side-fallback-2026-07-01"


class ClaudeRefusal(Exception):
    """Raised when Claude (and any fallback) declined the request."""


class ClaudeProvider(BaseAIProvider):
    """Anthropic Claude provider for phishing detection"""

    def __init__(self, api_key: str):
        super().__init__(api_key)
        self.client = AsyncAnthropic(api_key=api_key)
        self.model = settings.CLAUDE_MODEL
        self.logger.info(f"Initialized Claude provider ({self.model})")

    async def _complete(self, system: str, prompt: str) -> str:
        """One classification call; returns the text of the answer.

        Current Claude models think adaptively, so the response can start with a
        thinking block: read the first *text* block rather than content[0].
        Sampling parameters (temperature) are not accepted on these models.
        """
        response = await self.client.beta.messages.create(
            model=self.model,
            max_tokens=4096,  # leaves room for thinking before the short JSON answer
            betas=[_FALLBACK_BETA],
            fallbacks="default",
            output_config={"effort": "low"},  # classification: low effort is enough
            system=system,
            messages=[{"role": "user", "content": prompt}],
        )
        if response.stop_reason == "refusal":
            category: Optional[str] = getattr(response.stop_details, "category", None)
            raise ClaudeRefusal(f"request declined (category={category})")
        return next((b.text for b in response.content if b.type == "text"), "").strip()

    @staticmethod
    def _parse_json(result_text: str) -> Dict[str, Any]:
        # Extract JSON from markdown code blocks if present
        if '```json' in result_text:
            result_text = result_text.split('```json')[1].split('```')[0].strip()
        elif '```' in result_text:
            result_text = result_text.split('```')[1].split('```')[0].strip()
        return json.loads(result_text)

    async def analyze_email(self, email_content: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze email using Claude"""
        try:
            result_text = await self._complete(
                "You are a cybersecurity expert specializing in phishing detection. "
                "Analyze emails and respond only with valid JSON.",
                self._create_analysis_prompt(email_content),
            )
            result = self._parse_json(result_text)
            self.logger.info(f"Claude analysis: {result.get('risk_level', 'unknown')} risk")
            return result

        except (json.JSONDecodeError, ClaudeRefusal) as e:
            self.logger.error(f"Claude analysis unusable: {e}")
            return self._fallback_response(email_content)
        except Exception as e:
            self.logger.error(f"Claude analysis error: {e}")
            raise

    async def extract_iocs(self, email_content: Dict[str, Any]) -> Dict[str, Any]:
        """Extract IOCs using Claude"""
        try:
            result_text = await self._complete(
                "You are a cybersecurity analyst. Extract Indicators of Compromise "
                "from emails. Respond only with valid JSON.",
                self._create_ioc_extraction_prompt(email_content),
            )
            result = self._parse_json(result_text)
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
