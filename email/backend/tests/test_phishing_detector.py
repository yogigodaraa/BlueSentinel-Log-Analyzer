"""
Tests for the phishing detection pipeline (PhishingDetector.analyze_email).

The AI provider and threat-intel lookups are mocked, so these run offline and
exercise the real orchestration: IOC extraction, merging, and risk scoring.
"""
from unittest.mock import AsyncMock, patch

import pytest

from app.services.phishing_detector import PhishingDetector

CLEAN = {"reputation": "clean", "threat_score": 0}
MALICIOUS = {"reputation": "malicious", "threat_score": 0.95}
NO_AI_IOCS = {"domains": [], "urls": [], "ip_addresses": [], "email_addresses": [], "file_hashes": []}


def make_detector(ai_verdict: dict, url_rep: dict = CLEAN, domain_rep: dict = CLEAN) -> PhishingDetector:
    ai = AsyncMock()
    ai.analyze_email.return_value = ai_verdict
    ai.extract_iocs.return_value = NO_AI_IOCS
    with patch("app.services.phishing_detector.get_ai_provider", return_value=ai):
        detector = PhishingDetector()
    detector.threat_intel = AsyncMock()
    detector.threat_intel.check_url_reputation.return_value = url_rep
    detector.threat_intel.check_domain_reputation.return_value = domain_rep
    return detector


class TestPhishingDetector:
    @pytest.mark.asyncio
    async def test_confident_phishing_verdict_is_critical(self, sample_phishing_email):
        detector = make_detector(
            {"is_phishing": True, "confidence": 0.95, "risk_level": "high",
             "indicators": ["Spoofed domain"], "explanation": "Lookalike PayPal domain"}
        )

        result = await detector.analyze_email(sample_phishing_email)

        assert result["is_phishing"] is True
        assert result["risk_level"] == "critical"  # confidence >= HIGH_RISK_THRESHOLD (0.9)
        assert "secure-paypal-verify.tk" in " ".join(result["iocs"]["domains"])

    @pytest.mark.asyncio
    async def test_low_confidence_legitimate_email_is_low_risk(self, sample_legitimate_email):
        detector = make_detector(
            {"is_phishing": False, "confidence": 0.1, "risk_level": "low",
             "indicators": [], "explanation": "Internal meeting invite"}
        )

        result = await detector.analyze_email(sample_legitimate_email)

        assert result["is_phishing"] is False
        assert result["risk_level"] == "low"

    @pytest.mark.asyncio
    async def test_malicious_threat_intel_is_reported(self, sample_phishing_email):
        detector = make_detector(
            {"is_phishing": True, "confidence": 0.8, "risk_level": "high",
             "indicators": [], "explanation": ""},
            url_rep=MALICIOUS,
        )

        result = await detector.analyze_email(sample_phishing_email)

        assert result["suspicious_url_count"] >= 1
        assert result["malicious_indicators_count"] >= 1
        assert any("Malicious URLs" in factor for factor in result["risk_factors"])
