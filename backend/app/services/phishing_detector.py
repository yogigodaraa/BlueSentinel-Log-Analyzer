"""
Phishing Detection Service
Orchestrates email analysis, IOC extraction, and threat intelligence
"""

import time
from typing import Dict, Any
from datetime import datetime

from app.ai.factory import get_ai_provider
from app.services.ioc_extractor import IOCExtractor
from app.services.threat_intel import threat_intel
from app.core.config import settings
from app.core.logging import get_logger
from app.core.metrics import SecurityMetrics, Timer
from app.core.exceptions import EmailProcessingException

logger = get_logger(__name__)


class PhishingDetector:
    """Main phishing detection orchestrator"""
    
    def __init__(self):
        self.ai_provider = get_ai_provider()
        self.ioc_extractor = IOCExtractor()
        self.threat_intel = threat_intel
        self.logger = get_logger(__name__)
    
    async def analyze_email(self, email_content: Dict[str, Any]) -> Dict[str, Any]:
        """
        Comprehensive email analysis
        
        Args:
            email_content: Parsed email data
        
        Returns:
            Complete analysis results including AI analysis and IOCs
        """
        start_time = time.time()
        email_subject = email_content.get('subject', 'No Subject')
        
        try:
            # Use context logger
            log = self.logger.with_context(
                email_subject=email_subject,
                sender=email_content.get('sender', 'unknown')
            )
            
            async with Timer('phishing.analysis.duration'):
                # Step 1: Extract IOCs
                log.info("Starting phishing analysis")
                iocs = self.ioc_extractor.extract_all(email_content)
                
                # Record IOC metrics
                for ioc_type, items in iocs.items():
                    await SecurityMetrics.record_ioc_extraction(ioc_type, len(items))
            
                # Step 2: AI Analysis
                log.info("Performing AI analysis")
                ai_analysis = await self.ai_provider.analyze_email(email_content)
                
                # Step 3: AI IOC Extraction (to supplement regex extraction)
                log.info("Extracting IOCs with AI")
                ai_iocs = await self.ai_provider.extract_iocs(email_content)
                
                # Merge IOCs
                merged_iocs = self._merge_iocs(iocs, ai_iocs)
                
                # Step 4: URL and Threat Intel Analysis
                log.info(f"Analyzing {len(merged_iocs.get('urls', []))} URLs")
                url_analysis = await self._analyze_urls_with_threat_intel(
                    merged_iocs.get('urls', [])
                )
                
                # Step 5: Domain reputation check
                log.info(f"Checking {len(merged_iocs.get('domains', []))} domains")
                domain_reputation = await self._check_domain_reputation(
                    merged_iocs.get('domains', [])
                )
                
                # Step 6: Calculate final risk score
                final_analysis = self._calculate_final_risk(
                    ai_analysis,
                    merged_iocs,
                    url_analysis,
                    domain_reputation
                )
            
                # Add metadata
                duration = time.time() - start_time
                final_analysis.update({
                    'iocs': merged_iocs,
                    'url_analysis': url_analysis,
                    'domain_reputation': domain_reputation,
                    'analysis_duration': duration,
                    'analyzed_at': datetime.utcnow().isoformat(),
                    'ai_provider': settings.AI_PROVIDER
                })
                
                # Record metrics
                await SecurityMetrics.record_phishing_detection(
                    is_phishing=final_analysis['is_phishing'],
                    confidence=final_analysis['confidence'],
                    risk_level=final_analysis['risk_level']
                )
                await SecurityMetrics.record_email_processed(success=True)
                
                log.info(
                    f"✅ Analysis complete: {final_analysis['risk_level']} "
                    f"(confidence: {final_analysis['confidence']:.2f}) "
                    f"in {duration:.2f}s"
                )
                
                return final_analysis
            
        except Exception as e:
            await SecurityMetrics.record_email_processed(success=False)
            self.logger.exception(f"❌ Analysis failed: {e}")
            raise EmailProcessingException(
                message=f"Failed to analyze email: {str(e)}",
                email_id=email_content.get('id')
            )
    
    def _merge_iocs(
        self,
        regex_iocs: Dict[str, list],
        ai_iocs: Dict[str, list]
    ) -> Dict[str, list]:
        """Merge IOCs from regex and AI extraction"""
        merged = {}
        
        for key in ['domains', 'urls', 'ip_addresses', 'email_addresses', 'file_hashes']:
            regex_items = set(regex_iocs.get(key, []))
            ai_items = set(ai_iocs.get(key, []))
            merged[key] = list(regex_items.union(ai_items))
        
        return merged
    
    async def _analyze_urls_with_threat_intel(self, urls: list) -> list:
        """Analyze URLs with suspiciousness checks and threat intel"""
        analyses = []
        
        for url in urls[:20]:  # Limit to first 20 URLs
            # Basic suspiciousness analysis
            analysis = self.ioc_extractor.analyze_url_suspiciousness(url)
            
            # Add threat intelligence if available
            if settings.ENABLE_THREAT_INTEL:
                reputation = await self.threat_intel.check_url_reputation(url)
                analysis['threat_intel'] = reputation
                
                # Adjust suspiciousness based on threat intel
                if reputation.get('reputation') == 'malicious':
                    analysis['is_suspicious'] = True
                    analysis['suspiciousness_score'] = max(
                        analysis['suspiciousness_score'],
                        reputation.get('threat_score', 0)
                    )
            
            analyses.append(analysis)
        
        return analyses
    
    async def _check_domain_reputation(self, domains: list) -> list:
        """Check domain reputation via threat intelligence"""
        reputations = []
        
        if not settings.ENABLE_THREAT_INTEL:
            return reputations
        
        for domain in domains[:10]:  # Limit to first 10 domains
            reputation = await self.threat_intel.check_domain_reputation(domain)
            reputations.append(reputation)
        
        return reputations
    
    def _calculate_final_risk(
        self,
        ai_analysis: Dict[str, Any],
        iocs: Dict[str, list],
        url_analysis: list,
        domain_reputation: list = None
    ) -> Dict[str, Any]:
        """Calculate final risk assessment with threat intelligence"""
        
        # Start with AI confidence
        base_confidence = ai_analysis.get('confidence', 0.0)
        risk_factors = []
        
        # Adjust based on IOC count
        ioc_count = sum(len(v) for v in iocs.values())
        if ioc_count > 10:
            base_confidence = min(base_confidence + 0.1, 1.0)
            risk_factors.append(f"High IOC count: {ioc_count}")
        
        # Adjust based on suspicious URLs
        suspicious_url_count = sum(
            1 for ua in url_analysis if ua.get('is_suspicious', False)
        )
        if suspicious_url_count > 0:
            base_confidence = min(base_confidence + (suspicious_url_count * 0.05), 1.0)
            risk_factors.append(f"Suspicious URLs: {suspicious_url_count}")
        
        # Adjust based on threat intelligence
        malicious_urls = sum(
            1 for ua in url_analysis 
            if ua.get('threat_intel', {}).get('reputation') == 'malicious'
        )
        if malicious_urls > 0:
            base_confidence = min(base_confidence + 0.2, 1.0)
            risk_factors.append(f"Malicious URLs detected: {malicious_urls}")
        
        # Check domain reputation
        if domain_reputation:
            malicious_domains = sum(
                1 for dr in domain_reputation
                if dr.get('reputation') == 'malicious'
            )
            if malicious_domains > 0:
                base_confidence = min(base_confidence + 0.15, 1.0)
                risk_factors.append(f"Malicious domains: {malicious_domains}")
        
        # Determine final risk level
        if base_confidence >= settings.HIGH_RISK_THRESHOLD:
            risk_level = "critical"
        elif base_confidence >= settings.PHISHING_CONFIDENCE_THRESHOLD:
            risk_level = "high"
        elif base_confidence >= 0.5:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        # Override AI decision if confidence is high enough
        is_phishing = (
            ai_analysis.get('is_phishing', False) or
            base_confidence >= settings.PHISHING_CONFIDENCE_THRESHOLD
        )
        
        return {
            'is_phishing': is_phishing,
            'confidence': base_confidence,
            'risk_level': risk_level,
            'indicators': ai_analysis.get('indicators', []),
            'explanation': ai_analysis.get('explanation', ''),
            'risk_factors': risk_factors,
            'ioc_count': ioc_count,
            'suspicious_url_count': suspicious_url_count,
            'malicious_indicators_count': malicious_urls + (
                malicious_domains if domain_reputation else 0
            )
        }


# Convenience function
async def analyze_email_for_phishing(email_content: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze email for phishing"""
    detector = PhishingDetector()
    return await detector.analyze_email(email_content)
