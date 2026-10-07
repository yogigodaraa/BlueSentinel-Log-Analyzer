"""
Threat Intelligence Integration Service
Query external threat intelligence sources for IOC reputation
"""

import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime

from app.core.config import settings
from app.core.logging import get_logger
from app.core.cache import cache_manager

logger = get_logger(__name__)


class ThreatIntelService:
    """Aggregate threat intelligence from multiple sources"""
    
    def __init__(self):
        self.timeout = 10.0
        self.enabled = settings.ENABLE_THREAT_INTEL
    
    async def check_url_reputation(self, url: str) -> Dict[str, Any]:
        """
        Check URL reputation across multiple sources
        
        Returns:
            Dict with reputation data and threat score
        """
        if not self.enabled:
            return self._default_reputation()
        
        try:
            # Check cache first
            cache_key = f"url_reputation:{url}"
            cached_result = await cache_manager.get(cache_key)
            if cached_result:
                return cached_result
            
            # Query multiple sources in parallel
            results = await asyncio.gather(
                self._check_virustotal_url(url),
                self._check_urlscan(url),
                self._check_phishtank(url),
                return_exceptions=True
            )
            
            # Aggregate results
            reputation = self._aggregate_reputation(results, url)
            
            # Cache for 1 hour
            await cache_manager.set(cache_key, reputation, expiry=3600)
            
            return reputation
            
        except Exception as e:
            logger.error(f"Error checking URL reputation: {e}")
            return self._default_reputation(error=str(e))
    
    async def check_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """Check domain reputation"""
        if not self.enabled:
            return self._default_reputation()
        
        try:
            cache_key = f"domain_reputation:{domain}"
            cached_result = await cache_manager.get(cache_key)
            if cached_result:
                return cached_result
            
            results = await asyncio.gather(
                self._check_virustotal_domain(domain),
                self._check_opendns(domain),
                return_exceptions=True
            )
            
            reputation = self._aggregate_reputation(results, domain)
            await cache_manager.set(cache_key, reputation, expiry=3600)
            
            return reputation
            
        except Exception as e:
            logger.error(f"Error checking domain reputation: {e}")
            return self._default_reputation(error=str(e))
    
    async def check_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """Check IP address reputation"""
        if not self.enabled:
            return self._default_reputation()
        
        try:
            cache_key = f"ip_reputation:{ip}"
            cached_result = await cache_manager.get(cache_key)
            if cached_result:
                return cached_result
            
            results = await asyncio.gather(
                self._check_abuseipdb(ip),
                self._check_virustotal_ip(ip),
                return_exceptions=True
            )
            
            reputation = self._aggregate_reputation(results, ip)
            await cache_manager.set(cache_key, reputation, expiry=3600)
            
            return reputation
            
        except Exception as e:
            logger.error(f"Error checking IP reputation: {e}")
            return self._default_reputation(error=str(e))
    
    async def _check_virustotal_url(self, url: str) -> Dict[str, Any]:
        """Check URL on VirusTotal (requires API key)"""
        # Placeholder - implement with actual VT API
        return {
            'source': 'virustotal',
            'malicious': 0,
            'suspicious': 0,
            'clean': 0,
            'available': False
        }
    
    async def _check_virustotal_domain(self, domain: str) -> Dict[str, Any]:
        """Check domain on VirusTotal"""
        return {
            'source': 'virustotal',
            'malicious': 0,
            'suspicious': 0,
            'available': False
        }
    
    async def _check_virustotal_ip(self, ip: str) -> Dict[str, Any]:
        """Check IP on VirusTotal"""
        return {
            'source': 'virustotal',
            'malicious': 0,
            'suspicious': 0,
            'available': False
        }
    
    async def _check_urlscan(self, url: str) -> Dict[str, Any]:
        """Check URL on URLScan.io"""
        return {
            'source': 'urlscan',
            'malicious': False,
            'available': False
        }
    
    async def _check_phishtank(self, url: str) -> Dict[str, Any]:
        """Check URL on PhishTank"""
        return {
            'source': 'phishtank',
            'is_phishing': False,
            'available': False
        }
    
    async def _check_abuseipdb(self, ip: str) -> Dict[str, Any]:
        """Check IP on AbuseIPDB"""
        return {
            'source': 'abuseipdb',
            'abuse_confidence': 0,
            'available': False
        }
    
    async def _check_opendns(self, domain: str) -> Dict[str, Any]:
        """Check domain via OpenDNS"""
        return {
            'source': 'opendns',
            'category': 'unknown',
            'available': False
        }
    
    def _aggregate_reputation(
        self,
        results: List[Any],
        indicator: str
    ) -> Dict[str, Any]:
        """Aggregate reputation results from multiple sources"""
        malicious_count = 0
        suspicious_count = 0
        clean_count = 0
        sources_checked = 0
        
        detailed_results = []
        
        for result in results:
            if isinstance(result, Exception):
                logger.warning(f"Threat intel check failed: {result}")
                continue
            
            if not result.get('available'):
                continue
            
            sources_checked += 1
            detailed_results.append(result)
            
            # Count based on source type
            if 'malicious' in result:
                malicious_count += result['malicious']
                suspicious_count += result.get('suspicious', 0)
                clean_count += result.get('clean', 0)
            elif result.get('is_phishing'):
                malicious_count += 1
            elif result.get('abuse_confidence', 0) > 50:
                malicious_count += 1
        
        # Calculate threat score (0-100)
        if sources_checked == 0:
            threat_score = 0
            reputation = 'unknown'
        else:
            total_checks = malicious_count + suspicious_count + clean_count
            if total_checks > 0:
                threat_score = int(
                    ((malicious_count * 100) + (suspicious_count * 50)) / 
                    (total_checks * 100) * 100
                )
            else:
                threat_score = 0
            
            # Determine reputation
            if malicious_count > 0 or threat_score >= 70:
                reputation = 'malicious'
            elif suspicious_count > 0 or threat_score >= 40:
                reputation = 'suspicious'
            elif clean_count > 0:
                reputation = 'clean'
            else:
                reputation = 'unknown'
        
        return {
            'indicator': indicator,
            'reputation': reputation,
            'threat_score': threat_score,
            'sources_checked': sources_checked,
            'malicious_sources': malicious_count,
            'suspicious_sources': suspicious_count,
            'clean_sources': clean_count,
            'details': detailed_results,
            'checked_at': datetime.utcnow().isoformat()
        }
    
    def _default_reputation(self, error: Optional[str] = None) -> Dict[str, Any]:
        """Return default reputation when service unavailable"""
        return {
            'reputation': 'unknown',
            'threat_score': 0,
            'sources_checked': 0,
            'available': False,
            'error': error
        }


# Global instance
threat_intel = ThreatIntelService()
