"""
IOC (Indicator of Compromise) Extraction Service
Extracts domains, URLs, IPs, email addresses from email content
"""

import re
import ipaddress
from typing import List, Dict, Any
from urllib.parse import urlparse
import tldextract
import logging

logger = logging.getLogger(__name__)


class IOCExtractor:
    """Extract and validate IOCs from email content"""
    
    # Regex patterns
    EMAIL_PATTERN = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    URL_PATTERN = r'https?://[^\s<>"{}|\\^`\[\]]+'
    IP_PATTERN = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    DOMAIN_PATTERN = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]\b'
    
    def extract_all(self, email_content: Dict[str, Any]) -> Dict[str, List[str]]:
        """
        Extract all IOCs from email content
        
        Args:
            email_content: Dictionary containing email data
        
        Returns:
            Dictionary with categorized IOCs
        """
        text = self._combine_text(email_content)
        
        return {
            'email_addresses': self.extract_emails(text),
            'urls': self.extract_urls(email_content.get('links', []), text),
            'domains': self.extract_domains(email_content.get('links', []), text),
            'ip_addresses': self.extract_ips(text),
            'file_hashes': []  # Placeholder for hash extraction
        }
    
    def _combine_text(self, email_content: Dict[str, Any]) -> str:
        """Combine all text from email for analysis"""
        parts = [
            email_content.get('subject', ''),
            email_content.get('body', ''),
            email_content.get('body_text', ''),
            email_content.get('sender', '')
        ]
        return ' '.join(str(p) for p in parts if p)
    
    def extract_emails(self, text: str) -> List[str]:
        """Extract email addresses"""
        emails = set(re.findall(self.EMAIL_PATTERN, text, re.IGNORECASE))
        return self._filter_valid_emails(list(emails))
    
    def extract_urls(self, text_or_links, text: str = '') -> List[str]:
        """Extract URLs from text or list of links"""
        urls = set()
        
        # Handle both string and list inputs
        if isinstance(text_or_links, list):
            urls.update(text_or_links)
            # Also extract from text parameter if provided
            if text:
                found_urls = re.findall(self.URL_PATTERN, text)
                urls.update(found_urls)
        else:
            # text_or_links is a string
            found_urls = re.findall(self.URL_PATTERN, text_or_links)
            urls.update(found_urls)
        
        return self._filter_valid_urls(list(urls))
    
    def extract_domains(self, text_or_links, text: str = '') -> List[str]:
        """Extract domains from URLs and text"""
        domains = set()
        
        # Handle both string and list inputs
        if isinstance(text_or_links, list):
            # Extract from URLs in list
            for url in text_or_links:
                try:
                    parsed = urlparse(url)
                    if parsed.netloc:
                        domains.add(parsed.netloc.lower())
                except Exception:
                    pass
            # Also extract from text parameter if provided
            if text:
                found_domains = re.findall(self.DOMAIN_PATTERN, text, re.IGNORECASE)
                domains.update(d.lower() for d in found_domains)
        else:
            # text_or_links is a string
            found_domains = re.findall(self.DOMAIN_PATTERN, text_or_links, re.IGNORECASE)
            domains.update(d.lower() for d in found_domains)
        
        return self._filter_valid_domains(list(domains))
    
    def extract_ips(self, text: str) -> List[str]:
        """Extract IP addresses"""
        ips = set(re.findall(self.IP_PATTERN, text))
        return self._filter_valid_ips(list(ips))
    
    # Alias methods for test compatibility
    def extract_ip_addresses(self, text: str) -> List[str]:
        """Alias for extract_ips"""
        return self.extract_ips(text)
    
    def extract_email_addresses(self, text: str) -> List[str]:
        """Alias for extract_emails"""
        return self.extract_emails(text)
    
    def extract_file_hashes(self, text: str) -> List[str]:
        """Extract file hashes (MD5, SHA1, SHA256)"""
        hashes = []
        # MD5: 32 hex chars
        md5_pattern = r'\b[a-fA-F0-9]{32}\b'
        # SHA1: 40 hex chars
        sha1_pattern = r'\b[a-fA-F0-9]{40}\b'
        # SHA256: 64 hex chars
        sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
        
        hashes.extend(re.findall(md5_pattern, text))
        hashes.extend(re.findall(sha1_pattern, text))
        hashes.extend(re.findall(sha256_pattern, text))
        
        return list(set(hashes))
    
    def _filter_valid_emails(self, emails: List[str]) -> List[str]:
        """Filter out invalid/common email addresses"""
        valid = []
        
        for email in emails:
            domain = email.split('@')[-1].lower()
            
            # Basic validation
            if '@' in email and '.' in domain:
                valid.append(email.lower())
        
        return list(set(valid))
    
    def _filter_valid_urls(self, urls: List[str]) -> List[str]:
        """Filter out invalid URLs"""
        valid = []
        
        for url in urls:
            try:
                parsed = urlparse(url)
                if parsed.scheme in ('http', 'https') and parsed.netloc:
                    valid.append(url)
            except Exception:
                continue
        
        return list(set(valid))
    
    def _filter_valid_domains(self, domains: List[str]) -> List[str]:
        """Filter out invalid/common domains"""
        valid = []
        
        # Very common legitimate domains to exclude
        common_tlds = {'localhost', 'example.com', 'test.com'}
        
        for domain in domains:
            try:
                # Use tldextract for better validation
                ext = tldextract.extract(domain)
                
                # Must have domain and suffix
                if ext.domain and ext.suffix:
                    full_domain = f"{ext.domain}.{ext.suffix}"
                    
                    if full_domain not in common_tlds:
                        # Include subdomain if present
                        if ext.subdomain:
                            full_domain = f"{ext.subdomain}.{full_domain}"
                        
                        valid.append(full_domain.lower())
            except Exception:
                continue
        
        return list(set(valid))
    
    def _filter_valid_ips(self, ips: List[str]) -> List[str]:
        """Filter out invalid/private IP addresses"""
        valid = []
        
        for ip in ips:
            try:
                ip_obj = ipaddress.ip_address(ip)
                
                # Exclude private/loopback IPs for suspicious IOCs
                # (but keep them if analyzing internal threats)
                if not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved):
                    valid.append(ip)
            except ValueError:
                continue
        
        return list(set(valid))
    
    def analyze_url_suspiciousness(self, url: str) -> Dict[str, Any]:
        """Analyze URL for suspicious characteristics"""
        suspicious_indicators = []
        score = 0
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            
            # Check for IP address in URL
            try:
                ipaddress.ip_address(domain)
                suspicious_indicators.append("URL uses IP address instead of domain")
                score += 30
            except ValueError:
                pass
            
            # Check for suspicious TLDs
            suspicious_tlds = {'.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top'}
            ext = tldextract.extract(url)
            if f".{ext.suffix}" in suspicious_tlds:
                suspicious_indicators.append(f"Suspicious TLD: .{ext.suffix}")
                score += 20
            
            # Check for URL shorteners
            shorteners = {'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly'}
            if any(short in domain for short in shorteners):
                suspicious_indicators.append("URL shortener detected")
                score += 15
            
            # Check for excessive subdomains
            if domain.count('.') > 3:
                suspicious_indicators.append("Excessive subdomains")
                score += 10
            
            # Check for suspicious keywords in path
            suspicious_keywords = [
                'login', 'signin', 'account', 'verify', 'secure', 'update',
                'confirm', 'banking', 'paypal', 'apple', 'microsoft'
            ]
            if any(keyword in path for keyword in suspicious_keywords):
                suspicious_indicators.append("Suspicious keywords in path")
                score += 15
            
            # Check for long URLs (common in phishing)
            if len(url) > 100:
                suspicious_indicators.append("Unusually long URL")
                score += 10
            
            return {
                'url': url,
                'domain': domain,
                'suspiciousness_score': min(score, 100),
                'indicators': suspicious_indicators,
                'is_suspicious': score > 30
            }
            
        except Exception as e:
            logger.error(f"Error analyzing URL {url}: {e}")
            return {
                'url': url,
                'suspiciousness_score': 0,
                'indicators': [],
                'is_suspicious': False
            }


# Convenience function
def extract_iocs(email_content: Dict[str, Any]) -> Dict[str, List[str]]:
    """Extract IOCs from email content"""
    extractor = IOCExtractor()
    return extractor.extract_all(email_content)
