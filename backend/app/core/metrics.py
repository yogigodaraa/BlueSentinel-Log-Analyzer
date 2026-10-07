"""
Metrics and Monitoring
Track application performance and security events
"""

import time
from typing import Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
import asyncio

from app.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class MetricPoint:
    """Individual metric data point"""
    timestamp: datetime
    value: float
    tags: Dict[str, str] = field(default_factory=dict)


class MetricsCollector:
    """Collect and aggregate application metrics"""
    
    def __init__(self):
        self.counters: Dict[str, int] = defaultdict(int)
        self.gauges: Dict[str, float] = {}
        self.histograms: Dict[str, list] = defaultdict(list)
        self.timers: Dict[str, list] = defaultdict(list)
        self._lock = asyncio.Lock()
    
    async def increment(self, metric: str, value: int = 1, tags: Optional[Dict[str, str]] = None):
        """Increment counter"""
        async with self._lock:
            key = self._build_key(metric, tags)
            self.counters[key] += value
    
    async def gauge(self, metric: str, value: float, tags: Optional[Dict[str, str]] = None):
        """Set gauge value"""
        async with self._lock:
            key = self._build_key(metric, tags)
            self.gauges[key] = value
    
    async def histogram(self, metric: str, value: float, tags: Optional[Dict[str, str]] = None):
        """Record histogram value"""
        async with self._lock:
            key = self._build_key(metric, tags)
            self.histograms[key].append(MetricPoint(
                timestamp=datetime.utcnow(),
                value=value,
                tags=tags or {}
            ))
            
            # Keep only last 1000 points
            if len(self.histograms[key]) > 1000:
                self.histograms[key] = self.histograms[key][-1000:]
    
    async def timing(self, metric: str, duration: float, tags: Optional[Dict[str, str]] = None):
        """Record timing (in seconds)"""
        await self.histogram(metric, duration, tags)
    
    def _build_key(self, metric: str, tags: Optional[Dict[str, str]]) -> str:
        """Build metric key with tags"""
        if not tags:
            return metric
        tag_str = ",".join(f"{k}={v}" for k, v in sorted(tags.items()))
        return f"{metric}[{tag_str}]"
    
    async def get_snapshot(self) -> Dict[str, Any]:
        """Get current metrics snapshot"""
        async with self._lock:
            return {
                'counters': dict(self.counters),
                'gauges': dict(self.gauges),
                'histograms': {
                    k: {
                        'count': len(v),
                        'avg': sum(p.value for p in v) / len(v) if v else 0,
                        'min': min(p.value for p in v) if v else 0,
                        'max': max(p.value for p in v) if v else 0,
                    }
                    for k, v in self.histograms.items()
                },
                'timestamp': datetime.utcnow().isoformat()
            }
    
    async def clear(self):
        """Clear all metrics"""
        async with self._lock:
            self.counters.clear()
            self.gauges.clear()
            self.histograms.clear()
            self.timers.clear()


# Global metrics collector
metrics = MetricsCollector()


class Timer:
    """Context manager for timing operations"""
    
    def __init__(self, metric: str, tags: Optional[Dict[str, str]] = None):
        self.metric = metric
        self.tags = tags
        self.start_time = None
    
    async def __aenter__(self):
        self.start_time = time.time()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        duration = time.time() - self.start_time
        await metrics.timing(self.metric, duration, self.tags)


class SecurityMetrics:
    """Track security-specific metrics"""
    
    @staticmethod
    async def record_phishing_detection(
        is_phishing: bool,
        confidence: float,
        risk_level: str
    ):
        """Record phishing detection event"""
        await metrics.increment('phishing.detections.total')
        
        if is_phishing:
            await metrics.increment('phishing.detections.positive')
            await metrics.increment(
                'phishing.detections.by_risk',
                tags={'risk_level': risk_level}
            )
        
        await metrics.histogram('phishing.confidence', confidence)
    
    @staticmethod
    async def record_ioc_extraction(ioc_type: str, count: int):
        """Record IOC extraction"""
        await metrics.increment(
            'ioc.extracted',
            value=count,
            tags={'type': ioc_type}
        )
    
    @staticmethod
    async def record_ai_request(provider: str, success: bool, duration: float):
        """Record AI provider request"""
        await metrics.increment(
            'ai.requests.total',
            tags={'provider': provider}
        )
        
        if success:
            await metrics.increment(
                'ai.requests.success',
                tags={'provider': provider}
            )
        else:
            await metrics.increment(
                'ai.requests.failure',
                tags={'provider': provider}
            )
        
        await metrics.timing(
            'ai.requests.duration',
            duration,
            tags={'provider': provider}
        )
    
    @staticmethod
    async def record_email_processed(success: bool):
        """Record email processing"""
        await metrics.increment('email.processed.total')
        
        if success:
            await metrics.increment('email.processed.success')
        else:
            await metrics.increment('email.processed.failure')
    
    @staticmethod
    async def record_threat_detected(threat_type: str, severity: str):
        """Record threat detection"""
        await metrics.increment('threat.detected.total')
        await metrics.increment(
            'threat.detected.by_type',
            tags={'type': threat_type, 'severity': severity}
        )
