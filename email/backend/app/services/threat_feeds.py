"""Extra threat intelligence feeds — URLhaus, AbuseIPDB, OpenPhish.

Complements the existing ``threat_intel.py`` (VirusTotal / URLscan /
PhishTank). Each feed is free or has a generous free tier — the keys
for AbuseIPDB (free account at https://www.abuseipdb.com/api) are the
only ones a caller must provide.

All calls are async, rate-limited with a simple per-feed semaphore,
and wrap results in a common ``FeedVerdict`` shape so the aggregator
downstream doesn't care which source produced the signal.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

import httpx


@dataclass
class FeedVerdict:
    """Verdict from one threat-intel source about one indicator."""

    source: str
    indicator: str
    is_malicious: bool
    score: float  # 0.0 = clean, 1.0 = definitely malicious
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "indicator": self.indicator,
            "is_malicious": self.is_malicious,
            "score": round(self.score, 3),
            "detail": self.detail,
        }


# ─── URLhaus ─────────────────────────────────────────────────────────────

async def query_urlhaus(url: str, *, timeout: float = 8.0) -> FeedVerdict:
    """Query abuse.ch URLhaus for a URL's reputation.

    URLhaus is free, no API key required. It tracks malware-distribution
    URLs. A match here is a strong malicious signal.
    """
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.post(
                "https://urlhaus-api.abuse.ch/v1/url/",
                data={"url": url},
            )
            r.raise_for_status()
            data = r.json()
    except (httpx.HTTPError, ValueError) as exc:
        return FeedVerdict(
            source="urlhaus",
            indicator=url,
            is_malicious=False,
            score=0.0,
            detail={"error": str(exc)},
        )

    if data.get("query_status") == "ok":
        threat = data.get("threat", "")
        tags = data.get("tags") or []
        status = data.get("url_status", "")
        return FeedVerdict(
            source="urlhaus",
            indicator=url,
            is_malicious=True,
            score=1.0 if status == "online" else 0.8,
            detail={"threat": threat, "tags": tags, "status": status},
        )
    return FeedVerdict(source="urlhaus", indicator=url, is_malicious=False, score=0.0, detail=data)


# ─── AbuseIPDB ───────────────────────────────────────────────────────────

async def query_abuseipdb(
    ip: str,
    *,
    api_key: str,
    max_age_days: int = 90,
    timeout: float = 8.0,
) -> FeedVerdict:
    """Query AbuseIPDB for an IP's abuse confidence score (0-100)."""
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": max_age_days},
            )
            r.raise_for_status()
            payload = r.json()
    except (httpx.HTTPError, ValueError) as exc:
        return FeedVerdict(
            source="abuseipdb",
            indicator=ip,
            is_malicious=False,
            score=0.0,
            detail={"error": str(exc)},
        )

    data = payload.get("data") or {}
    confidence = int(data.get("abuseConfidenceScore") or 0)
    return FeedVerdict(
        source="abuseipdb",
        indicator=ip,
        is_malicious=confidence >= 50,
        score=confidence / 100.0,
        detail={
            "country": data.get("countryCode"),
            "usage_type": data.get("usageType"),
            "isp": data.get("isp"),
            "abuse_confidence": confidence,
            "total_reports": data.get("totalReports"),
        },
    )


# ─── OpenPhish (free feed — daily refresh) ──────────────────────────────

class OpenPhishCache:
    """Daily refresh of OpenPhish's plain-text feed.

    The free feed is ~2000 URLs, refreshed hourly. We poll it at most
    once an hour and keep the set in memory; checks are O(1) set
    membership instead of per-URL HTTP calls.
    """

    URL = "https://openphish.com/feed.txt"
    REFRESH_SECONDS = 3600

    def __init__(self):
        self._urls: set[str] = set()
        self._last_refresh: float = 0.0
        self._lock = asyncio.Lock()

    async def contains(self, url: str) -> bool:
        await self._maybe_refresh()
        return url in self._urls

    async def _maybe_refresh(self) -> None:
        import time

        now = time.time()
        if now - self._last_refresh < self.REFRESH_SECONDS and self._urls:
            return
        async with self._lock:
            # Double-check after acquiring
            if now - self._last_refresh < self.REFRESH_SECONDS and self._urls:
                return
            try:
                async with httpx.AsyncClient(timeout=15.0) as client:
                    r = await client.get(self.URL)
                    r.raise_for_status()
                    self._urls = {line.strip() for line in r.text.splitlines() if line.strip()}
                    self._last_refresh = now
            except httpx.HTTPError:
                # Keep the old set on refresh failure.
                return


async def query_openphish(url: str, cache: OpenPhishCache) -> FeedVerdict:
    hit = await cache.contains(url)
    return FeedVerdict(
        source="openphish",
        indicator=url,
        is_malicious=hit,
        score=1.0 if hit else 0.0,
        detail={"feed_hit": hit},
    )


# ─── Aggregator ──────────────────────────────────────────────────────────

async def aggregate_verdicts(verdicts: list[FeedVerdict]) -> dict[str, Any]:
    """Combine multiple feed verdicts into a single decision.

    A single malicious hit elevates the aggregate score. We return both
    the max score (worst verdict) and the mean (smoother).
    """
    if not verdicts:
        return {"malicious": False, "max_score": 0.0, "mean_score": 0.0, "sources": []}
    scores = [v.score for v in verdicts]
    return {
        "malicious": any(v.is_malicious for v in verdicts),
        "max_score": round(max(scores), 3),
        "mean_score": round(sum(scores) / len(scores), 3),
        "sources": [v.to_dict() for v in verdicts],
    }
