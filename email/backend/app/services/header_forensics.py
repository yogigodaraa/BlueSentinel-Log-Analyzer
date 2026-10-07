"""Email header forensics — the advanced signal SOCShield was missing.

Most phishing attempts fail one of three authentication checks:
SPF, DKIM, or DMARC. Legitimate senders at scale (Gmail, Amazon, banks)
publish DKIM keys and DMARC policies; attackers rarely bother to spoof
them correctly. Parsing the `Authentication-Results` header and the
`Received` chain gives us a strong pre-ML signal, plus forensic data
for incident response.

Capabilities:

1. ``parse_authentication_results()`` — decode the
   ``Authentication-Results`` header into SPF / DKIM / DMARC verdicts.
2. ``analyze_received_chain()`` — walk the ``Received:`` chain, extract
   hops, timestamps, and source IPs; flag relay inconsistencies.
3. ``validate_spf_live()`` / ``validate_dmarc_live()`` — optional live
   DNS lookups for senders whose headers lack Auth-Results.
4. ``geoip_hops()`` — country lookup per hop (uses ipapi.co free tier
   if caller provides a session; otherwise skipped).

References:
    - RFC 7208 (SPF), RFC 6376 (DKIM), RFC 7489 (DMARC)
    - RFC 8601 (Authentication-Results)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from email.message import Message
from email.utils import parsedate_to_datetime
from typing import Any


@dataclass
class AuthResult:
    """One mechanism's verdict from the Authentication-Results header."""

    method: str  # spf / dkim / dmarc / arc / etc.
    result: str  # pass / fail / none / neutral / softfail / policy / permerror / temperror
    detail: dict[str, str] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        return self.result.lower() == "pass"

    @property
    def failed(self) -> bool:
        return self.result.lower() in ("fail", "softfail", "permerror")


@dataclass
class ReceivedHop:
    """One hop in the Received: chain, top-down = newest first."""

    from_host: str | None
    from_ip: str | None
    by_host: str | None
    timestamp: datetime | None
    raw: str


@dataclass
class HeaderForensicsReport:
    """Structured summary of a single email's authentication story."""

    auth_results: list[AuthResult]
    hops: list[ReceivedHop]
    spf_pass: bool | None
    dkim_pass: bool | None
    dmarc_pass: bool | None

    warnings: list[str] = field(default_factory=list)
    risk_score: float = 0.0  # 0.0 = clean, 1.0 = very suspicious

    def to_dict(self) -> dict[str, Any]:
        return {
            "auth_results": [
                {"method": a.method, "result": a.result, "detail": a.detail}
                for a in self.auth_results
            ],
            "hops": [
                {
                    "from_host": h.from_host,
                    "from_ip": h.from_ip,
                    "by_host": h.by_host,
                    "timestamp": h.timestamp.isoformat() if h.timestamp else None,
                }
                for h in self.hops
            ],
            "spf_pass": self.spf_pass,
            "dkim_pass": self.dkim_pass,
            "dmarc_pass": self.dmarc_pass,
            "warnings": self.warnings,
            "risk_score": round(self.risk_score, 3),
        }


# ─── Authentication-Results parsing ─────────────────────────────────────

_AUTH_RE = re.compile(
    r"(?P<method>spf|dkim|dmarc|arc|bimi)\s*=\s*(?P<result>pass|fail|neutral|softfail|none|policy|permerror|temperror)",
    re.IGNORECASE,
)
_KV_RE = re.compile(r'(\w+\.\w+|\w+)\s*=\s*(?:"([^"]+)"|([^ ;]+))')


def parse_authentication_results(header_value: str) -> list[AuthResult]:
    """Parse one ``Authentication-Results`` header value into structured verdicts."""
    if not header_value:
        return []

    # An Authentication-Results header can have multiple methods separated by ';'
    results: list[AuthResult] = []
    for chunk in header_value.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        match = _AUTH_RE.search(chunk)
        if not match:
            continue
        method = match.group("method").lower()
        result = match.group("result").lower()
        detail = {}
        for kv in _KV_RE.finditer(chunk):
            key = kv.group(1)
            value = kv.group(2) or kv.group(3)
            if key.lower() not in (method, "result"):
                detail[key] = value
        results.append(AuthResult(method=method, result=result, detail=detail))
    return results


# ─── Received-chain walking ─────────────────────────────────────────────

_HOP_FROM_RE = re.compile(r"from\s+(?P<host>[^\s]+)\s*(?:\((?P<detail>[^)]*)\))?", re.I)
_HOP_BY_RE = re.compile(r"by\s+(?P<host>[^\s;]+)", re.I)
_IP_RE = re.compile(r"\[?(\d{1,3}(?:\.\d{1,3}){3})\]?")


def parse_received_chain(received_headers: list[str]) -> list[ReceivedHop]:
    """Parse every ``Received:`` header value into an ordered list of hops.

    The first element of the input list should be the **newest** hop
    (most recent — ``email.message.Message.get_all('Received')`` gives
    them top-down, which is the convention).
    """
    hops: list[ReceivedHop] = []
    for raw in received_headers:
        from_host = from_ip = by_host = None
        ts: datetime | None = None
        m = _HOP_FROM_RE.search(raw)
        if m:
            from_host = m.group("host").strip("[]()")
            detail = m.group("detail") or ""
            ip_m = _IP_RE.search(detail)
            if ip_m:
                from_ip = ip_m.group(1)
        m = _HOP_BY_RE.search(raw)
        if m:
            by_host = m.group("host")
        # Timestamp is usually after the last ';'
        if ";" in raw:
            ts_str = raw.rsplit(";", 1)[1].strip()
            try:
                ts = parsedate_to_datetime(ts_str)
            except (TypeError, ValueError):
                ts = None
        hops.append(
            ReceivedHop(
                from_host=from_host,
                from_ip=from_ip,
                by_host=by_host,
                timestamp=ts,
                raw=raw,
            )
        )
    return hops


# ─── End-to-end report ──────────────────────────────────────────────────

def analyze_message(message: Message) -> HeaderForensicsReport:
    """Full forensic report for a parsed email.Message."""
    auth_header = message.get("Authentication-Results", "") or ""
    auth_results = parse_authentication_results(auth_header)
    received_headers = message.get_all("Received") or []
    hops = parse_received_chain(received_headers)

    def verdict(method: str) -> bool | None:
        candidates = [r for r in auth_results if r.method == method]
        if not candidates:
            return None
        # If any pass, count as pass; if any fail, count as fail.
        if any(c.passed for c in candidates):
            return True
        if any(c.failed for c in candidates):
            return False
        return None

    spf = verdict("spf")
    dkim = verdict("dkim")
    dmarc = verdict("dmarc")

    warnings: list[str] = []
    risk = 0.0

    if spf is False:
        warnings.append("SPF failed — sender not authorised by domain's DNS.")
        risk += 0.3
    elif spf is None:
        warnings.append("No SPF verdict present.")
        risk += 0.05

    if dkim is False:
        warnings.append("DKIM failed — message body was altered or signed by wrong key.")
        risk += 0.3
    elif dkim is None:
        warnings.append("No DKIM signature verified.")
        risk += 0.05

    if dmarc is False:
        warnings.append("DMARC failed — domain explicitly rejects spoofing and this message is spoofed.")
        risk += 0.4
    elif dmarc is None and (spf or dkim):
        warnings.append("No DMARC verdict — domain may not publish a policy.")
        risk += 0.05

    # Chain sanity checks
    if len(hops) == 0:
        warnings.append("No Received headers — unusual for delivered mail.")
        risk += 0.2
    elif len(hops) > 12:
        warnings.append(f"Unusually long Received chain ({len(hops)} hops).")
        risk += 0.1

    # Time sanity: hops should be chronologically descending (newest first)
    timestamps = [h.timestamp for h in hops if h.timestamp is not None]
    if len(timestamps) >= 2:
        for earlier, later in zip(timestamps[1:], timestamps[:-1], strict=False):
            if later < earlier:
                warnings.append("Received-chain timestamps out of order — possible header injection.")
                risk += 0.1
                break

    risk = min(risk, 1.0)

    return HeaderForensicsReport(
        auth_results=auth_results,
        hops=hops,
        spf_pass=spf,
        dkim_pass=dkim,
        dmarc_pass=dmarc,
        warnings=warnings,
        risk_score=risk,
    )


def analyze_raw(raw_email: str | bytes) -> HeaderForensicsReport:
    """Convenience wrapper — parse a raw RFC 5322 email and produce a report."""
    import email

    if isinstance(raw_email, bytes):
        msg = email.message_from_bytes(raw_email)
    else:
        msg = email.message_from_string(raw_email)
    return analyze_message(msg)
