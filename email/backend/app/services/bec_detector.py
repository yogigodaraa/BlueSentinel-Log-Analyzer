"""Business Email Compromise (BEC) detection.

BEC attacks don't rely on malicious links or malware. They impersonate
a trusted identity (CEO, vendor, colleague) and manipulate the
recipient into taking an action — wire transfer, changing payroll
details, sharing credentials. Detection hinges on *identity* signals:

1. **Display name ≠ From address** — "CEO Name <attacker@gmail.com>"
2. **Lookalike domains** — typosquatting, IDN homographs, cousin
   domains (e.g., ``paypa1.com``, ``raicrosoft.com``, ``xn--pypl-loa.com``)
3. **First-time sender for high-trust content** — common with mailbox
   takeover: the real account is compromised and the attacker emails
   its contacts for the first time in years
4. **Reply-To mismatch** — ``From:`` says CFO, ``Reply-To:`` is a Gmail

This module covers (1), (2), and (4). (3) needs historical per-user
context — see ``services/behavioral_baseline.py`` (TODO).

References:
    - FBI IC3 BEC Report 2024
    - APWG Phishing Activity Trends Report
    - https://phishing.army/domain-squatting/
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from email.message import Message
from email.utils import getaddresses, parseaddr
from typing import Iterable


@dataclass
class BECSignal:
    """One BEC indicator fired on this message."""

    code: str
    severity: str  # info / low / medium / high / critical
    message: str
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass
class BECReport:
    signals: list[BECSignal] = field(default_factory=list)
    risk_score: float = 0.0  # 0 = clean, 1 = critical

    def to_dict(self) -> dict:
        return {
            "signals": [
                {"code": s.code, "severity": s.severity, "message": s.message, "metadata": s.metadata}
                for s in self.signals
            ],
            "risk_score": round(self.risk_score, 3),
        }


_VIP_KEYWORDS = (
    "ceo",
    "cfo",
    "president",
    "director",
    "manager",
    "head of",
    "founder",
    "executive",
)

_URGENT_KEYWORDS = (
    "urgent",
    "asap",
    "immediately",
    "wire transfer",
    "wire this",
    "pay this",
    "update banking",
    "gift card",
    "payroll",
    "confidential — only",
)


def _levenshtein(a: str, b: str) -> int:
    """Classic iterative Levenshtein — used for lookalike-domain scoring."""
    if len(a) < len(b):
        a, b = b, a
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            ins = curr[j - 1] + 1
            dlt = prev[j] + 1
            sub = prev[j - 1] + (ca != cb)
            curr.append(min(ins, dlt, sub))
        prev = curr
    return prev[-1]


def _to_ascii_domain(domain: str) -> str:
    """Convert IDN (punycode) back to its ASCII form for display, or return as-is."""
    try:
        return domain.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        return domain


def _has_homograph(domain: str) -> bool:
    """True if the domain contains confusable non-ASCII characters.

    Classic examples: Cyrillic 'а' (U+0430) that looks like Latin 'a',
    Greek 'ο' (U+03BF) that looks like Latin 'o', etc.
    """
    for ch in domain:
        if ord(ch) < 128:
            continue
        # Any non-ASCII letter in a domain is suspicious for BEC; IDN
        # domains are rare in legitimate business mail.
        cat = unicodedata.category(ch)
        if cat.startswith("L"):
            return True
    return False


# ─── Public API ──────────────────────────────────────────────────────────

def detect_bec(
    message: Message,
    *,
    known_senders: Iterable[str] = (),
    protected_domains: Iterable[str] = (),
) -> BECReport:
    """Run all BEC checks against a parsed email.

    Args:
        message: Parsed ``email.message.Message``.
        known_senders: Previously-seen sender addresses — used to flag
            first-time VIP impersonation.
        protected_domains: Your organisation's own domains — lookalike
            detection compares against these.

    Returns:
        A ``BECReport`` with per-signal detail + cumulative risk score.
    """
    report = BECReport()

    from_header = message.get("From", "") or ""
    reply_to = message.get("Reply-To", "") or ""
    display_name, from_addr = parseaddr(from_header)

    if not from_addr:
        report.signals.append(
            BECSignal(
                "malformed_from",
                "medium",
                "From: header missing or malformed — unusual for delivered mail.",
            )
        )
        report.risk_score += 0.2
        return report

    from_domain = from_addr.split("@", 1)[1].lower() if "@" in from_addr else ""

    # 1. Display name impersonation
    if display_name:
        if any(kw in display_name.lower() for kw in _VIP_KEYWORDS):
            if from_domain in {"gmail.com", "outlook.com", "yahoo.com", "hotmail.com", "icloud.com"}:
                report.signals.append(
                    BECSignal(
                        "vip_display_freemail",
                        "high",
                        f"Display name claims a VIP role ({display_name}) but is sending from a free email domain.",
                        metadata={"display_name": display_name, "from_domain": from_domain},
                    )
                )
                report.risk_score += 0.5

        # Display name contains an email address that differs from the actual From
        email_in_dn = re.search(r"([\w.+-]+@[\w.-]+\.\w+)", display_name)
        if email_in_dn and email_in_dn.group(1).lower() != from_addr.lower():
            report.signals.append(
                BECSignal(
                    "display_name_spoof",
                    "high",
                    f"Display name contains a different email ({email_in_dn.group(1)}) than the actual sender.",
                    metadata={"display_name_email": email_in_dn.group(1), "from_addr": from_addr},
                )
            )
            report.risk_score += 0.4

    # 2. Reply-To mismatch
    if reply_to:
        _, reply_addr = parseaddr(reply_to)
        if reply_addr and from_addr:
            r_domain = reply_addr.split("@", 1)[1].lower() if "@" in reply_addr else ""
            if r_domain and r_domain != from_domain:
                sev = "high" if r_domain in {"gmail.com", "outlook.com", "yahoo.com"} else "medium"
                report.signals.append(
                    BECSignal(
                        "reply_to_mismatch",
                        sev,
                        f"Reply-To domain ({r_domain}) differs from From domain ({from_domain}).",
                        metadata={"reply_to": reply_addr, "from": from_addr},
                    )
                )
                report.risk_score += 0.3 if sev == "high" else 0.15

    # 3. Lookalike domain — compare against protected domains
    for protected in protected_domains:
        p = protected.lower().strip()
        if not p or from_domain == p:
            continue
        dist = _levenshtein(from_domain, p)
        # Small edit distance + similar length = lookalike
        if 0 < dist <= 2 and abs(len(from_domain) - len(p)) <= 2:
            report.signals.append(
                BECSignal(
                    "lookalike_domain",
                    "critical",
                    f"Sender domain '{from_domain}' is a lookalike of protected domain '{p}' (edit distance {dist}).",
                    metadata={"from_domain": from_domain, "protected": p, "edit_distance": str(dist)},
                )
            )
            report.risk_score += 0.6

    # 4. IDN homograph attack
    if _has_homograph(from_domain):
        report.signals.append(
            BECSignal(
                "idn_homograph",
                "high",
                f"Sender domain contains non-ASCII characters (punycode: {_to_ascii_domain(from_domain)}).",
                metadata={"from_domain": from_domain, "punycode": _to_ascii_domain(from_domain)},
            )
        )
        report.risk_score += 0.4

    # 5. First-time sender bonus — only elevate if we have a known_senders list
    if known_senders:
        known_lower = {s.lower() for s in known_senders}
        if from_addr.lower() not in known_lower:
            # Combine with urgent language to bump severity
            subject = (message.get("Subject") or "").lower()
            body_preview = ""
            if message.is_multipart():
                for part in message.walk():
                    if part.get_content_type() == "text/plain":
                        try:
                            body_preview = part.get_payload(decode=True) or b""  # type: ignore[assignment]
                            body_preview = body_preview.decode("utf-8", "replace")[:2000].lower()
                        except Exception:
                            body_preview = ""
                        break
            else:
                payload = message.get_payload(decode=True)
                if isinstance(payload, bytes):
                    body_preview = payload.decode("utf-8", "replace")[:2000].lower()
            if any(kw in subject or kw in body_preview for kw in _URGENT_KEYWORDS):
                report.signals.append(
                    BECSignal(
                        "first_time_urgent",
                        "high",
                        "First-time sender with urgent/financial language — classic BEC mailbox-takeover signal.",
                        metadata={"from_addr": from_addr},
                    )
                )
                report.risk_score += 0.35

    report.risk_score = min(report.risk_score, 1.0)
    return report


# ─── Helpers exported for tests ─────────────────────────────────────────

def extract_all_addresses(message: Message) -> list[str]:
    """Return every email address in every header we care about."""
    out: set[str] = set()
    for header in ("From", "To", "Cc", "Bcc", "Reply-To"):
        for _, addr in getaddresses(message.get_all(header) or []):
            if addr:
                out.add(addr.lower())
    return sorted(out)
