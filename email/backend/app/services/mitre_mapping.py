"""MITRE ATT&CK mapping for email-threat signals.

SOCShield operates at the Initial-Access phase, covering Phishing
(T1566) and its sub-techniques. Each detection signal (BEC check,
URL reputation, header forensics verdict) gets tagged with the
technique it maps to so downstream reporting, SIEM export, and the
dashboard's ATT&CK heatmap all work from the same taxonomy.

Reference: https://attack.mitre.org/techniques/T1566/
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ATTACKTechnique:
    technique_id: str
    tactic: str
    name: str
    description: str


# Curated subset of ATT&CK techniques relevant to email threats.
EMAIL_TECHNIQUES: dict[str, ATTACKTechnique] = {
    "T1566": ATTACKTechnique(
        "T1566",
        "initial-access",
        "Phishing",
        "Adversaries send phishing messages to gain access to victim systems.",
    ),
    "T1566.001": ATTACKTechnique(
        "T1566.001",
        "initial-access",
        "Phishing: Spearphishing Attachment",
        "Specific to attackers who include malicious attachments in email.",
    ),
    "T1566.002": ATTACKTechnique(
        "T1566.002",
        "initial-access",
        "Phishing: Spearphishing Link",
        "Phishing messages that contain malicious URLs.",
    ),
    "T1566.003": ATTACKTechnique(
        "T1566.003",
        "initial-access",
        "Phishing: Spearphishing via Service",
        "Third-party services used for phishing (LinkedIn messages, Twitter DMs).",
    ),
    "T1566.004": ATTACKTechnique(
        "T1566.004",
        "initial-access",
        "Phishing: Spearphishing Voice",
        "Voice-based phishing as a secondary channel.",
    ),
    "T1534": ATTACKTechnique(
        "T1534",
        "lateral-movement",
        "Internal Spearphishing",
        "Using a compromised email account to phish other users in the org.",
    ),
    "T1598": ATTACKTechnique(
        "T1598",
        "reconnaissance",
        "Phishing for Information",
        "Phishing aimed at gathering data rather than initial access.",
    ),
    "T1589": ATTACKTechnique(
        "T1589",
        "reconnaissance",
        "Gather Victim Identity Information",
        "Collecting PII used in later BEC attacks.",
    ),
    "T1204.001": ATTACKTechnique(
        "T1204.001",
        "execution",
        "User Execution: Malicious Link",
        "User clicks a malicious URL in the phishing email.",
    ),
    "T1204.002": ATTACKTechnique(
        "T1204.002",
        "execution",
        "User Execution: Malicious File",
        "User opens a malicious attachment.",
    ),
    "T1036": ATTACKTechnique(
        "T1036",
        "defense-evasion",
        "Masquerading",
        "Display name spoofing, lookalike domains — BEC identity tricks.",
    ),
    "T1036.005": ATTACKTechnique(
        "T1036.005",
        "defense-evasion",
        "Masquerading: Match Legitimate Name or Location",
        "IDN homograph / typosquat domains.",
    ),
}


def map_signal_to_techniques(signal_code: str) -> list[str]:
    """Map a detection signal code (e.g. ``vip_display_freemail``) to ATT&CK IDs."""
    return {
        # BEC detector signals
        "vip_display_freemail": ["T1566", "T1036"],
        "display_name_spoof": ["T1566", "T1036"],
        "reply_to_mismatch": ["T1566"],
        "lookalike_domain": ["T1566", "T1036.005"],
        "idn_homograph": ["T1566", "T1036.005"],
        "first_time_urgent": ["T1566", "T1534"],
        # Header forensics
        "spf_fail": ["T1566"],
        "dkim_fail": ["T1566"],
        "dmarc_fail": ["T1566", "T1036"],
        # URL / attachment
        "malicious_url": ["T1566.002", "T1204.001"],
        "malicious_attachment": ["T1566.001", "T1204.002"],
        # Threat intel hits
        "urlhaus_hit": ["T1566.002"],
        "abuseipdb_hit": ["T1566"],
        "phishtank_hit": ["T1566.002"],
    }.get(signal_code, [])


def coverage_matrix() -> list[dict]:
    """Return every technique this service can potentially tag — feeds the dashboard."""
    return [
        {
            "technique_id": t.technique_id,
            "tactic": t.tactic,
            "name": t.name,
            "description": t.description,
        }
        for t in EMAIL_TECHNIQUES.values()
    ]
