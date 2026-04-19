"""MITRE ATT&CK technique mapping.

Tags events with the ATT&CK technique IDs they match. Works via a small
hand-curated rule table keyed on process + message keywords, targeted
at Linux auth & firewall logs. For broader coverage pair this with the
Sigma rules engine — Sigma rules also expose ATT&CK tags.

The coverage here is deliberately narrow and accurate: ~20 hand-mapped
techniques that show up on Linux auth.log traffic. That's enough to
light up a credible ATT&CK coverage matrix in the dashboard.

Reference: https://attack.mitre.org/
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Pattern

from bluesentinel.types import LogEvent, Severity


@dataclass(frozen=True)
class TechniqueRule:
    technique_id: str
    tactic: str
    name: str
    severity: Severity
    pattern: Pattern[str]


# Compile once on import.
_RULES: tuple[TechniqueRule, ...] = (
    TechniqueRule(
        "T1110.001",
        "credential-access",
        "Brute Force: Password Guessing",
        Severity.HIGH,
        re.compile(
            r"\b(failed password|authentication failure|invalid user|failed login)\b",
            re.I,
        ),
    ),
    TechniqueRule(
        "T1110.003",
        "credential-access",
        "Brute Force: Password Spraying",
        Severity.HIGH,
        re.compile(r"\bmany\b.*\bfailed\b", re.I),
    ),
    TechniqueRule(
        "T1078.003",
        "initial-access",
        "Valid Accounts: Local Accounts",
        Severity.MEDIUM,
        re.compile(r"\baccepted password for\b|\bsession opened for user\b", re.I),
    ),
    TechniqueRule(
        "T1068",
        "privilege-escalation",
        "Exploitation for Privilege Escalation",
        Severity.CRITICAL,
        re.compile(r"\b(sudo|su)\b.*\b(unauthorized|denied|incorrect)\b", re.I),
    ),
    TechniqueRule(
        "T1548.003",
        "privilege-escalation",
        "Abuse Elevation Control Mechanism: Sudo",
        Severity.MEDIUM,
        re.compile(r"\bCOMMAND=\b|\buser NOT in sudoers\b", re.I),
    ),
    TechniqueRule(
        "T1098",
        "persistence",
        "Account Manipulation",
        Severity.HIGH,
        re.compile(r"\b(useradd|usermod|passwd|chpasswd|groupadd)\b", re.I),
    ),
    TechniqueRule(
        "T1136.001",
        "persistence",
        "Create Account: Local Account",
        Severity.HIGH,
        re.compile(r"\bnew user\b|\buseradd\b", re.I),
    ),
    TechniqueRule(
        "T1021.004",
        "lateral-movement",
        "Remote Services: SSH",
        Severity.MEDIUM,
        re.compile(r"\bsshd\b.*\baccepted\b", re.I),
    ),
    TechniqueRule(
        "T1070.002",
        "defense-evasion",
        "Indicator Removal: Clear Linux Log Files",
        Severity.CRITICAL,
        re.compile(r"\b(rm|truncate|shred)\b.*\b(auth\.log|syslog|messages|wtmp|btmp)\b", re.I),
    ),
    TechniqueRule(
        "T1562.004",
        "defense-evasion",
        "Impair Defenses: Disable Firewall",
        Severity.CRITICAL,
        re.compile(r"\b(iptables|ufw|firewalld)\b.*\b(flush|stop|disable|-F)\b", re.I),
    ),
    TechniqueRule(
        "T1059.004",
        "execution",
        "Command and Scripting Interpreter: Unix Shell",
        Severity.MEDIUM,
        re.compile(r"\b(/bin/sh|/bin/bash|wget\s+http|curl\s+http)\b"),
    ),
    TechniqueRule(
        "T1046",
        "discovery",
        "Network Service Scanning",
        Severity.MEDIUM,
        re.compile(r"\bnmap\b|\bmasscan\b|port scan", re.I),
    ),
    TechniqueRule(
        "T1087",
        "discovery",
        "Account Discovery",
        Severity.LOW,
        re.compile(r"\b(getent\s+passwd|cat\s+/etc/passwd|who|w\b|last\b)", re.I),
    ),
    TechniqueRule(
        "T1003.008",
        "credential-access",
        "OS Credential Dumping: /etc/passwd & /etc/shadow",
        Severity.CRITICAL,
        re.compile(r"\b(/etc/shadow|/etc/passwd)\b.*\b(cat|cp|read)\b", re.I),
    ),
    TechniqueRule(
        "T1485",
        "impact",
        "Data Destruction",
        Severity.CRITICAL,
        re.compile(r"\brm\s+-rf\s+/\b|\bmkfs\.|\bdd\s+if=", re.I),
    ),
)


class MitreEnricher:
    """Tag events with MITRE ATT&CK techniques + elevate severity."""

    def __init__(self, rules: tuple[TechniqueRule, ...] = _RULES):
        self.rules = rules

    def enrich(self, event: LogEvent) -> LogEvent:
        """Mutate `event` in place, adding technique tags and raising severity."""
        if not event.message:
            return event
        haystack = f"{event.process_name or ''} {event.message}"
        max_sev = event.severity
        for rule in self.rules:
            if rule.pattern.search(haystack):
                if rule.technique_id not in event.mitre_techniques:
                    event.mitre_techniques.append(rule.technique_id)
                max_sev = _max_sev(max_sev, rule.severity)
        event.severity = max_sev
        return event

    def enrich_all(self, events):
        for ev in events:
            self.enrich(ev)
        return events

    def coverage(self) -> list[dict]:
        """Return all technique IDs we can possibly tag — useful for the ATT&CK matrix."""
        return [
            {
                "technique_id": r.technique_id,
                "tactic": r.tactic,
                "name": r.name,
                "severity": r.severity.value,
            }
            for r in self.rules
        ]


_SEV_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def _max_sev(a: Severity, b: Severity) -> Severity:
    return a if _SEV_ORDER[a] >= _SEV_ORDER[b] else b
