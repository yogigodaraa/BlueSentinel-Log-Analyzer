/**
 * Client-side MITRE ATT&CK technique enricher. Subset of the Python
 * version (`src/bluesentinel/enrichment/mitre.py`) — same rules, same
 * technique IDs, so a Sigma rule or attack-graph node tagged by the
 * backend matches what we tag here.
 */

import type { LogEvent, Severity } from "./types";

interface Rule {
  id: string;
  tactic: string;
  name: string;
  severity: Severity;
  regex: RegExp;
}

export const MITRE_RULES: Rule[] = [
  {
    id: "T1110.001",
    tactic: "credential-access",
    name: "Brute Force: Password Guessing",
    severity: "high",
    regex: /\b(failed password|authentication failure|invalid user|failed login)\b/i,
  },
  {
    id: "T1078.003",
    tactic: "initial-access",
    name: "Valid Accounts: Local Accounts",
    severity: "medium",
    regex: /\baccepted password for\b|\bsession opened for user\b/i,
  },
  {
    id: "T1548.003",
    tactic: "privilege-escalation",
    name: "Abuse Elevation Control Mechanism: Sudo",
    severity: "medium",
    regex: /\b(user NOT in sudoers|authentication failure for|COMMAND=)\b/i,
  },
  {
    id: "T1068",
    tactic: "privilege-escalation",
    name: "Exploitation for Privilege Escalation",
    severity: "critical",
    regex: /\b(sudo|su)\b.*\b(unauthorized|denied|incorrect)\b/i,
  },
  {
    id: "T1136.001",
    tactic: "persistence",
    name: "Create Account: Local Account",
    severity: "high",
    regex: /\bnew user\b|\buseradd\b/i,
  },
  {
    id: "T1021.004",
    tactic: "lateral-movement",
    name: "Remote Services: SSH",
    severity: "medium",
    regex: /\bsshd\b.*\baccepted\b/i,
  },
  {
    id: "T1070.002",
    tactic: "defense-evasion",
    name: "Clear Linux Log Files",
    severity: "critical",
    regex:
      /\b(rm|truncate|shred)\b.*\b(auth\.log|syslog|messages|wtmp|btmp|secure)\b/i,
  },
  {
    id: "T1562.004",
    tactic: "defense-evasion",
    name: "Impair Defenses: Disable Firewall",
    severity: "critical",
    regex: /\b(iptables|ufw|firewalld)\b.*\b(flush|stop|disable|-F)\b/i,
  },
  {
    id: "T1087",
    tactic: "discovery",
    name: "Account Discovery",
    severity: "low",
    regex: /\b(getent\s+passwd|cat\s+\/etc\/passwd|who\b|last\b)\b/i,
  },
  {
    id: "T1003.008",
    tactic: "credential-access",
    name: "OS Credential Dumping: /etc/shadow",
    severity: "critical",
    regex: /\b(\/etc\/shadow|\/etc\/passwd)\b.*\b(cat|cp|read)\b/i,
  },
  {
    id: "T1485",
    tactic: "impact",
    name: "Data Destruction",
    severity: "critical",
    regex: /\brm\s+-rf\s+\/|\bmkfs\.|\bdd\s+if=/i,
  },
];

const SEV_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export function enrich(event: LogEvent): LogEvent {
  const haystack = `${event.processName ?? ""} ${event.message}`;
  let maxSev: Severity = event.severity;
  for (const rule of MITRE_RULES) {
    if (rule.regex.test(haystack)) {
      if (!event.mitreTechniques.includes(rule.id)) {
        event.mitreTechniques.push(rule.id);
      }
      if (SEV_RANK[rule.severity] > SEV_RANK[maxSev]) maxSev = rule.severity;
    }
  }
  event.severity = maxSev;
  return event;
}

export function enrichAll(events: LogEvent[]): LogEvent[] {
  for (const e of events) enrich(e);
  return events;
}

/** Map every known technique ID → its tactic (for the kill-chain scorer). */
export const TECHNIQUE_TO_TACTIC: Record<string, string> =
  MITRE_RULES.reduce<Record<string, string>>((acc, r) => {
    acc[r.id] = r.tactic;
    return acc;
  }, {});

/** Canonical MITRE tactic ordering for kill-chain scoring. */
export const TACTIC_ORDER = [
  "reconnaissance",
  "resource-development",
  "initial-access",
  "execution",
  "persistence",
  "privilege-escalation",
  "defense-evasion",
  "credential-access",
  "discovery",
  "lateral-movement",
  "collection",
  "command-and-control",
  "exfiltration",
  "impact",
];
