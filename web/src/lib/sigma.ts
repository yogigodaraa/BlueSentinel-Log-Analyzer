/**
 * Tiny client-side Sigma-style rules engine. A real port of the
 * backend pySigma integration would be heavier; this version hard-codes
 * the same five rules we ship in `src/bluesentinel/rules/builtin/` so
 * the browser demo fires on the same synthetic attack sequences the
 * backend does.
 *
 * Every rule here matches the YAML in builtin/ 1:1 — if you add or
 * tweak a rule there, update this too.
 */

import type { Detection, LogEvent } from "./types";

interface Rule {
  id: string;
  title: string;
  level: "info" | "low" | "medium" | "high" | "critical";
  mitre: string[];
  match: (event: LogEvent) => boolean;
}

const RULES: Rule[] = [
  {
    id: "bs-001-ssh-brute-force",
    title: "SSH brute-force — many failed passwords from one host",
    level: "high",
    mitre: ["T1110.001"],
    match: (e) =>
      e.processName === "sshd" &&
      /(Failed password|authentication failure|Invalid user)/.test(e.message),
  },
  {
    id: "bs-002-sudo-denied",
    title: "Unauthorised sudo attempt",
    level: "high",
    mitre: ["T1548.003", "T1068"],
    match: (e) =>
      /(user NOT in sudoers|is not in the sudoers file|incorrect password attempts)/.test(
        e.message,
      ) ||
      (e.processName === "sudo" && /authentication failure/.test(e.message)),
  },
  {
    id: "bs-003-user-created",
    title: "Local account created",
    level: "medium",
    mitre: ["T1136.001"],
    match: (e) => /(new user|useradd|adduser|new account)/i.test(e.message),
  },
  {
    id: "bs-004-log-tampering",
    title: "Auth log tampering",
    level: "critical",
    mitre: ["T1070.002"],
    match: (e) =>
      /(rm\s+.*\/var\/log\/(auth|secure|syslog|messages)|truncate\s+-s\s+0\s+\/var\/log\/|shred\s+\/var\/log\/|wtmp|btmp)/.test(
        e.message,
      ),
  },
  {
    id: "bs-005-firewall-disabled",
    title: "Host firewall disabled",
    level: "critical",
    mitre: ["T1562.004"],
    match: (e) =>
      /(iptables\s+(-F|--flush)|ufw\s+disable|systemctl\s+stop\s+(firewalld|ufw)|service\s+iptables\s+stop)/.test(
        e.message,
      ),
  },
];

const LEVEL_TO_SCORE: Record<Rule["level"], number> = {
  info: 0.1,
  low: 0.3,
  medium: 0.5,
  high: 0.75,
  critical: 0.95,
};

export function evaluateAll(events: LogEvent[]): Detection[] {
  const hits: Detection[] = [];
  for (const event of events) {
    for (const rule of RULES) {
      if (rule.match(event)) {
        hits.push({
          event,
          detector: "sigma",
          score: LEVEL_TO_SCORE[rule.level],
          threshold: LEVEL_TO_SCORE.low,
          explanation: `Sigma rule matched: ${rule.title}`,
          mitreTechniques: rule.mitre,
          sigmaRuleId: rule.id,
        });
      }
    }
  }
  return hits;
}

export function listRules(): { id: string; title: string; level: string; mitre: string[] }[] {
  return RULES.map(({ id, title, level, mitre }) => ({ id, title, level, mitre }));
}
