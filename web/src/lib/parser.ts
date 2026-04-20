/**
 * Client-side syslog (RFC 3164) / auth.log parser.
 *
 * Mirrors the Python `SyslogParser` output shape closely enough that
 * downstream logic (detectors, attack graph) doesn't need to know which
 * side parsed the line.
 */

import type { LogEvent } from "./types";

const SYSLOG_RE =
  /^(?<month>\w{3})\s+(?<day>\d{1,2})\s+(?<time>\d{2}:\d{2}:\d{2})\s+(?<host>\S+)\s+(?<process>[\w/.\-]+)(?:\[(?<pid>\d+)\])?:\s+(?<message>.+)$/;

const USER_RE = /\b(?:user|for)\s+(?<user>[A-Za-z_][\w.\-]*)\b/i;
const IP_RE = /\bfrom\s+(?<ip>\d{1,3}(?:\.\d{1,3}){3})\b/i;
const RHOST_RE = /\brhost=(?<rhost>[\w.\-]+)/;

const MONTHS: Record<string, number> = {
  Jan: 0,
  Feb: 1,
  Mar: 2,
  Apr: 3,
  May: 4,
  Jun: 5,
  Jul: 6,
  Aug: 7,
  Sep: 8,
  Oct: 9,
  Nov: 10,
  Dec: 11,
};

export function parseLines(lines: string[]): LogEvent[] {
  const out: LogEvent[] = [];
  const year = new Date().getUTCFullYear();
  for (const rawLine of lines) {
    const line = rawLine.trimEnd();
    if (!line) continue;
    const m = SYSLOG_RE.exec(line);
    if (!m || !m.groups) continue;
    const { month, day, time, host, process, pid, message } = m.groups;
    const monthIdx = MONTHS[month];
    if (monthIdx === undefined) continue;
    const [h, mm, s] = time.split(":").map(Number);
    const ts = new Date(Date.UTC(year, monthIdx, Number(day), h, mm, s));

    const userMatch = USER_RE.exec(message);
    const ipMatch = IP_RE.exec(message);
    const rhostMatch = RHOST_RE.exec(message);

    out.push({
      timestamp: ts,
      message,
      host,
      user: userMatch?.groups?.user ?? null,
      sourceIp: ipMatch?.groups?.ip ?? rhostMatch?.groups?.rhost ?? null,
      processName: process,
      processPid: pid ? Number(pid) : null,
      severity: "info",
      mitreTechniques: [],
      raw: line,
    });
  }
  return out;
}

export function parseText(text: string): LogEvent[] {
  return parseLines(text.split(/\r?\n/));
}
