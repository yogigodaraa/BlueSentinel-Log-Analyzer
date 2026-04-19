"""Syslog / Linux auth.log parser (RFC 3164).

Pulls out host, process, pid, and message from the classic syslog format:

    Jan 15 10:02:34 prod-01 sshd[4221]: Failed password for root from 1.2.3.4 port 51222 ssh2

This is the same parser the v1 tool shipped, just moved into the new
module layout and given a proper streaming interface. For template
extraction — which is what the detectors actually want — use
`DrainParser` instead.
"""

from __future__ import annotations

import re
from datetime import datetime

from bluesentinel.parsers.base import BaseParser
from bluesentinel.types import LogEvent

# Month Day HH:MM:SS host process[pid]: message
_SYSLOG = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<process>[\w/.\-]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.+)$"
)

# Common extractions from auth.log messages
_USER_RE = re.compile(r"\b(?:user|for)\s+(?P<user>[A-Za-z_][\w.\-]*)\b", re.IGNORECASE)
_RHOST_RE = re.compile(r"\brhost=(?P<rhost>[\w.\-]+)")
_FROM_IP_RE = re.compile(r"\bfrom\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b", re.IGNORECASE)


class SyslogParser(BaseParser):
    """RFC 3164 syslog parser with auth.log-specific field extraction."""

    def __init__(self, default_year: int | None = None):
        self.default_year = default_year or datetime.utcnow().year

    def parse_line(self, line: str) -> LogEvent | None:
        m = _SYSLOG.match(line.strip())
        if not m:
            return None
        g = m.groupdict()
        try:
            ts = datetime.strptime(
                f"{g['month']} {g['day']} {self.default_year} {g['time']}",
                "%b %d %Y %H:%M:%S",
            )
        except ValueError:
            return None

        message = g["message"]
        user = _extract_first(_USER_RE, message, "user")
        source_ip = _extract_first(_FROM_IP_RE, message, "ip") or _extract_first(
            _RHOST_RE, message, "rhost"
        )

        return LogEvent(
            timestamp=ts,
            message=message,
            host=g["host"],
            process_name=g["process"],
            process_pid=int(g["pid"]) if g["pid"] else None,
            user=user,
            source_ip=source_ip,
            raw={"source": "syslog"},
        )


def _extract_first(regex: re.Pattern[str], text: str, group: str) -> str | None:
    m = regex.search(text)
    return m.group(group) if m else None
