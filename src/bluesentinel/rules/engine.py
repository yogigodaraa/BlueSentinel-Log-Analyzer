"""pySigma-backed detection rules engine.

Sigma (https://github.com/SigmaHQ/sigma) is the open standard for
detection-as-code — every rule is a portable YAML file that describes
what to match and which MITRE technique(s) it covers. Real SOCs have
thousands of these; we ship a small starter set under
``bluesentinel/rules/builtin/``.

This engine is intentionally simple: load YAML rules, evaluate them
against parsed events in Python (not via conversion to an external
backend's query language). Good enough for local analysis and unit
tests; we can plug a pysigma Elasticsearch / Splunk backend in later
for production-scale queries.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from bluesentinel.types import Detection, LogEvent, Severity


@dataclass
class SigmaRule:
    """Subset of the Sigma rule schema we evaluate natively."""

    id: str
    title: str
    description: str
    level: Severity
    detection: dict[str, Any]
    tags: list[str] = field(default_factory=list)
    author: str = ""
    references: list[str] = field(default_factory=list)

    @property
    def mitre_techniques(self) -> list[str]:
        """Extract T-number technique IDs from tags (e.g., attack.t1110 → T1110)."""
        out = []
        for tag in self.tags:
            if tag.lower().startswith("attack.t"):
                out.append(tag.split(".", 1)[1].upper())
        return out

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SigmaRule":
        level = _parse_level(data.get("level", "medium"))
        return cls(
            id=str(data.get("id", data.get("title", "unnamed"))),
            title=data.get("title", "unnamed rule"),
            description=data.get("description", ""),
            level=level,
            detection=data.get("detection", {}),
            tags=list(data.get("tags") or []),
            author=data.get("author", ""),
            references=list(data.get("references") or []),
        )


class SigmaEngine:
    """Load and evaluate Sigma rules against `LogEvent`s."""

    def __init__(self, rules: list[SigmaRule] | None = None):
        self.rules: list[SigmaRule] = rules or []

    # ─── Loading ───────────────────────────────────────────────────────
    def load_directory(self, path: str | Path) -> None:
        p = Path(path)
        for f in sorted(p.rglob("*.yml")):
            self.load_file(f)
        for f in sorted(p.rglob("*.yaml")):
            self.load_file(f)

    def load_file(self, path: str | Path) -> None:
        with Path(path).open() as f:
            data = yaml.safe_load(f)
        if data:
            self.rules.append(SigmaRule.from_dict(data))

    def load_builtin(self) -> None:
        """Load the rules shipped in `bluesentinel/rules/builtin/`."""
        builtin = Path(__file__).parent / "builtin"
        if builtin.exists():
            self.load_directory(builtin)

    # ─── Evaluation ────────────────────────────────────────────────────
    def evaluate(self, event: LogEvent) -> list[Detection]:
        """Return every rule that matches this event."""
        hits: list[Detection] = []
        for rule in self.rules:
            if _match_detection(event, rule.detection):
                hits.append(
                    Detection(
                        event=event,
                        detector="sigma",
                        score=_sev_to_score(rule.level),
                        threshold=_sev_to_score(Severity.LOW),
                        explanation=f"Sigma rule matched: {rule.title}",
                        mitre_techniques=rule.mitre_techniques,
                        sigma_rule_id=rule.id,
                    )
                )
        return hits

    def evaluate_all(self, events):
        all_hits: list[Detection] = []
        for ev in events:
            all_hits.extend(self.evaluate(ev))
        return all_hits


# ─── Sigma condition evaluation ──────────────────────────────────────────
def _match_detection(event: LogEvent, detection: dict[str, Any]) -> bool:
    """Evaluate a Sigma `detection` block against one event.

    We support the subset of Sigma most rules actually use:

    - Named selections (``selection``, ``keywords``, etc.) with fields
      containing strings or lists of strings. String values can include
      glob wildcards (``*``) à la Sigma spec.
    - ``condition`` field combining selections with ``and`` / ``or`` /
      ``not`` / ``1 of``. We parse the most common shapes.
    """
    if not detection:
        return False
    condition = detection.get("condition", "")
    selections = {k: v for k, v in detection.items() if k != "condition"}

    matches: dict[str, bool] = {
        name: _match_selection(event, sel) for name, sel in selections.items()
    }

    return _eval_condition(condition, matches)


def _match_selection(event: LogEvent, sel: Any) -> bool:
    if isinstance(sel, dict):
        # All key/value pairs must match
        return all(_match_field(event, k, v) for k, v in sel.items())
    if isinstance(sel, list):
        # Any listed keyword appears anywhere in the message
        msg = (event.message or "").lower()
        return any(kw.lower() in msg for kw in sel if isinstance(kw, str))
    return False


def _match_field(event: LogEvent, key: str, value: Any) -> bool:
    # Sigma field modifiers like `field|contains` — split off the modifier
    field, _, modifier = key.partition("|")
    actual = _field_from_event(event, field)
    if actual is None:
        return False
    actual_str = str(actual).lower()
    if isinstance(value, list):
        candidates = [str(v).lower() for v in value]
    else:
        candidates = [str(value).lower()]

    if modifier == "contains":
        return any(c in actual_str for c in candidates)
    if modifier == "startswith":
        return any(actual_str.startswith(c) for c in candidates)
    if modifier == "endswith":
        return any(actual_str.endswith(c) for c in candidates)
    if modifier in ("re", "regex"):
        import re as _re

        return any(_re.search(c, actual_str) for c in candidates)
    # default — glob match
    return any(fnmatch.fnmatchcase(actual_str, c) for c in candidates)


def _field_from_event(event: LogEvent, field: str) -> Any:
    # Support dotted paths into .raw
    if "." in field:
        top, rest = field.split(".", 1)
        raw = event.raw or {}
        if top in raw:
            return _nested_get(raw[top], rest)
        return None
    return {
        "message": event.message,
        "host": event.host,
        "user": event.user,
        "source_ip": event.source_ip,
        "sourceip": event.source_ip,
        "process": event.process_name,
        "process_name": event.process_name,
        "pid": event.process_pid,
        "template_id": event.template_id,
        "template": event.template,
    }.get(field.lower())


def _nested_get(obj: Any, path: str) -> Any:
    for part in path.split("."):
        if isinstance(obj, dict) and part in obj:
            obj = obj[part]
        else:
            return None
    return obj


def _eval_condition(condition: str, matches: dict[str, bool]) -> bool:
    """Tiny evaluator for the common Sigma condition shapes.

    Supported:
        selection
        selection and not filter
        selection1 or selection2
        1 of selection*
        all of selection*
    """
    if not condition:
        # If no condition, default to: all selections true
        return all(matches.values()) if matches else False
    c = condition.strip().lower()
    if c in matches:
        return matches[c]
    if c.startswith("1 of ") or c.startswith("any of "):
        glob = c.split(" of ", 1)[1].strip()
        return any(v for k, v in matches.items() if fnmatch.fnmatchcase(k, glob))
    if c.startswith("all of "):
        glob = c.split(" of ", 1)[1].strip()
        vals = [v for k, v in matches.items() if fnmatch.fnmatchcase(k, glob)]
        return bool(vals) and all(vals)
    # Fall back to python-evaluating a simple boolean expression where
    # selection names are variables.
    try:
        return bool(eval(c, {"__builtins__": {}}, matches))  # noqa: S307
    except Exception:
        return False


def _parse_level(raw: Any) -> Severity:
    s = str(raw).lower()
    return {
        "informational": Severity.INFO,
        "info": Severity.INFO,
        "low": Severity.LOW,
        "medium": Severity.MEDIUM,
        "high": Severity.HIGH,
        "critical": Severity.CRITICAL,
    }.get(s, Severity.MEDIUM)


def _sev_to_score(sev: Severity) -> float:
    return {
        Severity.INFO: 0.1,
        Severity.LOW: 0.3,
        Severity.MEDIUM: 0.5,
        Severity.HIGH: 0.75,
        Severity.CRITICAL: 0.95,
    }[sev]
