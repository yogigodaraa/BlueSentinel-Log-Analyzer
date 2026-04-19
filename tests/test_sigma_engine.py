"""Tests for the Sigma rules engine."""

from datetime import datetime

from bluesentinel.rules import SigmaEngine, SigmaRule
from bluesentinel.types import LogEvent, Severity


def _rule_from_dict(d: dict) -> SigmaRule:
    return SigmaRule.from_dict(d)


def make_event(msg: str, **kwargs) -> LogEvent:
    return LogEvent(
        timestamp=datetime(2026, 1, 1),
        message=msg,
        **kwargs,
    )


def test_simple_contains_match():
    rule = _rule_from_dict(
        {
            "id": "test-1",
            "title": "failed login",
            "level": "medium",
            "detection": {
                "selection": {"message|contains": ["Failed password"]},
                "condition": "selection",
            },
        }
    )
    engine = SigmaEngine([rule])
    ev = make_event("Failed password for admin from 1.2.3.4")
    hits = engine.evaluate(ev)
    assert len(hits) == 1
    assert hits[0].sigma_rule_id == "test-1"


def test_no_match():
    rule = _rule_from_dict(
        {
            "id": "test-2",
            "title": "anything",
            "detection": {
                "selection": {"message|contains": ["Failed password"]},
                "condition": "selection",
            },
        }
    )
    engine = SigmaEngine([rule])
    ev = make_event("session opened for user alice")
    assert engine.evaluate(ev) == []


def test_all_of_glob():
    rule = _rule_from_dict(
        {
            "id": "test-3",
            "title": "multi-selection",
            "detection": {
                "selection_a": {"message|contains": ["iptables"]},
                "selection_b": {"message|contains": ["-F"]},
                "condition": "all of selection_*",
            },
        }
    )
    engine = SigmaEngine([rule])
    assert engine.evaluate(make_event("iptables -F")) != []
    assert engine.evaluate(make_event("iptables -L")) == []


def test_mitre_techniques_extracted_from_tags():
    rule = _rule_from_dict(
        {
            "id": "test-4",
            "title": "with tags",
            "detection": {"selection": {"message|contains": ["xyz"]}, "condition": "selection"},
            "tags": ["attack.credential-access", "attack.t1110.001"],
        }
    )
    assert "T1110.001" in rule.mitre_techniques


def test_load_builtin_rules():
    engine = SigmaEngine()
    engine.load_builtin()
    # We ship 5 rules
    assert len(engine.rules) >= 5
    titles = [r.title for r in engine.rules]
    assert any("brute-force" in t.lower() for t in titles)


def test_builtin_rules_fire_on_attack():
    engine = SigmaEngine()
    engine.load_builtin()
    # brute force rule should fire on failed SSH
    ev = make_event("Failed password for admin from 1.2.3.4", process_name="sshd")
    hits = engine.evaluate(ev)
    assert any(h.sigma_rule_id == "bs-001-ssh-brute-force" for h in hits)


def test_builtin_rule_levels():
    engine = SigmaEngine()
    engine.load_builtin()
    sev_counts = {}
    for rule in engine.rules:
        sev_counts[rule.level.value] = sev_counts.get(rule.level.value, 0) + 1
    # We have a mix — at least one high and one critical
    assert sev_counts.get(Severity.CRITICAL.value, 0) >= 1
    assert sev_counts.get(Severity.HIGH.value, 0) >= 1
