"""Tests for the attack-graph engine.

Verifies the engine actually reconstructs a textbook kill-chain from a
synthetic attack sequence — and that it rejects random noise.
"""

from datetime import datetime, timedelta

from bluesentinel.graph import AttackGraphEngine
from bluesentinel.graph.kill_chain import score_path, tactic_of
from bluesentinel.types import Detection, LogEvent, Severity


def mk(msg: str, minutes: int, *, user="alice", host="prod-01", ip="10.0.0.5",
       techniques=None, severity=Severity.MEDIUM) -> Detection:
    ev = LogEvent(
        timestamp=datetime(2026, 4, 20, 9, 0, 0) + timedelta(minutes=minutes),
        message=msg,
        user=user,
        host=host,
        source_ip=ip,
        severity=severity,
        mitre_techniques=techniques or [],
    )
    return Detection(
        event=ev,
        detector="test",
        score=0.9,
        threshold=0.5,
        explanation="test",
        mitre_techniques=techniques or [],
    )


# ─── kill_chain ──────────────────────────────────────────────────────────

def test_tactic_lookup_known():
    assert tactic_of("T1110.001") == "credential-access"
    assert tactic_of("T1485") == "impact"
    assert tactic_of("T1566.002") == "initial-access"


def test_tactic_lookup_fallback_to_base():
    # Sub-technique not in the table but parent is — should fall back
    assert tactic_of("T1566.999") == "initial-access"


def test_perfect_kill_chain_scores_high():
    path = ["T1110.001", "T1078.003", "T1548.003", "T1021.004", "T1485"]
    # credential-access → initial-access → privilege-esc → lateral → impact
    # That's mostly-forward with one backward jump (cred-access → initial)
    score = score_path(path)
    assert score.score >= 0.6, f"Expected high score for near-textbook chain, got {score.score}"
    assert score.forward_steps >= 3


def test_random_path_scores_low():
    path = ["T1110.001", "T1110.001", "T1110.001"]  # stuck in credential-access
    score = score_path(path)
    # Same-tactic only — should score around 0.25 (same-tactic weight)
    assert score.score <= 0.4


def test_single_technique_returns_neutral():
    score = score_path(["T1110.001"])
    # single-step has no progression; neutral score
    assert 0 <= score.score <= 0.5


# ─── engine ──────────────────────────────────────────────────────────────

def test_engine_reconstructs_textbook_attack():
    # Textbook kill chain: brute force → login → privilege escalation → data destruction
    # All from the same user on the same host.
    detections = [
        mk("Failed password for admin from 203.0.113.5", 0,
           user="admin", techniques=["T1110.001"], severity=Severity.HIGH),
        mk("Accepted password for admin from 203.0.113.5", 5,
           user="admin", techniques=["T1078.003"]),
        mk("sudo: authentication failure for admin", 7,
           user="admin", techniques=["T1548.003"], severity=Severity.HIGH),
        mk("iptables -F", 15,
           user="admin", techniques=["T1562.004"], severity=Severity.CRITICAL),
        mk("rm /var/log/auth.log", 22,
           user="admin", techniques=["T1070.002"], severity=Severity.CRITICAL),
    ]
    engine = AttackGraphEngine()
    chains = engine.reconstruct(detections)
    assert len(chains) >= 1, "Expected at least one chain reconstructed"
    top = chains[0]
    assert len(top.detections) == 5
    # Should pick up all five tactics
    assert top.kill_chain is not None
    assert "credential-access" in top.kill_chain.tactics_covered
    assert "defense-evasion" in top.kill_chain.tactics_covered
    # Score should be well above the filter threshold
    assert top.overall_score >= 0.5, f"Expected strong score, got {top.overall_score}"
    # Summary should render without errors
    assert "chain-" in top.summary()


def test_engine_rejects_random_noise():
    # Five unrelated events from different users / hosts, no technique links
    detections = [
        mk("cron job ran", 0, user="alice", host="host-1", techniques=[]),
        mk("session opened", 60, user="bob", host="host-2", techniques=[]),
        mk("cron job ran", 120, user="carol", host="host-3", techniques=[]),
        mk("session opened", 180, user="dave", host="host-4", techniques=[]),
    ]
    engine = AttackGraphEngine(min_overall_score=0.3)
    chains = engine.reconstruct(detections)
    # Different users + hosts + no techniques → no connections
    assert chains == [], "Random noise should not produce chains"


def test_engine_respects_time_window():
    # Same user / same techniques but spaced 1 day apart — should not chain
    detections = [
        mk("brute force", 0, user="admin", techniques=["T1110.001"], severity=Severity.HIGH),
        mk("privilege escalation", 1440, user="admin", techniques=["T1548.003"], severity=Severity.HIGH),
    ]
    engine = AttackGraphEngine(time_window=timedelta(hours=4))
    chains = engine.reconstruct(detections)
    assert chains == [], "Events beyond the time window should not chain"


def test_chain_to_dict_round_trip():
    detections = [
        mk("brute force", 0, techniques=["T1110.001"], severity=Severity.HIGH),
        mk("login", 3, techniques=["T1078.003"]),
        mk("firewall disable", 8, techniques=["T1562.004"], severity=Severity.CRITICAL),
    ]
    engine = AttackGraphEngine()
    chains = engine.reconstruct(detections)
    assert chains
    d = chains[0].to_dict()
    assert set(d.keys()) >= {
        "id", "summary", "detections", "entities", "mitre_techniques",
        "kill_chain", "severity_integral", "time_compactness",
        "entity_consistency", "overall_score",
    }
    assert d["overall_score"] >= 0.5


def test_mermaid_rendering():
    from bluesentinel.graph import chain_to_mermaid

    detections = [
        mk("failed login", 0, techniques=["T1110.001"], severity=Severity.HIGH),
        mk("iptables -F", 8, techniques=["T1562.004"], severity=Severity.CRITICAL),
    ]
    engine = AttackGraphEngine()
    chains = engine.reconstruct(detections)
    assert chains
    mermaid = chain_to_mermaid(chains[0])
    assert "flowchart LR" in mermaid
    assert "T1110.001" in mermaid
    assert "T1562.004" in mermaid
