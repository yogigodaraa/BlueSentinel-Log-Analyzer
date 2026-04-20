"""Kill-chain model — the ordering structure on MITRE ATT&CK tactics.

Real attacks don't move randomly between ATT&CK tactics; they follow a
rough progression: reconnaissance → initial-access → execution →
persistence → privilege-escalation → defense-evasion →
credential-access → discovery → lateral-movement → collection →
command-and-control → exfiltration → impact.

Detections that appear in that order — especially with consistent
entities (same user, same host) — are vastly more likely to be a real
attack than the same detections scattered randomly.

This module scores sequences of detections by how well they track that
progression. The path scorer is what separates "noise" from
"reconstructed attack chain" in the graph engine downstream.

Reference: MITRE ATT&CK Enterprise Matrix.
"""

from __future__ import annotations

from dataclasses import dataclass

# Ordering from MITRE ATT&CK Enterprise Matrix. Same tactic = 0 step, a
# forward jump across the chain is allowed but costs more than an
# adjacent step. Backwards jumps are penalised — real adversaries may
# loop back (e.g., from impact to credential-access in a ransomware
# pivot) but it's unusual.
TACTIC_ORDER: list[str] = [
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
]

_TACTIC_IDX: dict[str, int] = {t: i for i, t in enumerate(TACTIC_ORDER)}

# ATT&CK technique → tactic. Covers every technique the bundled Sigma
# rules + the MitreEnricher emit. Extend freely — unknown techniques
# still work (they just don't contribute to kill-chain scoring).
TECHNIQUE_TO_TACTIC: dict[str, str] = {
    # Reconnaissance
    "T1589": "reconnaissance",
    "T1598": "reconnaissance",
    # Initial access
    "T1078": "initial-access",
    "T1078.003": "initial-access",
    "T1566": "initial-access",
    "T1566.001": "initial-access",
    "T1566.002": "initial-access",
    "T1566.003": "initial-access",
    "T1566.004": "initial-access",
    # Execution
    "T1059": "execution",
    "T1059.004": "execution",
    "T1204": "execution",
    "T1204.001": "execution",
    "T1204.002": "execution",
    # Persistence
    "T1098": "persistence",
    "T1136": "persistence",
    "T1136.001": "persistence",
    # Privilege escalation
    "T1068": "privilege-escalation",
    "T1548": "privilege-escalation",
    "T1548.003": "privilege-escalation",
    # Defense evasion
    "T1036": "defense-evasion",
    "T1036.005": "defense-evasion",
    "T1070": "defense-evasion",
    "T1070.002": "defense-evasion",
    "T1562": "defense-evasion",
    "T1562.004": "defense-evasion",
    # Credential access
    "T1003": "credential-access",
    "T1003.008": "credential-access",
    "T1110": "credential-access",
    "T1110.001": "credential-access",
    "T1110.003": "credential-access",
    # Discovery
    "T1046": "discovery",
    "T1087": "discovery",
    # Lateral movement
    "T1021": "lateral-movement",
    "T1021.004": "lateral-movement",
    # Command and control
    "T1071": "command-and-control",
    # Exfiltration
    "T1048": "exfiltration",
    # Impact
    "T1485": "impact",
    "T1486": "impact",  # Ransomware
    "T1490": "impact",  # Inhibit System Recovery
    "T1534": "lateral-movement",
}


@dataclass
class KillChainScore:
    """Output of scoring a candidate attack path."""

    score: float
    """0.0 = random noise, 1.0 = textbook kill-chain progression."""

    tactics_covered: list[str]
    """Ordered list of tactics the path touches (deduplicated)."""

    forward_steps: int
    """How many transitions advanced along the kill chain."""

    backward_steps: int
    """How many transitions went backwards (penalised)."""

    same_tactic_steps: int
    """Lateral hops within the same tactic (slight penalty)."""


def tactic_of(technique_id: str) -> str | None:
    """Return the tactic for a technique ID (handles sub-techniques)."""
    if technique_id in TECHNIQUE_TO_TACTIC:
        return TECHNIQUE_TO_TACTIC[technique_id]
    # Fallback: strip a `.NNN` suffix and try again
    base = technique_id.split(".", 1)[0]
    return TECHNIQUE_TO_TACTIC.get(base)


def score_path(technique_ids: list[str]) -> KillChainScore:
    """Score a sequence of ATT&CK techniques by kill-chain progression.

    Higher score means the sequence moves forward along the standard
    kill chain (initial-access → credential-access → lateral-movement →
    impact is a perfect 1.0) with minimal back-tracking. Pure in-tactic
    noise scores near 0.
    """
    tactics = [tactic_of(t) for t in technique_ids]
    tactics = [t for t in tactics if t is not None]
    if len(tactics) < 2:
        # Single-step paths have no progression — neutral score.
        return KillChainScore(score=0.25 if tactics else 0.0, tactics_covered=tactics, forward_steps=0, backward_steps=0, same_tactic_steps=0)

    forward = backward = same = 0
    unique_tactics: list[str] = []
    for t in tactics:
        if not unique_tactics or unique_tactics[-1] != t:
            unique_tactics.append(t)

    for a, b in zip(tactics, tactics[1:], strict=False):
        ia, ib = _TACTIC_IDX.get(a, -1), _TACTIC_IDX.get(b, -1)
        if ia < 0 or ib < 0:
            continue
        if ib > ia:
            forward += 1
        elif ib < ia:
            backward += 1
        else:
            same += 1

    total = forward + backward + same
    if total == 0:
        return KillChainScore(score=0.0, tactics_covered=unique_tactics, forward_steps=0, backward_steps=0, same_tactic_steps=0)

    # Weights: forward +1, same-tactic +0.25, backward -0.5.
    raw = forward + 0.25 * same - 0.5 * backward
    # Normalise to [0, 1] relative to the ideal (every step forward).
    ideal = total
    score = max(0.0, min(1.0, raw / ideal))

    # Bonus for covering multiple distinct tactics — a 5-tactic chain
    # is meaningfully stronger evidence than a 2-tactic chain.
    coverage_bonus = min(0.2, 0.04 * (len(set(unique_tactics)) - 2))
    score = min(1.0, score + max(0.0, coverage_bonus))

    return KillChainScore(
        score=round(score, 3),
        tactics_covered=unique_tactics,
        forward_steps=forward,
        backward_steps=backward,
        same_tactic_steps=same,
    )
