"""Attack-graph reconstruction — the capability that separates toy anomaly
detectors from real UBA platforms (Splunk UBA, Exabeam, Microsoft Sentinel).

Given a stream of ``Detection`` objects, the ``AttackGraphEngine`` builds
a temporal + entity graph and finds connected detection sequences that
look like coordinated attacks, scored by:

- Kill-chain progression (MITRE ATT&CK tactic advancement)
- Severity integral
- Entity consistency (same user/host across the chain)
- Temporal compactness

Output: ranked ``AttackChain`` objects with full detection trail,
involved entities, covered tactics, timeline, and a Mermaid flowchart
renderer for the dashboard / SIEM alerts.
"""

from bluesentinel.graph.engine import (
    AttackChain,
    AttackGraphEngine,
    chain_to_mermaid,
)
from bluesentinel.graph.kill_chain import (
    KillChainScore,
    TACTIC_ORDER,
    TECHNIQUE_TO_TACTIC,
    score_path,
    tactic_of,
)

__all__ = [
    "AttackChain",
    "AttackGraphEngine",
    "KillChainScore",
    "TACTIC_ORDER",
    "TECHNIQUE_TO_TACTIC",
    "chain_to_mermaid",
    "score_path",
    "tactic_of",
]
