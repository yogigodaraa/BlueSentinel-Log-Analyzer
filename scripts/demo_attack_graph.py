#!/usr/bin/env python3
"""End-to-end demo: feed a synthetic attack sequence + noise into the
graph engine, print the reconstructed chains with scores, emit a Mermaid
diagram of the top chain.

Run:
    python scripts/demo_attack_graph.py
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta

from bluesentinel.graph import AttackGraphEngine, chain_to_mermaid
from bluesentinel.types import Detection, LogEvent, Severity


def synthetic() -> list[Detection]:
    """Realistic auth.log-ish attack sequence interleaved with background noise."""
    t0 = datetime(2026, 4, 20, 9, 0, 0)

    def mk(msg, minutes, *, user="root", host="prod-01", ip="203.0.113.5",
           techniques=None, severity=Severity.MEDIUM):
        ev = LogEvent(
            timestamp=t0 + timedelta(minutes=minutes),
            message=msg,
            user=user,
            host=host,
            source_ip=ip,
            severity=severity,
            mitre_techniques=techniques or [],
        )
        return Detection(
            event=ev,
            detector="demo",
            score=0.9,
            threshold=0.5,
            explanation="demo",
            mitre_techniques=techniques or [],
        )

    events: list[Detection] = []
    # --- BACKGROUND NOISE (should not be in the attack chain) ---
    events += [
        mk("cron: job ran", 30 * i, user=f"svc-{i%3}", host=f"host-{i%5}",
           ip=f"10.0.{i}.2", techniques=[])
        for i in range(6)
    ]

    # --- ATTACK CHAIN ---
    # Textbook kill chain across ~25 minutes, one source IP, one user
    attack_ip = "203.0.113.5"
    attack_host = "prod-01"
    events += [
        # 20x brute force attempts
        *[
            mk(f"Failed password for root from {attack_ip}", 5 + i,
               user="root", host=attack_host, ip=attack_ip,
               techniques=["T1110.001"], severity=Severity.HIGH)
            for i in range(4)
        ],
        mk("Accepted password for root from 203.0.113.5", 10,
           user="root", host=attack_host, ip=attack_ip,
           techniques=["T1078.003"], severity=Severity.HIGH),
        mk("sudo: authentication failure for root", 12,
           user="root", host=attack_host, ip=attack_ip,
           techniques=["T1548.003"], severity=Severity.HIGH),
        mk("discovery: cat /etc/passwd", 15,
           user="root", host=attack_host, ip=attack_ip,
           techniques=["T1087"], severity=Severity.MEDIUM),
        mk("ssh to db-03 succeeded", 18,
           user="root", host=attack_host, ip=attack_ip,
           techniques=["T1021.004"], severity=Severity.HIGH),
        mk("iptables -F", 22,
           user="root", host=attack_host, ip=attack_ip,
           techniques=["T1562.004"], severity=Severity.CRITICAL),
        mk("rm /var/log/auth.log", 25,
           user="root", host=attack_host, ip=attack_ip,
           techniques=["T1070.002"], severity=Severity.CRITICAL),
        mk("rm -rf /data/warehouse/*", 27,
           user="root", host=attack_host, ip=attack_ip,
           techniques=["T1485"], severity=Severity.CRITICAL),
    ]
    return events


def main() -> int:
    detections = synthetic()
    engine = AttackGraphEngine(min_overall_score=0.4)
    chains = engine.reconstruct(detections)

    print(f"Input: {len(detections)} detections")
    print(f"Reconstructed: {len(chains)} attack chains (score ≥ 0.4)\n")

    if not chains:
        print("No chains found above threshold.")
        return 0

    for i, c in enumerate(chains, 1):
        print(f"─── Chain {i} ─── overall {c.overall_score:.2f} " f"(kill-chain {c.kill_chain.score:.2f} · " f"severity {c.severity_integral:.2f} · " f"entity {c.entity_consistency:.2f} · " f"time {c.time_compactness:.2f})")
        print(f"  {c.summary()}")
        print(f"  Techniques: {' → '.join(c.mitre_techniques)}")
        print(f"  Tactics:    {' → '.join(c.kill_chain.tactics_covered)}")
        print(f"  Events:     {len(c.detections)}")
        print()

    # Dump top chain as JSON
    print("\n=== Top chain (JSON) ===")
    print(json.dumps(chains[0].to_dict(), indent=2, default=str))

    # Mermaid diagram
    print("\n=== Top chain (Mermaid) ===")
    print(chain_to_mermaid(chains[0]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
