"""Attack-graph reconstruction engine.

Given a stream of `Detection`s, this builds a temporal + entity graph
and finds sequences of detections that look like coordinated attacks
— not random noise.

Entities tracked:
    user, host, source_ip, process_name

Two detections are connected in the graph if they:

1. Share at least one entity (same user, same host, same source IP, or
   same process); and
2. Occur within a configurable time window (default 4 hours).

We then mine connected paths through the graph and score each by:

- **kill-chain progression** — does the MITRE ATT&CK tactic sequence
  advance forward? (See ``kill_chain.py``.)
- **severity integral** — sum of per-detection severities.
- **entity consistency** — fraction of hops that share the *same*
  entity (not just any entity).
- **time compactness** — dense attacks in a short window are stronger
  evidence than detections scattered across days.

Output: ranked list of ``AttackChain`` objects with full detection
trail, involved entities, covered tactics, timeline, and a narrative
description suitable for a SIEM alert.

This is the capability that separates toy anomaly detectors from real
UBA platforms (Splunk UBA, Exabeam Fusion, Microsoft Sentinel Fusion).
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Iterable

from bluesentinel.graph.kill_chain import KillChainScore, score_path, tactic_of
from bluesentinel.types import Detection, Severity


# ─── Public types ────────────────────────────────────────────────────────

@dataclass
class AttackChain:
    """A reconstructed multi-step attack."""

    id: str
    detections: list[Detection]
    entities: dict[str, set[str]] = field(default_factory=dict)
    mitre_techniques: list[str] = field(default_factory=list)
    kill_chain: KillChainScore | None = None

    # Derived scores
    severity_integral: float = 0.0
    time_compactness: float = 0.0
    entity_consistency: float = 0.0
    overall_score: float = 0.0
    """Combined 0-1 score. Anything ≥ 0.5 is worth an analyst's attention."""

    def summary(self) -> str:
        """Plain-English summary of the attack — suitable for an alert body."""
        if not self.detections:
            return "(empty chain)"
        start = min(d.event.timestamp for d in self.detections)
        end = max(d.event.timestamp for d in self.detections)
        dur = end - start
        tactics = self.kill_chain.tactics_covered if self.kill_chain else []
        entities_summary = ", ".join(
            f"{k}={','.join(sorted(v))[:60]}" for k, v in self.entities.items() if v
        )
        return (
            f"Attack chain {self.id} — {len(self.detections)} events over {_fmt_duration(dur)} — "
            f"tactics: {' → '.join(tactics) or '(none)'} — "
            f"entities: {entities_summary or '(none)'} — "
            f"overall score {self.overall_score:.2f}"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "summary": self.summary(),
            "detections": [d.to_dict() for d in self.detections],
            "entities": {k: sorted(v) for k, v in self.entities.items()},
            "mitre_techniques": self.mitre_techniques,
            "kill_chain": (
                {
                    "score": self.kill_chain.score,
                    "tactics_covered": self.kill_chain.tactics_covered,
                    "forward_steps": self.kill_chain.forward_steps,
                    "backward_steps": self.kill_chain.backward_steps,
                    "same_tactic_steps": self.kill_chain.same_tactic_steps,
                }
                if self.kill_chain
                else None
            ),
            "severity_integral": round(self.severity_integral, 3),
            "time_compactness": round(self.time_compactness, 3),
            "entity_consistency": round(self.entity_consistency, 3),
            "overall_score": round(self.overall_score, 3),
        }


# ─── Engine ──────────────────────────────────────────────────────────────

_SEV_WEIGHT = {
    Severity.INFO: 0.1,
    Severity.LOW: 0.25,
    Severity.MEDIUM: 0.5,
    Severity.HIGH: 0.75,
    Severity.CRITICAL: 1.0,
}

_ENTITY_FIELDS = ("user", "host", "source_ip", "process_name")


@dataclass
class AttackGraphEngine:
    """Build + score attack graphs from a detection stream."""

    time_window: timedelta = timedelta(hours=4)
    min_chain_length: int = 2
    min_overall_score: float = 0.3
    max_chains: int = 50
    """Cap on chains returned — beyond this, trim the lowest-scoring."""

    def reconstruct(self, detections: Iterable[Detection]) -> list[AttackChain]:
        """Run the full pipeline: graph build → path mining → scoring → ranking."""
        dets = sorted(detections, key=lambda d: d.event.timestamp)
        if len(dets) < self.min_chain_length:
            return []

        adjacency = self._build_graph(dets)
        raw_paths = self._mine_paths(dets, adjacency)
        chains = [self._score(path, dets) for path in raw_paths]
        chains = [c for c in chains if c.overall_score >= self.min_overall_score]
        chains.sort(key=lambda c: c.overall_score, reverse=True)
        return chains[: self.max_chains]

    # ─── Internals ──────────────────────────────────────────────────────

    def _build_graph(self, dets: list[Detection]) -> dict[int, set[int]]:
        """Adjacency list: index → indices it's connected to."""
        adj: dict[int, set[int]] = defaultdict(set)
        for i, di in enumerate(dets):
            for j in range(i + 1, len(dets)):
                dj = dets[j]
                gap = dj.event.timestamp - di.event.timestamp
                if gap > self.time_window:
                    break  # dets is sorted, everything after is further away
                if gap < timedelta(0):
                    continue
                if _shares_entity(di, dj):
                    adj[i].add(j)
                    adj[j].add(i)
        return adj

    def _mine_paths(
        self,
        dets: list[Detection],
        adj: dict[int, set[int]],
    ) -> list[list[int]]:
        """Find connected components that respect temporal ordering.

        Simpler than full path enumeration: we DFS forward from each
        detection and collect the earliest-to-latest chain through
        connected nodes. This gets us one chain per weakly connected
        cluster, which is what analysts actually want — not an
        exponential blow-up of overlapping paths.
        """
        visited: set[int] = set()
        chains: list[list[int]] = []
        for start in range(len(dets)):
            if start in visited:
                continue
            # BFS-style accumulation of all reachable indices
            cluster: set[int] = set()
            stack = [start]
            while stack:
                node = stack.pop()
                if node in cluster:
                    continue
                cluster.add(node)
                stack.extend(adj[node])
            visited |= cluster
            if len(cluster) >= self.min_chain_length:
                chains.append(sorted(cluster))
        return chains

    def _score(self, indices: list[int], dets: list[Detection]) -> AttackChain:
        path = [dets[i] for i in indices]

        # Entity accumulation
        entities: dict[str, set[str]] = {f: set() for f in _ENTITY_FIELDS}
        for d in path:
            for f in _ENTITY_FIELDS:
                v = getattr(d.event, f, None)
                if v:
                    entities[f].add(str(v))

        # Entity consistency: fraction of hops that preserve the same
        # value in AT LEAST ONE entity field.
        consistent_hops = 0
        total_hops = max(len(path) - 1, 1)
        for a, b in zip(path, path[1:], strict=False):
            for f in _ENTITY_FIELDS:
                va = getattr(a.event, f, None)
                vb = getattr(b.event, f, None)
                if va and vb and va == vb:
                    consistent_hops += 1
                    break
        entity_consistency = consistent_hops / total_hops

        # Severity integral — sum of per-detection severity weights,
        # normalised by path length so 10-event paths don't dominate.
        sev_total = sum(_SEV_WEIGHT.get(d.event.severity, 0.5) for d in path)
        severity_integral = min(sev_total / max(len(path), 1) + min(sev_total, 5) * 0.1, 1.0)

        # Time compactness: a chain finishing in 30 min is stronger
        # evidence than one spread over 4 hours.
        start = path[0].event.timestamp
        end = path[-1].event.timestamp
        span = (end - start).total_seconds()
        # Scale: < 5 min = 1.0, >= full window = 0.0
        window_sec = self.time_window.total_seconds()
        compactness = max(0.0, min(1.0, 1.0 - span / max(window_sec, 1)))

        # MITRE techniques along the path, deduplicated while preserving order
        seen: set[str] = set()
        techniques: list[str] = []
        for d in path:
            pool = d.mitre_techniques or d.event.mitre_techniques or []
            for t in pool:
                if t not in seen:
                    seen.add(t)
                    techniques.append(t)

        kc = score_path(techniques)

        # Combined score — weighted blend. Weights chosen so no single
        # component can fully dominate; kill-chain progression matters
        # most because that's what distinguishes attacks from noise.
        overall = (
            0.40 * kc.score
            + 0.25 * severity_integral
            + 0.20 * entity_consistency
            + 0.15 * compactness
        )

        chain = AttackChain(
            id=_chain_id(path),
            detections=path,
            entities=entities,
            mitre_techniques=techniques,
            kill_chain=kc,
            severity_integral=severity_integral,
            time_compactness=compactness,
            entity_consistency=entity_consistency,
            overall_score=overall,
        )
        return chain


# ─── Helpers ─────────────────────────────────────────────────────────────

def _shares_entity(a: Detection, b: Detection) -> bool:
    for f in _ENTITY_FIELDS:
        va = getattr(a.event, f, None)
        vb = getattr(b.event, f, None)
        if va and vb and va == vb:
            return True
    return False


def _chain_id(path: list[Detection]) -> str:
    first = path[0].event.timestamp.strftime("%Y%m%d-%H%M%S")
    return f"chain-{first}-{len(path):03d}"


def _fmt_duration(d: timedelta) -> str:
    secs = int(d.total_seconds())
    if secs < 60:
        return f"{secs}s"
    if secs < 3600:
        return f"{secs // 60}m"
    if secs < 86400:
        return f"{secs // 3600}h{(secs % 3600) // 60:02d}m"
    return f"{secs // 86400}d{(secs % 86400) // 3600}h"


# ─── Path-rendering helpers ─────────────────────────────────────────────

def chain_to_mermaid(chain: AttackChain) -> str:
    """Render an AttackChain as a Mermaid flowchart (for README / dashboard embed).

    Each detection becomes a node; the edge labels show the MITRE
    technique chain. Nodes are coloured by severity.
    """
    lines = ["flowchart LR"]
    colour_for = {
        Severity.CRITICAL: "#ef4444",
        Severity.HIGH: "#f97316",
        Severity.MEDIUM: "#eab308",
        Severity.LOW: "#22c55e",
        Severity.INFO: "#94a3b8",
    }
    for i, d in enumerate(chain.detections):
        nid = f"N{i}"
        label = (d.event.message or d.detector)[:40].replace('"', "'")
        ts = d.event.timestamp.strftime("%H:%M:%S")
        lines.append(f'    {nid}["{ts} — {label}"]')
        lines.append(f'    style {nid} fill:{colour_for.get(d.event.severity, "#94a3b8")}')
    for i, (a, b) in enumerate(zip(chain.detections, chain.detections[1:], strict=False)):
        tech = (b.mitre_techniques or b.event.mitre_techniques or [""])[0]
        tactic = tactic_of(tech) if tech else ""
        edge_label = f"{tech} ({tactic})" if tech else ""
        lines.append(f"    N{i} -->|{edge_label}| N{i+1}")
    return "\n".join(lines)
