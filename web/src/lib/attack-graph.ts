/**
 * Client-side port of the Python AttackGraphEngine.
 *
 * Same scoring model:
 *   overall = 0.4*killChain + 0.25*severity + 0.2*entityConsistency + 0.15*timeCompactness
 *
 * Same graph construction: connect two detections if they share any
 * entity (user/host/sourceIp/processName) AND occur within a time
 * window (default 4 hours).
 */

import type { AttackChain, Detection, Severity } from "./types";
import { TACTIC_ORDER, TECHNIQUE_TO_TACTIC } from "./mitre";

const TIME_WINDOW_MS = 4 * 60 * 60 * 1000;
const MIN_CHAIN_LEN = 2;
const MIN_OVERALL = 0.3;

const ENTITY_FIELDS = ["user", "host", "sourceIp", "processName"] as const;
type EntityField = (typeof ENTITY_FIELDS)[number];

const SEV_WEIGHT: Record<Severity, number> = {
  info: 0.1,
  low: 0.25,
  medium: 0.5,
  high: 0.75,
  critical: 1.0,
};

const TACTIC_IDX: Record<string, number> = TACTIC_ORDER.reduce<Record<string, number>>(
  (acc, t, i) => {
    acc[t] = i;
    return acc;
  },
  {},
);

export function tacticOf(technique: string): string | undefined {
  if (TECHNIQUE_TO_TACTIC[technique]) return TECHNIQUE_TO_TACTIC[technique];
  const base = technique.split(".")[0];
  return TECHNIQUE_TO_TACTIC[base];
}

/** Kill-chain progression score — higher = more adversarial-looking order. */
export function scorePath(techniqueIds: string[]) {
  const tactics = techniqueIds
    .map((t) => tacticOf(t))
    .filter((t): t is string => !!t);
  if (tactics.length < 2) {
    return {
      score: tactics.length ? 0.25 : 0,
      tacticsCovered: tactics,
      forward: 0,
      backward: 0,
      same: 0,
    };
  }
  let forward = 0;
  let backward = 0;
  let same = 0;
  for (let i = 1; i < tactics.length; i++) {
    const ia = TACTIC_IDX[tactics[i - 1]];
    const ib = TACTIC_IDX[tactics[i]];
    if (ia === undefined || ib === undefined) continue;
    if (ib > ia) forward++;
    else if (ib < ia) backward++;
    else same++;
  }
  const total = forward + backward + same;
  if (total === 0) {
    return { score: 0, tacticsCovered: dedupeOrdered(tactics), forward, backward, same };
  }
  const raw = forward + 0.25 * same - 0.5 * backward;
  const unique = dedupeOrdered(tactics);
  const bonus = Math.min(0.2, 0.04 * Math.max(0, unique.length - 2));
  return {
    score: Math.max(0, Math.min(1, raw / total + bonus)),
    tacticsCovered: unique,
    forward,
    backward,
    same,
  };
}

function dedupeOrdered(arr: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const a of arr) {
    if (!seen.has(a)) {
      seen.add(a);
      out.push(a);
    }
  }
  return out;
}

function sharesEntity(a: Detection, b: Detection): boolean {
  for (const f of ENTITY_FIELDS) {
    const va = a.event[f as EntityField];
    const vb = b.event[f as EntityField];
    if (va && vb && va === vb) return true;
  }
  return false;
}

export function reconstructChains(detections: Detection[]): AttackChain[] {
  if (detections.length < MIN_CHAIN_LEN) return [];
  const sorted = [...detections].sort(
    (a, b) => a.event.timestamp.getTime() - b.event.timestamp.getTime(),
  );

  // Build adjacency
  const adj: number[][] = sorted.map(() => []);
  for (let i = 0; i < sorted.length; i++) {
    for (let j = i + 1; j < sorted.length; j++) {
      const gap = sorted[j].event.timestamp.getTime() - sorted[i].event.timestamp.getTime();
      if (gap > TIME_WINDOW_MS) break;
      if (gap < 0) continue;
      if (sharesEntity(sorted[i], sorted[j])) {
        adj[i].push(j);
        adj[j].push(i);
      }
    }
  }

  // Connected components via BFS
  const visited = new Set<number>();
  const chains: AttackChain[] = [];
  for (let start = 0; start < sorted.length; start++) {
    if (visited.has(start)) continue;
    const cluster: number[] = [];
    const stack = [start];
    while (stack.length) {
      const node = stack.pop()!;
      if (visited.has(node)) continue;
      visited.add(node);
      cluster.push(node);
      for (const n of adj[node]) if (!visited.has(n)) stack.push(n);
    }
    if (cluster.length < MIN_CHAIN_LEN) continue;
    cluster.sort((a, b) => a - b);
    chains.push(scoreChain(cluster.map((i) => sorted[i])));
  }

  return chains
    .filter((c) => c.overallScore >= MIN_OVERALL)
    .sort((a, b) => b.overallScore - a.overallScore);
}

function scoreChain(path: Detection[]): AttackChain {
  // Entities
  const entities: Record<string, string[]> = {};
  for (const f of ENTITY_FIELDS) entities[f] = [];
  for (const d of path) {
    for (const f of ENTITY_FIELDS) {
      const v = d.event[f as EntityField];
      if (v && !entities[f].includes(String(v))) entities[f].push(String(v));
    }
  }

  // Entity consistency — fraction of hops that preserve at least one entity
  let consistentHops = 0;
  const totalHops = Math.max(path.length - 1, 1);
  for (let i = 1; i < path.length; i++) {
    for (const f of ENTITY_FIELDS) {
      const va = path[i - 1].event[f as EntityField];
      const vb = path[i].event[f as EntityField];
      if (va && vb && va === vb) {
        consistentHops++;
        break;
      }
    }
  }
  const entityConsistency = consistentHops / totalHops;

  // Severity integral
  const sevTotal = path.reduce((acc, d) => acc + (SEV_WEIGHT[d.event.severity] ?? 0.5), 0);
  const severityIntegral = Math.min(sevTotal / path.length + Math.min(sevTotal, 5) * 0.1, 1);

  // Time compactness
  const span =
    (path[path.length - 1].event.timestamp.getTime() - path[0].event.timestamp.getTime()) /
    1000;
  const timeCompactness = Math.max(0, Math.min(1, 1 - span / (TIME_WINDOW_MS / 1000)));

  // MITRE techniques across the chain (dedup, preserve order)
  const seen = new Set<string>();
  const techniques: string[] = [];
  for (const d of path) {
    const pool = d.mitreTechniques.length ? d.mitreTechniques : d.event.mitreTechniques;
    for (const t of pool) {
      if (!seen.has(t)) {
        seen.add(t);
        techniques.push(t);
      }
    }
  }
  const kc = scorePath(techniques);

  const overallScore =
    0.4 * kc.score + 0.25 * severityIntegral + 0.2 * entityConsistency + 0.15 * timeCompactness;

  const start = path[0].event.timestamp;
  const id = `chain-${start.toISOString().replace(/[:TZ.]/g, "-").slice(0, 17)}-${path.length
    .toString()
    .padStart(3, "0")}`;

  const summary = buildSummary(path, entities, kc.tacticsCovered, overallScore);

  return {
    id,
    detections: path,
    entities,
    mitreTechniques: techniques,
    tacticsCovered: kc.tacticsCovered,
    killChainScore: kc.score,
    severityIntegral,
    entityConsistency,
    timeCompactness,
    overallScore,
    summary,
  };
}

function buildSummary(
  path: Detection[],
  entities: Record<string, string[]>,
  tactics: string[],
  overall: number,
): string {
  const start = path[0].event.timestamp;
  const end = path[path.length - 1].event.timestamp;
  const dur = end.getTime() - start.getTime();
  const ents = Object.entries(entities)
    .filter(([, v]) => v.length)
    .map(([k, v]) => `${k}=${v.slice(0, 3).join(",")}`)
    .join(" · ");
  return `${path.length} events over ${fmtDuration(dur)} — tactics: ${tactics.join(
    " → ",
  ) || "(none)"} — ${ents} — overall ${overall.toFixed(2)}`;
}

function fmtDuration(ms: number): string {
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m`;
  return `${Math.floor(s / 3600)}h${Math.floor((s % 3600) / 60).toString().padStart(2, "0")}m`;
}

/** Render chain as Mermaid flowchart for display. */
export function chainToMermaid(chain: AttackChain): string {
  const colour: Record<Severity, string> = {
    critical: "#ef4444",
    high: "#f97316",
    medium: "#eab308",
    low: "#22c55e",
    info: "#94a3b8",
  };
  const lines: string[] = ["flowchart LR"];
  chain.detections.forEach((d, i) => {
    const nid = `N${i}`;
    const label = (d.event.message || d.detector).replace(/"/g, "'").slice(0, 40);
    const ts = d.event.timestamp.toISOString().slice(11, 19);
    lines.push(`    ${nid}["${ts} — ${label}"]`);
    lines.push(`    style ${nid} fill:${colour[d.event.severity] ?? "#94a3b8"},color:#fff`);
  });
  for (let i = 0; i < chain.detections.length - 1; i++) {
    const nextTech = chain.detections[i + 1].mitreTechniques[0] ?? "";
    const tactic = nextTech ? tacticOf(nextTech) : "";
    const edge = nextTech ? `${nextTech} (${tactic})` : " ";
    lines.push(`    N${i} -->|${edge}| N${i + 1}`);
  }
  return lines.join("\n");
}
