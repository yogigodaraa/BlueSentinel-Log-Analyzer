/**
 * Types for the client-side analysis engine. Mirrors the Python
 * equivalents in `src/bluesentinel/types.py` closely enough that a
 * JSON payload from the FastAPI service would round-trip.
 */

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface LogEvent {
  timestamp: Date;
  message: string;
  host: string | null;
  user: string | null;
  sourceIp: string | null;
  processName: string | null;
  processPid: number | null;
  severity: Severity;
  mitreTechniques: string[];
  raw: string;
}

export interface Detection {
  event: LogEvent;
  detector: string;
  score: number;
  threshold: number;
  explanation: string;
  mitreTechniques: string[];
  sigmaRuleId: string | null;
}

export interface AttackChain {
  id: string;
  detections: Detection[];
  entities: Record<string, string[]>;
  mitreTechniques: string[];
  tacticsCovered: string[];
  killChainScore: number;
  severityIntegral: number;
  entityConsistency: number;
  timeCompactness: number;
  overallScore: number;
  summary: string;
}
