"use client";

import { useMemo, useState } from "react";

import { enrichAll } from "@/lib/mitre";
import { parseText } from "@/lib/parser";
import { SAMPLES } from "@/lib/samples";
import { evaluateAll } from "@/lib/sigma";
import { reconstructChains, chainToMermaid } from "@/lib/attack-graph";
import type { AttackChain, Detection, Severity } from "@/lib/types";

const SEV_COLOR: Record<Severity, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
  info: "#94a3b8",
};

export default function DemoPage() {
  const [logText, setLogText] = useState<string>(SAMPLES[0].log);
  const [activeSample, setActiveSample] = useState<string>(SAMPLES[0].id);

  const result = useMemo(() => analyse(logText), [logText]);

  return (
    <main className="min-h-screen">
      {/* Header */}
      <section className="border-b border-zinc-800 px-6 py-10">
        <div className="mx-auto max-w-6xl">
          <p className="text-xs uppercase tracking-widest text-zinc-500">Interactive demo</p>
          <h1 className="mt-3 text-4xl font-extrabold tracking-tight">
            <span
              className="bg-clip-text text-transparent"
              style={{ backgroundImage: "linear-gradient(135deg,#3b82f6,#60a5fa)" }}
            >
              BlueSentinel
            </span>{" "}
            in your browser
          </h1>
          <p className="mt-3 max-w-2xl text-zinc-400">
            Paste auth.log lines below — or pick a preset. The parser, MITRE ATT&amp;CK enricher,
            Sigma rules engine, and attack-graph reconstructor all run client-side in TypeScript.
            No server call. No API key. Real output.
          </p>
        </div>
      </section>

      {/* Presets + textarea */}
      <section className="px-6 py-8">
        <div className="mx-auto max-w-6xl space-y-4">
          <div className="flex flex-wrap gap-2">
            {SAMPLES.map((s) => (
              <button
                key={s.id}
                type="button"
                onClick={() => {
                  setLogText(s.log);
                  setActiveSample(s.id);
                }}
                className="rounded-full border px-4 py-1.5 text-xs font-medium transition-colors"
                style={{
                  backgroundColor: activeSample === s.id ? "#1e293b" : "transparent",
                  borderColor: activeSample === s.id ? "#60a5fa" : "#1e2130",
                  color: activeSample === s.id ? "#e4e4e7" : "#9ca3af",
                }}
              >
                {s.title}
              </button>
            ))}
          </div>
          {activeSample && (
            <p className="text-xs text-zinc-500">
              {SAMPLES.find((s) => s.id === activeSample)?.description}
            </p>
          )}
          <textarea
            value={logText}
            onChange={(e) => {
              setLogText(e.target.value);
              setActiveSample("");
            }}
            spellCheck={false}
            className="block h-60 w-full rounded-xl border p-4 font-mono text-[12px] leading-relaxed text-zinc-200 focus:outline-none focus:ring-1 focus:ring-[#60a5fa]"
            style={{ backgroundColor: "#0a0b0f", borderColor: "#1e2130" }}
            placeholder="Apr 20 09:05:00 host sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2"
          />
          <div className="flex gap-6 text-xs text-zinc-500">
            <span>{result.lines} lines parsed</span>
            <span>{result.detections.length} detections</span>
            <span>{result.chains.length} attack chains reconstructed</span>
          </div>
        </div>
      </section>

      {/* Results */}
      <section className="px-6 pb-16">
        <div className="mx-auto max-w-6xl grid gap-8 md:grid-cols-2">
          <DetectionsPanel detections={result.detections} />
          <ChainPanel chains={result.chains} />
        </div>
      </section>

      {/* How it works */}
      <section className="border-t border-zinc-800 px-6 py-10 text-sm text-zinc-400">
        <div className="mx-auto max-w-4xl space-y-4">
          <h2 className="text-lg font-semibold text-zinc-200">How this works</h2>
          <p>
            Same algorithm that ships in the Python backend (<code>src/bluesentinel/</code>),
            ported to TypeScript for the browser. Pipeline:
          </p>
          <ol className="list-decimal space-y-1 pl-6">
            <li>
              <span className="font-semibold">Parse</span> — RFC 3164 syslog format, extract
              host, process, user, source IP.
            </li>
            <li>
              <span className="font-semibold">Enrich</span> — tag events with MITRE ATT&amp;CK
              technique IDs using 11 regex-based rules.
            </li>
            <li>
              <span className="font-semibold">Sigma rules</span> — 5 shipped detection rules
              (SSH brute force, sudo abuse, new account, log tampering, firewall disable).
            </li>
            <li>
              <span className="font-semibold">Attack graph</span> — connect detections that
              share entities within 4 hours; score each connected cluster by kill-chain
              progression (40%), severity (25%), entity consistency (20%), time compactness
              (15%).
            </li>
          </ol>
          <p className="pt-4">
            <a
              href="https://github.com/yogigodaraa/BlueSentinel-Log-Analyzer"
              target="_blank"
              rel="noopener noreferrer"
              className="text-blue-400 hover:underline"
            >
              GitHub repo →
            </a>{" "}
            · Python backend ships additional detectors (Drain3 template mining, DeepLog LSTM,
            LogBERT transformer embeddings) and evaluation against the LogHub datasets.
          </p>
        </div>
      </section>
    </main>
  );
}

// ─── Panels ────────────────────────────────────────────────────────────

function DetectionsPanel({ detections }: { detections: Detection[] }) {
  return (
    <div>
      <h2 className="mb-4 text-lg font-semibold text-zinc-200">Detections</h2>
      {detections.length === 0 ? (
        <div
          className="rounded-xl border p-6 text-center text-sm text-zinc-500"
          style={{ backgroundColor: "#12141c", borderColor: "#1e2130" }}
        >
          No detections — looks benign.
        </div>
      ) : (
        <ul className="space-y-2">
          {detections.slice(0, 30).map((d, i) => (
            <li
              key={`${d.sigmaRuleId}-${i}`}
              className="rounded-lg border p-3"
              style={{ backgroundColor: "#12141c", borderColor: "#1e2130" }}
            >
              <div className="flex items-start gap-3">
                <span
                  className="rounded-full px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider"
                  style={{
                    backgroundColor: `${SEV_COLOR[d.event.severity]}22`,
                    color: SEV_COLOR[d.event.severity],
                    border: `1px solid ${SEV_COLOR[d.event.severity]}55`,
                  }}
                >
                  {d.event.severity}
                </span>
                <div className="min-w-0 flex-1">
                  <p className="text-sm text-zinc-200">{d.explanation}</p>
                  <p className="mt-1 font-mono text-[11px] text-zinc-500 break-all">
                    {d.event.raw}
                  </p>
                  <div className="mt-1 flex flex-wrap gap-2 text-[10px]">
                    {d.mitreTechniques.map((t) => (
                      <span
                        key={t}
                        className="rounded bg-zinc-800 px-1.5 py-0.5 font-mono text-zinc-300"
                      >
                        {t}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </li>
          ))}
          {detections.length > 30 && (
            <li className="pt-2 text-center text-xs text-zinc-500">
              +{detections.length - 30} more…
            </li>
          )}
        </ul>
      )}
    </div>
  );
}

function ChainPanel({ chains }: { chains: AttackChain[] }) {
  return (
    <div>
      <h2 className="mb-4 text-lg font-semibold text-zinc-200">Reconstructed attack chains</h2>
      {chains.length === 0 ? (
        <div
          className="rounded-xl border p-6 text-center text-sm text-zinc-500"
          style={{ backgroundColor: "#12141c", borderColor: "#1e2130" }}
        >
          No chains reconstructed at threshold 0.30.
        </div>
      ) : (
        <div className="space-y-4">
          {chains.map((c) => (
            <div
              key={c.id}
              className="rounded-xl border p-4"
              style={{ backgroundColor: "#12141c", borderColor: "#1e2130" }}
            >
              <div className="mb-2 flex items-center justify-between">
                <p className="font-mono text-xs text-zinc-500">{c.id}</p>
                <span
                  className="rounded-full px-2.5 py-0.5 text-xs font-bold"
                  style={{
                    backgroundColor:
                      c.overallScore > 0.7
                        ? "rgba(239,68,68,0.15)"
                        : c.overallScore > 0.5
                          ? "rgba(249,115,22,0.15)"
                          : "rgba(234,179,8,0.15)",
                    color:
                      c.overallScore > 0.7
                        ? "#ef4444"
                        : c.overallScore > 0.5
                          ? "#f97316"
                          : "#eab308",
                  }}
                >
                  overall {c.overallScore.toFixed(2)}
                </span>
              </div>
              <p className="text-sm text-zinc-200">{c.summary}</p>
              <div className="mt-3 grid grid-cols-4 gap-2 text-[10px] text-zinc-500">
                <div>
                  <p>Kill-chain</p>
                  <p className="font-mono text-zinc-300">{c.killChainScore.toFixed(2)}</p>
                </div>
                <div>
                  <p>Severity</p>
                  <p className="font-mono text-zinc-300">{c.severityIntegral.toFixed(2)}</p>
                </div>
                <div>
                  <p>Entity</p>
                  <p className="font-mono text-zinc-300">{c.entityConsistency.toFixed(2)}</p>
                </div>
                <div>
                  <p>Time</p>
                  <p className="font-mono text-zinc-300">{c.timeCompactness.toFixed(2)}</p>
                </div>
              </div>
              {c.tacticsCovered.length > 0 && (
                <div className="mt-3">
                  <p className="mb-1 text-[10px] uppercase tracking-wider text-zinc-500">
                    Tactics (kill-chain order)
                  </p>
                  <div className="flex flex-wrap gap-1.5 text-[10px]">
                    {c.tacticsCovered.map((t, i) => (
                      <span key={t} className="inline-flex items-center gap-1">
                        <code className="rounded bg-zinc-800 px-1.5 py-0.5 font-mono text-zinc-300">
                          {t}
                        </code>
                        {i < c.tacticsCovered.length - 1 && (
                          <span className="text-zinc-600">→</span>
                        )}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              <details className="mt-3">
                <summary className="cursor-pointer text-xs text-zinc-500 hover:text-zinc-300">
                  Mermaid flowchart source
                </summary>
                <pre className="mt-2 overflow-x-auto rounded bg-zinc-900 p-3 text-[10px] leading-relaxed text-zinc-400">
                  {chainToMermaid(c)}
                </pre>
              </details>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Pipeline ──────────────────────────────────────────────────────────

function analyse(text: string) {
  const events = parseText(text);
  enrichAll(events);
  const detections = evaluateAll(events);
  // Also add MITRE-enriched events as synthetic detections so the
  // attack-graph engine has signals even when no Sigma rule fires.
  for (const ev of events) {
    if (ev.mitreTechniques.length && !detections.find((d) => d.event === ev)) {
      detections.push({
        event: ev,
        detector: "mitre-regex",
        score: 0.5,
        threshold: 0.3,
        explanation: `MITRE ATT&CK regex: ${ev.mitreTechniques.join(", ")}`,
        mitreTechniques: ev.mitreTechniques,
        sigmaRuleId: null,
      });
    }
  }
  const chains = reconstructChains(detections);
  return { lines: events.length, detections, chains };
}
