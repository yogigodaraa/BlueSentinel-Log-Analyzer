export default function Home() {
  const stages = [
    { n: "01", name: "Parse", desc: "Regex-based ingestion of Linux auth + firewall logs" },
    { n: "02", name: "Detect", desc: "Unsupervised Isolation Forest — no labeled data required" },
    { n: "03", name: "Classify", desc: "Rule-based severity + IP frequency analysis" },
    { n: "04", name: "Summarize", desc: "Natural-language incident reports via OpenAI" },
    { n: "05", name: "Report", desc: "Console alerts + dated alerts_report.txt export" },
  ];

  return (
    <main className="min-h-screen flex flex-col">
      {/* Hero */}
      <section className="flex-1 flex items-center justify-center px-6 py-24 relative overflow-hidden">
        <div
          aria-hidden="true"
          className="pointer-events-none absolute -top-40 left-1/2 -translate-x-1/2 w-[800px] h-[600px] rounded-full opacity-20 blur-[120px]"
          style={{ background: "radial-gradient(ellipse at center, #3b82f6, #1e40af 50%, transparent 80%)" }}
        />
        <div className="relative max-w-2xl text-center">
          <p className="text-xs uppercase tracking-widest text-zinc-500">SOC Defense, Automated</p>
          <h1 className="mt-4 text-5xl sm:text-6xl font-extrabold tracking-tight">
            <span className="bg-clip-text text-transparent" style={{ backgroundImage: "linear-gradient(135deg,#3b82f6,#60a5fa)" }}>
              BlueSentinel
            </span>
          </h1>
          <p className="mt-6 text-lg text-zinc-400 leading-relaxed">
            AI-powered log anomaly detection for security operations. Parses system logs,
            flags suspicious behavior with ML, writes plain-English incident summaries.
          </p>
          <div className="mt-8 flex flex-wrap justify-center gap-3">
            <a href="https://github.com/yogigodaraa/BlueSentinel-Log-Analyzer" target="_blank" rel="noopener noreferrer"
              className="rounded-full px-6 py-3 text-sm font-semibold text-white shadow-lg"
              style={{ backgroundImage: "linear-gradient(135deg,#3b82f6,#1e40af)" }}>
              View on GitHub →
            </a>
          </div>
        </div>
      </section>

      {/* Pipeline */}
      <section className="px-6 py-16 border-t border-zinc-800">
        <div className="mx-auto max-w-4xl">
          <h2 className="text-2xl font-bold text-center">The 5-stage pipeline</h2>
          <div className="mt-10 space-y-3">
            {stages.map((s) => (
              <div key={s.n} className="flex gap-5 rounded-xl border border-zinc-800 bg-zinc-900/50 p-5">
                <span className="text-3xl font-black text-transparent bg-clip-text"
                  style={{ backgroundImage: "linear-gradient(180deg,#3b82f6,#1e40af)" }}>
                  {s.n}
                </span>
                <div>
                  <p className="text-base font-semibold text-zinc-200">{s.name}</p>
                  <p className="mt-1 text-sm text-zinc-400">{s.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Stack */}
      <section className="px-6 py-16 border-t border-zinc-800">
        <div className="mx-auto max-w-3xl text-center">
          <h2 className="text-2xl font-bold">Tech stack</h2>
          <p className="mt-4 text-zinc-400">
            Python 3 · scikit-learn (Isolation Forest) · pandas · numpy ·
            OpenAI API (summaries) · Flask (optional dashboard) · loguru · joblib
          </p>
        </div>
      </section>

      <footer className="border-t border-zinc-800 px-6 py-8 text-center text-xs text-zinc-600">
        <p>
          Built by <a href="https://github.com/yogigodaraa" className="hover:text-zinc-400">Yogi</a>.
          Licensed MIT.
        </p>
      </footer>
    </main>
  );
}
