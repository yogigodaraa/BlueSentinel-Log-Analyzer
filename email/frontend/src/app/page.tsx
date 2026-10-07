"use client";

import React from "react";
import { useRouter } from "next/navigation";
import { Shield, Mail, TrendingUp, AlertTriangle, Activity } from "lucide-react";

export default function HomePage() {
  const router = useRouter();

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900">
      {/* Navigation */}
      <nav className="border-b border-slate-800 bg-slate-900/50 backdrop-blur-lg">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center space-x-3">
              <Shield className="h-8 w-8 text-blue-400" />
              <span className="text-2xl font-bold text-white">SOCShield</span>
            </div>
            <div className="flex items-center space-x-4">
              <button
                onClick={() => router.push("/dashboard")}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
              >
                Dashboard
              </button>
            </div>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-20 pb-16">
        <div className="text-center">
          <div className="flex justify-center mb-6">
            <Shield className="h-24 w-24 text-blue-400" />
          </div>
          <h1 className="text-5xl md:text-6xl font-bold text-white mb-6">
            AI-Driven Phishing Detection
          </h1>
          <p className="text-xl text-slate-300 mb-8 max-w-3xl mx-auto">
            Enterprise-grade autonomous security platform powered by advanced AI.
            Detect, analyze, and respond to phishing threats in real-time.
          </p>
          <div className="flex justify-center gap-4">
            <button
              onClick={() => router.push("/dashboard")}
              className="px-8 py-4 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-semibold text-lg transition-colors shadow-lg shadow-blue-500/50"
            >
              Launch Dashboard
            </button>
            <button
              onClick={() => window.open("https://github.com/yogigodaraa/SOCShield", "_blank")}
              className="px-8 py-4 bg-slate-800 hover:bg-slate-700 text-white rounded-lg font-semibold text-lg transition-colors border border-slate-700"
            >
              View on GitHub
            </button>
          </div>
        </div>

        {/* Features Grid */}
        <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6 mt-20">
          <FeatureCard
            icon={<Mail className="h-8 w-8 text-blue-400" />}
            title="Email Analysis"
            description="Real-time phishing detection with multi-provider AI analysis"
          />
          <FeatureCard
            icon={<AlertTriangle className="h-8 w-8 text-yellow-400" />}
            title="Threat Intelligence"
            description="Multi-source IOC reputation checks and enrichment"
          />
          <FeatureCard
            icon={<Activity className="h-8 w-8 text-green-400" />}
            title="Real-time Monitoring"
            description="Live dashboard with metrics and security events"
          />
          <FeatureCard
            icon={<TrendingUp className="h-8 w-8 text-purple-400" />}
            title="Advanced Analytics"
            description="Comprehensive risk scoring and trend analysis"
          />
        </div>

        {/* Stats Section */}
        <div className="grid md:grid-cols-3 gap-8 mt-20">
          <StatCard
            value="95%+"
            label="Detection Accuracy"
            description="AI-powered phishing detection"
          />
          <StatCard
            value="<3s"
            label="Analysis Time"
            description="Average email processing"
          />
          <StatCard
            value="24/7"
            label="Monitoring"
            description="Continuous threat detection"
          />
        </div>

        {/* Technology Stack */}
        <div className="mt-20 text-center">
          <h2 className="text-3xl font-bold text-white mb-8">
            Production-Grade Technology Stack
          </h2>
          <div className="grid md:grid-cols-3 gap-6">
            <TechCard
              title="Backend"
              items={["FastAPI", "Python", "PostgreSQL", "Redis", "Celery"]}
            />
            <TechCard
              title="AI & ML"
              items={["OpenAI GPT", "Google Gemini", "Claude", "Transformers"]}
            />
            <TechCard
              title="Frontend"
              items={["Next.js", "React", "TypeScript", "TailwindCSS"]}
            />
          </div>
        </div>

        {/* Footer */}
        <div className="mt-20 pt-8 border-t border-slate-800 text-center text-slate-400">
          <p>
            Built with ❤️ for Security Operations Centers | Open Source on{" "}
            <a
              href="https://github.com/yogigodaraa/SOCShield"
              target="_blank"
              rel="noopener noreferrer"
              className="text-blue-400 hover:text-blue-300"
            >
              GitHub
            </a>
          </p>
          <p className="mt-2 text-sm">© 2025 SOCShield | Version 2.0</p>
        </div>
      </div>
    </div>
  );
}

function FeatureCard({
  icon,
  title,
  description,
}: {
  icon: React.ReactNode;
  title: string;
  description: string;
}) {
  return (
    <div className="bg-slate-800/50 backdrop-blur-lg border border-slate-700 rounded-lg p-6 hover:border-blue-500/50 transition-colors">
      <div className="mb-4">{icon}</div>
      <h3 className="text-xl font-semibold text-white mb-2">{title}</h3>
      <p className="text-slate-400">{description}</p>
    </div>
  );
}

function StatCard({
  value,
  label,
  description,
}: {
  value: string;
  label: string;
  description: string;
}) {
  return (
    <div className="bg-gradient-to-br from-slate-800 to-slate-900 border border-slate-700 rounded-lg p-8 text-center">
      <div className="text-4xl font-bold text-blue-400 mb-2">{value}</div>
      <div className="text-xl font-semibold text-white mb-1">{label}</div>
      <div className="text-sm text-slate-400">{description}</div>
    </div>
  );
}

function TechCard({ title, items }: { title: string; items: string[] }) {
  return (
    <div className="bg-slate-800/50 backdrop-blur-lg border border-slate-700 rounded-lg p-6">
      <h3 className="text-xl font-semibold text-white mb-4">{title}</h3>
      <ul className="space-y-2">
        {items.map((item, index) => (
          <li key={index} className="text-slate-300 flex items-center">
            <span className="w-2 h-2 bg-blue-400 rounded-full mr-3"></span>
            {item}
          </li>
        ))}
      </ul>
    </div>
  );
}
