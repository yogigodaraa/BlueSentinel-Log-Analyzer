import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "BlueSentinel — AI Log Anomaly Detection",
  description:
    "Machine-learning log monitoring for SOC teams. Ingests auth and firewall logs, detects anomalies with Isolation Forest, and generates plain-English incident summaries.",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" className="antialiased">
      <body>{children}</body>
    </html>
  );
}
