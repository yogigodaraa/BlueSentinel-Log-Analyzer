# 🛡️ BlueSentinel-Log-Analyzer

**BlueSentinel** is an AI-powered log anomaly detection tool built for Security Operations Centers (SOCs). Designed to ingest raw system logs, detect suspicious behavior using machine learning, and generate plain-English incident summaries — it empowers defenders to act faster and smarter.

---

## 🚀 Key Features

🔍 **Log Ingestion & Parsing**  
Supports Linux auth logs, firewall logs, and more. Clean parsing and normalization using Python.

🤖 **Anomaly Detection**  
Uses Isolation Forest to uncover threats like brute-force attacks, privilege escalation, and lateral movement — without needing labeled data.

🧠 **Natural Language Summaries**  
Converts complex log patterns into readable incident reports with context and suggested actions.

📊 **(Optional) Web Dashboard**  
A lightweight Flask UI for viewing alerts, filtering logs by severity, and exporting reports.

📜 **Shell Script Automation**  
CLI tool for quick integration into cron jobs or CI pipelines.

---

## 📂 Project Structure

BlueSentinel-Log-Analyzer/
├── data/ # Sample logs
├── scripts/ # Shell scripts
├── blue_sentinel/ # Core Python modules
│ ├── log_parser.py
│ ├── anomaly_detector.py
│ ├── summarizer.py
│ └── dashboard.py # (optional)
├── tests/ # Unit tests
├── main.py # Entry point
├── requirements.txt
└── README.md


---

## ⚙️ Tech Stack

- Python 3.x
- scikit-learn (Isolation Forest)
- pandas, numpy
- loguru (for logging)
- OpenAI API or HuggingFace Transformers
- Flask (for dashboard)
- Docker (optional)
- Bash (for automation)

---

## 🧪 How It Works

1. **Feed logs** → Linux auth logs, firewall logs, or your own dataset  
2. **Parse + Normalize** → Convert to structured format  
3. **Detect Anomalies** → Isolation Forest flags abnormal entries  
4. **Summarize** → Alerts are explained in natural language  
5. **Act** → Readable reports + optional UI help SOC teams respond

---

## 📦 Quick Start

```bash
git clone https://github.com/yourname/BlueSentinel-Log-Analyzer.git
cd BlueSentinel-Log-Analyzer
pip install -r requirements.txt
python main.py --logfile data/sample_auth.log
