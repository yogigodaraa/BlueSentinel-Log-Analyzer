
#!/bin/bash

# === BlueSentinel Automated Log Analyzer ===

# Check if a log file was provided
if [ -z "$1" ]; then
  echo "❌ Usage: $0 <log_file_path>"
  exit 1
fi

LOGFILE="$1"

echo "🔍 Running BlueSentinel on: $LOGFILE"
echo "----------------------------------------"

# Run the Python analyzer
python3 main.py --logfile "$LOGFILE"

# Show top 5 alerts from report
echo "----------------------------------------"
echo "📄 Top 5 Alerts from alerts_report.txt:"
echo "----------------------------------------"
head -n 25 alerts_report.txt
