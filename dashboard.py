from flask import Flask, render_template, request, jsonify, Response
import os
import json

app = Flask(__name__)

def load_alerts(filter_level=None):
    alerts = []
    if os.path.exists("alerts_report.txt"):
        with open("alerts_report.txt", "r") as f:
            block = []
            for line in f:
                if line.strip() == "":
                    if block:
                        full_alert = "\n".join(block)
                        if not filter_level or f"[{filter_level.upper()} Severity]" in full_alert:
                            alerts.append(full_alert)
                        block = []
                else:
                    block.append(line.strip())
            if block:
                full_alert = "\n".join(block)
                if not filter_level or f"[{filter_level.upper()} Severity]" in full_alert:
                    alerts.append(full_alert)
    return alerts

@app.route("/")
def home():
    severity = request.args.get("severity")  # e.g., "high", "medium", "low"
    alerts = load_alerts(severity)
    return render_template("dashboard.html", alerts=alerts, current_filter=severity or "all")

def parse_alert_block(block):
    """Convert a single alert block into a structured dictionary"""
    data = {
        "severity": "LOW",
        "message": "",
        "time": "",
        "description": "",
        "raw": block
    }

    lines = block.split("\n")
    for line in lines:
        if "[HIGH" in line:
            data["severity"] = "HIGH"
        elif "[MEDIUM" in line:
            data["severity"] = "MEDIUM"
        elif "[LOW" in line:
            data["severity"] = "LOW"

        if line.startswith("> Message:"):
            data["message"] = line.replace("> Message:", "").strip()
        elif line.startswith("> Time:"):
            data["time"] = line.replace("> Time:", "").strip()
        elif line.startswith(">"):
            data["description"] = line.replace(">", "").strip()

    return data

@app.route("/api/alerts")
def api_alerts():
    raw_alerts = load_alerts()
    parsed_alerts = [parse_alert_block(alert) for alert in raw_alerts if "[ALERT]" in alert]
    return Response(
        json.dumps(parsed_alerts, indent=2),
        mimetype='application/json',
        headers={'Content-Disposition': 'attachment;filename=alerts.json'}
    )

if __name__ == "__main__":
    app.run(debug=True)
