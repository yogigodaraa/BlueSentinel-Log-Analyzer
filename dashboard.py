from flask import Flask, render_template
import os

app = Flask(__name__)

def load_alerts():
    alerts = []
    if os.path.exists("alerts_report.txt"):
        with open("alerts_report.txt", "r") as f:
            block = []
            for line in f:
                if line.strip() == "":
                    if block:
                        alerts.append("\n".join(block))
                        block = []
                else:
                    block.append(line.strip())
            if block:
                alerts.append("\n".join(block))
    return alerts

@app.route("/")
def home():
    alerts = load_alerts()
    return render_template("dashboard.html", alerts=alerts)

if __name__ == "__main__":
    app.run(debug=True)
