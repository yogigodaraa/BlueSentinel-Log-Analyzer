from sklearn.ensemble import IsolationForest
import numpy as np

def extract_features(logs):
    """
    Converts log entries into numerical features for anomaly detection.
    Currently uses:
    - Length of message
    - Count of digits (e.g., IPs, ports)
    - Count of failed/success keywords
    """
    features = []
    for entry in logs:
        message = entry["message"].lower()
        features.append([
            len(message),
            sum(c.isdigit() for c in message),
            int("failed" in message),
        ])
    return np.array(features)

def detect_anomalies(logs):
    if not logs:
        return []

    X = extract_features(logs)
    model = IsolationForest(contamination=0.1, random_state=42)
    preds = model.fit_predict(X)

    # Tag log entries with prediction
    anomalies = [log for log, pred in zip(logs, preds) if pred == -1]
    return anomalies
