def generate_summaries(anomalies):
    summaries = []

    for log in anomalies:
        msg = log.get("message", "").lower()
        timestamp = log.get("timestamp")
        alert = ""

        if "failed password" in msg:
            alert = "Possible brute force attempt."
        elif "accepted password" in msg:
            alert = "Successful login – verify legitimacy."
        elif "invalid user" in msg:
            alert = "Attempt to access using a non-existent user."

        summaries.append(
            f"[ALERT] {alert}\n> {log['message']}\n> Time: {timestamp}"
        )

    return summaries
