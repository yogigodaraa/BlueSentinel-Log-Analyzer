from collections import Counter
import re

def extract_ip_or_host(msg):
    # Try extracting IPv4 address
    match = re.search(r'from (\d{1,3}(?:\.\d{1,3}){3})', msg)
    if match:
        return match.group(1)

    # Try extracting from rhost=... (handle IPs or hostnames with hyphens)
    match = re.search(r'rhost=([a-zA-Z0-9\.\-]+)', msg)
    if match:
        return match.group(1)

    # Try extracting from "connection from <hostname>"
    match = re.search(r'connection from ([a-zA-Z0-9\.\-]+)', msg)
    if match:
        return match.group(1)

    # Try parentheses e.g. (something.com)
    match = re.search(r'\(([a-zA-Z0-9\.\-]+)\)', msg)
    if match:
        return match.group(1)

    return "Unknown"



def generate_summaries(anomalies):
    summaries = []
    ip_counter = Counter()

    for log in anomalies:
        msg = log.get("message", "").lower()
        timestamp = log.get("timestamp")
        alert = "Suspicious activity detected."
        severity = "LOW"

        # Extract IP or host
        ip = extract_ip_or_host(msg)
        ip_counter[ip] += 1

        # Determine severity & alert content
        if "failed password" in msg or "authentication failure" in msg:
            alert = f"Multiple failed login attempts from {ip}"
            severity = "HIGH"
        elif "invalid user" in msg:
            alert = f"Login attempt using invalid user from {ip}"
            severity = "MEDIUM"
        elif "kerberos" in msg:
            alert = f"Kerberos authentication issue from {ip}"
            severity = "MEDIUM"
        elif "ftp login" in msg:
            alert = f"Anonymous FTP login attempt from {ip}"
            severity = "HIGH"
        elif "connection from" in msg:
            alert = f"Incoming connection from {ip}"
            severity = "LOW"

        # Create summary
        summaries.append(
            f"[ALERT] [{severity} Severity]\n> {alert}\n> Message: {log['message']}\n> Time: {timestamp}"
        )

    # Add high-level summary
    most_common_ip = ip_counter.most_common(1)
    if most_common_ip:
        ip, count = most_common_ip[0]
        summaries.append(f"\n[SUMMARY] 🔍 {count} anomalies were flagged from IP: {ip} — review for potential brute-force or scanning activity.")

    return summaries
