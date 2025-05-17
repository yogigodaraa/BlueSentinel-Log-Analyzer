from blue_sentinel import log_parser, anomaly_detector, summarizer

def main(log_file_path):
    # Step 1: Parse the log file
    parsed_logs = log_parser.parse_log(log_file_path)
    print(f"\n📄 Parsed {len(parsed_logs)} log entries.")

    # Step 2: Detect anomalies
    anomalies = anomaly_detector.detect_anomalies(parsed_logs)
    print(f"\n🚨 Detected {len(anomalies)} anomalies.\n")

    # Step 3: Generate summaries
    summaries = summarizer.generate_summaries(anomalies)

    # Step 4: Print to console
    for i, summary in enumerate(summaries, start=1):
        print(f"--- Alert {i} ---")
        print(summary)
        print()

    # Step 5: Save to text file
    with open("alerts_report.txt", "w") as report_file:
        for summary in summaries:
            report_file.write(summary + "\n\n")

    print(f"📝 Alerts report saved to alerts_report.txt")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Run BlueSentinel log analyzer")
    parser.add_argument("--logfile", required=True, help="Path to the log file to analyze")
    args = parser.parse_args()
    main(args.logfile)
