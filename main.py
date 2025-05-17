from blue_sentinel import log_parser, anomaly_detector, summarizer

def main(log_file_path):
    # Step 1: Parse the log file
    parsed_logs = log_parser.parse_log(log_file_path)
    print(f"\n📄 Parsed {len(parsed_logs)} log entries.")

    # Step 2: Detect anomalies
    anomalies = anomaly_detector.detect_anomalies(parsed_logs)
    print(f"\n🚨 Detected {len(anomalies)} anomalies.\n")

    # Step 3: Generate summaries for anomalies
    summaries = summarizer.generate_summaries(anomalies)

    # Step 4: Display alerts
    for i, summary in enumerate(summaries, start=1):
        print(f"--- Alert {i} ---")
        print(summary)
        print()

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Run BlueSentinel on a log file.")
    parser.add_argument("--logfile", required=True, help="Path to the log file to analyze")
    args = parser.parse_args()
    main(args.logfile)
