from blue_sentinel import log_parser, anomaly_detector, summarizer

def main(log_file_path):
    parsed_logs = log_parser.parse_log(log_file_path)
    anomalies = anomaly_detector.detect_anomalies(parsed_logs)
    summaries = summarizer.generate_summaries(anomalies)
    for alert in summaries:
        print(alert)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--logfile", required=True, help="Path to log file")
    args = parser.parse_args()
    main(args.logfile)
