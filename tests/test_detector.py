from blue_sentinel import anomaly_detector, log_parser


def test_anomaly_detector():
    logs = log_parser.parse_log("data/sample_auth.log")
    anomalies = anomaly_detector.detect_anomalies(logs)
    assert isinstance(anomalies, list)
