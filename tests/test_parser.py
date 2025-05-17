from blue_sentinel import log_parser

def test_parser():
    logs = log_parser.parse_log("data/sample_auth.log")
    assert isinstance(logs, list)
    assert all("timestamp" in log for log in logs)
    assert all("message" in log for log in logs)
