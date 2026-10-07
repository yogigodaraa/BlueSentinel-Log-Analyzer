"""Tests for the header forensics service."""

from email import message_from_string

from app.services.header_forensics import (
    analyze_message,
    parse_authentication_results,
    parse_received_chain,
)


def test_parse_auth_results_basic():
    header = (
        "mx.google.com; "
        "spf=pass (google.com: domain of x@y.com designates 1.2.3.4) smtp.mailfrom=x@y.com; "
        "dkim=pass header.i=@y.com; "
        "dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=y.com"
    )
    results = parse_authentication_results(header)
    methods = {r.method: r for r in results}
    assert methods["spf"].passed
    assert methods["dkim"].passed
    assert methods["dmarc"].passed


def test_parse_auth_results_with_failures():
    header = "mx.google.com; spf=fail; dkim=none; dmarc=fail (p=REJECT)"
    results = parse_authentication_results(header)
    methods = {r.method: r for r in results}
    assert methods["spf"].failed
    assert methods["dmarc"].failed


def test_parse_received_chain():
    received = [
        "from relay.company.com (relay.company.com [10.0.0.1])\n"
        "  by mx.company.com with ESMTPS; Mon, 20 Jan 2026 10:00:00 +0000",
        "from external.example.org (example.org [203.0.113.5])\n"
        "  by relay.company.com with ESMTP; Mon, 20 Jan 2026 09:59:58 +0000",
    ]
    hops = parse_received_chain(received)
    assert len(hops) == 2
    assert hops[0].from_host == "relay.company.com"
    assert hops[0].from_ip == "10.0.0.1"
    assert hops[1].from_ip == "203.0.113.5"


def test_full_report_all_pass():
    raw = (
        "Received: from relay.company.com (relay.company.com [10.0.0.1]) "
        "by mx.company.com; Mon, 20 Jan 2026 10:00:00 +0000\r\n"
        "Authentication-Results: mx.company.com; spf=pass smtp.mailfrom=x@y.com; "
        "dkim=pass header.i=@y.com; dmarc=pass header.from=y.com\r\n"
        "From: Alice <alice@company.com>\r\n"
        "To: bob@company.com\r\n"
        "Subject: hello\r\n"
        "\r\n"
        "body"
    )
    msg = message_from_string(raw)
    report = analyze_message(msg)
    assert report.spf_pass is True
    assert report.dkim_pass is True
    assert report.dmarc_pass is True
    assert report.risk_score < 0.1


def test_full_report_dmarc_fail():
    raw = (
        "Authentication-Results: mx.company.com; spf=fail; dkim=fail; dmarc=fail\r\n"
        "From: CEO <ceo@paypaI.com>\r\n"
        "To: cfo@company.com\r\n"
        "Subject: urgent\r\n"
        "\r\n"
        "body"
    )
    msg = message_from_string(raw)
    report = analyze_message(msg)
    assert report.spf_pass is False
    assert report.dkim_pass is False
    assert report.dmarc_pass is False
    assert report.risk_score > 0.7
    assert len(report.warnings) >= 3
