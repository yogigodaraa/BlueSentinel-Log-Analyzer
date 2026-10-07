"""Tests for the BEC detector."""

from email import message_from_string

from app.services.bec_detector import detect_bec


def _email(headers: dict[str, str], body: str = "Hello") -> str:
    """Build a minimal RFC 5322 email from a headers dict."""
    lines = [f"{k}: {v}" for k, v in headers.items()]
    return "\r\n".join(lines) + "\r\n\r\n" + body


def test_vip_display_from_freemail_flagged():
    msg = message_from_string(
        _email(
            {
                "From": "CEO Jane Doe <ceo.jane@gmail.com>",
                "To": "cfo@company.com",
                "Subject": "Urgent: Wire transfer",
            },
            body="Please wire $50,000 to this account — ASAP.",
        )
    )
    report = detect_bec(msg, protected_domains=["company.com"])
    codes = [s.code for s in report.signals]
    assert "vip_display_freemail" in codes
    assert report.risk_score > 0.3


def test_display_name_spoof_flagged():
    msg = message_from_string(
        _email(
            {
                "From": "jane.doe@company.com <attacker@evil.com>",
                "To": "bob@company.com",
            }
        )
    )
    report = detect_bec(msg)
    codes = [s.code for s in report.signals]
    assert "display_name_spoof" in codes


def test_reply_to_mismatch_flagged():
    msg = message_from_string(
        _email(
            {
                "From": "CFO <cfo@company.com>",
                "Reply-To": "cfo.external@gmail.com",
                "To": "payments@company.com",
            }
        )
    )
    report = detect_bec(msg)
    codes = [s.code for s in report.signals]
    assert "reply_to_mismatch" in codes


def test_lookalike_domain_flagged():
    # paypaI.com (capital I) vs paypal.com — edit distance 1
    msg = message_from_string(
        _email(
            {
                "From": "PayPal <billing@paypaI.com>",
                "To": "user@example.com",
            }
        )
    )
    report = detect_bec(msg, protected_domains=["paypal.com"])
    codes = [s.code for s in report.signals]
    assert "lookalike_domain" in codes
    assert report.risk_score > 0.5


def test_clean_email_not_flagged():
    msg = message_from_string(
        _email(
            {
                "From": "Colleague <alice@company.com>",
                "To": "bob@company.com",
                "Subject": "Lunch?",
            }
        )
    )
    report = detect_bec(msg, protected_domains=["company.com"])
    assert not report.signals
    assert report.risk_score == 0.0


def test_first_time_urgent_with_known_senders():
    msg = message_from_string(
        _email(
            {
                "From": "Stranger <newone@external.com>",
                "To": "cfo@company.com",
                "Subject": "URGENT: Wire this payment immediately",
            },
            body="Please process this wire transfer ASAP.",
        )
    )
    report = detect_bec(msg, known_senders=["alice@company.com", "bob@external.com"])
    codes = [s.code for s in report.signals]
    assert "first_time_urgent" in codes
