"""Tests for the MITRE ATT&CK enrichment layer."""

from datetime import datetime

from bluesentinel.enrichment import MitreEnricher
from bluesentinel.types import LogEvent, Severity


def make_event(msg: str, process: str = "sshd") -> LogEvent:
    return LogEvent(timestamp=datetime(2026, 1, 1), message=msg, process_name=process)


def test_brute_force_tagged():
    enricher = MitreEnricher()
    ev = make_event("Failed password for root from 1.2.3.4 port 22 ssh2")
    enricher.enrich(ev)
    assert "T1110.001" in ev.mitre_techniques
    assert ev.severity == Severity.HIGH


def test_unauthorised_sudo_tagged():
    enricher = MitreEnricher()
    ev = make_event("user NOT in sudoers ; TTY=pts/0 ; USER=root ; COMMAND=/bin/bash", process="sudo")
    enricher.enrich(ev)
    # "NOT in sudoers" matches the sudoers rule (T1548.003)
    assert "T1548.003" in ev.mitre_techniques


def test_firewall_disable_is_critical():
    enricher = MitreEnricher()
    ev = make_event("iptables -F", process="root")
    enricher.enrich(ev)
    assert "T1562.004" in ev.mitre_techniques
    assert ev.severity == Severity.CRITICAL


def test_log_tampering_is_critical():
    enricher = MitreEnricher()
    ev = make_event("rm /var/log/auth.log -- cleanup")
    enricher.enrich(ev)
    assert "T1070.002" in ev.mitre_techniques
    assert ev.severity == Severity.CRITICAL


def test_benign_event_untagged():
    enricher = MitreEnricher()
    ev = make_event("CRON session opened for user alice")
    enricher.enrich(ev)
    assert ev.mitre_techniques == []
    assert ev.severity == Severity.INFO


def test_coverage_is_non_empty():
    enricher = MitreEnricher()
    cov = enricher.coverage()
    assert len(cov) > 10  # we hand-mapped 15
    assert all("technique_id" in c for c in cov)
    assert all(c["technique_id"].startswith("T") for c in cov)
