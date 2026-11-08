"""
test_engine.py - Unit Tests for Detection Engine & MITRE ATT&CK Mapping
"""

import os
import pytest
from sentinel.parser import LogEntry
from sentinel.engine import DetectionEngine, Rule, Alert


@pytest.fixture
def rules_directory():
    # Return path to rules directory
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, "rules")


def test_rule_loading_and_mitre_mapping(rules_directory):
    engine = DetectionEngine(rules_dir=rules_directory)
    assert len(engine.rules) >= 8

    # Verify all rules have valid MITRE mappings
    for r in engine.rules:
        assert r.id.startswith("SEC-")
        assert r.mitre_id.startswith("T")
        assert len(r.mitre_technique) > 0
        assert len(r.mitre_tactic) > 0
        assert r.severity in ("Critical", "High", "Medium", "Low")


def test_sqli_detection(rules_directory):
    engine = DetectionEngine(rules_dir=rules_directory)
    entry = LogEntry(
        timestamp="08/Nov/2026:14:05:01 +0400",
        log_type="web",
        source_ip="198.51.100.24",
        user="-",
        action="http_request",
        target="/login.php?user=admin' OR '1'='1",
        raw="GET /login.php?user=admin' OR '1'='1 HTTP/1.1",
        status_code=200,
        details={"decoded_uri": "/login.php?user=admin' OR '1'='1"}
    )
    alerts = engine.analyze_stream([entry])
    assert len(alerts) >= 1
    sqli_alert = next((a for a in alerts if a.rule_id == "SEC-WEB-001"), None)
    assert sqli_alert is not None
    assert sqli_alert.severity == "Critical"
    assert sqli_alert.mitre_id == "T1190"


def test_path_traversal_detection(rules_directory):
    engine = DetectionEngine(rules_dir=rules_directory)
    entry = LogEntry(
        timestamp="08/Nov/2026:14:08:22 +0400",
        log_type="web",
        source_ip="185.220.101.5",
        user="-",
        action="http_request",
        target="/view.php?file=../../../../../../etc/passwd",
        raw="GET /view.php?file=../../../../../../etc/passwd HTTP/1.1",
        status_code=403,
        details={"decoded_uri": "/view.php?file=../../../../../../etc/passwd"}
    )
    alerts = engine.analyze_stream([entry])
    pt_alert = next((a for a in alerts if a.rule_id == "SEC-WEB-002"), None)
    assert pt_alert is not None
    assert pt_alert.mitre_id == "T1083"


def test_os_command_injection_detection(rules_directory):
    engine = DetectionEngine(rules_dir=rules_directory)
    entry = LogEntry(
        timestamp="08/Nov/2026:14:12:44 +0400",
        log_type="web",
        source_ip="45.33.32.156",
        user="-",
        action="http_request",
        target="/cgi-bin/status.sh?host=127.0.0.1; cat /etc/passwd",
        raw="GET /cgi-bin/status.sh?host=127.0.0.1; cat /etc/passwd HTTP/1.1",
        status_code=200,
        details={"decoded_uri": "/cgi-bin/status.sh?host=127.0.0.1; cat /etc/passwd"}
    )
    alerts = engine.analyze_stream([entry])
    cmd_alert = next((a for a in alerts if a.rule_id == "SEC-WEB-003"), None)
    assert cmd_alert is not None
    assert cmd_alert.severity == "Critical"
    assert cmd_alert.mitre_id == "T1059.004"


def test_powershell_obfuscation_detection(rules_directory):
    engine = DetectionEngine(rules_dir=rules_directory)
    entry = LogEntry(
        timestamp="2026-11-08 14:15:22",
        log_type="windows",
        source_ip="10.0.0.45",
        user="SYSTEM",
        action="process_creation",
        target="powershell.exe",
        raw="EventID=4688",
        command_line="powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3...",
        event_id=4688
    )
    alerts = engine.analyze_stream([entry])
    ps_alert = next((a for a in alerts if a.rule_id == "SEC-WIN-001"), None)
    assert ps_alert is not None
    assert ps_alert.severity == "Critical"
    assert ps_alert.mitre_id == "T1059.001"


def test_ssh_brute_force_threshold_trigger(rules_directory):
    engine = DetectionEngine(rules_dir=rules_directory)
    # Generate 6 failed attempts (rule threshold is 5)
    entries = [
        LogEntry(
            timestamp=f"Nov 08 14:11:{10+i}",
            log_type="auth",
            source_ip="192.168.1.105",
            user=f"user{i}",
            action="failed_login",
            target="sshd",
            raw=f"Failed password for user{i}"
        )
        for i in range(6)
    ]
    alerts = engine.analyze_stream(entries)
    bf_alert = next((a for a in alerts if a.rule_id == "SEC-AUTH-001"), None)
    assert bf_alert is not None
    assert bf_alert.count == 6
    assert bf_alert.source_ip == "192.168.1.105"
    assert bf_alert.mitre_id == "T1110.001"


def test_ssh_brute_force_under_threshold_ignored(rules_directory):
    engine = DetectionEngine(rules_dir=rules_directory)
    # Only 2 failed attempts (under default threshold of 5)
    entries = [
        LogEntry(
            timestamp="Nov 08 14:11:10",
            log_type="auth",
            source_ip="192.168.1.99",
            user="admin",
            action="failed_login",
            target="sshd",
            raw="Failed password for admin"
        ),
        LogEntry(
            timestamp="Nov 08 14:11:15",
            log_type="auth",
            source_ip="192.168.1.99",
            user="admin",
            action="failed_login",
            target="sshd",
            raw="Failed password for admin"
        )
    ]
    alerts = engine.analyze_stream(entries)
    bf_alert = next((a for a in alerts if a.rule_id == "SEC-AUTH-001"), None)
    assert bf_alert is None


def test_threshold_override_in_engine(rules_directory):
    engine = DetectionEngine(rules_dir=rules_directory)
    # 3 entries - normally under 5, but override threshold to 3
    entries = [
        LogEntry(
            timestamp=f"Nov 08 14:11:{10+i}",
            log_type="auth",
            source_ip="192.168.1.77",
            user=f"user{i}",
            action="failed_login",
            target="sshd",
            raw="Failed password"
        )
        for i in range(3)
    ]
    alerts = engine.analyze_stream(entries, threshold_override=3)
    bf_alert = next((a for a in alerts if a.rule_id == "SEC-AUTH-001"), None)
    assert bf_alert is not None
    assert bf_alert.count == 3
