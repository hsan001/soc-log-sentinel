import pytest
from src.parser import AuthLogEntry, WebLogEntry
from src.detector import DetectionEngine, SecurityAlert


def test_auth_brute_force_trigger():
    engine = DetectionEngine(brute_force_threshold=3)
    entries = [
        AuthLogEntry("ts", "sshd", "failed", "root", "192.168.1.100", "22", "raw1"),
        AuthLogEntry("ts", "sshd", "failed", "root", "192.168.1.100", "22", "raw2"),
        AuthLogEntry("ts", "sshd", "failed", "root", "192.168.1.100", "22", "raw3"),
    ]
    alerts = engine.analyze_auth_entries(entries)
    assert len(alerts) == 1
    assert alerts[0].category == "SSH Brute-Force Attempt"
    assert alerts[0].source_ip == "192.168.1.100"
    assert alerts[0].count == 3


def test_auth_below_threshold_no_alert():
    engine = DetectionEngine(brute_force_threshold=5)
    entries = [
        AuthLogEntry("ts", "sshd", "failed", "root", "192.168.1.100", "22", "raw1"),
        AuthLogEntry("ts", "sshd", "failed", "root", "192.168.1.100", "22", "raw2"),
    ]
    alerts = engine.analyze_auth_entries(entries)
    assert len(alerts) == 0


def test_credential_stuffing_detection():
    engine = DetectionEngine(brute_force_threshold=3)
    entries = [
        AuthLogEntry("ts", "sshd", "invalid_user", "admin", "10.0.0.99", "22", "raw1"),
        AuthLogEntry("ts", "sshd", "invalid_user", "oracle", "10.0.0.99", "22", "raw2"),
        AuthLogEntry("ts", "sshd", "invalid_user", "postgres", "10.0.0.99", "22", "raw3"),
    ]
    alerts = engine.analyze_auth_entries(entries)
    assert len(alerts) == 1
    assert alerts[0].category == "Credential Spraying / Stuffing"
    assert alerts[0].source_ip == "10.0.0.99"


def test_sqli_detection():
    engine = DetectionEngine()
    entries = [
        WebLogEntry("203.0.113.1", "ts", "GET", "/items?id=1' UNION SELECT 1,2,3--", "/items?id=1' UNION SELECT 1,2,3--", 200, 100, "", "", "raw")
    ]
    alerts = engine.analyze_web_entries(entries)
    assert len(alerts) == 1
    assert alerts[0].category == "SQL Injection (SQLi)"
    assert alerts[0].severity == "Critical"
    assert "T1190" in alerts[0].mitre_attack


def test_xss_detection():
    engine = DetectionEngine()
    entries = [
        WebLogEntry("198.51.100.2", "ts", "GET", "/search?q=<script>alert('xss')</script>", "/search?q=<script>alert('xss')</script>", 200, 100, "", "", "raw")
    ]
    alerts = engine.analyze_web_entries(entries)
    assert len(alerts) == 1
    assert alerts[0].category == "Cross-Site Scripting (XSS)"
    assert alerts[0].severity == "High"


def test_path_traversal_detection():
    engine = DetectionEngine()
    entries = [
        WebLogEntry("198.51.100.3", "ts", "GET", "/download?file=../../../../etc/passwd", "/download?file=../../../../etc/passwd", 403, 100, "", "", "raw")
    ]
    alerts = engine.analyze_web_entries(entries)
    assert len(alerts) == 1
    assert alerts[0].category == "Path Traversal / LFI"
    assert "T1083" in alerts[0].mitre_attack


def test_command_injection_detection():
    engine = DetectionEngine()
    entries = [
        WebLogEntry("203.0.113.4", "ts", "GET", "/ping?ip=127.0.0.1;cat /etc/shadow", "/ping?ip=127.0.0.1;cat /etc/shadow", 500, 100, "", "", "raw")
    ]
    alerts = engine.analyze_web_entries(entries)
    assert len(alerts) == 1
    assert alerts[0].category == "OS Command Injection (RCE)"
    assert alerts[0].severity == "Critical"


def test_ssrf_detection():
    engine = DetectionEngine()
    entries = [
        WebLogEntry("203.0.113.5", "ts", "GET", "/proxy?url=http://169.254.169.254/latest/meta-data/", "/proxy?url=http://169.254.169.254/latest/meta-data/", 403, 100, "", "", "raw")
    ]
    alerts = engine.analyze_web_entries(entries)
    assert len(alerts) == 1
    assert alerts[0].category == "Server-Side Request Forgery (SSRF)"
    assert alerts[0].severity == "Critical"


def test_analyze_stream_sorting():
    engine = DetectionEngine(brute_force_threshold=2)
    stream = [
        ("auth", AuthLogEntry("ts", "sshd", "failed", "user1", "10.0.0.1", "22", "raw")),
        ("auth", AuthLogEntry("ts", "sshd", "failed", "user1", "10.0.0.1", "22", "raw")),
        ("web", WebLogEntry("203.0.113.1", "ts", "GET", "/?id=1' UNION SELECT 1--", "/?id=1' UNION SELECT 1--", 200, 100, "", "", "raw")),
    ]
    alerts = engine.analyze_stream(stream)
    assert len(alerts) == 2
    # Critical SQLi should be sorted before High Brute Force
    assert alerts[0].severity == "Critical"
    assert alerts[1].severity == "High"
