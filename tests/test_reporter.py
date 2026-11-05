import json
import pytest
from src.detector import SecurityAlert
from src.reporter import compile_metadata, generate_json_report, generate_markdown_report, generate_terminal_summary


@pytest.fixture
def sample_alert():
    return SecurityAlert(
        alert_id="TEST-001",
        category="SQL Injection (SQLi)",
        severity="Critical",
        source_ip="203.0.113.10",
        target="GET /products",
        mitre_attack="T1190",
        description="SQLi test description",
        evidence="GET /products?id=1' OR 1=1--",
        count=3,
        recommendation="Use parameterized queries"
    )


def test_compile_metadata(sample_alert):
    meta = compile_metadata([sample_alert], ["auth.log"], 150)
    assert meta["total_log_lines_analyzed"] == 150
    assert meta["total_alerts"] == 1
    assert meta["severity_breakdown"]["Critical"] == 1
    assert "203.0.113.10" in meta["unique_attacker_ips"]
    assert "T1190" in meta["mitre_techniques_observed"]


def test_generate_json_report(sample_alert):
    meta = compile_metadata([sample_alert], ["access.log"], 100)
    json_str = generate_json_report([sample_alert], meta)
    data = json.loads(json_str)
    assert "metadata" in data
    assert "alerts" in data
    assert len(data["alerts"]) == 1
    assert data["alerts"][0]["alert_id"] == "TEST-001"
    assert data["alerts"][0]["severity"] == "Critical"


def test_generate_markdown_report(sample_alert):
    meta = compile_metadata([sample_alert], ["access.log"], 100)
    md_str = generate_markdown_report([sample_alert], meta)
    assert "# 🛡️ SOC Log Sentinel — Incident Triage Report" in md_str
    assert "TEST-001" in md_str
    assert "SQL Injection (SQLi)" in md_str
    assert "🔴 CRITICAL" in md_str
    assert "203.0.113.10" in md_str
    assert "MITRE ATT&CK" in md_str


def test_generate_terminal_summary(sample_alert):
    meta = compile_metadata([sample_alert], ["access.log"], 100)
    term_str = generate_terminal_summary([sample_alert], meta)
    assert "SOC LOG SENTINEL" in term_str
    assert "TEST-001" in term_str
    assert "Critical: 1" in term_str
