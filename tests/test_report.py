"""
test_report.py - Unit Tests for IncidentReporter (Rich, JSON, Markdown)
"""

import json
import tempfile
import os
import pytest
from io import StringIO
from rich.console import Console

from sentinel.engine import Alert
from sentinel.report import IncidentReporter


@pytest.fixture
def sample_alert():
    return Alert(
        alert_id="ALT-001",
        rule_id="SEC-WEB-001",
        rule_name="Web SQL Injection (SQLi)",
        severity="Critical",
        source_ip="198.51.100.24",
        target="/login.php",
        user="N/A",
        mitre_id="T1190",
        mitre_technique="Exploit Public-Facing Application",
        mitre_tactic="Initial Access",
        description="SQL Injection syntax detected in URI.",
        evidence="' OR 1=1--",
        count=3,
        timestamp="08/Nov/2026:14:05:01",
        remediation="Implement parameterized queries."
    )


def test_compile_metadata(sample_alert):
    metadata = IncidentReporter.compile_metadata(
        alerts=[sample_alert],
        log_files=["/var/log/access.log"],
        total_events=100
    )
    assert metadata["total_events_parsed"] == 100
    assert metadata["total_alerts"] == 1
    assert metadata["severity_counts"]["Critical"] == 1
    assert "198.51.100.24" in metadata["unique_attackers"]
    assert "Initial Access" in metadata["mitre_tactics_observed"]


def test_json_report_serialization(sample_alert):
    metadata = IncidentReporter.compile_metadata([sample_alert], ["test.log"], 50)
    json_output = IncidentReporter.generate_json_report([sample_alert], metadata)
    
    data = json.loads(json_output)
    assert data["sentinel_version"] == "2.0.0"
    assert len(data["alerts"]) == 1
    alert_dict = data["alerts"][0]
    assert alert_dict["alert_id"] == "ALT-001"
    assert alert_dict["severity"] == "Critical"
    assert alert_dict["mitre"]["id"] == "T1190"


def test_json_report_file_export(sample_alert):
    metadata = IncidentReporter.compile_metadata([sample_alert], ["test.log"], 50)
    with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".json") as tmp:
        tmp_name = tmp.name

    try:
        IncidentReporter.generate_json_report([sample_alert], metadata, file_path=tmp_name)
        with open(tmp_name, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["alerts"][0]["rule_id"] == "SEC-WEB-001"
    finally:
        if os.path.exists(tmp_name):
            os.remove(tmp_name)


def test_markdown_report_generation(sample_alert):
    metadata = IncidentReporter.compile_metadata([sample_alert], ["test.log"], 50)
    md = IncidentReporter.generate_markdown_report([sample_alert], metadata)
    assert "# 🛡️ SOC Log Sentinel — Incident Triage Report" in md
    assert "ALT-001" in md
    assert "Web SQL Injection (SQLi)" in md
    assert "T1190" in md
    assert "SOC Analyst Action Checklist" in md


def test_rich_terminal_rendering(sample_alert):
    metadata = IncidentReporter.compile_metadata([sample_alert], ["test.log"], 50)
    string_io = StringIO()
    test_console = Console(file=string_io, force_terminal=False, width=140)
    # Should render cleanly without raising any exceptions
    IncidentReporter.render_terminal_summary([sample_alert], metadata, console=test_console)
    output = string_io.getvalue()
    assert "SOC LOG SENTINEL" in output
    assert "ALT-001" in output
    assert "CRITICAL" in output

