"""
tests/test_adversarial_and_streaming.py - Adversarial Robustness, Streaming, and Navigator Tests
================================================================================================
Validates:
  1. Memory-safe streaming generator log parsing.
  2. Sysmon / EVTX JSON and Zeek (JSON/TSV) log normalization.
  3. Resilience against null bytes (\x00), invalid UTF-8, and oversized lines.
  4. Malformed JSON handling without crashing the stream.
  5. ReDoS mitigation on massive inputs.
  6. MITRE ATT&CK Navigator layer JSON generation and validation.
"""

from __future__ import annotations

import json
import types
from pathlib import Path


from sentinel.cli import main as cli_main
from sentinel.engine import Alert, DetectionEngine, is_potential_redos
from sentinel.parser import (
    LogEntry,
    stream_log_file,
)
from sentinel.report import IncidentReporter


def test_streaming_log_file_generator(tmp_path: Path) -> None:
    """Verify stream_log_file yields a generator that produces LogEntry records line-by-line."""
    log_file = tmp_path / "stream_auth.log"
    lines = [
        "Nov 15 01:00:01 web-server sshd[1001]: Failed password for invalid user admin from 192.168.1.100 port 44123",
        "Nov 15 01:00:02 web-server sshd[1002]: Failed password for invalid user root from 192.168.1.100 port 44124",
        "Nov 15 01:00:03 web-server sshd[1003]: Accepted password for deploy from 192.168.1.50 port 44125",
    ]
    log_file.write_text("\n".join(lines), encoding="utf-8")

    stream_gen = stream_log_file(str(log_file), log_type="auth")
    assert isinstance(stream_gen, types.GeneratorType)

    entries = list(stream_gen)
    assert len(entries) == 3
    assert entries[0].user == "admin"
    assert entries[0].action == "failed_login"
    assert entries[2].action == "accepted_login"


def test_sysmon_and_evtx_json_streaming_ingestion(tmp_path: Path) -> None:
    """Verify streaming ingestion of Sysmon EID 1 (Process Create), EID 3 (Network Connect), and EVTX JSON."""
    json_log = tmp_path / "sysmon_events.json"
    events = [
        # Sysmon Event ID 1: Process Creation
        json.dumps({
            "EventID": 1,
            "UtcTime": "2026-11-15 02:00:00",
            "ProcessGuid": "{1111-2222-3333}",
            "Image": "C:\\Windows\\System32\\powershell.exe",
            "CommandLine": "powershell.exe -ExecutionPolicy Bypass -enc SQBFAFgA",
            "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            "User": "CORP\\victim_user"
        }),
        # Sysmon Event ID 3: Network Connection
        json.dumps({
            "EventID": 3,
            "UtcTime": "2026-11-15 02:00:05",
            "SourceIp": "10.0.0.15",
            "DestinationIp": "198.51.100.42",
            "DestinationPort": 443,
            "Image": "C:\\Windows\\System32\\powershell.exe",
            "User": "CORP\\victim_user"
        }),
        # Windows Security EVTX nested JSON (Event ID 4688)
        json.dumps({
            "Event": {
                "System": {"EventID": 4688, "TimeCreated": {"@SystemTime": "2026-11-15T02:01:00Z"}},
                "EventData": {
                    "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
                    "CommandLine": "cmd.exe /c whoami.exe",
                    "SubjectUserName": "victim_user"
                }
            }
        })
    ]
    json_log.write_text("\n".join(events), encoding="utf-8")

    entries = list(stream_log_file(str(json_log), log_type="json"))
    assert len(entries) == 3

    # Sysmon EID 1 check
    assert entries[0].event_id == 1
    assert entries[0].action == "process_creation"
    assert "powershell.exe" in entries[0].target
    assert entries[0].command_line == "powershell.exe -ExecutionPolicy Bypass -enc SQBFAFgA"

    # Sysmon EID 3 check
    assert entries[1].event_id == 3
    assert entries[1].action == "network_connection"
    assert entries[1].target == "198.51.100.42:443"

    # EVTX 4688 check
    assert entries[2].event_id == 4688
    assert entries[2].action == "process_creation"
    assert "cmd.exe" in entries[2].target


def test_zeek_json_and_tsv_streaming_ingestion(tmp_path: Path) -> None:
    """Verify streaming ingestion of Zeek HTTP and Conn logs in both JSON and TSV dialect."""
    # 1. Zeek JSON
    zeek_json_file = tmp_path / "zeek_http.log"
    zeek_json_lines = [
        json.dumps({
            "ts": 1700000001.0,
            "uid": "CHfSZ818",
            "id.orig_h": "192.168.1.150",
            "id.orig_p": 51234,
            "id.resp_h": "10.0.0.5",
            "id.resp_p": 80,
            "method": "GET",
            "uri": "/login.php?id=1%27%20OR%201=1",
            "status_code": 200,
            "user_agent": "sqlmap/1.7"
        })
    ]
    zeek_json_file.write_text("\n".join(zeek_json_lines), encoding="utf-8")
    json_entries = list(stream_log_file(str(zeek_json_file), log_type="json"))
    assert len(json_entries) == 1
    assert json_entries[0].source_ip == "192.168.1.150"
    assert "OR 1=1" in json_entries[0].details["decoded_uri"]

    # 2. Zeek TSV with #fields header
    zeek_tsv_file = tmp_path / "conn.log"
    tsv_content = (
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\n"
        "1700000010.5\tCabc123\t192.168.1.200\t49152\t198.51.100.99\t443\ttcp\tssl\n"
        "1700000011.5\tCabc124\t192.168.1.200\t49153\t198.51.100.99\t443\ttcp\tssl\n"
    )
    zeek_tsv_file.write_text(tsv_content, encoding="utf-8")
    tsv_entries = list(stream_log_file(str(zeek_tsv_file), log_type="zeek"))
    assert len(tsv_entries) == 2
    assert tsv_entries[0].source_ip == "192.168.1.200"
    assert tsv_entries[0].action == "network_connection"


def test_adversarial_null_bytes_and_invalid_utf8(tmp_path: Path) -> None:
    """Verify logs containing embedded null bytes and invalid UTF-8 sequences are sanitized safely."""
    corrupt_log = tmp_path / "corrupt_auth.log"
    # Write binary content with null bytes and invalid UTF-8 sequences
    raw_bytes = (
        b"Nov 15 03:00:00 server sshd[999]: Failed password for \x00admin\x00 from 192.168.1.55 port 22\n"
        b"Nov 15 03:00:01 server sshd[999]: Failed password for user\xff\xfe from 192.168.1.55 port 22\n"
    )
    corrupt_log.write_bytes(raw_bytes)

    entries = list(stream_log_file(str(corrupt_log), log_type="auth"))
    assert len(entries) >= 1
    # Null bytes stripped cleanly
    assert "\x00" not in entries[0].raw
    assert entries[0].source_ip == "192.168.1.55"


def test_adversarial_oversized_lines_truncation(tmp_path: Path) -> None:
    """Verify oversized lines (>256KB) are truncated safely and parsed without memory exhaustion."""
    giant_log = tmp_path / "giant_web.log"
    huge_uri = "/test?" + ("A" * 300000)
    huge_line = f'192.168.1.10 - - [15/Nov/2026:03:00:00 +0000] "GET {huge_uri} HTTP/1.1" 414 0 "-" "test-agent"'
    giant_log.write_text(huge_line, encoding="utf-8")

    # Should not crash or exhaust heap
    entries = list(stream_log_file(str(giant_log), log_type="web", max_line_len=50000))
    # Line was safely capped/handled
    assert len(entries) <= 1


def test_adversarial_malformed_json_resilience(tmp_path: Path) -> None:
    """Verify malformed JSON syntax is gracefully skipped while valid entries in the same stream are preserved."""
    mixed_log = tmp_path / "broken_stream.json"
    lines = [
        "{ this is clearly: not: valid JSON }",
        json.dumps({"EventID": 1, "CommandLine": "powershell.exe -enc AAAA", "User": "admin"}),
        "{ corrupted: trailing: brackets: }}}",
        json.dumps({"EventID": 4625, "TargetUserName": "attacker", "WorkstationName": "PC1"}),
    ]
    mixed_log.write_text("\n".join(lines), encoding="utf-8")

    entries = list(stream_log_file(str(mixed_log), log_type="json"))
    assert len(entries) == 2
    assert entries[0].command_line == "powershell.exe -enc AAAA"
    assert entries[1].action == "failed_login"


def test_redos_pattern_mitigation_and_safety() -> None:
    """Verify detection engine ReDoS warning helper and string truncation protections."""
    # 1. Potential ReDoS pattern detection helper
    hazardous_pattern = r"(a+)+$"
    assert is_potential_redos(hazardous_pattern) is True

    safe_pattern = r"\bUNION\s+SELECT\b"
    assert is_potential_redos(safe_pattern) is False

    # 2. String evaluation on oversized input
    engine = DetectionEngine()
    test_entry = LogEntry(
        timestamp="2026-11-15 00:00:00",
        log_type="web",
        source_ip="10.0.0.1",
        user="-",
        action="http_request",
        target="/index.php?" + ("X" * 50000),
        raw="raw",
    )
    # Ensure analysis does not freeze
    alerts = engine.analyze_stream([test_entry])
    assert isinstance(alerts, list)


def test_mitre_navigator_layer_json_export(tmp_path: Path) -> None:
    """Verify MITRE ATT&CK Navigator v4.5 JSON layer export schema, techniques, and scoring."""
    alerts = [
        Alert(
            alert_id="ALT-001",
            rule_id="SEC-WIN-001",
            rule_name="Suspicious PowerShell Obfuscation & Download",
            severity="Critical",
            source_ip="192.168.1.50",
            target="powershell.exe",
            user="victim",
            mitre_id="T1059.001",
            mitre_technique="Command and Scripting Interpreter: PowerShell",
            mitre_tactic="Execution",
            description="PowerShell encoded payload detected",
            evidence="powershell.exe -enc SQBFAFgA",
            count=3,
            timestamp="2026-11-15 00:00:00",
            remediation="Enforce Constrained Language Mode",
        ),
        Alert(
            alert_id="ALT-002",
            rule_id="SEC-WEB-001",
            rule_name="Web SQL Injection",
            severity="High",
            source_ip="10.10.10.5",
            target="/login.php",
            user="N/A",
            mitre_id="T1190",
            mitre_technique="Exploit Public-Facing Application",
            mitre_tactic="Initial Access",
            description="SQL injection pattern observed",
            evidence="' OR '1'='1",
            count=12,
            timestamp="2026-11-15 00:01:00",
            remediation="Use parameterized queries",
        ),
    ]

    layer_path = tmp_path / "navigator_layer.json"
    layer_str = IncidentReporter.generate_navigator_layer(alerts, file_path=str(layer_path))
    assert layer_path.exists()

    layer = json.loads(layer_str)
    assert layer["versions"]["navigator"] == "4.8.0"
    assert layer["versions"]["layer"] == "4.5"
    assert layer["domain"] == "enterprise-attack"

    techs = layer["techniques"]
    assert len(techs) == 2

    # Verify T1059.001
    t1 = next(t for t in techs if t["techniqueID"] == "T1059.001")
    assert t1["tactic"] == "execution"
    assert t1["score"] == 95
    assert t1["color"] == "#ef4444"

    # Verify T1190
    t2 = next(t for t in techs if t["techniqueID"] == "T1190")
    assert t2["tactic"] == "initial-access"
    assert t2["score"] == 80
    assert t2["color"] == "#f97316"


def test_cli_navigator_export(tmp_path: Path) -> None:
    """Verify CLI accepts --navigator and writes the layer JSON file."""
    sample_log = Path(__file__).resolve().parent.parent / "samples" / "auth.log"
    rules_dir = Path(__file__).resolve().parent.parent / "rules"
    nav_output = tmp_path / "cli_navigator.json"

    exit_code = cli_main([
        "--file", str(sample_log),
        "--rules", str(rules_dir),
        "--navigator", str(nav_output),
        "--quiet",
    ])
    assert exit_code == 0
    assert nav_output.exists()
    data = json.loads(nav_output.read_text(encoding="utf-8"))
    assert "techniques" in data
