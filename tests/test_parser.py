"""
test_parser.py - Comprehensive Unit Tests for Normalized Multi-Source Log Parser
"""

import os
import tempfile
import pytest
from sentinel.parser import (
    LogParser,
    LogEntry,
    parse_auth_line,
    parse_web_line,
    parse_windows_line,
    detect_and_parse_line,
    detect_log_format,
    parse_log_file
)


# ==============================================================================
# Linux Auth Log Tests
# ==============================================================================

def test_parse_auth_failed_password():
    line = "Nov 08 14:11:15 web-prod-01 sshd[1050]: Failed password for invalid user admin from 192.168.1.105 port 41234 ssh2"
    entry = parse_auth_line(line)
    assert entry is not None
    assert entry.log_type == "auth"
    assert entry.source_ip == "192.168.1.105"
    assert entry.user == "admin"
    assert entry.action == "failed_login"
    assert entry.event_type == "failed"
    assert entry.target == "sshd"
    assert entry.details.get("port") == "41234"


def test_parse_auth_accepted_login():
    line = "Nov 08 14:10:01 web-prod-01 sshd[1024]: Accepted publickey for devops from 192.168.1.50 port 54322 ssh2: RSA SHA256:abc"
    entry = parse_auth_line(line)
    assert entry is not None
    assert entry.log_type == "auth"
    assert entry.source_ip == "192.168.1.50"
    assert entry.user == "devops"
    assert entry.action == "accepted_login"
    assert entry.event_type == "accepted"


def test_parse_auth_invalid_user():
    line = "Nov 08 14:11:18 web-prod-01 sshd[1052]: Invalid user test from 10.0.0.99 port 33112 ssh2"
    entry = parse_auth_line(line)
    assert entry is not None
    assert entry.user == "test"
    assert entry.action == "invalid_user"
    assert entry.source_ip == "10.0.0.99"


def test_parse_auth_sudo_failure():
    line = "Nov 08 14:15:20 web-prod-01 sudo[2040]: pam_unix(sudo:auth): authentication failure; logname=uid=1001 euid=0 tty=/dev/pts/1 ruser=intern rhost= user=intern"
    entry = parse_auth_line(line)
    assert entry is not None
    assert entry.log_type == "auth"
    assert entry.user == "intern"
    assert entry.action == "sudo_fail"
    assert entry.event_type == "sudo_failure"


def test_parse_auth_sudo_command():
    line = "Nov 08 14:16:00 web-prod-01 sudo[2050]: devops : TTY=pts/0 ; PWD=/home/devops ; USER=root ; COMMAND=/bin/systemctl restart nginx"
    entry = parse_auth_line(line)
    assert entry is not None
    assert entry.action == "sudo_cmd"
    assert entry.user == "devops"
    assert entry.command_line == "/bin/systemctl restart nginx"


# ==============================================================================
# Web Log Tests
# ==============================================================================

def test_parse_web_combined_format():
    line = '192.168.1.50 - - [08/Nov/2026:14:01:10 +0400] "GET /index.html?ref=login HTTP/1.1" 200 4520 "https://example.com/" "Mozilla/5.0 (Windows NT 10.0)"'
    entry = parse_web_line(line)
    assert entry is not None
    assert entry.log_type == "web"
    assert entry.source_ip == "192.168.1.50"
    assert entry.http_method == "GET"
    assert entry.method == "GET"
    assert entry.target == "/index.html?ref=login"
    assert entry.status_code == 200
    assert entry.bytes_sent == 4520
    assert entry.user_agent == "Mozilla/5.0 (Windows NT 10.0)"


def test_parse_web_url_decoding():
    line = '198.51.100.24 - - [08/Nov/2026:14:05:01 +0400] "GET /login.php?user=admin%27%20OR%20%271%27%3D%271 HTTP/1.1" 200 2410 "-" "sqlmap"'
    entry = parse_web_line(line)
    assert entry is not None
    assert "' OR '1'='1" in entry.decoded_uri


# ==============================================================================
# Windows Security Event Tests
# ==============================================================================

def test_parse_windows_event_4625_failed_logon():
    line = 'EventID=4625 Timestamp="2026-11-08 14:05:01" User="Administrator" Workstation="ATTACK-STATION" SourceIP="10.0.0.45" LogonType=3 Status="0xC000006A" Message="An account failed to log on"'
    entry = parse_windows_line(line)
    assert entry is not None
    assert entry.log_type == "windows"
    assert entry.event_id == 4625
    assert entry.action == "failed_login"
    assert entry.user == "Administrator"
    assert entry.source_ip == "10.0.0.45"


def test_parse_windows_event_4688_powershell():
    line = 'EventID=4688 Timestamp="2026-11-08 14:15:22" User="SYSTEM" Process="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" CommandLine="powershell.exe -ExecutionPolicy Bypass -EncodedCommand ABC123DEF456=="'
    entry = parse_windows_line(line)
    assert entry is not None
    assert entry.event_id == 4688
    assert entry.action == "process_creation"
    assert entry.command_line is not None
    assert "-ExecutionPolicy Bypass" in entry.command_line


def test_parse_windows_event_4672_privilege():
    line = 'EventID=4672 Timestamp="2026-11-08 14:10:00" User="svc_admin" Workstation="DC01" SourceIP="10.0.0.2" Message="Special privileges assigned to new logon: SeSecurityPrivilege"'
    entry = parse_windows_line(line)
    assert entry is not None
    assert entry.event_id == 4672
    assert entry.action == "privilege_assigned"


# ==============================================================================
# File Parsing & Dialect Detection
# ==============================================================================

def test_detect_log_format():
    auth_sample = [
        "Nov 08 14:11:15 web-prod-01 sshd[1050]: Failed password for invalid user admin from 192.168.1.105 port 41234 ssh2",
        "Nov 08 14:11:18 web-prod-01 sshd[1052]: Failed password for invalid user root from 192.168.1.105 port 41236 ssh2"
    ]
    web_sample = [
        '192.168.1.50 - - [08/Nov/2026:14:01:10 +0400] "GET /index.html HTTP/1.1" 200 4520 "-" "-"'
    ]
    win_sample = [
        'EventID=4625 Timestamp="2026-11-08 14:05:01" User="Administrator" SourceIP="10.0.0.45"'
    ]
    assert detect_log_format(auth_sample) == "auth"
    assert detect_log_format(web_sample) == "web"
    assert detect_log_format(win_sample) == "windows"


def test_parse_log_file_resilience():
    with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".log") as tmp:
        tmp.write("Nov 08 14:10:01 web-prod-01 sshd[1024]: Accepted publickey for devops from 192.168.1.50 port 54322 ssh2\n")
        tmp.write("Corrupted garbage line that cannot be parsed\n")
        tmp.write("   \n")
        tmp.write("Nov 08 14:11:15 web-prod-01 sshd[1050]: Failed password for invalid user admin from 192.168.1.105 port 41234 ssh2\n")
        tmp_name = tmp.name

    try:
        entries = parse_log_file(tmp_name, log_type="auto")
        assert len(entries) == 2
        assert entries[0].action == "accepted_login"
        assert entries[1].action == "failed_login"
    finally:
        if os.path.exists(tmp_name):
            os.remove(tmp_name)


def test_parse_nonexistent_file_raises():
    with pytest.raises(FileNotFoundError):
        parse_log_file("nonexistent_path_to_log.log")
