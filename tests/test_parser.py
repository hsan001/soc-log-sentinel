import pytest
from src.parser import (
    parse_auth_line,
    parse_web_line,
    detect_and_parse_line,
    parse_log_file,
    AuthLogEntry,
    WebLogEntry
)


def test_parse_auth_failed_password():
    line = "Nov 05 10:15:10 soc-server sshd[2855]: Failed password for invalid user admin from 192.168.1.105 port 42100 ssh2"
    entry = parse_auth_line(line)
    assert entry is not None
    assert entry.service == "sshd"
    assert entry.event_type == "failed"
    assert entry.user == "admin"
    assert entry.ip == "192.168.1.105"
    assert entry.port == "42100"


def test_parse_auth_accepted():
    line = "Nov 05 10:14:02 soc-server sshd[2841]: Accepted publickey for mjalal from 192.168.1.50 port 51234 ssh2"
    entry = parse_auth_line(line)
    assert entry is not None
    assert entry.service == "sshd"
    assert entry.event_type == "accepted"
    assert entry.user == "mjalal"
    assert entry.ip == "192.168.1.50"


def test_parse_auth_sudo_failure():
    line = "Nov 05 10:18:40 soc-server sudo[2901]: pam_unix(sudo:auth): authentication failure; logname=mjalal uid=1000 euid=0 tty=/dev/pts/0 ruser=mjalal rhost= user=mjalal"
    entry = parse_auth_line(line)
    assert entry is not None
    assert entry.service == "sudo"
    assert entry.event_type == "sudo_failure"
    assert entry.user == "mjalal"


def test_parse_web_combined():
    line = '192.168.1.50 - - [05/Nov/2026:10:00:12 +0400] "GET /index.html?ref=home HTTP/1.1" 200 4520 "https://company.ae/" "Mozilla/5.0"'
    entry = parse_web_line(line)
    assert entry is not None
    assert entry.client_ip == "192.168.1.50"
    assert entry.method == "GET"
    assert entry.uri == "/index.html?ref=home"
    assert entry.status_code == 200
    assert entry.bytes_sent == 4520
    assert entry.user_agent == "Mozilla/5.0"


def test_parse_web_url_decoding():
    line = '203.0.113.42 - - [05/Nov/2026:10:02:40 +0400] "GET /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1" 200 512 "-" "-"'
    entry = parse_web_line(line)
    assert entry is not None
    assert "<script>alert(1)</script>" in entry.decoded_uri


def test_parse_malformed_lines():
    assert parse_auth_line("random garbage log line") is None
    assert parse_auth_line("") is None
    assert parse_web_line("invalid web request log line") is None
    assert parse_web_line("   ") is None


def test_detect_and_parse_line():
    auth_line = "Nov 05 10:15:10 soc-server sshd[2855]: Failed password for invalid user admin from 192.168.1.105 port 42100 ssh2"
    web_line = '192.168.1.50 - - [05/Nov/2026:10:00:12 +0400] "GET / HTTP/1.1" 200 1024 "-" "-"'
    junk_line = "SYSTEM REBOOT"

    k1, e1 = detect_and_parse_line(auth_line)
    assert k1 == "auth"
    assert isinstance(e1, AuthLogEntry)

    k2, e2 = detect_and_parse_line(web_line)
    assert k2 == "web"
    assert isinstance(e2, WebLogEntry)

    k3, e3 = detect_and_parse_line(junk_line)
    assert k3 == "unknown"


def test_parse_log_file(tmp_path):
    f = tmp_path / "test.log"
    f.write_text(
        '192.168.1.50 - - [05/Nov/2026:10:00:12 +0400] "GET / HTTP/1.1" 200 100 "-" "-"\n'
        'Nov 05 10:15:10 soc-server sshd[2855]: Failed password for invalid user admin from 10.0.0.1 port 22 ssh2\n'
    )
    entries = parse_log_file(str(f), log_type="auto")
    assert len(entries) == 2
    assert entries[0][0] == "web"
    assert entries[1][0] == "auth"
