"""
parser.py - Log Parsing Engine for Linux Auth & Web Server Access Logs
Supports:
- Linux /var/log/auth.log and secure.log (SSH, sudo, pam)
- Apache/Nginx Combined & Common Log Format (CLF)
"""

import re
from dataclasses import dataclass
from typing import Optional, List, Tuple, Any
from urllib.parse import unquote


@dataclass
class AuthLogEntry:
    timestamp: str
    service: str
    event_type: str  # 'failed', 'accepted', 'invalid_user', 'sudo_failure'
    user: str
    ip: str
    port: Optional[str]
    raw: str


@dataclass
class WebLogEntry:
    client_ip: str
    timestamp: str
    method: str
    uri: str
    decoded_uri: str
    status_code: int
    bytes_sent: int
    referer: str
    user_agent: str
    raw: str


# Regex for Linux auth.log SSH failed/accepted patterns
RE_AUTH_SSH_FAILED = re.compile(
    r'^([A-Z][a-z]{2}\s+\d+\s+[\d:]+)\s+\S+\s+(sshd)\[\d+\]:\s+Failed password for (?:invalid user )?(\S+) from ([\d\.:a-fA-F]+)(?: port (\d+))?'
)
RE_AUTH_SSH_ACCEPTED = re.compile(
    r'^([A-Z][a-z]{2}\s+\d+\s+[\d:]+)\s+\S+\s+(sshd)\[\d+\]:\s+Accepted (?:password|publickey) for (\S+) from ([\d\.:a-fA-F]+)(?: port (\d+))?'
)
RE_AUTH_SSH_INVALID = re.compile(
    r'^([A-Z][a-z]{2}\s+\d+\s+[\d:]+)\s+\S+\s+(sshd)\[\d+\]:\s+Invalid user (\S+) from ([\d\.:a-fA-F]+)(?: port (\d+))?'
)
RE_AUTH_SUDO_FAIL = re.compile(
    r'^([A-Z][a-z]{2}\s+\d+\s+[\d:]+)\s+\S+\s+(sudo)\[\d+\]:\s+pam_unix\(sudo:auth\):\s+authentication failure;.*?user=(\S+)'
)

# Regex for Apache / Nginx Combined Log Format:
# 192.168.1.100 - - [05/Nov/2026:14:22:10 +0400] "GET /index.html HTTP/1.1" 200 1024 "http://ref.com" "Mozilla/5.0..."
RE_COMBINED_LOG = re.compile(
    r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^ "]+)?(?:\s+HTTP/[\d\.]+)"\s+(\d{3})\s+(\d+|-)\s*(?:"([^"]*)")?\s*(?:"([^"]*)")?'
)


def parse_auth_line(line: str) -> Optional[AuthLogEntry]:
    """Parse a single line from an authentication log (auth.log / secure)."""
    line_clean = line.strip()
    if not line_clean:
        return None

    # Failed SSH password
    m = RE_AUTH_SSH_FAILED.search(line_clean)
    if m:
        ts, svc, user, ip, port = m.groups()
        return AuthLogEntry(
            timestamp=ts,
            service=svc,
            event_type="failed",
            user=user,
            ip=ip,
            port=port,
            raw=line_clean
        )

    # Invalid SSH user
    m = RE_AUTH_SSH_INVALID.search(line_clean)
    if m:
        ts, svc, user, ip, port = m.groups()
        return AuthLogEntry(
            timestamp=ts,
            service=svc,
            event_type="invalid_user",
            user=user,
            ip=ip,
            port=port,
            raw=line_clean
        )

    # Accepted SSH login
    m = RE_AUTH_SSH_ACCEPTED.search(line_clean)
    if m:
        ts, svc, user, ip, port = m.groups()
        return AuthLogEntry(
            timestamp=ts,
            service=svc,
            event_type="accepted",
            user=user,
            ip=ip,
            port=port,
            raw=line_clean
        )

    # Sudo failure
    m = RE_AUTH_SUDO_FAIL.search(line_clean)
    if m:
        ts, svc, user = m.groups()
        return AuthLogEntry(
            timestamp=ts,
            service=svc,
            event_type="sudo_failure",
            user=user,
            ip="127.0.0.1",
            port=None,
            raw=line_clean
        )

    return None


def parse_web_line(line: str) -> Optional[WebLogEntry]:
    """Parse a single line from an Apache or Nginx access log."""
    line_clean = line.strip()
    if not line_clean:
        return None

    m = RE_COMBINED_LOG.search(line_clean)
    if not m:
        return None

    ip, ts, method, uri, status, bytes_val, ref, ua = m.groups()
    uri = uri or "/"
    decoded_uri = unquote(unquote(uri))  # Multi-layer URL unquoting to catch obfuscation
    bytes_int = int(bytes_val) if bytes_val and bytes_val != "-" else 0

    return WebLogEntry(
        client_ip=ip,
        timestamp=ts,
        method=method,
        uri=uri,
        decoded_uri=decoded_uri,
        status_code=int(status),
        bytes_sent=bytes_int,
        referer=ref or "",
        user_agent=ua or "",
        raw=line_clean
    )


def detect_and_parse_line(line: str) -> Tuple[str, Any]:
    """Auto-detect format of a log line and parse it."""
    web_entry = parse_web_line(line)
    if web_entry:
        return "web", web_entry

    auth_entry = parse_auth_line(line)
    if auth_entry:
        return "auth", auth_entry

    return "unknown", line.strip()


def parse_log_file(filepath: str, log_type: str = "auto") -> List[Tuple[str, Any]]:
    """Parse entire log file according to selected or detected type."""
    entries = []
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if log_type == "web":
                res = parse_web_line(line)
                if res:
                    entries.append(("web", res))
            elif log_type == "auth":
                res = parse_auth_line(line)
                if res:
                    entries.append(("auth", res))
            else:
                cat, res = detect_and_parse_line(line)
                if cat != "unknown":
                    entries.append((cat, res))
    return entries
