"""
parser.py - Multi-Source Security Log Normalization & Ingestion Engine
Supports:
- Linux Authentication Logs (/var/log/auth.log, secure, audit.log)
- Web Server Logs (Apache / Nginx Combined & Common Log Format)
- Windows Security Event Logs (Events 4625, 4624, 4688, 4672, Sysmon/Syslog format)
"""

import re
import os
import logging
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Union
from urllib.parse import unquote

logger = logging.getLogger("sentinel.parser")


@dataclass
class LogEntry:
    """Normalized security log event schema across heterogeneous data sources."""
    timestamp: str
    log_type: str  # 'auth', 'web', 'windows', 'generic'
    source_ip: str
    user: str
    action: str  # 'failed_login', 'accepted_login', 'invalid_user', 'sudo_fail', 'sudo_cmd', 'http_request', 'process_creation', 'privilege_assigned'
    target: str  # Service, URI, Host, or Process
    raw: str
    status_code: Optional[int] = None
    bytes_sent: Optional[int] = None
    http_method: Optional[str] = None
    user_agent: Optional[str] = None
    command_line: Optional[str] = None
    event_id: Optional[int] = None
    details: Dict[str, Any] = field(default_factory=dict)

    # Backward compatibility helpers
    @property
    def client_ip(self) -> str:
        return self.source_ip

    @property
    def uri(self) -> str:
        return self.target

    @property
    def decoded_uri(self) -> str:
        return self.details.get("decoded_uri", self.target)

    @property
    def method(self) -> Optional[str]:
        return self.http_method

    @property
    def event_type(self) -> str:
        if self.action == "sudo_fail":
            return "sudo_failure"
        if self.action == "failed_login":
            return "failed"
        if self.action == "accepted_login":
            return "accepted"
        return self.action

    @property
    def service(self) -> str:
        return self.details.get("service", self.target)

    @property
    def ip(self) -> str:
        return self.source_ip

    @property
    def port(self) -> Optional[str]:
        return self.details.get("port")


# Backward compatibility aliases
AuthLogEntry = LogEntry
WebLogEntry = LogEntry


# ==============================================================================
# Regex Definitions for Log Extraction
# ==============================================================================

# Linux Auth Log Signatures
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
RE_AUTH_SUDO_CMD = re.compile(
    r'^([A-Z][a-z]{2}\s+\d+\s+[\d:]+)\s+\S+\s+(sudo)\[\d+\]:\s+(\S+)\s*:\s*TTY=\S+\s*;\s*PWD=\S+\s*;\s*USER=(\S+)\s*;\s*COMMAND=(.*)'
)

# Web Server Combined Log Format (CLF)
RE_COMBINED_LOG = re.compile(
    r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^ "]+)?(?:\s+HTTP/[\d\.]+)"\s+(\d{3})\s+(\d+|-)\s*(?:"([^"]*)")?\s*(?:"([^"]*)")?'
)

# Windows Security Event Patterns (Key-Value & Syslog-like)
RE_WIN_KV = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')
RE_WIN_EVENT_ID = re.compile(r'\b(?:EventID|Event\s*ID)[:=]\s*(\d{4,5})\b', re.IGNORECASE)


class LogParser:
    """Multi-format log parser with automatic dialect detection."""

    @staticmethod
    def parse_auth_line(line: str) -> Optional[LogEntry]:
        """Parse Linux /var/log/auth.log or secure line."""
        clean = line.strip()
        if not clean:
            return None

        # 1. Failed SSH password
        m = RE_AUTH_SSH_FAILED.search(clean)
        if m:
            ts, svc, user, ip, port = m.groups()
            return LogEntry(
                timestamp=ts,
                log_type="auth",
                source_ip=ip,
                user=user,
                action="failed_login",
                target=svc,
                raw=clean,
                details={"service": svc, "port": port}
            )

        # 2. Invalid user attempt
        m = RE_AUTH_SSH_INVALID.search(clean)
        if m:
            ts, svc, user, ip, port = m.groups()
            return LogEntry(
                timestamp=ts,
                log_type="auth",
                source_ip=ip,
                user=user,
                action="invalid_user",
                target=svc,
                raw=clean,
                details={"service": svc, "port": port}
            )

        # 3. Accepted SSH password/key
        m = RE_AUTH_SSH_ACCEPTED.search(clean)
        if m:
            ts, svc, user, ip, port = m.groups()
            return LogEntry(
                timestamp=ts,
                log_type="auth",
                source_ip=ip,
                user=user,
                action="accepted_login",
                target=svc,
                raw=clean,
                details={"service": svc, "port": port}
            )

        # 4. Sudo authentication failure
        m = RE_AUTH_SUDO_FAIL.search(clean)
        if m:
            ts, svc, user = m.groups()
            return LogEntry(
                timestamp=ts,
                log_type="auth",
                source_ip="127.0.0.1",
                user=user,
                action="sudo_fail",
                target=svc,
                raw=clean,
                details={"service": svc}
            )

        # 5. Sudo command execution
        m = RE_AUTH_SUDO_CMD.search(clean)
        if m:
            ts, svc, invoker, target_user, cmd = m.groups()
            return LogEntry(
                timestamp=ts,
                log_type="auth",
                source_ip="127.0.0.1",
                user=invoker,
                action="sudo_cmd",
                target=svc,
                raw=clean,
                command_line=cmd.strip(),
                details={"service": svc, "target_user": target_user}
            )

        return None

    @staticmethod
    def parse_web_line(line: str) -> Optional[LogEntry]:
        """Parse Apache / Nginx Combined & Common Log Format line."""
        clean = line.strip()
        if not clean:
            return None

        m = RE_COMBINED_LOG.match(clean)
        if not m:
            return None

        ip, ts, method, uri, status, byte_count, referer, ua = m.groups()
        bytes_sent = int(byte_count) if byte_count and byte_count != '-' else 0
        decoded_uri = unquote(uri) if uri else ""

        return LogEntry(
            timestamp=ts,
            log_type="web",
            source_ip=ip,
            user="-",
            action="http_request",
            target=uri or "/",
            raw=clean,
            status_code=int(status),
            bytes_sent=bytes_sent,
            http_method=method,
            user_agent=ua or "-",
            details={
                "decoded_uri": decoded_uri,
                "referer": referer or "-"
            }
        )

    @staticmethod
    def parse_windows_line(line: str) -> Optional[LogEntry]:
        """
        Parse Windows Security Event log line (Key-Value or Syslog audit event format).
        Handles Events 4625 (Failed Logon), 4624 (Logon), 4688 (Process Creation), 4672 (Privilege).
        """
        clean = line.strip()
        if not clean:
            return None

        # Check for Event ID
        event_id_m = RE_WIN_EVENT_ID.search(clean)
        if not event_id_m and "Microsoft-Windows-Security-Auditing" not in clean and "EventID=" not in clean:
            return None

        event_id = int(event_id_m.group(1)) if event_id_m else None

        # Extract Key-Value pairs
        kv_pairs = {}
        for match in RE_WIN_KV.finditer(clean):
            k = match.group(1).lower()
            val = match.group(2) if match.group(2) is not None else match.group(3)
            kv_pairs[k] = val

        # Resolve standard fields
        timestamp = kv_pairs.get("timestamp") or kv_pairs.get("time") or "2026-11-08 00:00:00"
        user = kv_pairs.get("user") or kv_pairs.get("targetusername") or kv_pairs.get("accountname") or "SYSTEM"
        source_ip = kv_pairs.get("sourceip") or kv_pairs.get("ipaddress") or kv_pairs.get("sourcenetworkaddress") or "127.0.0.1"
        command_line = kv_pairs.get("commandline") or kv_pairs.get("cmd") or ""
        process = kv_pairs.get("process") or kv_pairs.get("newprocessname") or kv_pairs.get("image") or ""

        # Syslog audit text fallback extraction if KV didn't find specific fields
        if not event_id and "4625" in clean:
            event_id = 4625
        elif not event_id and "4688" in clean:
            event_id = 4688
        elif not event_id and "4624" in clean:
            event_id = 4624
        elif not event_id and "4672" in clean:
            event_id = 4672

        action = "windows_event"
        target = process or "Windows Security"

        if event_id == 4625:
            action = "failed_login"
            target = kv_pairs.get("workstation") or "Windows-Host"
        elif event_id == 4624:
            action = "accepted_login"
            target = kv_pairs.get("workstation") or "Windows-Host"
        elif event_id == 4688:
            action = "process_creation"
            target = process or "powershell.exe"
            if not command_line:
                # Try finding commandline in text
                cmd_match = re.search(r'CommandLine=["\'](.*?)["\']', clean, re.IGNORECASE)
                if cmd_match:
                    command_line = cmd_match.group(1)
        elif event_id == 4672:
            action = "privilege_assigned"
            target = "SeSecurityPrivilege"

        return LogEntry(
            timestamp=timestamp,
            log_type="windows",
            source_ip=source_ip,
            user=user,
            action=action,
            target=target,
            raw=clean,
            command_line=command_line if command_line else None,
            event_id=event_id,
            details=kv_pairs
        )


parse_auth_line = LogParser.parse_auth_line
parse_web_line = LogParser.parse_web_line
parse_windows_line = LogParser.parse_windows_line


def detect_and_parse_line(line: str) -> Optional[LogEntry]:
    """Auto-detect format and parse an individual log line."""
    return (
        LogParser.parse_auth_line(line) or
        LogParser.parse_web_line(line) or
        LogParser.parse_windows_line(line)
    )



def detect_log_format(sample_lines: List[str]) -> str:
    """Inspect sample log lines to automatically identify log dialect."""
    auth_score = 0
    web_score = 0
    win_score = 0

    for line in sample_lines[:25]:
        clean = line.strip()
        if not clean:
            continue
        if RE_COMBINED_LOG.match(clean):
            web_score += 1
        elif RE_AUTH_SSH_FAILED.search(clean) or RE_AUTH_SSH_ACCEPTED.search(clean) or "sudo[" in clean or "sshd[" in clean:
            auth_score += 1
        elif RE_WIN_EVENT_ID.search(clean) or "EventID=" in clean or "Microsoft-Windows-Security-Auditing" in clean:
            win_score += 1

    if web_score > auth_score and web_score > win_score:
        return "web"
    elif win_score > auth_score and win_score > web_score:
        return "windows"
    return "auth"


def parse_log_file(file_path: str, log_type: str = "auto") -> List[LogEntry]:
    """
    Ingest a log file, detect or enforce format, and return normalized LogEntry instances.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Log file not found: {file_path}")

    # Read lines with robust fallback encoding
    raw_lines = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            raw_lines = f.readlines()
    except Exception as e:
        logger.warning(f"Error reading {file_path} as utf-8: {e}. Falling back to latin-1.")
        with open(file_path, "r", encoding="latin-1", errors="replace") as f:
            raw_lines = f.readlines()

    if not raw_lines:
        return []

    if log_type == "auto":
        resolved_format = detect_log_format(raw_lines)
    else:
        resolved_format = log_type.lower()

    entries: List[LogEntry] = []
    parser = LogParser()

    for line in raw_lines:
        entry = None
        if resolved_format == "web":
            entry = parser.parse_web_line(line)
        elif resolved_format == "windows":
            entry = parser.parse_windows_line(line)
        elif resolved_format == "auth":
            entry = parser.parse_auth_line(line)
        else:
            # Fallback auto-try
            entry = parser.parse_auth_line(line) or parser.parse_web_line(line) or parser.parse_windows_line(line)

        if entry:
            entries.append(entry)

    return entries
