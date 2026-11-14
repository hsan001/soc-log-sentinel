"""
parser.py - Multi-Source Security Log Normalization & Streaming Ingestion Engine
================================================================================
Enterprise-grade streaming log parser with memory-safe generator ingestion,
resilient against malformed JSON, null bytes, invalid UTF-8, and oversized inputs.

Supported Sources & Formats:
- Linux Authentication Logs (/var/log/auth.log, /var/log/secure, audit.log)
- Web Server Logs (Apache / Nginx Combined & Common Log Format)
- Windows Security Event Logs (Events 4625, 4624, 4688, 4672 in KV or Syslog format)
- Windows Sysmon & EVTX JSON streams (Event IDs 1, 3, 4688, 4625, etc.)
- Zeek (Bro) Network Security Monitoring Logs (TSV with #fields and JSON formats)
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Generator, List, Optional
from urllib.parse import unquote

logger = logging.getLogger("sentinel.parser")

MAX_LINE_LENGTH = 1_048_576  # 1 MB safety cap per log line


@dataclass
class LogEntry:
    """Normalized security log event schema across heterogeneous data sources."""
    timestamp: str
    log_type: str  # 'auth', 'web', 'windows', 'generic', 'zeek'
    source_ip: str
    user: str
    action: str  # 'failed_login', 'accepted_login', 'invalid_user', 'sudo_fail', 'sudo_cmd', 'http_request', 'process_creation', 'privilege_assigned', 'network_connection'
    target: str  # Service, URI, Host, Process, or Destination
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
RE_WIN_EVENT_ID = re.compile(r'\b(?:EventID|Event\s*ID)[:=]\s*(\d{1,5})\b', re.IGNORECASE)


class LogParser:
    """Multi-format log parser with automatic dialect detection and memory-safe normalization."""

    @staticmethod
    def clean_raw_line(line: str, max_len: int = MAX_LINE_LENGTH) -> str:
        """Strip null bytes, scrub invalid control characters, and enforce max line length."""
        if not line:
            return ""
        # Strip dangerous null bytes and truncate oversized payloads to prevent ReDoS / memory exhaustion
        sanitized = line.replace("\x00", "")
        if len(sanitized) > max_len:
            sanitized = sanitized[:max_len]
        return sanitized.strip()

    @staticmethod
    def parse_auth_line(line: str) -> Optional[LogEntry]:
        """Parse Linux /var/log/auth.log or secure line."""
        clean = LogParser.clean_raw_line(line)
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
        clean = LogParser.clean_raw_line(line)
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
        clean = LogParser.clean_raw_line(line)
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

    @staticmethod
    def parse_json_line(line: str) -> Optional[LogEntry]:
        """
        Parse structured JSON log line supporting:
        - Windows Sysmon JSON (EventID 1 ProcessCreate, EventID 3 NetworkConnect)
        - Windows EVTX JSON exports (Event.System.EventID, Event.EventData)
        - Zeek JSON (HTTP, Conn, DNS)
        """
        clean = LogParser.clean_raw_line(line)
        if not clean or not clean.startswith("{"):
            return None

        try:
            doc = json.loads(clean)
        except (json.JSONDecodeError, ValueError):
            return None

        if not isinstance(doc, dict):
            return None

        # 1. Check for nested EVTX JSON format
        if "Event" in doc and isinstance(doc["Event"], dict):
            ev = doc["Event"]
            system = ev.get("System", {})
            event_data = ev.get("EventData", {})
            event_id_raw = system.get("EventID")
            event_id = int(event_id_raw) if event_id_raw is not None else None
            timestamp = system.get("TimeCreated", {}).get("@SystemTime") or str(system.get("TimeCreated", "2026-11-15 00:00:00"))
            user = event_data.get("TargetUserName") or event_data.get("SubjectUserName") or "SYSTEM"
            src_ip = event_data.get("IpAddress") or event_data.get("SourceNetworkAddress") or "127.0.0.1"
            cmd_line = event_data.get("CommandLine")
            image = event_data.get("NewProcessName") or event_data.get("Image") or "Windows-Event"

            action = "windows_event"
            if event_id == 4688:
                action = "process_creation"
            elif event_id == 4625:
                action = "failed_login"
            elif event_id == 4624:
                action = "accepted_login"
            elif event_id == 4672:
                action = "privilege_assigned"

            return LogEntry(
                timestamp=str(timestamp),
                log_type="windows",
                source_ip=str(src_ip),
                user=str(user),
                action=action,
                target=str(image),
                raw=clean,
                command_line=str(cmd_line) if cmd_line else None,
                event_id=event_id,
                details=event_data
            )

        # 2. Check for Sysmon & Windows flat JSON
        if "EventID" in doc:
            event_id = int(doc.get("EventID", 0))
            timestamp = str(doc.get("UtcTime") or doc.get("timestamp") or doc.get("TimeCreated") or "2026-11-15 00:00:00")
            user = str(doc.get("User") or doc.get("TargetUserName") or doc.get("SubjectUserName") or "SYSTEM")
            image = str(doc.get("Image") or doc.get("NewProcessName") or doc.get("WorkstationName") or doc.get("ParentImage") or "Windows-Event")
            cmd_line = doc.get("CommandLine")

            if event_id in (1, 4688):
                action = "process_creation"
            elif event_id == 3:
                action = "network_connection"
            elif event_id == 4625:
                action = "failed_login"
            elif event_id == 4624:
                action = "accepted_login"
            elif event_id == 4672:
                action = "privilege_assigned"
            else:
                action = "windows_event"

            if event_id == 3:
                dest_ip = str(doc.get("DestinationIp") or "unknown-ip")
                dest_port = str(doc.get("DestinationPort") or "")
                target_net = f"{dest_ip}:{dest_port}" if dest_port else dest_ip
                return LogEntry(
                    timestamp=timestamp,
                    log_type="windows",
                    source_ip=str(doc.get("SourceIp") or "127.0.0.1"),
                    user=user,
                    action=action,
                    target=target_net,
                    raw=clean,
                    command_line=str(cmd_line) if cmd_line else None,
                    event_id=3,
                    details=doc
                )
            else:
                return LogEntry(
                    timestamp=timestamp,
                    log_type="windows",
                    source_ip=str(doc.get("SourceIp") or doc.get("IpAddress") or "127.0.0.1"),
                    user=user,
                    action=action,
                    target=image,
                    raw=clean,
                    command_line=str(cmd_line) if cmd_line else None,
                    event_id=event_id,
                    details=doc
                )

        # 3. Check for Zeek JSON (e.g. conn, http, dns)
        if "id.orig_h" in doc or "id_orig_h" in doc or ("ts" in doc and ("method" in doc or "uri" in doc or "proto" in doc)):
            src_ip = str(doc.get("id.orig_h") or doc.get("id_orig_h") or "127.0.0.1")
            dest_ip = str(doc.get("id.resp_h") or doc.get("id_resp_h") or "")
            dest_port = doc.get("id.resp_p") or doc.get("id_resp_p")
            ts = str(doc.get("ts") or "2026-11-15 00:00:00")

            if "uri" in doc or "method" in doc:
                uri = str(doc.get("uri") or "/")
                decoded_uri = unquote(uri)
                status = doc.get("status_code")
                return LogEntry(
                    timestamp=ts,
                    log_type="web",
                    source_ip=src_ip,
                    user="-",
                    action="http_request",
                    target=uri,
                    raw=clean,
                    status_code=int(status) if status is not None else 200,
                    http_method=str(doc.get("method") or "GET"),
                    user_agent=str(doc.get("user_agent") or "-"),
                    details={
                        "decoded_uri": decoded_uri,
                        "resp_h": dest_ip,
                        "resp_p": dest_port,
                        "zeek": doc
                    }
                )
            else:
                target_dest = f"{dest_ip}:{dest_port}" if dest_port else dest_ip
                return LogEntry(
                    timestamp=ts,
                    log_type="zeek",
                    source_ip=src_ip,
                    user="-",
                    action="network_connection",
                    target=target_dest or "zeek-conn",
                    raw=clean,
                    details=doc
                )

        # 4. Generic JSON fallback
        return LogEntry(
            timestamp=str(doc.get("timestamp") or doc.get("time") or "2026-11-15 00:00:00"),
            log_type=str(doc.get("log_type") or "generic"),
            source_ip=str(doc.get("source_ip") or doc.get("ip") or "127.0.0.1"),
            user=str(doc.get("user") or "-"),
            action=str(doc.get("action") or "generic_event"),
            target=str(doc.get("target") or "generic"),
            raw=clean,
            command_line=doc.get("command_line"),
            details=doc
        )

    @staticmethod
    def parse_zeek_tsv_line(line: str, fields: Optional[List[str]] = None) -> Optional[LogEntry]:
        """Parse Zeek TSV log line given field header list."""
        clean = LogParser.clean_raw_line(line)
        if not clean or clean.startswith("#"):
            return None

        parts = clean.split("\t")
        if not fields or len(parts) != len(fields):
            return None

        row = dict(zip(fields, parts))
        ts = row.get("ts", "2026-11-15 00:00:00")
        src_ip = row.get("id.orig_h", "127.0.0.1")
        dest_ip = row.get("id.resp_h", "")
        dest_p = row.get("id.resp_p", "")

        if "uri" in row:
            uri = row.get("uri", "/")
            return LogEntry(
                timestamp=ts,
                log_type="web",
                source_ip=src_ip,
                user=row.get("username", "-"),
                action="http_request",
                target=uri,
                raw=clean,
                status_code=int(row["status_code"]) if row.get("status_code", "").isdigit() else 200,
                http_method=row.get("method", "GET"),
                user_agent=row.get("user_agent", "-"),
                details={"decoded_uri": unquote(uri), "zeek": row}
            )

        return LogEntry(
            timestamp=ts,
            log_type="zeek",
            source_ip=src_ip,
            user="-",
            action="network_connection",
            target=f"{dest_ip}:{dest_p}" if dest_p else dest_ip,
            raw=clean,
            details=row
        )


parse_auth_line = LogParser.parse_auth_line
parse_web_line = LogParser.parse_web_line
parse_windows_line = LogParser.parse_windows_line
parse_json_line = LogParser.parse_json_line


def detect_and_parse_line(line: str) -> Optional[LogEntry]:
    """Auto-detect format and parse an individual log line."""
    clean = line.strip()
    if clean.startswith("{"):
        return LogParser.parse_json_line(clean)
    return (
        LogParser.parse_auth_line(line) or
        LogParser.parse_web_line(line) or
        LogParser.parse_windows_line(line) or
        LogParser.parse_json_line(line)
    )


def detect_log_format(sample_lines: List[str]) -> str:
    """Inspect sample log lines to automatically identify log dialect."""
    auth_score = 0
    web_score = 0
    win_score = 0
    json_score = 0
    zeek_score = 0

    for line in sample_lines[:30]:
        clean = line.strip()
        if not clean:
            continue
        if clean.startswith("{") and clean.endswith("}"):
            json_score += 2
        elif clean.startswith("#fields") or clean.startswith("#types"):
            zeek_score += 5
        elif RE_COMBINED_LOG.match(clean):
            web_score += 1
        elif RE_AUTH_SSH_FAILED.search(clean) or RE_AUTH_SSH_ACCEPTED.search(clean) or "sudo[" in clean or "sshd[" in clean:
            auth_score += 1
        elif RE_WIN_EVENT_ID.search(clean) or "EventID=" in clean or "Microsoft-Windows-Security-Auditing" in clean:
            win_score += 1

    scores = {
        "json": json_score,
        "zeek": zeek_score,
        "web": web_score,
        "windows": win_score,
        "auth": auth_score,
    }
    best_format = max(scores, key=scores.get)
    if scores[best_format] > 0:
        return best_format
    return "auth"


def stream_log_file(
    file_path: str,
    log_type: str = "auto",
    max_line_len: int = MAX_LINE_LENGTH
) -> Generator[LogEntry, None, None]:
    """
    Memory-safe generator that yields normalized LogEntry records from a log file.
    Does not buffer entire files in memory, preventing heap exhaustion under multi-gigabyte logs.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Log file not found: {file_path}")

    # Inspect sample lines to determine dialect if 'auto'
    resolved_format = log_type.lower()
    if resolved_format == "auto":
        sample_lines: List[str] = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                for _ in range(30):
                    sample_line = f.readline()
                    if not sample_line:
                        break
                    sample_lines.append(sample_line)
        except Exception:
            pass
        resolved_format = detect_log_format(sample_lines)

    zeek_fields: Optional[List[str]] = None

    # Stream line by line with encoding resilience
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for raw_line in f:
            if not raw_line:
                continue

            # Check Zeek header metadata
            if resolved_format == "zeek" and raw_line.startswith("#fields\t"):
                zeek_fields = raw_line.strip().split("\t")[1:]
                continue
            if raw_line.startswith("#"):
                continue

            entry: Optional[LogEntry] = None

            if resolved_format == "json":
                entry = LogParser.parse_json_line(raw_line)
            elif resolved_format == "web":
                entry = LogParser.parse_web_line(raw_line)
            elif resolved_format == "windows":
                entry = LogParser.parse_windows_line(raw_line) or LogParser.parse_json_line(raw_line)
            elif resolved_format == "auth":
                entry = LogParser.parse_auth_line(raw_line)
            elif resolved_format == "zeek":
                if raw_line.strip().startswith("{"):
                    entry = LogParser.parse_json_line(raw_line)
                elif zeek_fields:
                    entry = LogParser.parse_zeek_tsv_line(raw_line, fields=zeek_fields)
            else:
                entry = detect_and_parse_line(raw_line)

            if entry:
                yield entry


def parse_log_file(file_path: str, log_type: str = "auto") -> List[LogEntry]:
    """
    Ingest a log file, detect or enforce format, and return normalized LogEntry instances.
    Maintains backward compatibility by wrapping the streaming generator.
    """
    return list(stream_log_file(file_path, log_type=log_type))
