"""
detector.py - Threat Detection Engine for Authentication & Web Logs
Identifies:
- SSH / Sudo Brute-Force & Credential Stuffing
- OWASP Top 10 Web Injections:
  * SQL Injection (SQLi) [CWE-89]
  * Cross-Site Scripting (XSS) [CWE-79]
  * Path Traversal / LFI [CWE-22]
  * OS Command Injection (RCE) [CWE-78]
  * Server-Side Request Forgery (SSRF) [CWE-918]
Maps threats to MITRE ATT&CK framework.
"""

import re
from dataclasses import dataclass
from typing import List, Dict, Any, Tuple
from collections import defaultdict

from .parser import AuthLogEntry, WebLogEntry


@dataclass
class SecurityAlert:
    alert_id: str
    category: str
    severity: str  # 'Critical', 'High', 'Medium', 'Low'
    source_ip: str
    target: str
    mitre_attack: str
    description: str
    evidence: str
    count: int
    recommendation: str


# OWASP Web Injection Regex Signatures (Prioritized by Criticality & Specificity)
WEB_SIGNATURES = [
    {
        "category": "OS Command Injection (RCE)",
        "mitre": "T1059 - Command and Scripting Interpreter",
        "severity": "Critical",
        "pattern": re.compile(
            r"(?:;|\||&&|\`|\$\()\s*(?:cat|id|whoami|uname|pwd|curl|wget|nc|bash|sh|powershell)\b|"
            r"/bin/(?:sh|bash)|"
            r"\bcmd\.exe\b|\bpowershell(?:\.exe)?\b",
            re.IGNORECASE
        ),
        "desc": "System shell command execution delimiter and binary invocation detected.",
        "rec": "Avoid invoking system shells directly; use safe APIs with arguments passed as discrete lists without shell=True."
    },
    {
        "category": "Server-Side Request Forgery (SSRF)",
        "mitre": "T1190 - Exploit Public-Facing Application",
        "severity": "Critical",
        "pattern": re.compile(
            r"(?:https?|gopher|dict|file)://(?:169\.254\.169\.254|metadata\.google\.internal|127\.0\.0\.1|localhost)",
            re.IGNORECASE
        ),
        "desc": "SSRF payload targeting cloud instance metadata service (IMDS) or loopback interface.",
        "rec": "Enforce IMDSv2 with token hops, restrict outbound HTTP requests from web servers to private ranges."
    },
    {
        "category": "SQL Injection (SQLi)",
        "mitre": "T1190 - Exploit Public-Facing Application",
        "severity": "Critical",
        "pattern": re.compile(
            r"('|\%27)\s*(OR|AND)\s*('|\%27)?\d+('|\%27)?\s*=\s*('|\%27)?\d+|"
            r"\bUNION\s+(?:ALL\s+)?SELECT\b|"
            r"\b(?:SLEEP|BENCHMARK)\s*\(\s*\d+\s*\)|"
            r"\bWAITFOR\s+DELAY\b|"
            r"\bINFORMATION_SCHEMA\b|"
            r"(?:--|#|/\*).{0,20}$",
            re.IGNORECASE
        ),
        "desc": "SQL Injection syntax detected in URI/query parameter attempting backend database tampering.",
        "rec": "Implement parameterized queries / prepared statements (CWE-89) and restrict database account privileges."
    },
    {
        "category": "Path Traversal / LFI",
        "mitre": "T1083 - File and Directory Discovery",
        "severity": "High",
        "pattern": re.compile(
            r"(?:\.\./|\.\.\\|\%2e\%2e|\%252e\%252e){2,}|"
            r"/etc/(?:passwd|shadow|hosts)|"
            r"(?:win\.ini|boot\.ini|c:\\windows\\system32)",
            re.IGNORECASE
        ),
        "desc": "Directory traversal sequence detected attempting unauthorized file system access.",
        "rec": "Validate file requests against an absolute whitelist and avoid passing direct file paths from client."
    },
    {
        "category": "Cross-Site Scripting (XSS)",
        "mitre": "T1190 - Exploit Public-Facing Application",
        "severity": "High",
        "pattern": re.compile(
            r"<script[^>]*>|"
            r"javascript:\s*|"
            r"on(?:error|load|click|mouseover)\s*=\s*['\"][^'\"]*|"
            r"<img[^>]+src\s*=\s*['\"]?x['\"]?|"
            r"<svg[^>]+onload|"
            r"\balert\s*\([^\)]*\)|"
            r"document\.cookie",
            re.IGNORECASE
        ),
        "desc": "XSS vector identified in request payload attempting browser-side JavaScript execution.",
        "rec": "Sanitize and context-encode all untrusted input and enforce a strict Content Security Policy (CSP)."
    }
]


class DetectionEngine:
    """Configurable security detection engine for log streams."""

    def __init__(self, brute_force_threshold: int = 5):
        self.brute_force_threshold = brute_force_threshold

    def analyze_auth_entries(self, entries: List[AuthLogEntry]) -> List[SecurityAlert]:
        """Detect SSH / Sudo brute force and credential spraying patterns."""
        alerts = []
        # Group failed attempts by IP -> set of usernames, list of raws
        ip_failures = defaultdict(list)
        ip_users = defaultdict(set)

        for entry in entries:
            if entry.event_type in ("failed", "invalid_user", "sudo_failure"):
                ip_failures[entry.ip].append(entry)
                ip_users[entry.ip].add(entry.user)

        alert_idx = 1
        for ip, attempts in ip_failures.items():
            count = len(attempts)
            users_targeted = list(ip_users[ip])
            
            if count >= self.brute_force_threshold:
                # Differentiate between targeted single-user brute force and credential spraying
                if len(users_targeted) > 2:
                    category = "Credential Spraying / Stuffing"
                    severity = "Critical" if count >= 15 else "High"
                    desc = (
                        f"Detected {count} authentication failures from IP {ip} targeting multiple accounts "
                        f"({', '.join(users_targeted[:4])}). Indicates automated credential stuffing."
                    )
                    rec = "Immediately block attacker IP via firewall (iptables/ufw), enforce account lockout and MFA."
                else:
                    category = "SSH Brute-Force Attempt"
                    severity = "Critical" if count >= 15 else "High"
                    desc = (
                        f"Detected {count} failed authentication attempts from IP {ip} targeting user(s) "
                        f"'{', '.join(users_targeted)}'."
                    )
                    rec = "Block IP at perimeter/firewall, enforce SSH key-based authentication and disable password logins."

                alert = SecurityAlert(
                    alert_id=f"AUTH-{alert_idx:03d}",
                    category=category,
                    severity=severity,
                    source_ip=ip,
                    target=f"Accounts: {', '.join(users_targeted[:5])}",
                    mitre_attack="T1110 - Brute Force",
                    description=desc,
                    evidence=attempts[-1].raw,
                    count=count,
                    recommendation=rec
                )
                alerts.append(alert)
                alert_idx += 1

        return alerts

    def analyze_web_entries(self, entries: List[WebLogEntry]) -> List[SecurityAlert]:
        """Inspect web request URIs, query strings, and payloads against OWASP Top 10 signatures."""
        alerts = []
        # Aggregate matches by (IP, Category)
        detected_groups = defaultdict(list)

        for entry in entries:
            test_string = f"{entry.uri} {entry.decoded_uri} {entry.referer} {entry.user_agent}"
            
            for sig in WEB_SIGNATURES:
                if sig["pattern"].search(test_string):
                    key = (entry.client_ip, sig["category"])
                    detected_groups[key].append((sig, entry))
                    break  # One alert category per log line to avoid duplication

        alert_idx = 1
        for (ip, category), occurrences in detected_groups.items():
            sig, last_entry = occurrences[-1]
            count = len(occurrences)
            
            alert = SecurityAlert(
                alert_id=f"WEB-{alert_idx:03d}",
                category=category,
                severity=sig["severity"],
                source_ip=ip,
                target=f"{last_entry.method} {last_entry.uri.split('?')[0]}",
                mitre_attack=sig["mitre"],
                description=f"{sig['desc']} ({count} request(s) observed from this source).",
                evidence=last_entry.raw,
                count=count,
                recommendation=sig["rec"]
            )
            alerts.append(alert)
            alert_idx += 1

        return alerts

    def analyze_stream(self, parsed_stream: List[Tuple[str, Any]]) -> List[SecurityAlert]:
        """Analyze a mixed stream of parsed log entries."""
        auth_entries = [entry for kind, entry in parsed_stream if kind == "auth"]
        web_entries = [entry for kind, entry in parsed_stream if kind == "web"]

        alerts = []
        alerts.extend(self.analyze_auth_entries(auth_entries))
        alerts.extend(self.analyze_web_entries(web_entries))
        
        # Sort by severity (Critical -> High -> Medium -> Low)
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        alerts.sort(key=lambda a: (severity_order.get(a.severity, 99), -a.count))
        return alerts
