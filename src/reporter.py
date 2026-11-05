"""
reporter.py - Incident Triage Reporting Engine
Formats security detection alerts into:
- Structured JSON (SIEM / SOAR / Splunk ingestion)
- SOC L1/L2 Incident Triage Markdown handover report
- Terminal summary tables
"""

import json
from datetime import datetime, timezone
from typing import List, Dict, Any
from .detector import SecurityAlert


def compile_metadata(alerts: List[SecurityAlert], file_paths: List[str], total_logs: int) -> Dict[str, Any]:
    """Calculate summary statistics and incident metrics."""
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    unique_ips = set()
    mitre_techniques = set()

    for a in alerts:
        severity_counts[a.severity] = severity_counts.get(a.severity, 0) + 1
        unique_ips.add(a.source_ip)
        mitre_techniques.add(a.mitre_attack)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "files_analyzed": file_paths,
        "total_log_lines_analyzed": total_logs,
        "total_alerts": len(alerts),
        "severity_breakdown": severity_counts,
        "unique_attacker_ips": sorted(list(unique_ips)),
        "mitre_techniques_observed": sorted(list(mitre_techniques))
    }


def generate_json_report(alerts: List[SecurityAlert], metadata: Dict[str, Any]) -> str:
    """Export incident telemetry to structured JSON."""
    report = {
        "metadata": metadata,
        "alerts": [
            {
                "alert_id": a.alert_id,
                "category": a.category,
                "severity": a.severity,
                "source_ip": a.source_ip,
                "target": a.target,
                "mitre_attack": a.mitre_attack,
                "description": a.description,
                "evidence": a.evidence,
                "count": a.count,
                "recommendation": a.recommendation
            }
            for a in alerts
        ]
    }
    return json.dumps(report, indent=2)


def generate_markdown_report(alerts: List[SecurityAlert], metadata: Dict[str, Any]) -> str:
    """Generate professional SOC incident triage report in Markdown."""
    lines = []
    lines.append("# 🛡️ SOC Log Sentinel — Incident Triage Report")
    lines.append("")
    lines.append(f"**Generated:** `{metadata['generated_at']}` | **Status:** `Active Incident Triage`")
    lines.append(f"**Target Files Analyzed:** `{', '.join(metadata['files_analyzed'])}`")
    lines.append("")
    lines.append("---")
    lines.append("")
    
    # Executive Summary
    lines.append("## 1. Executive Incident Summary")
    crit = metadata["severity_breakdown"].get("Critical", 0)
    high = metadata["severity_breakdown"].get("High", 0)
    total = metadata["total_alerts"]
    lines.append(
        f"Automated log analysis ingested **{metadata['total_log_lines_analyzed']} log entries** and flagged "
        f"**{total} security alert(s)** across **{len(metadata['unique_attacker_ips'])} hostile IP address(es)**. "
        f"Threat landscape contains **{crit} Critical** and **{high} High** severity incidents requiring immediate "
        f"containment and firewall quarantine."
    )
    lines.append("")

    # Metrics Table
    lines.append("## 2. Security Metrics & Threat Breakdown")
    lines.append("| Metric | Value |")
    lines.append("|---|---|")
    lines.append(f"| **Total Log Lines Ingested** | `{metadata['total_log_lines_analyzed']}` |")
    lines.append(f"| **Total Security Alerts** | `{total}` |")
    lines.append(f"| **Critical Severity Alerts** | `🔴 {crit}` |")
    lines.append(f"| **High Severity Alerts** | `🟠 {high}` |")
    lines.append(f"| **Unique Hostile IP Sources** | `{len(metadata['unique_attacker_ips'])}` |")
    lines.append(f"| **MITRE ATT&CK Techniques** | `{len(metadata['mitre_techniques_observed'])}` |")
    lines.append("")

    # MITRE ATT&CK Alignment
    lines.append("## 3. MITRE ATT&CK® Mapping")
    if metadata["mitre_techniques_observed"]:
        for t in metadata["mitre_techniques_observed"]:
            lines.append(f"- `[{t}]`")
    else:
        lines.append("- *No adversarial techniques detected.*")
    lines.append("")

    # Attacker IPs Table
    lines.append("## 4. Threat Actor Source IPs")
    if metadata["unique_attacker_ips"]:
        lines.append("| Source IP | Associated Threat Categories | Proposed Firewall Action |")
        lines.append("|---|---|---|")
        for ip in metadata["unique_attacker_ips"]:
            ip_cats = {a.category for a in alerts if a.source_ip == ip}
            lines.append(f"| `{ip}` | {', '.join(ip_cats)} | `DROP / Null-Route` |")
    else:
        lines.append("*No hostile source IPs identified.*")
    lines.append("")

    # Detailed Alerts
    lines.append("## 5. Detailed Incident Triage Log")
    if not alerts:
        lines.append("✅ *Clean log stream. Zero adversarial signatures detected.*")
    else:
        for a in alerts:
            badge = "🔴 CRITICAL" if a.severity == "Critical" else ("🟠 HIGH" if a.severity == "High" else "🟡 MEDIUM")
            lines.append(f"### `[{a.alert_id}]` {a.category} — {badge}")
            lines.append(f"- **Source IP:** `{a.source_ip}`")
            lines.append(f"- **Target Asset:** `{a.target}`")
            lines.append(f"- **MITRE ATT&CK:** `{a.mitre_attack}`")
            lines.append(f"- **Occurrences:** `{a.count}` event(s)")
            lines.append(f"- **Description:** {a.description}")
            lines.append(f"- **Containment Action:** {a.recommendation}")
            lines.append("- **Raw Forensic Evidence:**")
            lines.append(f"  ```text\n  {a.evidence}\n  ```")
            lines.append("")

    # Remediation Playbook
    lines.append("## 6. Containment & Remediation Playbook")
    lines.append("1. **Perimeter Isolation:** Enforce perimeter firewall blocks on flagged IP addresses.")
    lines.append("2. **Account Hardening:** Terminate active sessions for targeted accounts and require credential resets.")
    lines.append("3. **Web Application Firewall (WAF):** Ensure WAF rulesets are active for SQLi, XSS, and RCE signatures.")
    lines.append("4. **Audit Logging:** Maintain log retention and ship event streams to enterprise SIEM for long-term correlation.")
    lines.append("")

    return "\n".join(lines)


def generate_terminal_summary(alerts: List[SecurityAlert], metadata: Dict[str, Any]) -> str:
    """Format a clean, readable ASCII summary table for terminal display."""
    lines = []
    lines.append("=" * 72)
    lines.append("🛡️  SOC LOG SENTINEL — INCIDENT ANALYSIS SUMMARY")
    lines.append("=" * 72)
    lines.append(f"Total Logs Analyzed: {metadata['total_log_lines_analyzed']}")
    lines.append(f"Alerts Identified:   {metadata['total_alerts']}")
    crit = metadata['severity_breakdown'].get('Critical', 0)
    high = metadata['severity_breakdown'].get('High', 0)
    lines.append(f"Severity Breakdown:  Critical: {crit} | High: {high} | Medium: {metadata['severity_breakdown'].get('Medium', 0)}")
    lines.append(f"Attacker IPs:        {', '.join(metadata['unique_attacker_ips']) or 'None'}")
    lines.append("-" * 72)
    
    if not alerts:
        lines.append("✅ No threats detected. All analyzed logs are within baseline parameters.")
    else:
        lines.append(f"{'ID':<10} {'SEVERITY':<10} {'CATEGORY':<28} {'SOURCE IP':<16} {'COUNT'}")
        lines.append("-" * 72)
        for a in alerts:
            lines.append(f"{a.alert_id:<10} {a.severity:<10} {a.category[:26]:<28} {a.source_ip:<16} {a.count}")
    lines.append("=" * 72)
    return "\n".join(lines)
