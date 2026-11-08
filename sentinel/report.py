"""
report.py - Multi-Channel Security Reporting & Visualization Engine
Renders sleek, color-coded terminal tables via Rich, and exports SIEM-ingestible JSON and Markdown reports.
"""

import os
import json
from datetime import datetime
from typing import List, Dict, Any, Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

from .engine import Alert


class IncidentReporter:
    """Formatter and exporter for incident triage alerts."""

    @staticmethod
    def compile_metadata(
        alerts: List[Alert],
        log_files: List[str],
        total_events: int
    ) -> Dict[str, Any]:
        """Compile executive incident telemetry and statistics."""
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        attackers = set()
        targets = set()
        mitre_tactics = set()

        for a in alerts:
            severity_counts[a.severity] = severity_counts.get(a.severity, 0) + 1
            if a.source_ip and a.source_ip not in ("127.0.0.1", "-", "N/A"):
                attackers.add(a.source_ip)
            if a.target and a.target != "-":
                targets.add(a.target)
            if a.mitre_tactic:
                mitre_tactics.add(a.mitre_tactic)

        return {
            "timestamp": datetime.now().isoformat(),
            "log_files": log_files,
            "total_events_parsed": total_events,
            "total_alerts": len(alerts),
            "severity_counts": severity_counts,
            "unique_attackers": sorted(list(attackers)),
            "unique_targets": sorted(list(targets)),
            "mitre_tactics_observed": sorted(list(mitre_tactics))
        }

    @staticmethod
    def render_terminal_summary(
        alerts: List[Alert],
        metadata: Dict[str, Any],
        console: Optional[Console] = None
    ) -> None:
        """Render beautiful, color-coded terminal dashboard using Rich."""
        if console is None:
            console = Console()

        # 1. Header Banner
        header_text = Text()
        header_text.append("🛡️  SOC LOG SENTINEL ", style="bold cyan")
        header_text.append("v2.0.0", style="dim white")
        header_text.append(" — Enterprise Detection & Incident Triage Engine\n", style="bold white")
        header_text.append("MITRE ATT&CK Aligned Detection Engineering Framework", style="italic dim cyan")
        console.print(Panel(header_text, border_style="cyan", box=box.ROUNDED))

        # 2. Executive Summary Metrics
        sev = metadata.get("severity_counts", {})
        summary_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        summary_table.add_column("Key", style="bold white")
        summary_table.add_column("Value")
        summary_table.add_column("Key2", style="bold white")
        summary_table.add_column("Value2")

        summary_table.add_row(
            "Log Sources Analyzed:",
            f"[cyan]{len(metadata.get('log_files', []))} files ({metadata.get('total_events_parsed', 0)} events)[/]",
            "Threat Severity:",
            f"[bold white on red] Critical: {sev.get('Critical', 0)} [/]  "
            f"[bold red] High: {sev.get('High', 0)} [/]  "
            f"[bold yellow] Med: {sev.get('Medium', 0)} [/]  "
            f"[bold blue] Low: {sev.get('Low', 0)} [/]"
        )
        summary_table.add_row(
            "Total Alerts Triggered:",
            f"[bold magenta]{metadata.get('total_alerts', 0)} security incidents[/]",
            "Unique Threat Actors:",
            f"[bold yellow]{len(metadata.get('unique_attackers', []))} source IPs[/] "
            f"({', '.join(metadata.get('unique_attackers', [])[:3]) or 'None'})"
        )
        console.print(Panel(summary_table, title="[bold]EXECUTIVE INCIDENT SUMMARY[/]", border_style="blue", box=box.ROUNDED))

        if not alerts:
            console.print("[bold green]✔ Zero threats detected. All events conform to baseline security policies.[/]\n")
            return

        # 3. Security Alerts Table
        table = Table(
            title="[bold red]🚨 DETECTED SECURITY INCIDENTS & THREAT VECTORS[/]",
            box=box.ROUNDED,
            header_style="bold cyan",
            border_style="dim white",
            show_lines=True
        )

        table.add_column("Alert ID", style="bold cyan", width=9, justify="center")
        table.add_column("Severity", justify="center", width=12)
        table.add_column("Rule & Threat Vector", style="bold white", width=26)
        table.add_column("Source -> Target", width=24)
        table.add_column("MITRE ATT&CK", style="magenta", width=22)
        table.add_column("Observed Evidence / Payload", style="yellow", width=30)
        table.add_column("Hits", justify="right", width=6)

        for a in alerts:
            # Severity Badge Styling
            if a.severity == "Critical":
                sev_badge = "[bold white on red] CRITICAL [/]"
            elif a.severity == "High":
                sev_badge = "[bold red] HIGH [/]"
            elif a.severity == "Medium":
                sev_badge = "[bold yellow] MEDIUM [/]"
            else:
                sev_badge = "[bold blue] LOW [/]"

            # Clean evidence display
            clean_evidence = a.evidence.replace("\n", " ").strip()
            if len(clean_evidence) > 45:
                clean_evidence = clean_evidence[:42] + "..."

            src_target = f"{a.source_ip}\n-> {a.target[:18]}"
            mitre_tag = f"[bold]{a.mitre_id}[/]\n{a.mitre_technique[:18]}"

            table.add_row(
                a.alert_id,
                sev_badge,
                a.rule_name,
                src_target,
                mitre_tag,
                clean_evidence,
                str(a.count)
            )

        console.print(table)

        # 4. MITRE ATT&CK Coverage Table
        mitre_table = Table(
            title="[bold magenta]🎯 MITRE ATT&CK TACTIC BREAKDOWN[/]",
            box=box.SIMPLE_HEAVY,
            header_style="bold magenta"
        )
        mitre_table.add_column("Tactic", style="bold white")
        mitre_table.add_column("Technique ID", style="cyan")
        mitre_table.add_column("Technique Name", style="white")
        mitre_table.add_column("Triggered Rule", style="yellow")
        mitre_table.add_column("Event Hits", justify="right", style="green")

        tactic_map = {}
        for a in alerts:
            key = (a.mitre_tactic, a.mitre_id, a.mitre_technique, a.rule_name)
            tactic_map[key] = tactic_map.get(key, 0) + a.count

        for (tactic, tid, tname, rname), count in sorted(tactic_map.items()):
            mitre_table.add_row(tactic, tid, tname, rname, str(count))

        console.print(mitre_table)
        console.print()

    @staticmethod
    def generate_json_report(
        alerts: List[Alert],
        metadata: Dict[str, Any],
        file_path: Optional[str] = None
    ) -> str:
        """Serialize complete incident telemetry to SIEM-compatible JSON."""
        data = {
            "sentinel_version": "2.0.0",
            "metadata": metadata,
            "alerts": [
                {
                    "alert_id": a.alert_id,
                    "rule_id": a.rule_id,
                    "rule_name": a.rule_name,
                    "severity": a.severity,
                    "source_ip": a.source_ip,
                    "target": a.target,
                    "user": a.user,
                    "mitre": {
                        "id": a.mitre_id,
                        "technique": a.mitre_technique,
                        "tactic": a.mitre_tactic
                    },
                    "description": a.description,
                    "evidence": a.evidence,
                    "count": a.count,
                    "timestamp": a.timestamp,
                    "remediation": a.remediation
                }
                for a in alerts
            ]
        }
        json_str = json.dumps(data, indent=2, ensure_ascii=False)
        if file_path:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(json_str)
        return json_str

    @staticmethod
    def generate_markdown_report(
        alerts: List[Alert],
        metadata: Dict[str, Any],
        file_path: Optional[str] = None
    ) -> str:
        """Generate executive-level Markdown incident triage report."""
        lines = [
            "# 🛡️ SOC Log Sentinel — Incident Triage Report",
            f"**Generated:** {metadata.get('timestamp')}  ",
            f"**Log Sources:** `{', '.join(metadata.get('log_files', []))}`  ",
            f"**Events Ingested:** {metadata.get('total_events_parsed', 0)}  ",
            f"**Total Incidents Flagged:** {metadata.get('total_alerts', 0)}  ",
            "",
            "## 1. Executive Summary",
            "",
            "| Severity | Incidents |",
            "|:---|:---:|",
        ]
        for sev, count in metadata.get("severity_counts", {}).items():
            badge = "🔴" if sev == "Critical" else "🟠" if sev == "High" else "🟡" if sev == "Medium" else "🔵"
            lines.append(f"| {badge} {sev} | **{count}** |")

        lines.extend([
            "",
            f"**Unique Attackers Identified:** `{', '.join(metadata.get('unique_attackers', [])) or 'None'}`  ",
            f"**MITRE ATT&CK Tactics Observed:** `{', '.join(metadata.get('mitre_tactics_observed', [])) or 'None'}`",
            "",
            "## 2. Detailed Security Incidents",
            ""
        ])

        for a in alerts:
            lines.extend([
                f"### [{a.alert_id}] {a.rule_name} (`{a.severity}`)",
                f"- **MITRE ATT&CK:** {a.mitre_id} ({a.mitre_technique}) — *{a.mitre_tactic}*",
                f"- **Attacker Source IP:** `{a.source_ip}`",
                f"- **Target / User:** `{a.target}` (User: `{a.user}`)",
                f"- **Event Count:** {a.count}",
                f"- **Observed Timestamp:** {a.timestamp}",
                f"- **Description:** {a.description}",
                f"- **Evidence Payload:**",
                "```text",
                a.evidence,
                "```",
                f"- **Remediation Recommendation:** {a.remediation}",
                ""
            ])

        lines.extend([
            "## 3. SOC Analyst Action Checklist",
            "- [ ] Isolate identified threat actor source IPs at edge perimeter firewalls.",
            "- [ ] Audit targeted endpoints and verify no unauthorized accounts or backdoors were established.",
            "- [ ] Update Web Application Firewall (WAF) rate limits and virtual patching signatures.",
            "- [ ] Correlate source IPs against SIEM threat intelligence feeds and dark web credential dumps.",
            "",
            "---",
            "*Report automatically compiled by SOC Log Sentinel v2.0.0 — Detection Engineering Toolkit*"
        ])

        md_content = "\n".join(lines)
        if file_path:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(md_content)
        return md_content
