"""
cli.py - Command Line Interface for SOC Log Sentinel
Usage:
  python -m sentinel.cli --file samples/auth.log --rules rules/
  python -m sentinel.cli samples/auth.log samples/access.log --export json -j report.json
"""

import sys
import os
import argparse
from typing import List, Optional

from rich.console import Console

from . import __version__
from .parser import parse_log_file, LogEntry
from .engine import DetectionEngine
from .report import IncidentReporter


def resolve_default_rules_dir() -> str:
    """Locate default rules directory relative to package or current working directory."""
    # Check current directory
    if os.path.exists("rules") and os.path.isdir("rules"):
        return os.path.abspath("rules")
    
    # Check sibling to package
    pkg_dir = os.path.dirname(os.path.abspath(__file__))
    parent_rules = os.path.join(os.path.dirname(pkg_dir), "rules")
    if os.path.exists(parent_rules) and os.path.isdir(parent_rules):
        return parent_rules
        
    return "rules"


def create_parser() -> argparse.ArgumentParser:
    default_rules = resolve_default_rules_dir()
    parser = argparse.ArgumentParser(
        prog="soc-log-sentinel",
        description="SOC Log Sentinel — Enterprise Detection Engineering & Incident Triage Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Quickstart evaluation on sample logs:
  python -m sentinel.cli --file samples/auth.log --rules rules/

  # Multi-log ingestion with Rich terminal summary:
  python -m sentinel.cli samples/auth.log samples/access.log samples/windows_security.log

  # Export SIEM-ready structured JSON telemetry:
  python -m sentinel.cli samples/access.log --export json -j triage_report.json

  # Generate Markdown incident report with custom brute-force threshold:
  python -m sentinel.cli samples/auth.log --threshold 3 -m incident_report.md
        """
    )
    parser.add_argument(
        "logs",
        nargs="*",
        default=[],
        help="One or more log files to analyze (e.g. auth.log, access.log, windows_events.log)"
    )
    parser.add_argument(
        "-f", "--file",
        dest="file_opt",
        action="append",
        default=[],
        help="Target log file path (can be specified multiple times)"
    )
    parser.add_argument(
        "-r", "--rules",
        type=str,
        default=default_rules,
        help=f"Path to directory containing YAML detection rules (default: {default_rules})"
    )
    parser.add_argument(
        "--format",
        choices=["auto", "web", "auth", "windows"],
        default="auto",
        help="Enforce specific log parser format: 'auto' (default), 'web', 'auth', 'windows'"
    )
    parser.add_argument(
        "--export",
        choices=["json", "markdown", "both"],
        default=None,
        help="Export format for SIEM pipeline or triage reporting ('json', 'markdown', 'both')"
    )
    parser.add_argument(
        "-j", "--output-json",
        type=str,
        default=None,
        help="File path to save JSON incident telemetry"
    )
    parser.add_argument(
        "-m", "--output-md",
        type=str,
        default=None,
        help="File path to save Markdown triage report"
    )
    parser.add_argument(
        "-t", "--threshold",
        type=int,
        default=None,
        help="Override failed authentication brute force threshold (e.g. 3)"
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Quiet mode: suppress Rich terminal interactive tables"
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"SOC Log Sentinel v{__version__}"
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = create_parser()
    args = parser.parse_args(argv)

    # Combine positional logs and -f / --file options
    target_logs = list(args.logs)
    if args.file_opt:
        target_logs.extend(args.file_opt)

    if not target_logs:
        parser.print_help(sys.stderr)
        print("\n[-] Error: No log files provided. Specify files via arguments or --file.", file=sys.stderr)
        return 1

    # Verify files exist
    all_entries: List[LogEntry] = []
    processed_files: List[str] = []

    for log_path in target_logs:
        if not os.path.exists(log_path):
            print(f"[-] Error: Log file not found: {log_path}", file=sys.stderr)
            return 1
        try:
            entries = parse_log_file(log_path, log_type=args.format)
            all_entries.extend(entries)
            processed_files.append(os.path.abspath(log_path))
        except Exception as e:
            print(f"[-] Error parsing {log_path}: {e}", file=sys.stderr)
            return 1

    # Load detection rules
    engine = DetectionEngine()
    if os.path.exists(args.rules):
        engine.load_rules(args.rules)
    else:
        print(f"[!] Warning: Rules directory not found at {args.rules}. Proceeding without rules.", file=sys.stderr)

    # Analyze logs
    alerts = engine.analyze_stream(all_entries, threshold_override=args.threshold)
    metadata = IncidentReporter.compile_metadata(alerts, processed_files, len(all_entries))

    # Terminal Dashboard rendering via Rich
    console = Console()
    if not args.quiet:
        IncidentReporter.render_terminal_summary(alerts, metadata, console=console)

    # Export handling
    # If --export json was passed without -j, default to sentinel_report.json
    json_path = args.output_json
    if args.export in ("json", "both") and not json_path:
        json_path = "sentinel_report.json"

    # If --export markdown was passed without -m, default to sentinel_report.md
    md_path = args.output_md
    if args.export in ("markdown", "both") and not md_path:
        md_path = "sentinel_report.md"

    if json_path:
        IncidentReporter.generate_json_report(alerts, metadata, file_path=json_path)
        if not args.quiet:
            console.print(f"[bold green]✔ JSON incident telemetry exported to:[/] [cyan]{json_path}[/]")

    if md_path:
        IncidentReporter.generate_markdown_report(alerts, metadata, file_path=md_path)
        if not args.quiet:
            console.print(f"[bold green]✔ Markdown triage report exported to:[/] [cyan]{md_path}[/]")

    return 0


if __name__ == "__main__":
    sys.exit(main())
