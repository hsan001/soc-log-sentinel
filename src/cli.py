"""
cli.py - Command Line Interface for SOC Log Sentinel
Usage:
  python -m src.cli sample_logs/auth.log sample_logs/access.log --output-md report.md --output-json report.json
"""

import sys
import os
import argparse
from typing import List, Optional

from . import __version__
from .parser import parse_log_file
from .detector import DetectionEngine
from .reporter import compile_metadata, generate_json_report, generate_markdown_report, generate_terminal_summary


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soc-log-sentinel",
        description="SOC Log Sentinel — Automated Cybersecurity Log Analysis & Incident Triage Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze auth and web logs with terminal summary:
  soc-log-sentinel sample_logs/auth.log sample_logs/access.log

  # Generate both Markdown and JSON reports:
  soc-log-sentinel sample_logs/access.log -m triage_report.md -j triage_report.json

  # Set custom brute-force threshold to 3:
  soc-log-sentinel sample_logs/auth.log --threshold 3
        """
    )
    parser.add_argument(
        "logs",
        nargs="+",
        help="One or more log file paths to ingest and analyze (e.g. auth.log, access.log)"
    )
    parser.add_argument(
        "-f", "--format",
        choices=["auto", "web", "auth"],
        default="auto",
        help="Log format parsing mode: 'auto' (default), 'web' (Apache/Nginx), 'auth' (Linux SSH/sudo)"
    )
    parser.add_argument(
        "-m", "--output-md",
        type=str,
        default=None,
        help="File path to export formatted Markdown incident triage report"
    )
    parser.add_argument(
        "-j", "--output-json",
        type=str,
        default=None,
        help="File path to export structured JSON incident telemetry"
    )
    parser.add_argument(
        "-t", "--threshold",
        type=int,
        default=5,
        help="Brute force failed attempt trigger threshold (default: 5)"
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Quiet mode: suppress terminal summary table"
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

    all_entries = []
    processed_files = []

    for log_path in args.logs:
        if not os.path.exists(log_path):
            print(f"[-] Error: File not found: {log_path}", file=sys.stderr)
            return 1
            
        entries = parse_log_file(log_path, log_type=args.format)
        all_entries.extend(entries)
        processed_files.append(log_path)

    # Detect threats
    engine = DetectionEngine(brute_force_threshold=args.threshold)
    alerts = engine.analyze_stream(all_entries)
    metadata = compile_metadata(alerts, processed_files, len(all_entries))

    # Terminal output
    if not args.quiet:
        summary_text = generate_terminal_summary(alerts, metadata)
        print(summary_text)

    # Export Markdown
    if args.output_md:
        md_text = generate_markdown_report(alerts, metadata)
        os.makedirs(os.path.dirname(args.output_md) or ".", exist_ok=True)
        with open(args.output_md, "w", encoding="utf-8") as f:
            f.write(md_text)
        if not args.quiet:
            print(f"[+] Markdown Incident Report saved to: {args.output_md}")

    # Export JSON
    if args.output_json:
        json_text = generate_json_report(alerts, metadata)
        os.makedirs(os.path.dirname(args.output_json) or ".", exist_ok=True)
        with open(args.output_json, "w", encoding="utf-8") as f:
            f.write(json_text)
        if not args.quiet:
            print(f"[+] JSON Incident Telemetry saved to:   {args.output_json}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
