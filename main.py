#!/usr/bin/env python3
"""
AI Security & Code Review Agent — Entry Point

Usage:
    python main.py /path/to/repo
    python main.py /path/to/repo --output my_report.md
    python main.py /path/to/repo --no-interactive
"""

import sys
import json
import argparse
from pathlib import Path

from scanner.config import apply_config_to_project, finding_key, load_baseline, load_config
from scanner.detector import ProjectDetector
from scanner.dependency_audit import run_dependency_audits
from scanner.runner import SecurityRunner
from reporter.terminal import TerminalReporter
from reporter.markdown_gen import MarkdownReporter


def parse_args():
    parser = argparse.ArgumentParser(
        description='AI Security & Code Review Agent — OWASP, Secrets, Web, Mobile, Embedded, AI/ML',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py ./my-project
  python main.py ~/repos/myapp --output reports/security.md
  python main.py . --no-interactive
        """
    )
    parser.add_argument('repo_path', help='Path to the repository to analyze')
    parser.add_argument('--output', '-o', default='security_report.md',
                        help='Output markdown report path (default: security_report.md)')
    parser.add_argument('--no-interactive', action='store_true',
                        help='Skip interactive Q&A mode, just generate report')
    parser.add_argument('--severity', '-s', default='LOW',
                        choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
                        help='Minimum severity to show (default: LOW)')
    parser.add_argument('--config', help='Path to .security-agent.yml/json config')
    return parser.parse_args()


def run_interactive_mode(findings: list, terminal: TerminalReporter):
    """Walk through each finding interactively, starting from highest severity."""
    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
    sorted_findings = sorted(findings, key=lambda x: severity_order.get(x['severity'], 5))

    if not sorted_findings:
        terminal.print_info("No findings to review interactively.")
        return

    terminal.print_info(
        f"Starting interactive review of {len(sorted_findings)} findings, highest severity first.\n"
        f"Commands: [Enter] = review  |  [s] = skip  |  [f] = fix suggestion  |  [q] = quit"
    )

    for i, finding in enumerate(sorted_findings, 1):
        terminal.print_finding_detail(finding, i, len(sorted_findings))

        while True:
            try:
                cmd = input(f"\n  Command (Enter/s/f/q): ").strip().lower()
            except (KeyboardInterrupt, EOFError):
                print("\n\nExiting interactive mode.")
                return

            if cmd == 'q':
                print("\n  Exiting interactive mode.")
                return
            elif cmd == 's':
                break
            elif cmd == 'f':
                terminal.print_fix_suggestions(finding)
                break
            else:
                # Show description + fix
                terminal.print_detailed_analysis(finding)
                terminal.print_fix_suggestions(finding)
                break

        # Ask if they want to continue after first critical/high
        if i < len(sorted_findings) and finding['severity'] in ('CRITICAL', 'HIGH'):
            try:
                cont = input(f"\n  Continue to next finding? (Enter=yes / q=quit): ").strip().lower()
                if cont == 'q':
                    print("\n  Exiting interactive mode.")
                    return
            except (KeyboardInterrupt, EOFError):
                return


def main():
    args = parse_args()
    terminal = TerminalReporter()
    terminal.print_banner()

    # Validate path
    repo_path = Path(args.repo_path).resolve()
    if not repo_path.exists():
        terminal.print_error(f"Path does not exist: {repo_path}")
        sys.exit(1)

    config = load_config(repo_path, args.config)

    # ─── PHASE 1: Architecture Detection ───────────────────────────
    terminal.print_phase("PHASE 1 — Architecture & Technology Detection")
    detector = ProjectDetector(repo_path)
    project_info = detector.detect()
    project_info = apply_config_to_project(project_info, config)
    terminal.print_project_info(project_info)

    # ─── PHASE 2: Security Scan ─────────────────────────────────────
    terminal.print_phase("PHASE 2 — Security Analysis & Code Review")
    terminal.print_info(f"Scanning {project_info['total_files']} files...")
    runner = SecurityRunner(repo_path, project_info, config)
    findings = runner.run_all_checks()

    dependency_findings = run_dependency_audits(repo_path, config)
    if dependency_findings:
        terminal.print_info(f"Dependency audit added {len(dependency_findings)} finding(s).")
        findings.extend(dependency_findings)

    baseline = load_baseline(repo_path, config.get('baseline_file'))
    if baseline:
        before = len(findings)
        findings = [finding for finding in findings if finding_key(finding) not in baseline]
        terminal.print_info(f"Baseline suppressed {before - len(findings)} accepted finding(s).")

    # Filter by minimum severity
    sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
    min_sev = sev_order.get(args.severity, 3)
    findings = [f for f in findings if sev_order.get(f['severity'], 5) <= min_sev]

    terminal.print_findings_summary(findings)
    terminal.print_findings_detail(findings)

    # ─── PHASE 3: Report Generation ─────────────────────────────────
    terminal.print_phase("PHASE 3 — Report Generation")

    # Generate markdown report
    output_path = Path(args.output)
    md_reporter = MarkdownReporter(repo_path, project_info, findings)
    md_reporter.generate(output_path)
    terminal.print_success(f"Markdown report saved: {output_path.absolute()}")

    # Save JSON findings for Claude Code slash command
    findings_json = repo_path / '.security_findings.json'
    with open(findings_json, 'w', encoding='utf-8') as f:
        json.dump({
            'project_info': {k: v for k, v in project_info.items() if k != 'file_list'},
            'config': {k: v for k, v in config.items() if k != 'ignore_patterns'},
            'findings': findings,
            'total': len(findings),
            'by_severity': {
                s: len([x for x in findings if x['severity'] == s])
                for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
            }
        }, f, indent=2, default=str)
    terminal.print_success(f"Findings JSON saved: {findings_json}")

    # ─── PHASE 4: Interactive Mode ───────────────────────────────────
    if not args.no_interactive and findings:
        terminal.print_phase("PHASE 4 — Interactive Review Mode")
        run_interactive_mode(findings, terminal)

    # Final summary
    critical_count = len([f for f in findings if f['severity'] == 'CRITICAL'])
    if critical_count > 0:
        terminal.print_error(
            f"{critical_count} CRITICAL issues found. Address these before deploying."
        )
    else:
        terminal.print_success("Scan complete. Review the report for details.")

    print()


if __name__ == '__main__':
    main()
