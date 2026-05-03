# AI Security Code Review Agent

A Python-based static security scanner and review assistant for codebases. It detects project architecture, scans source files with security pattern rules, prints terminal findings, and generates Markdown/JSON reports for deeper AI-assisted review workflows.

## What It Checks

- OWASP-style application security issues
- Hardcoded secrets and credentials
- Web, mobile, embedded, pipeline, cloud, and AI/ML security patterns
- Code quality patterns that can create security risk
- Project languages, frameworks, and architecture signals

## Project Structure

```text
.
├── main.py
├── requirements.txt
├── scanner/
│   ├── detector.py
│   ├── runner.py
│   └── patterns/
├── reporter/
│   ├── markdown_gen.py
│   └── terminal.py
└── .claude/
    └── commands/
        └── security-review.md
```

## Installation

```bash
pip install -r requirements.txt
```

## Usage

Scan a repository and create a Markdown report:

```bash
python main.py /path/to/repo
```

Write the report to a custom path:

```bash
python main.py /path/to/repo --output reports/security.md
```

Skip interactive review mode:

```bash
python main.py /path/to/repo --no-interactive
```

Filter by minimum severity:

```bash
python main.py /path/to/repo --severity HIGH
```

## Outputs

- `security_report.md`: human-readable Markdown report
- `.security_findings.json`: structured findings for follow-up analysis and Claude Code workflows

## Automation and Agent Boundaries

The scanner is domain-aware: core, secrets, and code-quality checks always run, while web, mobile, embedded, pipeline, and AI/ML checks run only when the repository has matching signals. Skipped domains are listed in the terminal output and Markdown report.

This repo also includes a GitHub Actions workflow for automatic scans after pushes and pull requests. For multi-agent projects, copy:

- `templates/CLAUDE_SECURITY_BOUNDARY.md` into `CLAUDE.md`
- `templates/AGENTS_SECURITY_BOUNDARY.md` into `AGENTS.md`

Those snippets tell non-security agents not to waste tokens on broad security/KVKK reviews unless explicitly asked.

## Claude Command

The project includes `.claude/commands/security-review.md`, a slash-command workflow for turning scanner results into a deeper security review with exploitability analysis, false-positive triage, and prioritized remediation.

## Skill Usage

This repository also includes `SKILL.md`, so it can be used as an installable Codex/Claude-style skill folder. The skill tells an agent how to run the scanner, read `.security_findings.json`, validate severe findings, and produce remediation guidance.

## Notes

This tool is based on static pattern matching. Treat findings as review candidates, not final truth. Validate high-impact findings manually before making release decisions.
