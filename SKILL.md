---
name: ai-security-code-review-agent
description: Run and interpret an AI-assisted static security review for a codebase using the bundled Python scanner. Use when Codex or Claude needs to scan repositories for OWASP risks, hardcoded secrets, web/mobile/embedded/pipeline/AI-ML security patterns, generate Markdown or JSON reports, triage high-severity findings, or produce remediation guidance from scanner output.
---

# AI Security Code Review Agent

Use this skill to run the bundled static security scanner, read its output, and turn findings into a practical security review.

## Workflow

1. Inspect the target repository structure and identify package/config files.
2. Install scanner dependencies if needed:

```bash
pip install -r requirements.txt
```

3. Run the scanner from this skill/repo directory:

```bash
python main.py /path/to/target/repo --no-interactive --output security_report.md
```

4. Read `.security_findings.json` from the target repo when present.
5. For every CRITICAL and HIGH finding, inspect the referenced source file before accepting the result.
6. Classify each important finding as true positive, false positive, or needs manual confirmation.
7. Provide exact remediation steps and tests, prioritized by exploitability.

## Scanner Capabilities

The scanner includes pattern groups for:

- OWASP application security issues
- hardcoded secrets and credentials
- web application risks
- mobile application risks
- embedded/IoT risks
- CI/CD, container, Kubernetes, Terraform, and pipeline risks
- AI/ML security issues
- security-relevant code quality issues

## Output Expectations

When summarizing results, lead with:

- counts by severity
- critical/high findings with file and line
- likely false positives
- attack surface notes
- prioritized remediation roadmap

Avoid treating static pattern matches as final truth. Always validate severe findings against the actual code context.

## Domain and Token Discipline

The scanner is domain-aware. It always runs core, secrets, and code-quality checks. It only runs web, mobile, embedded, pipeline, or AI/ML rules when the target repository has matching architecture or dependency signals.

Use `.security-agent.yml` when a repository needs custom behavior:

- `fail_threshold` sets the CI gate severity.
- `include_domains` and `exclude_domains` override auto-detected domains.
- `ignore_patterns` adds repo-local ignores.
- `baseline_file` suppresses accepted legacy findings.
- `dependency_audit.enabled` controls pip-audit, npm audit, and osv-scanner integration.

When using this skill in a project with other Claude or Codex agents, add the relevant boundary snippet:

- `templates/CLAUDE_SECURITY_BOUNDARY.md` into `CLAUDE.md`
- `templates/AGENTS_SECURITY_BOUNDARY.md` into `AGENTS.md`

This prevents ordinary implementation agents from spending tokens on duplicate security/KVKK reviews. They should let the security-agent workflow run after push and read the latest report only when the user asks.

## GitHub Actions Usage

For automatic scans after every push or pull request, copy `templates/security-agent-target-workflow.yml` into the target repository as `.github/workflows/ai-security-agent.yml`.

That workflow intentionally checks out two repositories:

- `target/`: the project being scanned
- `security-agent/`: this public scanner repo, used only as the tool source

This is separate from skill usage. Codex/Claude can read `SKILL.md` during a chat, but GitHub Actions runs on a clean CI machine and must fetch the scanner code explicitly.

## Claude Usage

This repo also includes `.claude/commands/security-review.md` for Claude Code slash-command usage. Use it when the user explicitly asks for `/security-review` or wants the Claude command workflow.
