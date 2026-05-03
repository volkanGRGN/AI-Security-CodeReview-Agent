# Security Agent Policy

This repository separates the security-review agent from other coding agents.

## Automatic Trigger

The security agent runs through GitHub Actions on:

- every push to `main`
- every pull request targeting `main`
- manual `workflow_dispatch`

The workflow runs `python main.py . --no-interactive --severity LOW --output security_report.md`, uploads the Markdown/JSON report as an artifact, and fails the job when CRITICAL findings are detected.

## Ownership Boundary

Only the security-agent workflow should create or modify scanner outputs:

- `security_report.md`
- `.security_findings.json`
- `security_summary.md`

These generated files are ignored by git and should not be committed.

Other agents may read security reports, but should not:

- edit scanner pattern rules without explicit security-agent ownership
- suppress or downgrade findings without source-code verification
- modify `.github/workflows/security-agent.yml`
- modify `SKILL.md` or `.claude/commands/security-review.md` for non-security work

## Change Discipline

When code, configuration, dependency, workflow, or changelog changes are committed, let the GitHub Action run. Treat the generated report as the security agent's current view of the repository.

For CRITICAL and HIGH findings, inspect the referenced source before accepting the result. Static rules can produce false positives.

## Domain-Aware Scanning

The scanner detects active security domains before applying rules. Core, secrets, and code-quality checks always run. Web, mobile, embedded, pipeline, and AI/ML checks run only when the repository has matching architecture or dependency signals.

This keeps reports focused and prevents other agents from spending tokens on security areas that do not exist in the target project.

## Project Instruction Snippets

Copy `templates/CLAUDE_SECURITY_BOUNDARY.md` into a target repository's `CLAUDE.md` so Claude agents know not to duplicate security work.

Copy `templates/AGENTS_SECURITY_BOUNDARY.md` into a target repository's `AGENTS.md` so Codex agents follow the same boundary.
