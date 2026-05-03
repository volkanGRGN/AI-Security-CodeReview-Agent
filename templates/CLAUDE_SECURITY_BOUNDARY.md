# Security Agent Boundary

This project uses a dedicated security agent.

## Rule for Non-Security Agents

Do not perform broad security reviews, OWASP audits, secret scans, KVKK/privacy audits, dependency security audits, or security-report generation during ordinary feature, refactor, documentation, changelog, or bug-fix work.

Do not read large security policy/report files such as `KVKK.md`, `security_report.md`, `.security_findings.json`, or security workflow outputs unless the user explicitly asks for security analysis.

## What Other Agents Should Do

- Implement the requested task.
- Run normal tests/build/lint relevant to the task.
- Avoid changing security scanner rules, security workflows, or generated security reports.
- After commit/push, let the security agent workflow run automatically.
- If the user asks about security results, read the latest security agent report instead of starting a new full review.

## What Only the Security Agent Should Do

- Run `/security-review` or the `ai-security-code-review-agent` skill.
- Scan the repository for OWASP, secrets, web/mobile/embedded/pipeline, AI/ML, or code security patterns.
- Triage CRITICAL/HIGH findings.
- Produce or update security reports.
- Modify `.github/workflows/security-agent.yml`, scanner rules, or security-agent skill files.

## Token Discipline

Security analysis is intentionally centralized to avoid duplicate token spend. If security review seems useful but was not requested, mention that the security agent will run after push or ask the user whether to invoke it.
