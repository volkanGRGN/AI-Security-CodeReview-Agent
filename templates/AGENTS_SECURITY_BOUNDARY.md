# Security Agent Boundary

This project has a dedicated security agent. Non-security agents must not spend context on broad security review unless the user explicitly asks for it.

Do not perform OWASP audits, secret scans, KVKK/privacy audits, dependency security audits, or generated security reports during ordinary implementation work. Do not open large security reports or policy files such as `KVKK.md`, `security_report.md`, or `.security_findings.json` unless the task is security-specific.

After code is committed or pushed, let the security-agent workflow run. If the user asks for the result, read the latest security-agent report instead of starting a new scan.

Only the security agent should run `/security-review`, use `ai-security-code-review-agent`, change scanner rules, edit security workflows, or triage CRITICAL/HIGH findings.
