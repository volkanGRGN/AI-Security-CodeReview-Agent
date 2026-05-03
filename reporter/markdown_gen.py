"""
Markdown Report Generator
Produces a comprehensive, sectioned security report.
"""

from pathlib import Path
from datetime import datetime
from collections import defaultdict


SEVERITY_EMOJI = {
    'CRITICAL': '🔴',
    'HIGH':     '🟠',
    'MEDIUM':   '🟡',
    'LOW':      '🔵',
    'INFO':     '⚪',
}


class MarkdownReporter:
    def __init__(self, repo_path: Path, project_info: dict, findings: list):
        self.repo_path = repo_path
        self.project_info = project_info
        self.findings = findings
        self.sorted_findings = sorted(
            findings,
            key=lambda x: {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}.get(x['severity'], 5)
        )

    def generate(self, output_path: Path):
        sections = [
            self._header(),
            self._executive_summary(),
            self._project_overview(),
            self._severity_breakdown(),
            self._findings_by_severity('CRITICAL'),
            self._findings_by_severity('HIGH'),
            self._findings_by_severity('MEDIUM'),
            self._findings_by_severity('LOW'),
            self._findings_by_category(),
            self._owasp_coverage(),
            self._recommendations(),
            self._footer(),
        ]
        report = '\n\n'.join(s for s in sections if s)
        output_path.write_text(report, encoding='utf-8')

    # ─────────────────────────────────────────────

    def _header(self) -> str:
        return f"""# Security & Code Review Report

> **Project:** `{self.project_info['name']}`
> **Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
> **Agent:** AI Security & Code Review Agent v1.0
> **Total Findings:** {len(self.findings)}

---"""

    def _executive_summary(self) -> str:
        counts = defaultdict(int)
        for f in self.findings:
            counts[f['severity']] += 1

        critical = counts.get('CRITICAL', 0)
        high = counts.get('HIGH', 0)
        medium = counts.get('MEDIUM', 0)
        low = counts.get('LOW', 0)

        risk_level = 'LOW'
        if critical > 0:
            risk_level = 'CRITICAL'
        elif high > 3:
            risk_level = 'HIGH'
        elif high > 0 or medium > 5:
            risk_level = 'MEDIUM'

        summary = f"""## Executive Summary

| Severity | Count |
|----------|-------|
| 🔴 CRITICAL | {critical} |
| 🟠 HIGH | {high} |
| 🟡 MEDIUM | {medium} |
| 🔵 LOW | {low} |
| **Total** | **{len(self.findings)}** |

**Overall Risk Level: {risk_level}**"""

        if critical > 0:
            summary += f"\n\n> ⚠️ **{critical} CRITICAL issue(s) require immediate attention before any deployment.**"

        return summary

    def _project_overview(self) -> str:
        info = self.project_info
        langs = ', '.join(f"`{k}` ({v} files)" for k, v in list(info['languages'].items())[:6])
        frameworks = ', '.join(f"`{f}`" for f in info['frameworks'][:8]) or 'None detected'
        arch = ', '.join(f"`{a}`" for a in info['arch_types'])

        return f"""## Project Overview

| Property | Value |
|----------|-------|
| **Project Name** | {info['name']} |
| **Total Files Scanned** | {info['total_files']} |
| **Primary Language** | `{info['primary_language']}` |
| **Languages** | {langs} |
| **Frameworks** | {frameworks} |
| **Architecture Types** | {arch} |"""

    def _severity_breakdown(self) -> str:
        by_category = defaultdict(lambda: defaultdict(int))
        for f in self.findings:
            by_category[f['category']][f['severity']] += 1

        if not by_category:
            return ""

        rows = []
        for cat, severities in sorted(by_category.items()):
            c = severities.get('CRITICAL', 0)
            h = severities.get('HIGH', 0)
            m = severities.get('MEDIUM', 0)
            l = severities.get('LOW', 0)
            total = c + h + m + l
            rows.append(f"| {cat} | {c} | {h} | {m} | {l} | **{total}** |")

        table = '\n'.join(rows)
        return f"""## Findings by Category

| Category | Critical | High | Medium | Low | Total |
|----------|----------|------|--------|-----|-------|
{table}"""

    def _findings_by_severity(self, severity: str) -> str:
        filtered = [f for f in self.sorted_findings if f['severity'] == severity]
        if not filtered:
            return ""

        emoji = SEVERITY_EMOJI.get(severity, '')
        sections = [f"## {emoji} {severity} Severity Findings\n"]

        for i, f in enumerate(filtered, 1):
            section = f"""### {i}. {f['name']}

| Field | Value |
|-------|-------|
| **ID** | `{f['id']}` |
| **File** | `{f['file']}:{f['line']}` |
| **Category** | {f['category']} |"""

            if f.get('cwe'):
                section += f"\n| **CWE** | [{f['cwe']}](https://cwe.mitre.org/data/definitions/{f['cwe'].replace('CWE-', '')}.html) |"
            if f.get('owasp'):
                section += f"\n| **OWASP** | {f['owasp']} |"

            section += f"""

**Description:**
{f['description']}

**Vulnerable Code:**
```
{f.get('context', f.get('code', 'N/A'))}
```

**Remediation:**
{f['fix']}

---"""
            sections.append(section)

        return '\n'.join(sections)

    def _findings_by_category(self) -> str:
        by_category = defaultdict(list)
        for f in self.sorted_findings:
            by_category[f['category']].append(f)

        if not by_category:
            return ""

        lines = ["## All Findings by Category\n"]
        for cat in sorted(by_category.keys()):
            findings = by_category[cat]
            lines.append(f"### {cat}\n")
            lines.append("| Severity | ID | Name | File | Line |")
            lines.append("|----------|-----|------|------|------|")
            for f in findings:
                emoji = SEVERITY_EMOJI.get(f['severity'], '')
                lines.append(f"| {emoji} {f['severity']} | `{f['id']}` | {f['name']} | `{f['file']}` | {f['line']} |")
            lines.append("")

        return '\n'.join(lines)

    def _owasp_coverage(self) -> str:
        owasp_map = {
            'A01:2021': 'Broken Access Control',
            'A02:2021': 'Cryptographic Failures',
            'A03:2021': 'Injection',
            'A04:2021': 'Insecure Design',
            'A05:2021': 'Security Misconfiguration',
            'A06:2021': 'Vulnerable and Outdated Components',
            'A07:2021': 'Identification and Authentication Failures',
            'A08:2021': 'Software and Data Integrity Failures',
            'A09:2021': 'Security Logging and Monitoring Failures',
            'A10:2021': 'Server-Side Request Forgery (SSRF)',
        }

        owasp_counts = defaultdict(int)
        for f in self.findings:
            if f.get('owasp'):
                owasp_counts[f['owasp']] += 1

        lines = ["## OWASP Top 10 (2021) Coverage\n"]
        lines.append("| # | Category | Findings | Status |")
        lines.append("|---|----------|----------|--------|")

        for owasp_id, name in owasp_map.items():
            count = owasp_counts.get(owasp_id, 0)
            status = f"⚠️ {count} issue(s) found" if count > 0 else "✅ No issues detected"
            lines.append(f"| {owasp_id} | {name} | {count} | {status} |")

        return '\n'.join(lines)

    def _recommendations(self) -> str:
        critical = [f for f in self.findings if f['severity'] == 'CRITICAL']
        high = [f for f in self.findings if f['severity'] == 'HIGH']

        recs = ["## Recommendations\n"]

        if critical:
            recs.append("### Immediate Actions (Before Next Deploy)\n")
            for f in critical[:10]:
                recs.append(f"- **[{f['id']}]** `{f['file']}:{f['line']}` — {f['name']}: {f['fix'][:100]}...")

        if high:
            recs.append("\n### Short-term Actions (This Sprint)\n")
            for f in high[:10]:
                recs.append(f"- **[{f['id']}]** `{f['file']}:{f['line']}` — {f['name']}")

        recs.append("""
### General Security Best Practices

1. **Secrets Management**: Use environment variables or a secrets manager (HashiCorp Vault, AWS Secrets Manager). Run `git-secrets` or `truffleHog` in CI/CD.
2. **Dependency Security**: Run `npm audit`, `pip-audit`, `safety`, or `snyk` on every build. Pin all dependency versions.
3. **Authentication**: Use battle-tested libraries. Never roll your own auth. Implement MFA.
4. **Input Validation**: Validate at the API boundary using strict schemas (Pydantic, Joi, Zod).
5. **Logging**: Use structured logging. Never log sensitive data. Set up alerting on security events.
6. **Security Testing**: Add SAST to CI/CD. Run DAST (OWASP ZAP) against staging. Do regular pen tests.
7. **Code Review**: Require security-focused review for auth, crypto, and data handling changes.""")

        return '\n'.join(recs)

    def _footer(self) -> str:
        return f"""---

## About This Report

Generated by **AI Security & Code Review Agent** on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}.

This report is based on static analysis and pattern matching. It may contain false positives.
Always validate findings manually before taking action.

**References:**
- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [CWE List](https://cwe.mitre.org/data/index.html)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/)
- [OWASP IoT Top 10](https://owasp.org/www-project-internet-of-things/)"""
