"""
Optional dependency vulnerability audits.
Runs installed tools when available and normalizes results as scanner findings.
"""

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List


def run_dependency_audits(repo_path: Path, config: Dict[str, Any]) -> List[Dict[str, Any]]:
    audit_config = config.get('dependency_audit') or {}
    if not audit_config.get('enabled', True):
        return []

    tools = audit_config.get('tools') or ['pip-audit', 'npm-audit', 'osv-scanner']
    findings: List[Dict[str, Any]] = []

    if 'pip-audit' in tools and (repo_path / 'requirements.txt').exists():
        findings.extend(_run_pip_audit(repo_path))
    if 'npm-audit' in tools and (repo_path / 'package.json').exists():
        findings.extend(_run_npm_audit(repo_path))
    if 'osv-scanner' in tools:
        findings.extend(_run_osv_scanner(repo_path))

    return findings


def _run_pip_audit(repo_path: Path) -> List[Dict[str, Any]]:
    executable = shutil.which('pip-audit')
    if not executable:
        return [_tool_unavailable('pip-audit', 'requirements.txt')]

    result = _run_command([executable, '-r', 'requirements.txt', '--format', 'json'], repo_path)
    if not result['stdout']:
        return []

    try:
        data = json.loads(result['stdout'])
    except json.JSONDecodeError:
        return [_tool_error('pip-audit', result['stderr'] or 'Invalid JSON output')]

    findings = []
    for dependency in data.get('dependencies', []):
        package = dependency.get('name', 'unknown')
        version = dependency.get('version', 'unknown')
        for vuln in dependency.get('vulns', []):
            findings.append(_finding(
                tool='pip-audit',
                package=package,
                version=version,
                vuln_id=vuln.get('id', 'unknown'),
                description=vuln.get('description', 'Python dependency vulnerability detected.'),
                fix=', '.join(vuln.get('fix_versions') or []) or 'Upgrade to a non-vulnerable version.',
                file='requirements.txt',
            ))
    return findings


def _run_npm_audit(repo_path: Path) -> List[Dict[str, Any]]:
    executable = shutil.which('npm')
    if not executable:
        return [_tool_unavailable('npm audit', 'package.json')]

    result = _run_command([executable, 'audit', '--json'], repo_path)
    if not result['stdout']:
        return []

    try:
        data = json.loads(result['stdout'])
    except json.JSONDecodeError:
        return [_tool_error('npm audit', result['stderr'] or 'Invalid JSON output')]

    findings = []
    for package, advisory in (data.get('vulnerabilities') or {}).items():
        findings.append(_finding(
            tool='npm audit',
            package=package,
            version='unknown',
            vuln_id=advisory.get('via', ['unknown'])[0] if isinstance(advisory.get('via'), list) else 'unknown',
            description=advisory.get('title', 'Node dependency vulnerability detected.'),
            fix=advisory.get('fixAvailable') if isinstance(advisory.get('fixAvailable'), str) else 'Run npm audit fix where safe.',
            file='package.json',
            severity=_map_severity(advisory.get('severity')),
        ))
    return findings


def _run_osv_scanner(repo_path: Path) -> List[Dict[str, Any]]:
    executable = shutil.which('osv-scanner')
    if not executable:
        return []

    result = _run_command([executable, '--format', 'json', '.'], repo_path)
    if not result['stdout']:
        return []

    try:
        data = json.loads(result['stdout'])
    except json.JSONDecodeError:
        return [_tool_error('osv-scanner', result['stderr'] or 'Invalid JSON output')]

    findings = []
    for result_item in data.get('results', []):
        source = result_item.get('source', {})
        file_path = source.get('path', 'dependency manifest')
        for package in result_item.get('packages', []):
            pkg = package.get('package', {})
            for vuln in package.get('vulnerabilities', []):
                findings.append(_finding(
                    tool='osv-scanner',
                    package=pkg.get('name', 'unknown'),
                    version=package.get('version', 'unknown'),
                    vuln_id=vuln.get('id', 'unknown'),
                    description=vuln.get('summary', 'Dependency vulnerability detected by OSV.'),
                    fix='Upgrade to a fixed version listed by OSV.',
                    file=file_path,
                ))
    return findings


def _run_command(command: List[str], cwd: Path) -> Dict[str, str]:
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {'stdout': '', 'stderr': str(exc)}
    return {'stdout': completed.stdout, 'stderr': completed.stderr}


def _finding(tool: str, package: str, version: str, vuln_id: str, description: str, fix: Any, file: str, severity: str = 'HIGH') -> Dict[str, Any]:
    return {
        'id': f'DEP-{tool.upper().replace(" ", "-")}',
        'category': 'Dependency Security',
        'name': f'{package} vulnerable dependency',
        'severity': severity,
        'description': f'{description} ({vuln_id}, installed: {version})',
        'fix': str(fix),
        'file': file,
        'line': 0,
        'code': package,
        'context': f'{tool} reported {package} {version}: {vuln_id}',
        'owasp': 'A06:2021',
        'cwe': 'CWE-1104',
    }


def _tool_unavailable(tool: str, file: str) -> Dict[str, Any]:
    return {
        'id': f'DEP-TOOL-MISSING-{tool.upper().replace(" ", "-")}',
        'category': 'Dependency Security',
        'name': f'{tool} not installed',
        'severity': 'INFO',
        'description': f'{tool} is not available, so dependency audit for {file} was skipped.',
        'fix': f'Install {tool} in CI or disable it in .security-agent.yml.',
        'file': file,
        'line': 0,
        'code': '',
        'context': '',
        'owasp': 'A06:2021',
        'cwe': '',
    }


def _tool_error(tool: str, error: str) -> Dict[str, Any]:
    return {
        'id': f'DEP-TOOL-ERROR-{tool.upper().replace(" ", "-")}',
        'category': 'Dependency Security',
        'name': f'{tool} failed',
        'severity': 'INFO',
        'description': f'{tool} could not complete dependency audit.',
        'fix': 'Review tool installation and manifest validity.',
        'file': 'dependency manifest',
        'line': 0,
        'code': '',
        'context': error[:500],
        'owasp': 'A06:2021',
        'cwe': '',
    }


def _map_severity(value: Any) -> str:
    mapping = {
        'critical': 'CRITICAL',
        'high': 'HIGH',
        'moderate': 'MEDIUM',
        'medium': 'MEDIUM',
        'low': 'LOW',
    }
    return mapping.get(str(value).lower(), 'HIGH')
