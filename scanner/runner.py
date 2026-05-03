"""
Security Scanner Runner
Walks the codebase, applies all pattern checks, returns structured findings.
"""

import re
import os
from pathlib import Path
from typing import List, Dict, Any

from scanner.patterns.owasp import OWASP_PATTERNS
from scanner.patterns.secrets import SECRETS_PATTERNS
from scanner.patterns.web import WEB_PATTERNS
from scanner.patterns.mobile import MOBILE_PATTERNS
from scanner.patterns.embedded import EMBEDDED_PATTERNS
from scanner.patterns.pipeline import PIPELINE_PATTERNS
from scanner.patterns.ai_ml import AI_ML_PATTERNS
from scanner.patterns.code_quality import CODE_QUALITY_PATTERNS

ALL_PATTERNS = (
    OWASP_PATTERNS
    + SECRETS_PATTERNS
    + WEB_PATTERNS
    + MOBILE_PATTERNS
    + EMBEDDED_PATTERNS
    + PIPELINE_PATTERNS
    + AI_ML_PATTERNS
    + CODE_QUALITY_PATTERNS
)

SKIP_DIRS = {
    'node_modules', '.git', '__pycache__', '.pytest_cache',
    'venv', 'env', '.env', 'dist', 'build', 'target',
    '.gradle', '.idea', '.vscode', 'vendor', 'Pods',
    '.dart_tool', '.pub-cache', 'coverage', 'htmlcov',
    'eggs', '.eggs', 'site-packages', '.tox', 'migrations',
    '.mypy_cache', '.ruff_cache', 'jspm_packages',
}

BINARY_EXTENSIONS = {
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.svg',
    '.pdf', '.zip', '.tar', '.gz', '.rar', '.7z', '.exe',
    '.dll', '.so', '.dylib', '.class', '.jar', '.war', '.ear',
    '.pyc', '.pyo', '.bin', '.hex', '.elf', '.o', '.a',
    '.woff', '.woff2', '.ttf', '.eot', '.mp3', '.mp4',
    '.webm', '.avi', '.mov', '.lock',
}

MAX_FILE_SIZE = 500_000  # 500KB
MAX_LINE_LENGTH = 2000   # skip minified lines


class SecurityRunner:
    def __init__(self, repo_path: Path, project_info: dict):
        self.repo_path = repo_path
        self.project_info = project_info
        self.findings: List[Dict[str, Any]] = []
        self._compiled_patterns = {}
        self._precompile_patterns()

    def _precompile_patterns(self):
        for pattern_def in ALL_PATTERNS:
            pid = pattern_def['id']
            try:
                self._compiled_patterns[pid] = {
                    'main': re.compile(pattern_def['pattern'], re.IGNORECASE | re.MULTILINE),
                    'negative': re.compile(
                        pattern_def.get('negative_pattern', r'(?!x)x'),
                        re.IGNORECASE | re.MULTILINE
                    ) if pattern_def.get('negative_pattern') else None,
                }
            except re.error:
                pass  # skip malformed patterns

    def run_all_checks(self) -> List[Dict[str, Any]]:
        files = self.project_info.get('file_list', [])
        for filepath in files:
            self._scan_file(Path(filepath))
        return self._deduplicate(self.findings)

    def _scan_file(self, filepath: Path):
        # Skip binary files
        if filepath.suffix.lower() in BINARY_EXTENSIONS:
            return

        # Skip files too large
        try:
            size = filepath.stat().st_size
            if size > MAX_FILE_SIZE:
                return
        except (OSError, PermissionError):
            return

        # Skip dirs
        for part in filepath.parts:
            if part in SKIP_DIRS:
                return

        try:
            content = filepath.read_text(encoding='utf-8', errors='ignore')
        except (OSError, PermissionError):
            return

        lines = content.splitlines()
        ext = filepath.suffix.lower()
        filename = filepath.name

        for pattern_def in ALL_PATTERNS:
            # Filter by applicable languages
            applicable_langs = pattern_def.get('langs', 'all')
            if applicable_langs != 'all':
                # Check by extension or filename
                match_found = False
                for lang in applicable_langs:
                    if lang.startswith('.'):
                        if ext == lang:
                            match_found = True
                            break
                    else:
                        if filename == lang:
                            match_found = True
                            break
                if not match_found:
                    continue

            # File-level check (e.g., .env file existence)
            if pattern_def.get('file_check'):
                if re.match(pattern_def['pattern'], filename, re.IGNORECASE):
                    self._add_finding(pattern_def, filepath, 0, '.env file detected', content[:200])
                continue

            # Line-by-line scan for context
            pid = pattern_def['id']
            compiled = self._compiled_patterns.get(pid)
            if not compiled:
                continue

            for lineno, line in enumerate(lines, 1):
                if len(line) > MAX_LINE_LENGTH:
                    continue  # skip minified code

                if compiled['main'].search(line):
                    # Check negative pattern on surrounding context (5 lines)
                    if compiled['negative']:
                        context_start = max(0, lineno - 5)
                        context_end = min(len(lines), lineno + 5)
                        context = '\n'.join(lines[context_start:context_end])
                        if compiled['negative'].search(context):
                            continue  # negative pattern matched, likely handled

                    self._add_finding(pattern_def, filepath, lineno, line.strip(), self._get_context(lines, lineno))

    def _get_context(self, lines: list, lineno: int, context: int = 3) -> str:
        start = max(0, lineno - context - 1)
        end = min(len(lines), lineno + context)
        result = []
        for i, line in enumerate(lines[start:end], start + 1):
            marker = '>>>' if i == lineno else '   '
            result.append(f"{marker} {i:4d}: {line}")
        return '\n'.join(result)

    def _add_finding(self, pattern_def: dict, filepath: Path, lineno: int, line: str, context: str):
        # Relative path for cleaner output
        try:
            rel_path = filepath.relative_to(self.repo_path)
        except ValueError:
            rel_path = filepath

        finding = {
            'id': pattern_def['id'],
            'category': pattern_def['category'],
            'name': pattern_def['name'],
            'severity': pattern_def['severity'],
            'description': pattern_def['description'],
            'fix': pattern_def['fix'],
            'file': str(rel_path),
            'line': lineno,
            'code': line[:200],  # truncate long lines
            'context': context,
            'owasp': pattern_def.get('owasp', ''),
            'cwe': pattern_def.get('cwe', ''),
        }
        self.findings.append(finding)

    def _deduplicate(self, findings: list) -> list:
        """Remove duplicate findings (same id + file + line)."""
        seen = set()
        unique = []
        for f in findings:
            key = (f['id'], f['file'], f['line'])
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    @staticmethod
    def severity_order(severity: str) -> int:
        return {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}.get(severity, 5)

    def get_sorted_findings(self) -> list:
        return sorted(self.findings, key=lambda x: self.severity_order(x['severity']))
