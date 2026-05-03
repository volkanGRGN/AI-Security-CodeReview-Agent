"""
Security Scanner Runner
Walks the codebase, applies all pattern checks, returns structured findings.
"""

import re
import os
import fnmatch
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

PATTERN_GROUPS = {
    'core': OWASP_PATTERNS,
    'secrets': SECRETS_PATTERNS,
    'web': WEB_PATTERNS,
    'mobile': MOBILE_PATTERNS,
    'embedded': EMBEDDED_PATTERNS,
    'pipeline': PIPELINE_PATTERNS,
    'ai_ml': AI_ML_PATTERNS,
    'code_quality': CODE_QUALITY_PATTERNS,
}

SKIP_DIRS = {
    'node_modules', '.git', '__pycache__', '.pytest_cache',
    'venv', 'env', '.env', 'dist', 'build', 'target',
    '.gradle', '.idea', '.vscode', 'vendor', 'Pods',
    '.dart_tool', '.pub-cache', 'coverage', 'htmlcov',
    'eggs', '.eggs', 'site-packages', '.tox', 'migrations',
    '.mypy_cache', '.ruff_cache', 'jspm_packages',
    'fixtures', 'testdata', '.tmp',
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
    def __init__(self, repo_path: Path, project_info: dict, config: dict | None = None):
        self.repo_path = repo_path
        self.project_info = project_info
        self.config = config or {}
        self.findings: List[Dict[str, Any]] = []
        self._compiled_patterns = {}
        self._ignore_patterns = self._load_ignore_patterns()
        self.active_domains = project_info.get('security_domains') or ['core', 'secrets', 'code_quality']
        self.active_patterns = self._select_patterns()
        self.has_tests = self._detect_test_presence()
        self._precompile_patterns()

    def _select_patterns(self) -> List[Dict[str, Any]]:
        patterns = []
        for domain in self.active_domains:
            patterns.extend(PATTERN_GROUPS.get(domain, []))
        return patterns

    def _load_ignore_patterns(self) -> List[str]:
        ignore_file = self.repo_path / '.securityignore'
        if not ignore_file.exists():
            return list(self.config.get('ignore_patterns') or [])

        patterns = []
        try:
            for line in ignore_file.read_text(encoding='utf-8', errors='ignore').splitlines():
                stripped = line.strip()
                if stripped and not stripped.startswith('#'):
                    patterns.append(stripped.replace('\\', '/'))
        except (OSError, PermissionError):
            return []
        patterns.extend(self.config.get('ignore_patterns') or [])
        return patterns

    def _precompile_patterns(self):
        for pattern_def in self.active_patterns:
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
        if self._is_ignored(filepath):
            return

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

        try:
            rel_parts = filepath.relative_to(self.repo_path).parts
        except ValueError:
            rel_parts = filepath.parts

        # Skip dirs
        for part in rel_parts:
            if part in SKIP_DIRS:
                return

        try:
            content = filepath.read_text(encoding='utf-8', errors='ignore')
        except (OSError, PermissionError):
            return

        lines = content.splitlines()
        ext = filepath.suffix.lower()
        filename = filepath.name

        for pattern_def in self.active_patterns:
            if self._should_skip_pattern(pattern_def, filepath, rel_parts):
                continue

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

    def _detect_test_presence(self) -> bool:
        for candidate in self.project_info.get('file_list', []):
            try:
                rel_path = Path(candidate).relative_to(self.repo_path).as_posix().lower()
            except ValueError:
                rel_path = Path(candidate).as_posix().lower()
            name = Path(rel_path).name
            if (
                rel_path.startswith(('tests/', 'test/'))
                or '/tests/' in rel_path
                or name.startswith('test_')
                or name.endswith(('_test.py', '.test.js', '.spec.js', '.test.ts', '.spec.ts'))
            ):
                return True
        return False

    def _should_skip_pattern(self, pattern_def: dict, filepath: Path, rel_parts: tuple) -> bool:
        if pattern_def.get('id') != 'CQ-050':
            return False
        if self.has_tests:
            return True
        name = filepath.name.lower()
        rel_path = '/'.join(rel_parts).lower()
        return (
            'tests' in rel_parts
            or rel_path.startswith(('test/', 'tests/'))
            or name.startswith('test_')
            or name.endswith(('_test.py', '.test.js', '.spec.js', '.test.ts', '.spec.ts'))
        )

    def _is_ignored(self, filepath: Path) -> bool:
        try:
            rel_path = filepath.relative_to(self.repo_path).as_posix()
        except ValueError:
            rel_path = filepath.as_posix()

        for pattern in self._ignore_patterns:
            normalized = pattern.lstrip('/')
            if normalized.endswith('/'):
                if rel_path.startswith(normalized):
                    return True
                continue
            if fnmatch.fnmatch(rel_path, normalized):
                return True
            if fnmatch.fnmatch(rel_path, f'{normalized}/**'):
                return True
        return False

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
